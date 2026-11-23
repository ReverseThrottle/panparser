"""Unit tests for export_edls() — issue #79 coverage backfill.

Covers ip/domain/url EDL types, recurring schedules (five-minute, hourly,
daily, weekly, monthly with partial fields), exception lists, entries
without a usable type (skipped), and name sorting.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_edls


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _edls(inner: str) -> str:
    return f"<external-list>{inner}</external-list>"


class TestExportEdls:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_edls(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_edls(_vsys("<address/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_edls(_vsys(_edls(""))) == []

    def test_ip_edl_five_minute_and_exceptions(self):
        xml = _edls("""
        <entry name="block-ips">
          <type>
            <ip>
              <url>https://lists.example.com/blocked-ips.txt</url>
              <recurring><five-minute/></recurring>
              <exception-list>
                <member>10.0.0.1</member>
                <member>10.0.0.2</member>
              </exception-list>
            </ip>
          </type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert out == [{
            "name": "block-ips",
            "type": {"ip": {
                "url": "https://lists.example.com/blocked-ips.txt",
                "recurring": {"five_minute": {}},
                "exception_list": ["10.0.0.1", "10.0.0.2"],
            }},
        }]

    def test_domain_edl_hourly(self):
        xml = _edls("""
        <entry name="bad-domains">
          <type>
            <domain>
              <url>https://lists.example.com/domains.txt</url>
              <recurring><hourly/></recurring>
            </domain>
          </type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert out[0]["type"] == {"domain": {
            "url": "https://lists.example.com/domains.txt",
            "recurring": {"hourly": {}},
        }}

    def test_url_edl_daily_at(self):
        xml = _edls("""
        <entry name="mal-urls">
          <type>
            <url>
              <url>https://lists.example.com/urls.txt</url>
              <recurring><daily><at>03</at></daily></recurring>
            </url>
          </type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert out[0]["type"]["url"]["recurring"] == {"daily": {"at": "03"}}

    def test_daily_without_at(self):
        xml = _edls("""
        <entry name="daily-noat">
          <type><ip><recurring><daily/></recurring></ip></type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert out[0]["type"]["ip"]["recurring"] == {"daily": {}}

    def test_weekly_full(self):
        xml = _edls("""
        <entry name="weekly-full">
          <type>
            <ip>
              <recurring>
                <weekly><day-of-week>monday</day-of-week><at>02</at></weekly>
              </recurring>
            </ip>
          </type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert out[0]["type"]["ip"]["recurring"] == {
            "weekly": {"day_of_week": "monday", "at": "02"},
        }

    def test_weekly_day_only_and_at_only(self):
        xml = _edls("""
        <entry name="weekly-dow">
          <type><ip><recurring><weekly><day-of-week>friday</day-of-week></weekly></recurring></ip></type>
        </entry>
        <entry name="weekly-at">
          <type><ip><recurring><weekly><at>23</at></weekly></recurring></ip></type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        by_name = {e["name"]: e for e in out}
        assert by_name["weekly-dow"]["type"]["ip"]["recurring"] == {
            "weekly": {"day_of_week": "friday"},
        }
        assert by_name["weekly-at"]["type"]["ip"]["recurring"] == {"weekly": {"at": "23"}}

    def test_monthly_full_and_partial(self):
        xml = _edls("""
        <entry name="monthly-full">
          <type>
            <ip>
              <recurring>
                <monthly><day-of-month>15</day-of-month><at>04</at></monthly>
              </recurring>
            </ip>
          </type>
        </entry>
        <entry name="monthly-dom">
          <type><ip><recurring><monthly><day-of-month>1</day-of-month></monthly></recurring></ip></type>
        </entry>
        <entry name="monthly-at">
          <type><ip><recurring><monthly><at>00</at></monthly></recurring></ip></type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        by_name = {e["name"]: e for e in out}
        assert by_name["monthly-full"]["type"]["ip"]["recurring"] == {
            "monthly": {"day_of_month": "15", "at": "04"},
        }
        assert by_name["monthly-dom"]["type"]["ip"]["recurring"] == {
            "monthly": {"day_of_month": "1"},
        }
        assert by_name["monthly-at"]["type"]["ip"]["recurring"] == {"monthly": {"at": "00"}}

    def test_edl_without_url_or_recurring(self):
        xml = _edls('<entry name="bare-ip"><type><ip/></type></entry>')
        out = export_edls(_vsys(xml))
        assert out == [{"name": "bare-ip", "type": {"ip": {}}}]

    def test_empty_recurring_container_omitted(self):
        xml = _edls('<entry name="empty-rec"><type><ip><recurring/></ip></type></entry>')
        out = export_edls(_vsys(xml))
        assert out == [{"name": "empty-rec", "type": {"ip": {}}}]

    def test_entry_without_type_skipped(self):
        xml = _edls('<entry name="no-type"/>')
        assert export_edls(_vsys(xml)) == []

    def test_entry_with_unsupported_type_skipped(self):
        """Predefined/read-only lists carry no ip/domain/url child and are
        skipped rather than exported as empty objects."""
        xml = _edls('<entry name="predefined"><type><predefined/></type></entry>')
        assert export_edls(_vsys(xml)) == []

    def test_first_supported_type_wins(self):
        xml = _edls("""
        <entry name="multi-type">
          <type>
            <ip><url>https://lists.example.com/ips.txt</url></ip>
            <domain><url>https://lists.example.com/domains.txt</url></domain>
          </type>
        </entry>
        """)
        out = export_edls(_vsys(xml))
        assert list(out[0]["type"].keys()) == ["ip"]

    def test_sorted_case_insensitive(self):
        xml = _edls("""
        <entry name="Z-list"><type><ip/></type></entry>
        <entry name="a-list"><type><ip/></type></entry>
        """)
        out = export_edls(_vsys(xml))
        assert [e["name"] for e in out] == ["a-list", "Z-list"]


def _scoped(vsys_inner: str = "", shared_inner: str = ""):
    """Return (vsys_root, shared_root) with EDLs in each scope."""
    vsys = _vsys(_edls(vsys_inner)) if vsys_inner else _vsys("")
    shared = ET.fromstring(f"<shared>{_edls(shared_inner)}</shared>") if shared_inner else None
    return vsys, shared


_IP = '<entry name="{n}"><type><ip><url>https://x.example/{n}.txt</url></ip></type></entry>'
_DOM = '<entry name="{n}"><type><domain><url>https://x.example/{n}.txt</url></domain></type></entry>'
_URL = '<entry name="{n}"><type><url><url>https://x.example/{n}.txt</url></url></type></entry>'


class TestExportEdlsSharedScope:
    """Panorama keeps EDLs under <shared>; export must merge vsys + shared."""

    def test_shared_only_edls_exported(self):
        vsys, shared = _scoped(shared_inner=_IP.format(n="sh-ip"))
        out = export_edls(vsys, shared)
        assert [e["name"] for e in out] == ["sh-ip"]

    def test_shared_only_with_vsys_root_none(self):
        _, shared = _scoped(shared_inner=_IP.format(n="sh-ip"))
        assert [e["name"] for e in export_edls(None, shared)] == ["sh-ip"]

    def test_vsys_only_with_shared_root_present(self):
        vsys, _ = _scoped(vsys_inner=_IP.format(n="v-ip"))
        shared = ET.fromstring("<shared/>")
        assert [e["name"] for e in export_edls(vsys, shared)] == ["v-ip"]

    def test_vsys_only_without_shared_arg_unchanged(self):
        vsys, _ = _scoped(vsys_inner=_IP.format(n="v-ip"))
        assert [e["name"] for e in export_edls(vsys)] == ["v-ip"]

    def test_all_types_from_shared(self):
        inner = _IP.format(n="i") + _DOM.format(n="d") + _URL.format(n="u")
        vsys, shared = _scoped(shared_inner=inner)
        out = {e["name"]: e for e in export_edls(vsys, shared)}
        assert set(out["i"]["type"]) == {"ip"}
        assert set(out["d"]["type"]) == {"domain"}
        assert set(out["u"]["type"]) == {"url"}

    def test_both_scopes_merged_and_sorted(self):
        vsys, shared = _scoped(
            vsys_inner=_IP.format(n="b-v"), shared_inner=_DOM.format(n="a-s"))
        assert [e["name"] for e in export_edls(vsys, shared)] == ["a-s", "b-v"]

    def test_name_collision_kept_once_per_scope(self):
        """#107 convention: same-name entries in both scopes appear twice."""
        vsys, shared = _scoped(
            vsys_inner=_IP.format(n="dup"), shared_inner=_DOM.format(n="dup"))
        out = export_edls(vsys, shared)
        assert [e["name"] for e in out] == ["dup", "dup"]
        assert list(out[0]["type"]) == ["ip"]  # vsys first
        assert list(out[1]["type"]) == ["domain"]

    def test_predefined_in_shared_still_skipped(self):
        vsys, shared = _scoped(
            shared_inner='<entry name="pre"><type><predefined/></type></entry>'
                         + _IP.format(n="real"))
        assert [e["name"] for e in export_edls(vsys, shared)] == ["real"]
