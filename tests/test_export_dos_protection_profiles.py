"""Field-asserting tests for export_dos_protection_profiles() — issue #92 backfill.

Covers aggregate/classified typing, flood protection per protocol (via
_parse_flood_proto), and resource/session protection including the
invalid-number guards.
"""
from __future__ import annotations

from export.objects import export_dos_protection_profiles
from export_fixtures import vsys_root


def _profiles(inner: str) -> str:
    return f"<profiles><dos-protection>{inner}</dos-protection></profiles>"


class TestExportDosProtectionProfiles:
    def test_none_root(self):
        assert export_dos_protection_profiles(None) == []

    def test_missing_container(self):
        assert export_dos_protection_profiles(vsys_root("<profiles><dos-rules/></profiles>")) == []

    def test_classified_full_flood_and_resource(self):
        root = vsys_root(_profiles("""
        <entry name="dos-classified">
          <description>classified profile</description>
          <type><classified/></type>
          <flood>
            <tcp-syn>
              <enable>yes</enable>
              <red>
                <alarm-rate>1000</alarm-rate>
                <activate-rate>2000</activate-rate>
                <maximal-rate>3000</maximal-rate>
                <block><duration>300</duration></block>
              </red>
              <syn-cookies>
                <alarm-rate>500</alarm-rate>
                <activate-rate>1000</activate-rate>
                <maximal-rate>2000</maximal-rate>
              </syn-cookies>
            </tcp-syn>
            <udp><enable>no</enable></udp>
            <icmp><enable>yes</enable></icmp>
            <icmpv6><enable>no</enable></icmpv6>
            <other-ip><enable>yes</enable></other-ip>
          </flood>
          <resource>
            <sessions>
              <enabled>yes</enabled>
              <max-concurrent-limit>1000</max-concurrent-limit>
            </sessions>
          </resource>
        </entry>
        """))
        assert export_dos_protection_profiles(root) == [{
            "name": "dos-classified",
            "description": "classified profile",
            "type": "classified",
            "flood": {
                "tcp-syn": {
                    "enable": True,
                    "red": {"alarm-rate": 1000, "activate-rate": 2000,
                            "maximal-rate": 3000, "block": {"duration": 300}},
                    "syn-cookies": {"alarm-rate": 500, "activate-rate": 1000,
                                    "maximal-rate": 2000},
                },
                "udp": {"enable": False},
                "icmp": {"enable": True},
                "icmpv6": {"enable": False},
                "other-ip": {"enable": True},
            },
            "resource": {"sessions": {"enabled": True, "max-concurrent-limit": 1000}},
        }]

    def test_aggregate_default_and_explicit(self):
        root = vsys_root(_profiles("""
        <entry name="no-type"/>
        <entry name="explicit-aggregate"><type><aggregate/></type></entry>
        """))
        out = export_dos_protection_profiles(root)
        assert out[0] == {"name": "explicit-aggregate", "type": "aggregate"}
        assert out[1] == {"name": "no-type", "type": "aggregate"}

    def test_empty_flood_and_resource_omitted(self):
        root = vsys_root(_profiles("""
        <entry name="empty-sections">
          <flood><tcp-syn/></flood>
          <resource><sessions/></resource>
        </entry>
        <entry name="no-sessions"><resource/></entry>
        """))
        out = export_dos_protection_profiles(root)
        assert out[0] == {"name": "empty-sections", "type": "aggregate"}
        assert out[1] == {"name": "no-sessions", "type": "aggregate"}

    def test_invalid_numbers_skipped_and_sessions_disabled(self):
        root = vsys_root(_profiles("""
        <entry name="bad-numbers">
          <flood>
            <tcp-syn>
              <red>
                <alarm-rate>lots</alarm-rate>
                <activate-rate>2000</activate-rate>
                <block><duration>forever</duration></block>
              </red>
            </tcp-syn>
          </flood>
          <resource>
            <sessions>
              <enabled>no</enabled>
              <max-concurrent-limit>many</max-concurrent-limit>
            </sessions>
          </resource>
        </entry>
        """))
        assert export_dos_protection_profiles(root) == [{
            "name": "bad-numbers",
            "type": "aggregate",
            "flood": {"tcp-syn": {"red": {"activate-rate": 2000}}},
            "resource": {"sessions": {"enabled": False}},
        }]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-dos"/><entry name="a-dos"/>'))
        assert [p["name"] for p in export_dos_protection_profiles(root)] == ["a-dos", "Z-dos"]
