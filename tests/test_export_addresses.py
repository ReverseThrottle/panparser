"""Unit tests for export_addresses() — issue #79 coverage backfill.

Exercises all four PAN-OS address types (ip-netmask / ip-range / ip-wildcard /
fqdn), description/tag handling, vsys+shared merging and name sorting.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_addresses


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _shared(xml_str: str):
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportAddresses:
    def test_returns_empty_when_both_roots_none(self):
        assert export_addresses(None, None) == []

    def test_returns_empty_when_no_address_container(self):
        assert export_addresses(_vsys("<address-group/>"), None) == []

    def test_returns_empty_when_container_has_no_entries(self):
        assert export_addresses(_vsys("<address/>"), _shared("<address/>")) == []

    def test_ip_netmask_full_fields(self):
        xml = """
        <address>
          <entry name="web-server">
            <ip-netmask>10.1.2.3/32</ip-netmask>
            <description>Primary web server</description>
            <tag><member>prod</member><member>dmz</member></tag>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{
            "name": "web-server",
            "ip_netmask": "10.1.2.3/32",
            "description": "Primary web server",
            "tag": ["prod", "dmz"],
        }]

    def test_ip_range(self):
        xml = """
        <address>
          <entry name="dhcp-pool">
            <ip-range>10.1.2.10-10.1.2.99</ip-range>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{"name": "dhcp-pool", "ip_range": "10.1.2.10-10.1.2.99"}]

    def test_fqdn(self):
        xml = """
        <address>
          <entry name="update-server">
            <fqdn>updates.example.com</fqdn>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{"name": "update-server", "fqdn": "updates.example.com"}]

    def test_ip_wildcard(self):
        xml = """
        <address>
          <entry name="wildcard-net">
            <ip-wildcard>10.20.0.0/0.0.255.255</ip-wildcard>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{"name": "wildcard-net", "ip_wildcard": "10.20.0.0/0.0.255.255"}]

    def test_first_matching_type_wins(self):
        """_ADDR_TYPE_MAP iteration order: ip-netmask beats later types."""
        xml = """
        <address>
          <entry name="multi">
            <ip-netmask>10.0.0.1/32</ip-netmask>
            <fqdn>should-not-win.example.com</fqdn>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{"name": "multi", "ip_netmask": "10.0.0.1/32"}]

    def test_entry_without_type_keeps_name_only(self):
        xml = '<address><entry name="bare"/></address>'
        assert export_addresses(_vsys(xml), None) == [{"name": "bare"}]

    def test_empty_description_and_tags_omitted(self):
        xml = """
        <address>
          <entry name="no-meta">
            <ip-netmask>10.0.0.2/32</ip-netmask>
            <description></description>
            <tag/>
          </entry>
        </address>
        """
        out = export_addresses(_vsys(xml), None)
        assert out == [{"name": "no-meta", "ip_netmask": "10.0.0.2/32"}]

    def test_shared_entries_included(self):
        xml = """
        <address>
          <entry name="shared-addr"><fqdn>shared.example.com</fqdn></entry>
        </address>
        """
        out = export_addresses(None, _shared(xml))
        assert out == [{"name": "shared-addr", "fqdn": "shared.example.com"}]

    def test_vsys_and_shared_merged_and_sorted_case_insensitive(self):
        vsys_xml = """
        <address>
          <entry name="Zebra"><ip-netmask>10.0.0.3/32</ip-netmask></entry>
          <entry name="apple"><ip-netmask>10.0.0.4/32</ip-netmask></entry>
        </address>
        """
        shared_xml = """
        <address>
          <entry name="Mango"><ip-netmask>10.0.0.5/32</ip-netmask></entry>
        </address>
        """
        out = export_addresses(_vsys(vsys_xml), _shared(shared_xml))
        assert [a["name"] for a in out] == ["apple", "Mango", "Zebra"]
