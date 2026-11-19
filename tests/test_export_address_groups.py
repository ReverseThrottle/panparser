"""Unit tests for export_address_groups() — issue #79 coverage backfill.

Static groups keep their member list; dynamic groups export the tag filter as
dynamic_filter. Static wins when both are present (exporter's elif).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_address_groups


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _shared(xml_str: str):
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportAddressGroups:
    def test_returns_empty_when_both_roots_none(self):
        assert export_address_groups(None, None) == []

    def test_returns_empty_when_no_container(self):
        assert export_address_groups(_vsys("<address/>"), None) == []

    def test_returns_empty_when_no_entries(self):
        assert export_address_groups(_vsys("<address-group/>"), None) == []

    def test_static_group_full_fields(self):
        xml = """
        <address-group>
          <entry name="web-servers">
            <static><member>web-1</member><member>web-2</member></static>
            <description>Frontend pool</description>
            <tag><member>prod</member></tag>
          </entry>
        </address-group>
        """
        out = export_address_groups(_vsys(xml), None)
        assert out == [{
            "name": "web-servers",
            "static": ["web-1", "web-2"],
            "description": "Frontend pool",
            "tag": ["prod"],
        }]

    def test_dynamic_group_exports_filter(self):
        xml = """
        <address-group>
          <entry name="dyn-prod">
            <dynamic><filter>'prod' and 'dmz'</filter></dynamic>
          </entry>
        </address-group>
        """
        out = export_address_groups(_vsys(xml), None)
        assert out == [{"name": "dyn-prod", "dynamic_filter": "'prod' and 'dmz'"}]

    def test_static_wins_over_dynamic_when_both_present(self):
        xml = """
        <address-group>
          <entry name="both">
            <static><member>addr-1</member></static>
            <dynamic><filter>'tag'</filter></dynamic>
          </entry>
        </address-group>
        """
        out = export_address_groups(_vsys(xml), None)
        assert out == [{"name": "both", "static": ["addr-1"]}]

    def test_group_without_members_or_filter(self):
        xml = '<address-group><entry name="empty"/></address-group>'
        assert export_address_groups(_vsys(xml), None) == [{"name": "empty"}]

    def test_empty_dynamic_filter_omitted(self):
        xml = """
        <address-group>
          <entry name="empty-filter"><dynamic><filter></filter></dynamic></entry>
        </address-group>
        """
        assert export_address_groups(_vsys(xml), None) == [{"name": "empty-filter"}]

    def test_shared_and_vsys_merged_sorted(self):
        vsys_xml = """
        <address-group>
          <entry name="z-group"><static><member>a</member></static></entry>
        </address-group>
        """
        shared_xml = """
        <address-group>
          <entry name="A-group"><static><member>b</member></static></entry>
        </address-group>
        """
        out = export_address_groups(_vsys(vsys_xml), _shared(shared_xml))
        assert [g["name"] for g in out] == ["A-group", "z-group"]
