"""Unit tests for export_service_groups() — issue #79 coverage backfill."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_service_groups


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _shared(xml_str: str):
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportServiceGroups:
    def test_returns_empty_when_both_roots_none(self):
        assert export_service_groups(None, None) == []

    def test_returns_empty_when_no_container(self):
        assert export_service_groups(_vsys("<service/>"), None) == []

    def test_returns_empty_when_no_entries(self):
        assert export_service_groups(_vsys("<service-group/>"), None) == []

    def test_group_with_members_and_tags(self):
        xml = """
        <service-group>
          <entry name="web-services">
            <members>
              <member>service-http</member>
              <member>service-https</member>
            </members>
            <tag><member>web</member></tag>
          </entry>
        </service-group>
        """
        out = export_service_groups(_vsys(xml), None)
        assert out == [{
            "name": "web-services",
            "members": ["service-http", "service-https"],
            "tag": ["web"],
        }]

    def test_group_without_tags_omits_tag_key(self):
        xml = """
        <service-group>
          <entry name="plain"><members><member>svc-a</member></members></entry>
        </service-group>
        """
        out = export_service_groups(_vsys(xml), None)
        assert out == [{"name": "plain", "members": ["svc-a"]}]

    def test_empty_group_keeps_empty_members_list(self):
        xml = '<service-group><entry name="empty"/></service-group>'
        assert export_service_groups(_vsys(xml), None) == [{"name": "empty", "members": []}]

    def test_shared_and_vsys_merged_sorted(self):
        vsys_xml = """
        <service-group>
          <entry name="z-group"><members><member>a</member></members></entry>
        </service-group>
        """
        shared_xml = """
        <service-group>
          <entry name="A-group"><members><member>b</member></members></entry>
        </service-group>
        """
        out = export_service_groups(_vsys(vsys_xml), _shared(shared_xml))
        assert [g["name"] for g in out] == ["A-group", "z-group"]
