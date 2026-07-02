"""Unit tests for export_virtual_wires()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_virtual_wires


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportVirtualWires:
    def test_returns_empty_when_network_root_none(self):
        assert export_virtual_wires(None) == []

    def test_returns_empty_when_no_virtual_wire_element(self):
        assert export_virtual_wires(_net("<zone/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_virtual_wires(_net("<virtual-wire/>")) == []

    def test_minimal_vwire_name_only(self):
        xml = '<virtual-wire><entry name="Basic"/></virtual-wire>'
        result = export_virtual_wires(_net(xml))
        assert result == [{"name": "Basic"}]

    def test_repro_from_issue_20(self):
        """Matches the network/virtual-wire/entry snippet from UA-HAARP-Cofnig_20260605.xml."""
        xml = """
        <virtual-wire>
          <entry name="default-vwire">
            <interface1>ethernet1/1</interface1>
            <interface2>ethernet1/2</interface2>
          </entry>
        </virtual-wire>
        """
        result = export_virtual_wires(_net(xml))
        assert result == [
            {
                "name": "default-vwire",
                "interface1": "ethernet1/1",
                "interface2": "ethernet1/2",
            }
        ]

    def test_tag_allowed_and_multi_vlan(self):
        xml = """
        <virtual-wire>
          <entry name="tagged-vwire">
            <interface1>ethernet1/3</interface1>
            <interface2>ethernet1/4</interface2>
            <tag-allowed>10-20</tag-allowed>
            <multi-vlan>yes</multi-vlan>
          </entry>
        </virtual-wire>
        """
        result = export_virtual_wires(_net(xml))
        assert result[0]["tag_allowed"] == "10-20"
        assert result[0]["multi_vlan"] is True

    def test_multi_vlan_no_maps_to_false(self):
        xml = """
        <virtual-wire>
          <entry name="vw">
            <multi-vlan>no</multi-vlan>
          </entry>
        </virtual-wire>
        """
        result = export_virtual_wires(_net(xml))
        assert result[0]["multi_vlan"] is False

    def test_absent_optional_fields_not_included(self):
        xml = '<virtual-wire><entry name="vw"><interface1>ethernet1/1</interface1></entry></virtual-wire>'
        result = export_virtual_wires(_net(xml))
        assert "interface2" not in result[0]
        assert "tag_allowed" not in result[0]
        assert "multi_vlan" not in result[0]

    def test_multiple_vwires_sorted_by_name(self):
        xml = """
        <virtual-wire>
          <entry name="Zebra-vwire">
            <interface1>ethernet1/5</interface1>
            <interface2>ethernet1/6</interface2>
          </entry>
          <entry name="Alpha-vwire">
            <interface1>ethernet1/1</interface1>
            <interface2>ethernet1/2</interface2>
          </entry>
        </virtual-wire>
        """
        result = export_virtual_wires(_net(xml))
        assert [v["name"] for v in result] == ["Alpha-vwire", "Zebra-vwire"]
