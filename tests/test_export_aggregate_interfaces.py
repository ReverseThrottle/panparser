"""Unit tests for export_aggregate_interfaces() virtual-wire/ha/tap handling.

Regression tests for issue #41: export_aggregate_interfaces() had the same
virtual-wire/ha/tap gap that export_ethernet_interfaces() had before it was
fixed for issue #19 (PR #37).

NOTE: None of the real PAN-OS config samples in this repo have an AE
(aggregate-ethernet) interface actually configured in virtual-wire, ha, or
tap mode, so every fixture below is hand-built synthetic XML rather than a
real capture. If a real AE-vwire/ha/tap config sample ever becomes
available, these fixtures should be re-verified against it.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_aggregate_interfaces


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportAggregateInterfacesModes:
    def test_layer3_interface(self):
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae1">
              <layer3>
                <ip>
                  <entry name="10.0.0.1/24"/>
                </ip>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents == [{"name": "ae1", "layer3": {"ip": [{"name": "10.0.0.1/24"}]}}]
        assert subs == []
        assert notes == []

    def test_layer2_interface(self):
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae2"><layer2/></entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents == [{"name": "ae2", "layer2": {}}]
        assert notes == []

    def test_virtual_wire_interface_is_tagged_not_blank(self):
        """Regression test for issue #41: virtual-wire AE interfaces were
        exported as a bare {"name": ...} dict with no indication of their
        configured mode, mirroring the ethernet bug fixed in issue #19."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae1"><virtual-wire/></entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents == [{"name": "ae1", "virtual_wire": {}}]
        assert parents[0] != {"name": "ae1"}
        assert len(notes) == 1
        assert "ae1" in notes[0]
        assert "virtual-wire" in notes[0]

    def test_ha_interface_is_tagged_not_blank(self):
        """Regression test for issue #41: ha-mode AE interfaces were exported
        as a bare {"name": ...} dict with no indication of their configured
        mode, mirroring the ethernet bug fixed in issue #19."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae2"><ha/></entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents == [{"name": "ae2", "ha": {}}]
        assert parents[0] != {"name": "ae2"}
        assert len(notes) == 1
        assert "ae2" in notes[0]
        assert "HA mode" in notes[0]

    def test_tap_interface_is_tagged_and_emits_note(self):
        """Unlike ethernet, the SCM SDK's aggregate interface model
        (AggregateInterfaceBaseModel) has no dedicated tap field at all --
        only layer2/layer3 are supported. So for AE interfaces, tap mode
        must also be tagged with a migration note, unlike the ethernet
        case where tap maps directly to EthernetTap with no note needed."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae3"><tap/></entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents == [{"name": "ae3", "tap": {}}]
        assert parents[0] != {"name": "ae3"}
        assert len(notes) == 1
        assert "ae3" in notes[0]
        assert "tap" in notes[0]

    def test_mixed_modes_only_unsupported_modes_emit_notes(self):
        """Mirrors the ethernet mixed-mode regression test: several AE
        interfaces in virtual-wire/ha/tap mode alongside normal layer3
        interfaces, confirming only the unsupported modes emit notes."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae1"><virtual-wire/></entry>
            <entry name="ae2"><virtual-wire/></entry>
            <entry name="ae3"><ha/></entry>
            <entry name="ae4"><tap/></entry>
            <entry name="ae7">
              <layer3>
                <ip><entry name="192.168.1.1/24"/></ip>
              </layer3>
            </entry>
            <entry name="ae8">
              <layer3>
                <ip><entry name="192.168.2.1/24"/></ip>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert len(parents) == 6
        by_name = {p["name"]: p for p in parents}
        assert by_name["ae1"]["virtual_wire"] == {}
        assert by_name["ae2"]["virtual_wire"] == {}
        assert by_name["ae3"]["ha"] == {}
        assert by_name["ae4"]["tap"] == {}
        assert "layer3" in by_name["ae7"]
        assert "layer3" in by_name["ae8"]
        assert len(notes) == 4

    def test_comment_preserved_on_virtual_wire_interface(self):
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae1">
              <comment>Vwire trust side</comment>
              <virtual-wire/>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert parents[0]["comment"] == "Vwire trust side"
        assert parents[0]["virtual_wire"] == {}

    def test_layer3_takes_precedence_when_multiple_children_present(self):
        """layer3/layer2 checks happen first; this documents the existing
        precedence order and ensures the new virtual-wire/ha/tap checks were
        added without disturbing it."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae9">
              <layer3><ip><entry name="10.1.1.1/24"/></ip></layer3>
              <ha/>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs, notes = export_aggregate_interfaces(_net(xml))
        assert "layer3" in parents[0]
        assert "ha" not in parents[0]
        assert notes == []
