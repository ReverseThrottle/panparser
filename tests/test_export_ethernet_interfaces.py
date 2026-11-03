"""Unit tests for export_ethernet_interfaces()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_ethernet_interfaces


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportEthernetInterfaces:
    def test_returns_empty_when_network_root_none(self):
        assert export_ethernet_interfaces(None) == ([], [], [])

    def test_returns_empty_when_no_ethernet_container(self):
        assert export_ethernet_interfaces(_net("<interface/>")) == ([], [], [])

    def test_layer3_interface(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/8">
              <layer3>
                <ip>
                  <entry name="10.0.0.1/24"/>
                </ip>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [{"name": "ethernet1/8", "layer3": {"ip": [{"name": "10.0.0.1/24"}]}}]
        assert subs == []
        assert notes == []

    def test_layer2_interface(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/4"><layer2/></entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [{"name": "ethernet1/4", "layer2": {}}]
        assert notes == []

    def test_virtual_wire_interface_is_tagged_not_blank(self):
        """Regression test for issue #19: virtual-wire interfaces were exported
        as a bare {"name": ...} dict with no indication of their configured mode."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><virtual-wire/></entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [{"name": "ethernet1/1", "virtual_wire": {}}]
        assert parents[0] != {"name": "ethernet1/1"}
        assert len(notes) == 1
        assert "ethernet1/1" in notes[0]
        assert "virtual-wire" in notes[0]

    def test_ha_interface_is_tagged_not_blank(self):
        """Regression test for issue #19: ha-mode interfaces were exported
        as a bare {"name": ...} dict with no indication of their configured mode."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/3"><ha/></entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [{"name": "ethernet1/3", "ha": {}}]
        assert parents[0] != {"name": "ethernet1/3"}
        assert len(notes) == 1
        assert "ethernet1/3" in notes[0]
        assert "HA mode" in notes[0]

    def test_tap_interface(self):
        """Tap mode maps directly to the SCM SDK's EthernetTap model, so it
        gets tagged but does not need a migration note."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/5"><tap/></entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [{"name": "ethernet1/5", "tap": {}}]
        assert notes == []

    def test_mixed_modes_only_unsupported_modes_emit_notes(self):
        """Matches the real-world repro from issue #19: 5 ethernet interfaces,
        3 of which (virtual-wire x2, ha x1) previously lost their mode entirely."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/1"><virtual-wire/></entry>
            <entry name="ethernet1/2"><virtual-wire/></entry>
            <entry name="ethernet1/3"><ha/></entry>
            <entry name="ethernet1/7">
              <layer3>
                <ip><entry name="192.168.1.1/24"/></ip>
              </layer3>
            </entry>
            <entry name="ethernet1/8">
              <layer3>
                <ip><entry name="192.168.2.1/24"/></ip>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert len(parents) == 5
        by_name = {p["name"]: p for p in parents}
        assert by_name["ethernet1/1"]["virtual_wire"] == {}
        assert by_name["ethernet1/2"]["virtual_wire"] == {}
        assert by_name["ethernet1/3"]["ha"] == {}
        assert "layer3" in by_name["ethernet1/7"]
        assert "layer3" in by_name["ethernet1/8"]
        assert len(notes) == 3

    def test_comment_preserved_on_virtual_wire_interface(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <comment>Vwire trust side</comment>
              <virtual-wire/>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0]["comment"] == "Vwire trust side"
        assert parents[0]["virtual_wire"] == {}

    def test_layer3_takes_precedence_when_multiple_children_present(self):
        """layer3/layer2 checks happen first; this documents the existing
        precedence order and ensures the new virtual-wire/ha/tap checks were
        added without disturbing it."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/9">
              <layer3><ip><entry name="10.1.1.1/24"/></ip></layer3>
              <ha/>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert "layer3" in parents[0]
        assert "ha" not in parents[0]
        assert notes == []


class TestEthernetMgmtProfileAndLldp:
    """REV-135(a): per-port interface management profile + LLDP enable."""

    XML = """
    <interface>
      <ethernet>
        <entry name="ethernet1/8">
          <layer3>
            <interface-management-profile>RemoteVPN-Mgmt</interface-management-profile>
            <lldp><enable>no</enable></lldp>
          </layer3>
        </entry>
        <entry name="ethernet1/1">
          <layer2>
            <lldp><enable>yes</enable><profile>LLDP-Profile-Default</profile></lldp>
          </layer2>
        </entry>
      </ethernet>
    </interface>
    """

    def test_layer3_mgmt_profile_and_lldp_disabled(self):
        parents, subs, notes = export_ethernet_interfaces(_net(self.XML))
        assert parents[0] == {
            "name": "ethernet1/8",
            "layer3": {
                "interface_management_profile": "RemoteVPN-Mgmt",
                "lldp": {"enable": False},
            },
        }
        assert subs == []

    def test_layer2_lldp_enabled_with_profile_warns(self):
        parents, subs, notes = export_ethernet_interfaces(_net(self.XML))
        assert parents[1] == {"name": "ethernet1/1", "layer2": {"lldp": {"enable": True}}}
        assert len(notes) == 1
        assert "ethernet1/1" in notes[0]
        assert "LLDP-Profile-Default" in notes[0]

    def test_layer3_lldp_profile_warns(self):
        xml = """
        <interface><ethernet>
          <entry name="ethernet1/3"><layer3>
            <lldp><enable>yes</enable><profile>P1</profile></lldp>
          </layer3></entry>
        </ethernet></interface>
        """
        parents, _, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0]["layer3"] == {"lldp": {"enable": True}}
        assert len(notes) == 1
        assert "ethernet1/3" in notes[0] and "P1" in notes[0]

    def test_plain_ports_unchanged(self):
        xml = """
        <interface><ethernet>
          <entry name="ethernet1/2"><layer3/></entry>
          <entry name="ethernet1/4"><layer2/></entry>
        </ethernet></interface>
        """
        parents, subs, notes = export_ethernet_interfaces(_net(xml))
        assert parents == [
            {"name": "ethernet1/2", "layer3": {}},
            {"name": "ethernet1/4", "layer2": {}},
        ]
        assert subs == []
        assert notes == []

    def test_build_export_surfaces_lldp_profile_warning(self):
        from export.writer import build_export

        data = build_export(
            ET.fromstring("<config version='11.1.0'/>"),
            ET.fromstring("<vsys/>"),
            None,
            _net(self.XML),
            "test.xml",
            "vsys1",
        )
        lldp_warns = [
            w for w in data["migration_warnings"] if "LLDP-Profile-Default" in w["message"]
        ]
        assert len(lldp_warns) == 1
        assert lldp_warns[0]["severity"] == "warn"
        assert lldp_warns[0]["object_path"] == "network/interfaces"

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.network.ethernet_interface import EthernetInterfaceCreateModel

        parents, _, _ = export_ethernet_interfaces(_net(self.XML))
        for p in parents:
            payload = {k: v for k, v in p.items() if k in ("layer2", "layer3")}
            # SCM interface names are $variables; scm-mcp maps the PAN-OS name.
            var_name = "$" + p["name"].replace("/", "-")
            EthernetInterfaceCreateModel(name=var_name, folder="All", **payload)
