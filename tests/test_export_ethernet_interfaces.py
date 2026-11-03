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


class TestEthernetPppoe:
    """REV-135(b): PPPoE settings are exported without ever reading the password."""

    SECRET = "-AQ==SECRET"

    XML = f"""
    <interface>
      <ethernet>
        <entry name="ethernet1/8">
          <layer3>
            <interface-management-profile>RemoteVPN-Mgmt</interface-management-profile>
            <pppoe>
              <enable>yes</enable>
              <username>isp-user</username>
              <password>{SECRET}</password>
              <authentication>PAP</authentication>
            </pppoe>
          </layer3>
        </entry>
        <entry name="ethernet1/2"><layer3/></entry>
      </ethernet>
    </interface>
    """

    def _build(self, xml: str):
        from export.writer import build_export

        return build_export(
            ET.fromstring("<config version='11.1.0'/>"),
            ET.fromstring("<vsys/>"),
            None,
            _net(xml),
            "test.xml",
            "vsys1",
        )

    def test_pppoe_is_sibling_of_layer3_without_password(self):
        parents, subs, _ = export_ethernet_interfaces(_net(self.XML))
        assert parents[0] == {
            "name": "ethernet1/8",
            "layer3": {"interface_management_profile": "RemoteVPN-Mgmt"},
            "pppoe": {"enable": True, "username": "isp-user", "authentication": "PAP"},
        }
        assert "password" not in parents[0]["pppoe"]
        assert "pppoe" not in parents[0]["layer3"]
        assert subs == []

    def test_port_without_pppoe_unchanged(self):
        parents, _, _ = export_ethernet_interfaces(_net(self.XML))
        assert parents[1] == {"name": "ethernet1/2", "layer3": {}}

    def test_exactly_one_reenter_warning(self):
        _, _, notes = export_ethernet_interfaces(_net(self.XML))
        reenter = [n for n in notes if "re-enter" in n]
        assert len(reenter) == 1
        assert "ethernet1/8" in reenter[0]
        assert len(notes) == 1

    def test_secret_absent_from_notes(self):
        """Fails if the password text is ever read into any note/warning."""
        _, _, notes = export_ethernet_interfaces(_net(self.XML))
        for n in notes:
            assert "SECRET" not in n
            assert self.SECRET not in n

    def test_secret_absent_from_full_export(self):
        import json

        data = self._build(self.XML)
        dumped = json.dumps(data)
        assert "SECRET" not in dumped
        for w in data["migration_warnings"]:
            assert "SECRET" not in json.dumps(w)
        reenter = [w for w in data["migration_warnings"] if "re-enter" in w["message"]]
        assert len(reenter) == 1
        assert reenter[0]["severity"] == "warn"
        assert reenter[0]["object_path"] == "network/interfaces"
        eth = {p["name"]: p for p in data["network"]["interfaces"]["ethernet"]}
        assert "pppoe" not in eth["ethernet1/8"]["layer3"]
        assert "password" not in eth["ethernet1/8"]["pppoe"]

    def test_password_only_pppoe_still_warns_once(self):
        xml = f"""
        <interface><ethernet>
          <entry name="ethernet1/9"><layer3>
            <pppoe><password>{self.SECRET}</password></pppoe>
          </layer3></entry>
        </ethernet></interface>
        """
        parents, _, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0] == {"name": "ethernet1/9", "layer3": {}, "pppoe": {}}
        assert len([n for n in notes if "re-enter" in n]) == 1
        assert all("SECRET" not in n for n in notes)

    def test_all_allow_listed_fields(self):
        xml = f"""
        <interface><ethernet>
          <entry name="ethernet1/5"><layer3>
            <pppoe>
              <enable>no</enable>
              <username>u@isp</username>
              <password>{self.SECRET}</password>
              <authentication>auto</authentication>
              <static-address><ip>203.0.113.9</ip></static-address>
              <default-route-metric>20</default-route-metric>
              <access-concentrator>AC-1</access-concentrator>
              <service>svc-a</service>
              <passive><enable>yes</enable></passive>
            </pppoe>
          </layer3></entry>
        </ethernet></interface>
        """
        parents, _, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0]["pppoe"] == {
            "enable": False,
            "username": "u@isp",
            "authentication": "auto",
            "static_address": {"ip": "203.0.113.9"},
            "default_route_metric": 20,
            "access_concentrator": "AC-1",
            "service": "svc-a",
            "passive": {"enable": True},
        }
        assert len(notes) == 1 and "re-enter" in notes[0]
        assert all("SECRET" not in n for n in notes)

    def test_unknown_child_warns_by_name(self):
        xml = f"""
        <interface><ethernet>
          <entry name="ethernet1/6"><layer3>
            <pppoe>
              <username>u</username>
              <password>{self.SECRET}</password>
              <future-knob>1</future-knob>
            </pppoe>
          </layer3></entry>
        </ethernet></interface>
        """
        parents, _, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0]["pppoe"] == {"username": "u"}
        assert len(notes) == 2
        assert len([n for n in notes if "re-enter" in n]) == 1
        unknown = [n for n in notes if "future-knob" in n]
        assert len(unknown) == 1 and "ethernet1/6" in unknown[0]
        assert all("SECRET" not in n for n in notes)

    def test_unsupported_authentication_warns_and_is_dropped(self):
        xml = """
        <interface><ethernet>
          <entry name="ethernet1/7"><layer3>
            <pppoe><username>u</username><authentication>MSCHAP</authentication></pppoe>
          </layer3></entry>
        </ethernet></interface>
        """
        parents, _, notes = export_ethernet_interfaces(_net(xml))
        assert parents[0]["pppoe"] == {"username": "u"}
        assert len(notes) == 2
        assert any("MSCHAP" in n for n in notes)

    def test_pppoe_keys_match_scm_sdk(self):
        """Exported keys are real PppoeConfig fields (password supplied by the operator)."""
        import pytest

        pytest.importorskip("scm")
        from scm.models.network._interface_common import PppoeConfig

        xml = """
        <interface><ethernet>
          <entry name="ethernet1/5"><layer3><pppoe>
            <enable>yes</enable><username>u</username><authentication>CHAP</authentication>
            <static-address><ip>203.0.113.9</ip></static-address>
            <default-route-metric>20</default-route-metric>
            <access-concentrator>AC</access-concentrator><service>s</service>
            <passive><enable>no</enable></passive>
          </pppoe></layer3></entry>
        </ethernet></interface>
        """
        parents, _, _ = export_ethernet_interfaces(_net(xml))
        PppoeConfig(password="operator-entered", **parents[0]["pppoe"])
