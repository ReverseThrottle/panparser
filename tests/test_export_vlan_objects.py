"""Tests for VLAN-object export (network/vlan) — issue #60.

VLAN objects bind Layer2 member interfaces to an SVI
(virtual-interface/interface). They are distinct from the SVI units
themselves (network/interface/vlan), which export_vlan_interfaces covers.

The real 20261008_tok.xml is not available in this repo, so the Tok repro
below is a synthetic config rebuilt from the issue's table: 9 VLAN objects
with their exact SVI and Layer2 member lists.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_vlan_objects
from export.writer import build_export
from parsers._data import get_vlans


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


def _build_export(network_xml: str, vsys_xml: str = "") -> dict:
    return build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        ET.fromstring(f"<vsys>{vsys_xml}</vsys>"),
        None,
        ET.fromstring(f"<network>{network_xml}</network>"),
        "test.xml",
        "vsys1",
    )


# ── Tok repro: the 9 VLAN objects from issue #60 ─────────────────────────────

# (name, SVI, Layer2 members) — verbatim from the issue table.
TOK_VLANS = [
    ("Staff", "vlan", []),
    ("Staff2", "vlan.981", ["ethernet1/2", "ethernet1/3"]),
    ("Staff3", "vlan.250", ["ethernet1/1.250"]),
    ("Staff4", "vlan.251", ["ethernet1/1.251", "ethernet1/7.251"]),
    ("Staff5", "vlan.983", ["ethernet1/1.983"]),
    ("Tok-Guest-LAN", "vlan.252", ["ethernet1/7.252"]),
    ("Tok-AP-Mgmt-LAN", "vlan.256", ["ethernet1/7.256"]),
    ("Tok-Mgmt-LAN", "vlan.257", ["ethernet1/7.257", "ethernet1/6",
                                   "ethernet1/5", "ethernet1/4"]),
    ("DeviceNet", "vlan.2520", ["ethernet1/7.2520"]),
]


def _tok_vlan_objects_xml() -> str:
    entries = []
    for name, svi, members in TOK_VLANS:
        member_xml = "".join(f"<member>{m}</member>" for m in members)
        interface_xml = f"<interface>{member_xml}</interface>" if members else ""
        entries.append(
            f'<entry name="{name}">'
            f"<virtual-interface><interface>{svi}</interface></virtual-interface>"
            f"{interface_xml}</entry>"
        )
    return "<vlan>" + "".join(entries) + "</vlan>"


def _tok_interfaces_xml() -> str:
    """SVI units + L2 ethernet parents/sub-interfaces carrying the members."""
    svi_units = "".join(
        f'<entry name="vlan.{tag}"><ip><entry name="10.0.{tag}.1/24"/></ip></entry>'
        for tag in (981, 250, 251, 983, 252, 256, 257, 2520)
    )
    # Bare 'vlan' parent carries an IP → normalized to vlan.1 by the exporter.
    vlan_ifaces = (
        "<vlan><ip><entry name='10.0.1.1/24'/></ip>"
        f"<units>{svi_units}</units></vlan>"
    )

    def l2_units(parent: str, tags: tuple[int, ...]) -> str:
        units = "".join(
            f'<entry name="{parent}.{tag}"><tag>{tag}</tag></entry>' for tag in tags
        )
        return (
            f'<entry name="{parent}"><layer2><units>{units}</units></layer2></entry>'
        )

    ethernet = (
        "<ethernet>"
        + l2_units("ethernet1/1", (250, 251, 983))
        + "".join(
            f'<entry name="ethernet1/{n}"><layer2/></entry>' for n in (2, 3, 4, 5, 6)
        )
        + l2_units("ethernet1/7", (251, 252, 256, 257, 2520))
        + "</ethernet>"
    )
    return f"<interface>{vlan_ifaces}{ethernet}</interface>"


def _tok_network_xml() -> str:
    return _tok_vlan_objects_xml() + _tok_interfaces_xml()


# ── export_vlan_objects unit tests ────────────────────────────────────────────

class TestExportVlanObjects:
    def test_returns_empty_when_network_root_none(self):
        assert export_vlan_objects(None) == []

    def test_returns_empty_when_no_vlan_element(self):
        assert export_vlan_objects(_net("<zone/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_vlan_objects(_net("<vlan/>")) == []

    def test_full_entry(self):
        xml = """
        <vlan>
          <entry name="Staff2">
            <virtual-interface><interface>vlan.981</interface></virtual-interface>
            <interface>
              <member>ethernet1/2</member>
              <member>ethernet1/3</member>
            </interface>
          </entry>
        </vlan>
        """
        assert export_vlan_objects(_net(xml)) == [{
            "name": "Staff2",
            "virtual_interface": "vlan.981",
            "interfaces": ["ethernet1/2", "ethernet1/3"],
        }]

    def test_no_members_yields_empty_interfaces_list(self):
        xml = """
        <vlan>
          <entry name="Staff">
            <virtual-interface><interface>vlan</interface></virtual-interface>
          </entry>
        </vlan>
        """
        assert export_vlan_objects(_net(xml)) == [{
            "name": "Staff",
            "virtual_interface": "vlan",
            "interfaces": [],
        }]

    def test_absent_svi_not_included(self):
        xml = '<vlan><entry name="L2only"><interface><member>ethernet1/1</member></interface></entry></vlan>'
        result = export_vlan_objects(_net(xml))
        assert result == [{"name": "L2only", "interfaces": ["ethernet1/1"]}]
        assert "virtual_interface" not in result[0]

    def test_sorted_by_name(self):
        xml = """
        <vlan>
          <entry name="Zebra"/>
          <entry name="Alpha"/>
        </vlan>
        """
        assert [v["name"] for v in export_vlan_objects(_net(xml))] == ["Alpha", "Zebra"]

    def test_tok_repro_nine_objects(self):
        result = export_vlan_objects(_net(_tok_vlan_objects_xml()))
        assert len(result) == 9
        by_name = {v["name"]: v for v in result}
        for name, svi, members in TOK_VLANS:
            assert by_name[name]["virtual_interface"] == svi
            assert by_name[name]["interfaces"] == members


# ── build_export integration: writer wiring + reconciliation ─────────────────

class TestVlanObjectsExportIntegration:
    def test_tok_export_contains_all_nine_vlan_objects(self):
        data = _build_export(_tok_network_xml())
        vlans = data["network"]["vlans"]
        assert len(vlans) == 9
        by_name = {v["name"]: v for v in vlans}
        for name, svi, members in TOK_VLANS:
            assert by_name[name]["interfaces"] == members
            if name == "Staff":
                # Bare 'vlan' SVI: kept as-is on main (same exemption zones/VRs
                # use). PR #62 (#58) rewrites it to vlan.1 through the shared
                # _reconcile_interface_members path this export reuses.
                assert by_name[name]["virtual_interface"] in ("vlan", "vlan.1")
            else:
                assert by_name[name]["virtual_interface"] == svi

    def test_tok_members_resolve_without_unmatched_warnings(self):
        data = _build_export(_tok_network_xml())
        messages = [w["message"] for w in data["migration_warnings"]]
        assert not any("doesn't match any exported interface" in m for m in messages)
        assert not any("Dropped bare parent" in m for m in messages)

    def test_tok_manual_step_warning_lists_full_mapping(self):
        data = _build_export(_tok_network_xml())
        manual = [
            w for w in data["migration_warnings"]
            if w["object_path"] == "network/vlans" and w["severity"] == "warn"
        ]
        assert len(manual) == 1
        message = manual[0]["message"]
        assert "9 VLAN object(s)" in message
        assert "manually" in message
        for name, svi, members in TOK_VLANS:
            assert name in message
            assert svi in message
            for member in members:
                assert member in message

    def test_unmatched_member_kept_with_warning(self):
        xml = """
        <vlan>
          <entry name="Staff2">
            <virtual-interface><interface>vlan.981</interface></virtual-interface>
            <interface><member>ethernet1/9</member></interface>
          </entry>
        </vlan>
        <interface>
          <vlan><units><entry name="vlan.981"/></units></vlan>
        </interface>
        """
        data = _build_export(xml)
        assert data["network"]["vlans"][0]["interfaces"] == ["ethernet1/9"]
        unmatched = [
            w for w in data["migration_warnings"]
            if "doesn't match any exported interface" in w["message"]
        ]
        assert len(unmatched) == 1
        assert unmatched[0]["object_path"] == "network/vlans/Staff2"
        assert "'ethernet1/9'" in unmatched[0]["message"]

    def test_unmatched_svi_kept_with_warning(self):
        xml = """
        <vlan>
          <entry name="Staff2">
            <virtual-interface><interface>vlan.999</interface></virtual-interface>
          </entry>
        </vlan>
        """
        data = _build_export(xml)
        assert data["network"]["vlans"][0]["virtual_interface"] == "vlan.999"
        unmatched = [
            w for w in data["migration_warnings"]
            if "doesn't match any exported interface" in w["message"]
        ]
        assert len(unmatched) == 1
        assert unmatched[0]["object_path"] == "network/vlans/Staff2"
        assert "'vlan.999'" in unmatched[0]["message"]

    def test_bare_tunnel_svi_dropped_with_warning(self):
        xml = """
        <vlan>
          <entry name="Odd">
            <virtual-interface><interface>tunnel</interface></virtual-interface>
          </entry>
        </vlan>
        """
        data = _build_export(xml)
        assert "virtual_interface" not in data["network"]["vlans"][0]
        dropped = [
            w for w in data["migration_warnings"]
            if "Dropped bare parent" in w["message"]
        ]
        assert len(dropped) == 1
        assert dropped[0]["object_path"] == "network/vlans/Odd"

    def test_no_vlan_objects_means_empty_section_and_no_vlan_warning(self):
        data = _build_export("<interface><ethernet/></interface>")
        assert data["network"]["vlans"] == []
        assert not any(
            w["object_path"].startswith("network/vlans")
            for w in data["migration_warnings"]
        )


# ── TUI getter ────────────────────────────────────────────────────────────────

class TestGetVlans:
    def test_none_and_missing_container(self):
        assert get_vlans(None) == []
        assert get_vlans(_net("<zone/>")) == []

    def test_tok_rows(self):
        rows = get_vlans(_net(_tok_vlan_objects_xml()))
        assert len(rows) == 9
        by_name = {r[0]: r for r in rows}
        assert by_name["Staff2"] == ("Staff2", "vlan.981", "ethernet1/2, ethernet1/3")
        assert by_name["Staff"] == ("Staff", "vlan", "")
        assert [r[0] for r in rows] == sorted((r[0] for r in rows), key=str.lower)
