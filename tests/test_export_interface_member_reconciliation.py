"""Tests for reconciling zone and virtual-router interface members."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.writer import _reconcile_interface_members, build_export


def _reconcile(
    interfaces: list[str],
    known_interfaces: set[str],
    normalized_bare_interfaces: set[str] | None = None,
) -> tuple[list[str], list[dict]]:
    owners = [{"name": "trust", "interfaces": interfaces}]
    warnings = _reconcile_interface_members(
        owners,
        known_interfaces,
        normalized_bare_interfaces or set(),
        "zone",
        "zones",
    )
    return owners[0]["interfaces"], warnings


def _build_export(vsys_xml: str, network_xml: str) -> dict:
    return build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        ET.fromstring(f"<vsys>{vsys_xml}</vsys>"),
        None,
        ET.fromstring(f"<network>{network_xml}</network>"),
        "test.xml",
        "vsys1",
    )


def test_defined_interface_is_kept_without_warning():
    interfaces, warnings = _reconcile(["tunnel.99"], {"tunnel.99"})

    assert interfaces == ["tunnel.99"]
    assert warnings == []


def test_bare_tunnel_is_dropped_without_numbered_interface():
    interfaces, warnings = _reconcile(["tunnel"], set())

    assert interfaces == []
    assert len(warnings) == 1
    assert warnings[0]["object_path"] == "zones/trust"
    assert "Dropped bare parent" in warnings[0]["message"]
    assert "'tunnel'" in warnings[0]["message"]
    assert "zone 'trust'" in warnings[0]["message"]


def test_bare_loopback_is_dropped_and_empty_owner_is_preserved():
    interfaces, warnings = _reconcile(["loopback"], set())

    assert interfaces == []
    assert len(warnings) == 1
    assert "Dropped bare parent" in warnings[0]["message"]
    assert "'loopback'" in warnings[0]["message"]


def test_bare_tunnel_is_dropped_when_numbered_sibling_exists():
    interfaces, warnings = _reconcile(
        ["tunnel", "tunnel.99"],
        {"tunnel.99"},
    )

    assert interfaces == ["tunnel.99"]
    assert len(warnings) == 1
    assert "Dropped bare parent" in warnings[0]["message"]


def test_normalized_bare_tunnel_is_kept_without_warning():
    interfaces, warnings = _reconcile(
        ["tunnel"],
        {"tunnel.1"},
        {"tunnel"},
    )

    assert interfaces == ["tunnel"]
    assert warnings == []


def test_bare_vlan_is_untouched_without_new_warning():
    interfaces, warnings = _reconcile(["vlan"], set())

    assert interfaces == ["vlan"]
    assert warnings == []


def test_undefined_interface_is_kept_with_distinct_warning():
    interfaces, warnings = _reconcile(["ethernet1/9"], set())

    assert interfaces == ["ethernet1/9"]
    assert len(warnings) == 1
    assert "doesn't match" in warnings[0]["message"]
    assert "Dropped bare parent" not in warnings[0]["message"]


def test_exported_ethernet_subinterface_and_aggregate_are_kept():
    interfaces, warnings = _reconcile(
        ["ethernet1/1.10", "ae1"],
        {"ethernet1/1.10", "ae1"},
    )

    assert interfaces == ["ethernet1/1.10", "ae1"]
    assert warnings == []


def test_eafb_style_export_drops_only_stale_bare_tunnel_members():
    member_xml = """
      <member>tunnel</member>
      <member>tunnel.99</member>
      <member>vlan</member>
      <member>vlan.981</member>
    """
    data = _build_export(
        f"""
        <zone>
          <entry name="trust">
            <network><layer3>{member_xml}</layer3></network>
          </entry>
        </zone>
        """,
        f"""
        <interface>
          <tunnel>
            <units><entry name="tunnel.99"/></units>
          </tunnel>
          <vlan>
            <units><entry name="vlan.981"/></units>
          </vlan>
        </interface>
        <virtual-router>
          <entry name="Internal">
            <interface>{member_xml}</interface>
          </entry>
        </virtual-router>
        """,
    )

    assert data["zones"][0]["interfaces"] == ["tunnel.99", "vlan", "vlan.981"]
    assert data["network"]["virtual_routers"][0]["interfaces"] == [
        "tunnel.99",
        "vlan",
        "vlan.981",
    ]

    drop_warnings = [
        warning
        for warning in data["migration_warnings"]
        if "Dropped bare parent" in warning["message"]
    ]
    assert [warning["object_path"] for warning in drop_warnings] == [
        "zones/trust",
        "network/virtual_routers/Internal",
    ]
    assert all("'tunnel'" in warning["message"] for warning in drop_warnings)


def test_fully_matching_export_has_no_interface_member_warnings():
    data = _build_export(
        """
        <zone>
          <entry name="trust">
            <network>
              <layer3>
                <member>ethernet1/1.10</member>
                <member>ae1</member>
              </layer3>
            </network>
          </entry>
        </zone>
        """,
        """
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <units><entry name="ethernet1/1.10"><tag>10</tag></entry></units>
              </layer3>
            </entry>
          </ethernet>
          <aggregate-ethernet>
            <entry name="ae1"><layer3/></entry>
          </aggregate-ethernet>
        </interface>
        <virtual-router>
          <entry name="Internal">
            <interface>
              <member>ethernet1/1.10</member>
              <member>ae1</member>
            </interface>
          </entry>
        </virtual-router>
        """,
    )

    expected_interfaces = ["ethernet1/1.10", "ae1"]
    assert data["zones"] == [{
        "name": "trust",
        "zone_type": "layer3",
        "interfaces": expected_interfaces,
    }]
    assert data["network"]["virtual_routers"][0]["interfaces"] == expected_interfaces
    assert data["migration_warnings"] == [{
        "severity": "info",
        "object_path": "network/interfaces",
        "message": (
            "3 interface(s) exported as SCM $variable templates "
            "(1 ethernet + 1 eth-subs, 1 aggregate + 0 ae-subs, "
            "0 loopback, 0 tunnel, 0 vlan). Bind each $variable to the real "
            "device interface in SCM device management."
        ),
    }]
