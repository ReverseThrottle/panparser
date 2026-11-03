"""Regression tests for issue #57: layer2 sub-interfaces were dropped.

The Tok fixture is synthetic. It copies the interface and tag layout that
issue #57 reports for 20261008_tok.xml (two L2 trunks, 8 units, all in the
Trust-LAN zone). It is not the real customer capture.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import (
    export_aggregate_interfaces,
    export_ethernet_interfaces,
    export_layer2_subinterfaces,
)
from export.writer import build_export
from parsers.interfaces import _extract_iface_detail

TOK_UNITS = {
    "ethernet1/1": [250, 251, 983],
    "ethernet1/7": [251, 252, 256, 257, 2520],
}


def _net(xml_str: str):
    return ET.fromstring(f"<network>{xml_str}</network>")


def _l2_port(name: str, tags: list[int]) -> str:
    units = "".join(
        f'<entry name="{name}.{t}"><tag>{t}</tag></entry>' for t in tags
    )
    return f'<entry name="{name}"><layer2><units>{units}</units></layer2></entry>'


def _tok_network() -> str:
    ports = "".join(_l2_port(n, tags) for n, tags in TOK_UNITS.items())
    return f"<interface><ethernet>{ports}</ethernet></interface>"


def test_ethernet_layer2_units_are_exported():
    xml = """
    <interface><ethernet>
      <entry name="ethernet1/3"><layer2><units>
        <entry name="ethernet1/3.10"><tag>10</tag><comment>users</comment></entry>
        <entry name="ethernet1/3.20"><tag>20</tag></entry>
      </units></layer2></entry>
    </ethernet></interface>
    """
    parents, l3_subs, notes = export_ethernet_interfaces(_net(xml))

    assert parents == [{"name": "ethernet1/3", "layer2": {}}]
    assert l3_subs == []
    assert notes == []
    assert export_layer2_subinterfaces(_net(xml)) == [
        {"name": "ethernet1/3.10", "parent_interface": "ethernet1/3", "tag": 10, "comment": "users"},
        {"name": "ethernet1/3.20", "parent_interface": "ethernet1/3", "tag": 20},
    ]


def test_aggregate_layer2_units_are_exported():
    xml = """
    <interface><aggregate-ethernet>
      <entry name="ae1"><layer2><units>
        <entry name="ae1.100"><tag>100</tag><comment>servers</comment></entry>
      </units></layer2></entry>
    </aggregate-ethernet></interface>
    """
    parents, l3_subs, notes = export_aggregate_interfaces(_net(xml))

    assert parents == [{"name": "ae1", "layer2": {}}]
    assert l3_subs == []
    assert notes == []
    assert export_layer2_subinterfaces(_net(xml)) == [
        {"name": "ae1.100", "parent_interface": "ae1", "tag": 100, "comment": "servers"},
    ]


def test_layer2_without_units_exports_no_subinterfaces():
    xml = '<interface><ethernet><entry name="ethernet1/4"><layer2/></entry></ethernet></interface>'
    assert export_layer2_subinterfaces(_net(xml)) == []


def test_tok_layer2_subinterfaces_export_and_match_trust_lan():
    expected = [
        {"name": f"{parent}.{tag}", "parent_interface": parent, "tag": tag}
        for parent, tags in TOK_UNITS.items()
        for tag in tags
    ]
    members = "".join(f"<member>{s['name']}</member>" for s in expected)
    data = build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        ET.fromstring(
            f'<vsys><zone><entry name="Trust-LAN"><network><layer2>{members}'
            "</layer2></network></entry></zone></vsys>"
        ),
        None,
        _net(_tok_network()),
        "20261008_tok.xml",
        "vsys1",
    )

    ifaces = data["network"]["interfaces"]
    assert ifaces["layer2_subinterfaces"] == expected
    assert len(ifaces["layer2_subinterfaces"]) == 8
    # scm-mcp pushes these keys as layer3 sub-interfaces; L2 units must stay out.
    assert ifaces["ethernet_subinterfaces"] == []
    assert ifaces["aggregate_subinterfaces"] == []
    unmatched = [
        w for w in data["migration_warnings"]
        if "doesn't match any exported interface" in w["message"]
    ]
    assert unmatched == []


def test_layer3_subinterfaces_stay_out_of_layer2_key():
    xml = """
    <interface><ethernet>
      <entry name="ethernet1/2"><layer3><units>
        <entry name="ethernet1/2.5"><tag>5</tag></entry>
      </units></layer3></entry>
    </ethernet></interface>
    """
    _parents, l3_subs, _notes = export_ethernet_interfaces(_net(xml))

    assert [s["name"] for s in l3_subs] == ["ethernet1/2.5"]
    assert export_layer2_subinterfaces(_net(xml)) == []


def test_viewer_lists_layer2_subinterfaces_under_parent():
    entry = ET.fromstring(_l2_port("ethernet1/1", TOK_UNITS["ethernet1/1"]))

    assert _extract_iface_detail(entry) == (
        "",
        "layer2",
        ["ethernet1/1.250", "ethernet1/1.251", "ethernet1/1.983"],
    )
