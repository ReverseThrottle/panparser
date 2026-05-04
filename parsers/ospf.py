from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_ospf_areas(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="OSPF Areas", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("VR", min_width=12)
    table.add_column("Area ID", min_width=14)
    table.add_column("Interface", style="bold", min_width=16)
    table.add_column("Enabled", min_width=8)
    table.add_column("Passive", min_width=8)
    table.add_column("Metric", min_width=8)
    table.add_column("Link Type", min_width=12)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        console.print("[dim]No OSPF areas found.[/dim]")
        return

    added = 0
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        area_container = vr.find("protocol/ospf/area")
        if area_container is None:
            continue
        for area in area_container.findall("entry"):
            area_id = area.get("name", "")
            iface_container = area.find("interface")
            if iface_container is None:
                continue
            for iface in iface_container.findall("entry"):
                iface_name = iface.get("name", "")
                enabled = iface.findtext("enable") or "yes"
                passive = iface.findtext("passive") or "no"
                metric = iface.findtext("metric") or ""
                link_type = iface.findtext("link-type") or ""

                if not grep_row(grep, vr_name, area_id, iface_name, link_type):
                    continue

                table.add_row(vr_name, area_id, iface_name, enabled, passive, metric, link_type)
                added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No OSPF areas found.[/dim]")
