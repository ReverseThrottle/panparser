from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_redist_profiles(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="Redistribution Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("VR", min_width=12)
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Action", min_width=12)
    table.add_column("Filter Type", min_width=12)
    table.add_column("Filter Value", min_width=16)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        console.print("[dim]No redistribution profiles found.[/dim]")
        return

    added = 0
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        rp_container = vr.find("protocol/redist-profile")
        if rp_container is None:
            continue
        for entry in rp_container.findall("entry"):
            name = entry.get("name", "")
            action = entry.findtext("action") or ""
            filter_el = entry.find("filter")
            if filter_el is not None:
                type_child = next(iter(filter_el), None)
                if type_child is not None:
                    filter_type = type_child.tag
                    val_child = next(iter(type_child), None)
                    filter_value = val_child.text if val_child is not None else (type_child.text or "")
                else:
                    filter_type = ""
                    filter_value = ""
            else:
                filter_type = ""
                filter_value = ""

            if not grep_row(grep, vr_name, name, action, filter_type, filter_value or ""):
                continue

            table.add_row(vr_name, name, action, filter_type, filter_value or "")
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No redistribution profiles found.[/dim]")
