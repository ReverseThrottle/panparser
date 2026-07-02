from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_virtual_wires(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Virtual Wires", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Interface 1")
    table.add_column("Interface 2")
    table.add_column("Tag Allowed", style="dim")
    table.add_column("Multi VLAN", style="dim")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("virtual-wire")
    if container is None:
        console.print("[dim]No virtual wires found.[/dim]")
        return

    rows = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        iface1 = entry.findtext("interface1") or ""
        iface2 = entry.findtext("interface2") or ""
        tag_allowed = entry.findtext("tag-allowed") or ""
        multi_vlan = entry.findtext("multi-vlan") or ""
        rows.append((name, iface1, iface2, tag_allowed, multi_vlan))

    rows.sort(key=lambda r: r[0].lower())
    added = 0
    for name, iface1, iface2, tag_allowed, multi_vlan in rows:
        if grep_row(grep, name, iface1, iface2):
            table.add_row(name, iface1, iface2, tag_allowed, multi_vlan)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No virtual wires found.[/dim]")
