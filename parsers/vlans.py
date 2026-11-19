from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import get_members, grep_row


def render_vlans(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="VLAN Objects", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("VLAN Interface (SVI)")
    table.add_column("Layer2 Members")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("vlan")
    if container is None:
        console.print("[dim]No VLAN objects found.[/dim]")
        return

    rows = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        svi = entry.findtext("virtual-interface/interface") or ""
        members = ", ".join(get_members(entry, "interface/member"))
        rows.append((name, svi, members))

    rows.sort(key=lambda r: r[0].lower())
    added = 0
    for name, svi, members in rows:
        if grep_row(grep, name, svi, members):
            table.add_row(name, svi, members)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No VLAN objects found.[/dim]")
