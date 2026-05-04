from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_zone_protection(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Zone Protection Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Flood Protection", min_width=28)
    table.add_column("Discard IP Spoof", justify="center", width=16)
    table.add_column("Discard IP Frag", justify="center", width=15)
    table.add_column("Strict IP Check", justify="center", width=15)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("profiles/zone-protection-profile")
    if container is None:
        console.print("[dim]No zone protection profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        flood_el = entry.find("flood")
        flood_types = ", ".join(c.tag for c in flood_el) if flood_el is not None else ""
        discard_spoof = entry.findtext("discard-ip-spoof") or "no"
        discard_frag = entry.findtext("discard-ip-frag") or "no"
        strict_ip = entry.findtext("strict-ip-check") or "no"

        if not grep_row(grep, name, flood_types, discard_spoof, discard_frag, strict_ip):
            continue

        def yn(v: str) -> str:
            return "[green]yes[/green]" if v == "yes" else "no"

        table.add_row(name, flood_types, yn(discard_spoof), yn(discard_frag), yn(strict_ip))
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No zone protection profiles found.[/dim]")
