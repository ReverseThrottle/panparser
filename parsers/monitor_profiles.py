from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_monitor_profiles(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Monitor Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Interval", justify="center", width=10)
    table.add_column("Threshold", justify="center", width=10)
    table.add_column("Action", min_width=15)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("profiles/monitor-profile")
    if container is None:
        console.print("[dim]No monitor profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        interval = entry.findtext("interval") or ""
        threshold = entry.findtext("threshold") or ""
        action = entry.findtext("action") or ""

        if not grep_row(grep, name, interval, threshold, action):
            continue

        table.add_row(name, interval, threshold, action)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No monitor profiles found.[/dim]")
