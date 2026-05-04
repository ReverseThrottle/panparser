from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_ssl_profiles(shared_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="SSL/TLS Service Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=24)
    table.add_column("Certificate", min_width=20)
    table.add_column("Min Version", min_width=12)
    table.add_column("Max Version", min_width=12)

    if shared_root is None:
        console.print("[dim]No shared configuration found.[/dim]")
        return

    container = shared_root.find("ssl-tls-service-profile")
    if container is None:
        console.print("[dim]No SSL/TLS service profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        certificate = entry.findtext("certificate") or ""
        min_ver = entry.findtext("protocol-settings/min-version") or ""
        max_ver = entry.findtext("protocol-settings/max-version") or ""

        if not grep_row(grep, name, certificate, min_ver, max_ver):
            continue

        table.add_row(name, certificate, min_ver, max_ver)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No SSL/TLS service profiles found.[/dim]")
