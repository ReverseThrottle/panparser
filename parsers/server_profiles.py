from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row

_PROFILE_TYPES = ["ldap", "radius", "syslog", "snmptrap", "email", "http"]


def render_server_profiles(shared_root: Element | None, console, grep=None) -> None:
    table = Table(title="Server Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Type", min_width=10)
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Servers", justify="right", min_width=8)
    table.add_column("Details", min_width=24)

    if shared_root is None:
        console.print("[dim]No shared configuration found.[/dim]")
        return

    added = 0
    for ptype in _PROFILE_TYPES:
        container = shared_root.find(f"server-profile/{ptype}")
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name", "")
            server_count = str(len(entry.findall("server/entry")))
            if ptype == "ldap":
                details = entry.findtext("base") or entry.findtext("ldap-type") or ""
            elif ptype == "radius":
                details = entry.findtext("server/entry/protocol") or ""
            else:
                details = entry.findtext("server/entry/address") or ""

            if not grep_row(grep, ptype, name, details):
                continue

            table.add_row(ptype, name, server_count, details)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No server profiles found.[/dim]")
