from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._data import get_server_profiles
from ._helpers import grep_row


def render_server_profiles(vsys_root: Element | None, shared_root: Element | None,
                           console, grep=None) -> None:
    """Render server profiles from vsys + shared (#122).

    Consumes get_server_profiles (canonical containers: ldap/radius under
    server-profile/, syslog/snmptrap/email/http under log-settings/) so the
    CLI and TUI share one extraction path. Row shape/columns are unchanged —
    shared rows render exactly as before (#122 AC5); same-name entries in
    both scopes appear as two rows.
    """
    table = Table(title="Server Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Type", min_width=10)
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Servers", justify="right", min_width=8)
    table.add_column("Details", min_width=24)

    added = 0
    for ptype, name, server_count, details in get_server_profiles(vsys_root, shared_root):
        if not grep_row(grep, ptype, name, details):
            continue

        table.add_row(ptype, name, server_count, details)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No server profiles found.[/dim]")
