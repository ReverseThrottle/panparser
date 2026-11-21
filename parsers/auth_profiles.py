from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._data import get_auth_profiles
from ._helpers import grep_row


def render_auth_profiles(vsys_root: Element | None, shared_root: Element | None,
                         console, grep: str | None = None) -> None:
    """Render authentication profiles from vsys + shared (#122).

    Consumes get_auth_profiles so the CLI and TUI share one extraction path
    (the duplicated extraction is what let the surfaces diverge in #122).
    Row shape/columns are unchanged — shared rows render exactly as before
    (#122 AC5); same-name entries in both scopes appear as two rows.
    """
    table = Table(title="Authentication Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Method", min_width=14)
    table.add_column("MFA", justify="center", width=5)
    table.add_column("Allow List", min_width=20)
    table.add_column("User Domain", min_width=12)

    added = 0
    for name, method, mfa_enabled, allow_list, user_domain in get_auth_profiles(vsys_root, shared_root):
        if not grep_row(grep, name, method, mfa_enabled, allow_list, user_domain):
            continue

        mfa_markup = "[green]yes[/green]" if mfa_enabled == "yes" else "no"
        table.add_row(name, method, mfa_markup, allow_list, user_domain)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No authentication profiles found.[/dim]")
