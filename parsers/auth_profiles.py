from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members


def render_auth_profiles(shared_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Authentication Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Method", min_width=14)
    table.add_column("MFA", justify="center", width=5)
    table.add_column("Allow List", min_width=20)
    table.add_column("User Domain", min_width=12)

    if shared_root is None:
        console.print("[dim]No shared configuration found.[/dim]")
        return

    container = shared_root.find("authentication-profile")
    if container is None:
        console.print("[dim]No authentication profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        method_el = entry.find("method")
        method = next((c.tag for c in method_el), "") if method_el is not None else ""
        mfa_enabled = entry.findtext("multi-factor-auth/mfa-enable") or "no"
        allow_list = ", ".join(get_members(entry, "allow-list/member"))
        user_domain = entry.findtext("user-domain") or ""

        if not grep_row(grep, name, method, mfa_enabled, allow_list, user_domain):
            continue

        mfa_markup = "[green]yes[/green]" if mfa_enabled == "yes" else "no"
        table.add_row(name, method, mfa_markup, allow_list, user_domain)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No authentication profiles found.[/dim]")
