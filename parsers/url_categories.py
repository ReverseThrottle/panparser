from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_url_categories(vsys_root: Element | None, console, grep=None) -> None:
    table = Table(title="Custom URL Categories", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Type", min_width=16)
    table.add_column("URL Count", justify="right", min_width=10)
    table.add_column("Description", min_width=20)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("profiles/custom-url-category")
    if container is None:
        console.print("[dim]No custom URL categories found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"),
                        key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        url_type = entry.findtext("type") or ""
        member_count = str(len(entry.findall("list/member")))
        description = entry.findtext("description") or ""

        if not grep_row(grep, name, url_type, description):
            continue

        table.add_row(name, url_type, member_count, description)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No custom URL categories found.[/dim]")
