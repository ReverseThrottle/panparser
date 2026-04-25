from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import iter_entries, scope_label, grep_row

PANOS_TAG_COLORS = {
    "color1": "red", "color2": "orange", "color3": "yellow", "color4": "green",
    "color5": "blue", "color6": "purple", "color7": "brown", "color8": "teal",
    "color9": "olive", "color10": "maroon", "color11": "cyan", "color12": "gold",
    "color13": "darkgreen", "color14": "blue2", "color15": "navy", "color16": "purple2",
    "color17": "gray",
}


def render_tags(vsys_root: Element | None, shared_root: Element | None,
                console, grep: str | None = None) -> None:
    table = Table(title="Tags", box=box.ROUNDED, show_lines=False,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Scope", style="dim")
    table.add_column("Color")
    table.add_column("Comments", style="dim")

    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "tag"):
        name = entry.get("name", "")
        color_val = entry.findtext("color") or ""
        color_label = PANOS_TAG_COLORS.get(color_val, color_val)
        comments = entry.findtext("comments") or ""
        rows.append((scope, name, color_val, color_label, comments))

    rows.sort(key=lambda r: r[1].lower())
    added = 0
    for scope, name, color_val, color_label, comments in rows:
        if grep_row(grep, name, color_label, comments):
            color_markup = f"[{color_label}]{color_label}[/]" if color_label else ""
            table.add_row(name, scope_label(scope), color_markup, comments)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No tags found.[/dim]")
