from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich.tree import Tree
from rich import box
from ._helpers import iter_entries, scope_label, grep_row, get_members, fmt_any


def render_addresses(vsys_root: Element | None, shared_root: Element | None,
                     console, grep: str | None = None) -> None:
    table = Table(title="Address Objects", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold")
    table.add_column("Scope", style="dim")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Description", style="dim")

    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "address"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        addr_type, value = _extract_addr(entry)
        rows.append((scope, name, addr_type, value, desc))

    rows.sort(key=lambda r: r[1].lower())
    added = 0
    for i, (scope, name, addr_type, value, desc) in enumerate(rows, 1):
        if grep_row(grep, name, addr_type, value, desc):
            table.add_row(str(i), name, scope_label(scope), addr_type, value, desc)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No address objects found.[/dim]")


def render_address_groups(vsys_root: Element | None, shared_root: Element | None,
                          console, grep: str | None = None) -> None:
    groups = []
    for entry, scope in iter_entries(vsys_root, shared_root, "address-group"):
        name = entry.get("name", "")
        static = get_members(entry, "static/member")
        dynamic_filter = entry.findtext("dynamic/filter") or ""
        desc = entry.findtext("description") or ""
        groups.append((scope, name, static, dynamic_filter, desc))

    groups.sort(key=lambda r: r[1].lower())

    tree = Tree("[bold cyan]Address Groups[/bold cyan]")
    added = 0
    for scope, name, static_members, dyn_filter, desc in groups:
        all_text = " ".join([name, *static_members, dyn_filter, desc])
        if not grep_row(grep, all_text):
            continue
        label = f"[bold]{name}[/bold] [dim]{scope_label(scope)}[/dim]"
        if desc:
            label += f"  [dim italic]{desc}[/dim italic]"
        branch = tree.add(label)
        if static_members:
            for m in static_members:
                branch.add(fmt_any(m))
        elif dyn_filter:
            branch.add(f"[yellow]dynamic:[/yellow] {dyn_filter}")
        else:
            branch.add("[dim](empty)[/dim]")
        added += 1

    if added:
        console.print(tree)
    else:
        console.print("[dim]No address groups found.[/dim]")


def _extract_addr(entry: Element) -> tuple[str, str]:
    for tag in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
        val = entry.findtext(tag)
        if val is not None:
            return tag, val
    return "unknown", ""
