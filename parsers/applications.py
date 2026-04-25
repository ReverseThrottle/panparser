from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich.tree import Tree
from rich import box
from ._helpers import iter_entries, scope_label, grep_row, get_members, fmt_any


def render_applications(vsys_root: Element | None, shared_root: Element | None,
                        console, grep: str | None = None) -> None:
    table = Table(title="Custom Applications", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold")
    table.add_column("Scope", style="dim")
    table.add_column("Category")
    table.add_column("Subcategory")
    table.add_column("Technology")
    table.add_column("Risk", justify="center")
    table.add_column("Default Port(s)", style="dim")

    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application"):
        name = entry.get("name", "")
        category = entry.findtext("category") or ""
        subcategory = entry.findtext("subcategory") or ""
        technology = entry.findtext("technology") or ""
        risk = entry.findtext("risk") or ""
        ports = _extract_default_ports(entry)
        rows.append((scope, name, category, subcategory, technology, risk, ports))

    rows.sort(key=lambda r: r[1].lower())
    added = 0
    for i, (scope, name, cat, subcat, tech, risk, ports) in enumerate(rows, 1):
        if grep_row(grep, name, cat, subcat, tech, ports):
            risk_markup = _risk_color(risk)
            table.add_row(str(i), name, scope_label(scope), cat, subcat, tech,
                          risk_markup, ports)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No custom applications found.[/dim]")


def render_application_groups(vsys_root: Element | None, shared_root: Element | None,
                               console, grep: str | None = None) -> None:
    groups = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application-group"):
        name = entry.get("name", "")
        members = get_members(entry, "members/member")
        groups.append((scope, name, members))

    groups.sort(key=lambda r: r[1].lower())

    tree = Tree("[bold cyan]Application Groups[/bold cyan]")
    added = 0
    for scope, name, members in groups:
        all_text = " ".join([name, *members])
        if not grep_row(grep, all_text):
            continue
        label = f"[bold]{name}[/bold] [dim]{scope_label(scope)}[/dim]"
        branch = tree.add(label)
        for m in members:
            branch.add(fmt_any(m))
        if not members:
            branch.add("[dim](empty)[/dim]")
        added += 1

    if added:
        console.print(tree)
    else:
        console.print("[dim]No application groups found.[/dim]")


def render_application_filters(vsys_root: Element | None, shared_root: Element | None,
                                console, grep: str | None = None) -> None:
    table = Table(title="Application Filters", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Scope", style="dim")
    table.add_column("Category")
    table.add_column("Subcategory")
    table.add_column("Technology")
    table.add_column("Risk")
    table.add_column("Characteristic")

    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application-filter"):
        name = entry.get("name", "")
        cat = ", ".join(get_members(entry, "category/member"))
        subcat = ", ".join(get_members(entry, "subcategory/member"))
        tech = ", ".join(get_members(entry, "technology/member"))
        risk = ", ".join(get_members(entry, "risk/member"))
        char = ", ".join(get_members(entry, "characteristic/member"))
        rows.append((scope, name, cat, subcat, tech, risk, char))

    rows.sort(key=lambda r: r[1].lower())
    added = 0
    for scope, name, cat, subcat, tech, risk, char in rows:
        if grep_row(grep, name, cat, subcat, tech):
            table.add_row(name, scope_label(scope), cat, subcat, tech, risk, char)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No application filters found.[/dim]")


def _extract_default_ports(entry: Element) -> str:
    ports = []
    for ident in entry.findall("default/ident-by-ip-protocol/ip-protocol/member"):
        ports.append(f"ip/{ident.text}")
    for port_el in entry.findall("default/port/member"):
        ports.append(port_el.text or "")
    return ", ".join(ports)


def _risk_color(risk: str) -> str:
    colors = {"1": "green", "2": "green", "3": "yellow", "4": "red", "5": "bold red"}
    color = colors.get(risk, "white")
    return f"[{color}]{risk}[/{color}]" if risk else ""
