from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich.tree import Tree
from rich import box
from ._helpers import iter_entries, scope_label, grep_row, get_members, fmt_any


def render_services(vsys_root: Element | None, shared_root: Element | None,
                    console, grep: str | None = None) -> None:
    table = Table(title="Service Objects", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold")
    table.add_column("Scope", style="dim")
    table.add_column("Protocol")
    table.add_column("Dst Port(s)")
    table.add_column("Src Port(s)", style="dim")
    table.add_column("Description", style="dim")

    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "service"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        proto, dst, src = _extract_service(entry)
        rows.append((scope, name, proto, dst, src, desc))

    rows.sort(key=lambda r: r[1].lower())
    added = 0
    for i, (scope, name, proto, dst, src, desc) in enumerate(rows, 1):
        if grep_row(grep, name, proto, dst, src, desc):
            table.add_row(str(i), name, scope_label(scope), proto, dst, src, desc)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No service objects found.[/dim]")


def render_service_groups(vsys_root: Element | None, shared_root: Element | None,
                          console, grep: str | None = None) -> None:
    groups = []
    for entry, scope in iter_entries(vsys_root, shared_root, "service-group"):
        name = entry.get("name", "")
        members = get_members(entry, "members/member")
        desc = entry.findtext("description") or ""
        groups.append((scope, name, members, desc))

    groups.sort(key=lambda r: r[1].lower())

    tree = Tree("[bold cyan]Service Groups[/bold cyan]")
    added = 0
    for scope, name, members, desc in groups:
        all_text = " ".join([name, *members, desc])
        if not grep_row(grep, all_text):
            continue
        label = f"[bold]{name}[/bold] [dim]{scope_label(scope)}[/dim]"
        if desc:
            label += f"  [dim italic]{desc}[/dim italic]"
        branch = tree.add(label)
        for m in members:
            branch.add(fmt_any(m))
        if not members:
            branch.add("[dim](empty)[/dim]")
        added += 1

    if added:
        console.print(tree)
    else:
        console.print("[dim]No service groups found.[/dim]")


def _extract_service(entry: Element) -> tuple[str, str, str]:
    for proto in ("tcp", "udp", "sctp"):
        proto_el = entry.find(f"protocol/{proto}")
        if proto_el is not None:
            dst = proto_el.findtext("port") or ""
            src = proto_el.findtext("source-port") or ""
            return proto.upper(), dst, src
    return "unknown", "", ""
