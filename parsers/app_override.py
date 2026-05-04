from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members


def render_app_override_rules(vsys_root: Element | None, console, grep=None) -> None:
    table = Table(title="Application Override Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("From Zone", min_width=10)
    table.add_column("To Zone", min_width=10)
    table.add_column("Src Address", min_width=12)
    table.add_column("Dst Address", min_width=12)
    table.add_column("Protocol", min_width=8)
    table.add_column("Port", min_width=8)
    table.add_column("Application", min_width=16)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = (vsys_root.find("rulebase/application-override/rules")
                 or vsys_root.find("application-override/rules"))
    if container is None:
        console.print("[dim]No application override rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        from_zone = fmt_members(get_members(rule, "from/member"))
        to_zone = fmt_members(get_members(rule, "to/member"))
        src_addr = fmt_members(get_members(rule, "source/member"))
        dst_addr = fmt_members(get_members(rule, "destination/member"))
        protocol = rule.findtext("protocol") or ""
        port = rule.findtext("port") or ""
        application = rule.findtext("application") or ""

        if not grep_row(grep, name, from_zone, to_zone, src_addr, dst_addr,
                        protocol, port, application):
            continue

        name_str = f"[dim]{name} [disabled][/dim]" if disabled else name
        table.add_row(str(i), name_str, fmt_any(from_zone), fmt_any(to_zone),
                      fmt_any(src_addr), fmt_any(dst_addr), protocol, port, application)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No application override rules found.[/dim]")
