from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members


def render_qos_rules(vsys_root: Element | None, console, grep=None) -> None:
    table = Table(title="QoS Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("From Zone", min_width=10)
    table.add_column("To Zone", min_width=10)
    table.add_column("Src Address", min_width=12)
    table.add_column("Dst Address", min_width=12)
    table.add_column("App", min_width=10)
    table.add_column("Service", min_width=10)
    table.add_column("Class", min_width=10)
    table.add_column("Schedule", min_width=10)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("rulebase/qos/rules") or vsys_root.find("qos/rules")
    if container is None:
        console.print("[dim]No QoS rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = fmt_members(get_members(rule, "from/member"))
        to_zone = fmt_members(get_members(rule, "to/member"))
        src_addr = fmt_members(get_members(rule, "source/member"))
        dst_addr = fmt_members(get_members(rule, "destination/member"))
        app = fmt_members(get_members(rule, "application/member"))
        service = fmt_members(get_members(rule, "service/member"))
        action_el = rule.find("action")
        if action_el is not None:
            action_class = rule.findtext("action/class") or next((c.tag for c in action_el), "")
        else:
            action_class = ""
        schedule = rule.findtext("schedule") or ""

        if not grep_row(grep, name, from_zone, to_zone, src_addr, dst_addr,
                        app, service, action_class, schedule):
            continue

        table.add_row(str(i), name, fmt_any(from_zone), fmt_any(to_zone),
                      fmt_any(src_addr), fmt_any(dst_addr), fmt_any(app), fmt_any(service),
                      action_class, schedule)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No QoS rules found.[/dim]")
