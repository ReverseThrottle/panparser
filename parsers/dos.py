from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members


def render_dos_rules(vsys_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="DoS Protection Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("From Zone", min_width=10)
    table.add_column("To Zone", min_width=10)
    table.add_column("Src Address", min_width=12)
    table.add_column("Dst Address", min_width=12)
    table.add_column("Service", min_width=10)
    table.add_column("Protection", min_width=10)
    table.add_column("Action", min_width=8)
    table.add_column("Log Setting", min_width=10)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("rulebase/dos/rules") or vsys_root.find("dos/rules")
    if container is None:
        console.print("[dim]No DoS rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = fmt_members(get_members(rule, "from/zone/member"))
        to_zone = fmt_members(get_members(rule, "to/zone/member"))
        src_addr = fmt_members(get_members(rule, "source/member"))
        dst_addr = fmt_members(get_members(rule, "destination/member"))
        service = fmt_members(get_members(rule, "service/member"))
        prot = rule.find("protection")
        if prot is not None:
            protection_type = "aggregate" if prot.find("aggregate") is not None else "classified"
        else:
            protection_type = ""
        action_el = rule.find("action")
        action = next((c.tag for c in action_el), "") if action_el is not None else ""
        log_setting = rule.findtext("log-setting") or ""

        if not grep_row(grep, name, from_zone, to_zone, src_addr, dst_addr, service,
                        protection_type, action, log_setting):
            continue

        table.add_row(str(i), name, fmt_any(from_zone), fmt_any(to_zone),
                      fmt_any(src_addr), fmt_any(dst_addr), fmt_any(service),
                      protection_type, action, log_setting)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No DoS rules found.[/dim]")
