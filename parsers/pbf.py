from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members


def render_pbf_rules(vsys_root: Element | None, console, grep=None) -> None:
    table = Table(title="Policy Based Forwarding Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("From Zone", min_width=10)
    table.add_column("Src Address", min_width=12)
    table.add_column("Dst Address", min_width=12)
    table.add_column("App", min_width=10)
    table.add_column("Service", min_width=10)
    table.add_column("Action", min_width=10)
    table.add_column("Egress Iface", min_width=12)
    table.add_column("Nexthop", min_width=12)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("rulebase/pbf/rules") or vsys_root.find("pbf/rules")
    if container is None:
        console.print("[dim]No PBF rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = fmt_members(get_members(rule, "from/zone/member"))
        src_addr = fmt_members(get_members(rule, "source/member"))
        dst_addr = fmt_members(get_members(rule, "destination/member"))
        app = fmt_members(get_members(rule, "application/member"))
        service = fmt_members(get_members(rule, "service/member"))
        action_el = rule.find("action")
        if action_el is not None:
            action = next((c.tag for c in action_el), "")
            fwd = action_el.find("forward")
            egress_iface = fwd.findtext("egress-interface") if fwd is not None else ""
            nh_el = fwd.find("nexthop") if fwd is not None else None
            nexthop = next((c.text or "" for c in nh_el), "") if nh_el is not None else ""
        else:
            action = ""
            egress_iface = ""
            nexthop = ""

        if not grep_row(grep, name, from_zone, src_addr, dst_addr, app, service,
                        action, egress_iface or "", nexthop or ""):
            continue

        table.add_row(str(i), name, fmt_any(from_zone), fmt_any(src_addr), fmt_any(dst_addr),
                      fmt_any(app), fmt_any(service), action, egress_iface or "", nexthop or "")
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No PBF rules found.[/dim]")
