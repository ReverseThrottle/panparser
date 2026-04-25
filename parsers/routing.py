from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_routing(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Static Routes", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Virtual Router", style="bold")
    table.add_column("Route Name")
    table.add_column("Destination")
    table.add_column("Next Hop")
    table.add_column("Interface", style="dim")
    table.add_column("Metric", justify="right", style="dim")
    table.add_column("Admin Dist", justify="right", style="dim")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        console.print("[dim]No virtual routers found.[/dim]")
        return

    rows = []
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        routing_table = vr.find("routing-table/ip/static-route")
        if routing_table is None:
            continue
        for route in routing_table.findall("entry"):
            rname = route.get("name", "")
            dest = route.findtext("destination") or ""
            nexthop, iface = _extract_nexthop(route)
            metric = route.findtext("metric") or ""
            admin_dist = route.findtext("admin-dist") or ""
            rows.append((vr_name, rname, dest, nexthop, iface, metric, admin_dist))

    rows.sort(key=lambda r: (r[0].lower(), _ip_sort_key(r[2])))
    added = 0
    for vr_name, rname, dest, nexthop, iface, metric, admin_dist in rows:
        if grep_row(grep, vr_name, rname, dest, nexthop, iface):
            table.add_row(vr_name, rname, dest, nexthop, iface, metric, admin_dist)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No static routes found.[/dim]")


def _extract_nexthop(route: Element) -> tuple[str, str]:
    nh = route.find("nexthop")
    if nh is None:
        return "", ""
    ip_addr = nh.findtext("ip-address")
    if ip_addr:
        return ip_addr, route.findtext("interface") or ""
    discard = nh.find("discard")
    if discard is not None:
        return "[dim]discard[/dim]", ""
    next_vr = nh.findtext("next-vr")
    if next_vr:
        return f"vr:{next_vr}", ""
    tunnel = nh.find("tunnel")
    if tunnel is not None:
        return "tunnel", ""
    return "", route.findtext("interface") or ""


def _ip_sort_key(cidr: str):
    import re
    m = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)(?:/(\d+))?", cidr)
    if m:
        a, b, c, d = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
        prefix = int(m.group(5)) if m.group(5) else 32
        return (a, b, c, d, prefix)
    return (999, 999, 999, 999, 999)
