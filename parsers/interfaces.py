from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_interfaces(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Network Interfaces", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Type")
    table.add_column("IP / Mode")
    table.add_column("Subinterfaces", style="dim")
    table.add_column("Comment", style="dim")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    rows = []
    iface_root = network_root.find("interface")
    if iface_root is None:
        console.print("[dim]No interfaces found.[/dim]")
        return

    for itype, itype_label in (("ethernet", "ethernet"), ("loopback", "loopback"),
                                ("tunnel", "tunnel"), ("vlan", "vlan"), ("aggregate-ethernet", "ae")):
        container = iface_root.find(itype)
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name", "")
            ip, mode, subs = _extract_iface_detail(entry)
            comment = entry.findtext("comment") or ""
            rows.append((name, itype_label, ip, mode, subs, comment))

    rows.sort(key=lambda r: _iface_sort_key(r[0]))
    added = 0
    for name, itype_label, ip, mode, subs, comment in rows:
        if grep_row(grep, name, itype_label, ip, mode, comment):
            ip_or_mode = ip if ip else f"[dim]{mode}[/dim]" if mode else ""
            table.add_row(name, itype_label, ip_or_mode,
                          "\n".join(subs) if subs else "", comment)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No interfaces found.[/dim]")


def _extract_iface_detail(entry: Element) -> tuple[str, str, list[str]]:
    layer3 = entry.find("layer3")
    layer2 = entry.find("layer2")
    if layer3 is not None:
        ip = _get_first_ip(layer3)
        dhcp_el = layer3.find("dhcp-client")
        mode = "dhcp" if dhcp_el is not None else "layer3"
        subs = _get_subinterfaces(layer3, ip)
        return ip, mode, subs
    if layer2 is not None:
        return "", "layer2", []

    # loopback / tunnel: IP may be at top level
    ip = _get_first_ip(entry)
    return ip, "", []


def _get_first_ip(el: Element) -> str:
    ip_el = el.find("ip/entry")
    if ip_el is not None:
        return ip_el.get("name", "")
    return ""


def _get_subinterfaces(layer3: Element, parent_ip: str) -> list[str]:
    subs = []
    for sub in layer3.findall("units/entry"):
        sub_name = sub.get("name", "")
        sub_ip = _get_first_ip(sub)
        subs.append(f"{sub_name}: {sub_ip}" if sub_ip else sub_name)
    return subs


def _iface_sort_key(name: str):
    import re
    parts = re.split(r"[./]", name)
    result = []
    for p in parts:
        try:
            result.append((0, int(p)))
        except ValueError:
            result.append((1, p))
    return result
