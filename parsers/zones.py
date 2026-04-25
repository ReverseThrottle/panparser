from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row

ZONE_TYPE_COLORS = {
    "layer3": "white", "layer2": "blue", "tap": "cyan",
    "tunnel": "magenta", "virtual-wire": "yellow", "external": "dim",
}


def render_zones(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Security Zones", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Type")
    table.add_column("Interfaces")
    table.add_column("Zone Protection Profile", style="dim")
    table.add_column("Log Setting", style="dim")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    zone_container = network_root.find("zone")
    if zone_container is None:
        console.print("[dim]No zones found.[/dim]")
        return

    rows = []
    for zone in zone_container.findall("entry"):
        name = zone.get("name", "")
        zone_type, ifaces = _extract_zone_type(zone)
        zpp = zone.findtext("zone-protection-profile") or ""
        log_setting = zone.findtext("log-setting") or ""
        rows.append((name, zone_type, ifaces, zpp, log_setting))

    rows.sort(key=lambda r: r[0].lower())
    added = 0
    for name, zone_type, ifaces, zpp, log_setting in rows:
        if grep_row(grep, name, zone_type, " ".join(ifaces), zpp):
            color = ZONE_TYPE_COLORS.get(zone_type, "white")
            type_markup = f"[{color}]{zone_type}[/{color}]"
            ifaces_str = "\n".join(ifaces) if ifaces else "[dim](none)[/dim]"
            table.add_row(name, type_markup, ifaces_str, zpp, log_setting)
            added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No zones found.[/dim]")


def _extract_zone_type(zone: Element) -> tuple[str, list[str]]:
    for ztype in ("layer3", "layer2", "tap", "tunnel", "virtual-wire", "external"):
        el = zone.find(f"network/{ztype}")
        if el is not None:
            ifaces = [m.text or "" for m in el.findall("member")]
            return ztype, ifaces
    return "unknown", []
