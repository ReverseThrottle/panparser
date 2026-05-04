from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_gp_gateways(vsys_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="GlobalProtect Gateways", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("SSL/TLS Profile", min_width=24)
    table.add_column("Tunnel Mode", justify="center", width=12)
    table.add_column("Tunnel Interface", min_width=16)
    table.add_column("Client Auth Entries", justify="right", width=20)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("global-protect/global-protect-gateway")
    if container is None:
        console.print("[dim]No GlobalProtect gateways found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        ssl_profile = entry.findtext("ssl-tls-service-profile") or ""
        tunnel_mode = entry.findtext("tunnel-mode") or "no"
        tunnel_iface = entry.findtext("remote-user-tunnel") or ""
        client_auth_count = str(len(entry.findall("client-auth/entry")))

        if not grep_row(grep, name, ssl_profile, tunnel_mode, tunnel_iface):
            continue

        tm_markup = "[green]yes[/green]" if tunnel_mode == "yes" else "no"
        table.add_row(name, ssl_profile, tm_markup, tunnel_iface, client_auth_count)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No GlobalProtect gateways found.[/dim]")


def render_gp_portals(vsys_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="GlobalProtect Portals", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Local Address", min_width=16)
    table.add_column("SSL/TLS Profile", min_width=24)
    table.add_column("Client Auth Entries", justify="right", width=20)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    container = vsys_root.find("global-protect/global-protect-portal")
    if container is None:
        console.print("[dim]No GlobalProtect portals found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        local_addr = entry.findtext("portal-config/local-address/ip/ipv4") or ""
        ssl_profile = entry.findtext("portal-config/ssl-tls-service-profile") or ""
        client_auth_count = str(len(entry.findall("portal-config/client-auth/entry")))

        if not grep_row(grep, name, local_addr, ssl_profile):
            continue

        table.add_row(name, local_addr, ssl_profile, client_auth_count)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No GlobalProtect portals found.[/dim]")
