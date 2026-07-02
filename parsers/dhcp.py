from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_dhcp_servers(network_root: Element | None, console, grep: str | None = None) -> None:
    """Render DHCP server configuration from network/dhcp/interface.

    Covers an interface acting as a DHCP *server* (leases, IP pool,
    reservations, DNS/gateway options). Separate from DHCP *client*
    configuration on layer3 interfaces (network/interface/.../dhcp-client).
    """
    table = Table(title="DHCP Servers", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Interface", style="bold")
    table.add_column("Mode")
    table.add_column("IP Pool")
    table.add_column("Gateway / Subnet")
    table.add_column("DNS")
    table.add_column("Lease (min)")
    table.add_column("Reserved", style="dim")

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("dhcp/interface")
    if container is None:
        console.print("[dim]No DHCP server configuration found.[/dim]")
        return

    rows = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        server = entry.find("server")
        if server is None:
            continue

        mode = server.findtext("mode") or ""
        pool = [m.text or "" for m in server.findall("ip-pool/member")]

        option = server.find("option")
        gateway, subnet, dns_primary, dns_secondary, lease = "", "", "", "", ""
        if option is not None:
            gateway = option.findtext("gateway") or ""
            subnet = option.findtext("subnet-mask") or ""
            dns_primary = option.findtext("dns/primary") or ""
            dns_secondary = option.findtext("dns/secondary") or ""
            lease = option.findtext("lease/timeout") or ""

        reserved = []
        for r in server.findall("reserved/entry"):
            ip = r.get("name", "")
            mac = r.findtext("mac") or ""
            reserved.append(f"{ip} ({mac})" if mac else ip)

        gw_subnet = f"{gateway} / {subnet}" if gateway or subnet else ""
        dns = "\n".join(x for x in (dns_primary, dns_secondary) if x)

        rows.append((name, mode, pool, gw_subnet, dns, lease, reserved))

    added = 0
    for name, mode, pool, gw_subnet, dns, lease, reserved in rows:
        if not grep_row(grep, name, mode, gw_subnet, dns):
            continue
        table.add_row(name, mode, "\n".join(pool), gw_subnet, dns, lease,
                      "\n".join(reserved))
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No DHCP server configuration found.[/dim]")
