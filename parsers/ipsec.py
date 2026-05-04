from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_ipsec_tunnels(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="IPSec Tunnels", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Tunnel Interface", min_width=16)
    table.add_column("IKE Gateway", min_width=20)
    table.add_column("IPSec Crypto Profile", min_width=24)
    table.add_column("Tunnel Monitor", min_width=14)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("tunnel/ipsec")
    if container is None:
        console.print("[dim]No IPSec tunnels found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"),
                        key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        tunnel_iface = entry.findtext("tunnel-interface") or ""
        gw_entry = entry.find("auto-key/ike-gateway/entry")
        ike_gateway = gw_entry.get("name", "") if gw_entry is not None else ""
        ipsec_crypto = entry.findtext("auto-key/ipsec-crypto-profile") or ""
        monitor_enabled = "yes" if entry.find("tunnel-monitor") is not None else "no"

        if not grep_row(grep, name, tunnel_iface, ike_gateway, ipsec_crypto):
            continue

        table.add_row(name, tunnel_iface, ike_gateway, ipsec_crypto, monitor_enabled)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No IPSec tunnels found.[/dim]")
