from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_bgp_peers(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="BGP Peers", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("VR", min_width=12)
    table.add_column("Peer Group", min_width=16)
    table.add_column("Peer Name", style="bold", min_width=16)
    table.add_column("Peer AS", min_width=10)
    table.add_column("Local IP", min_width=16)
    table.add_column("Peer IP", min_width=16)
    table.add_column("Enabled", min_width=8)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        console.print("[dim]No BGP peers found.[/dim]")
        return

    added = 0
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        pg_container = vr.find("protocol/bgp/peer-group")
        if pg_container is None:
            continue
        for pg in pg_container.findall("entry"):
            pg_name = pg.get("name", "")
            peer_container = pg.find("peer")
            if peer_container is None:
                continue
            for peer in peer_container.findall("entry"):
                peer_name = peer.get("name", "")
                peer_as = peer.findtext("peer-as") or ""
                local_ip = peer.findtext("local-address/ip") or ""
                peer_ip = peer.findtext("peer-address/ip") or ""
                enabled = peer.findtext("enable") or "yes"

                if not grep_row(grep, vr_name, pg_name, peer_name, peer_as, local_ip, peer_ip):
                    continue

                table.add_row(vr_name, pg_name, peer_name, peer_as, local_ip, peer_ip, enabled)
                added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No BGP peers found.[/dim]")
