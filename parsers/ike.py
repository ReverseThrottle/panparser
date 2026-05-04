from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members


def _lifetime_str(entry: Element) -> str:
    el = entry.find("lifetime")
    if el is None:
        return ""
    child = next(iter(el), None)
    return f"{child.text} {child.tag}" if child is not None else ""


def render_ike_gateways(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="IKE Gateways", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Peer IP", min_width=16)
    table.add_column("Local IP", min_width=16)
    table.add_column("Local Iface", min_width=12)
    table.add_column("Auth Type", min_width=14)
    table.add_column("IKE Version", min_width=10)
    table.add_column("Disabled", min_width=8)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("ike/gateway")
    if container is None:
        console.print("[dim]No IKE gateways found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"),
                        key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        peer_ip = entry.findtext("peer-address/ip") or ""
        local_ip = entry.findtext("local-address/ip") or ""
        local_iface = entry.findtext("local-address/interface") or ""
        auth_type = ("pre-shared-key"
                     if entry.find("authentication/pre-shared-key") is not None
                     else "certificate")
        ike_version = entry.findtext("protocol/version") or ""
        disabled = entry.findtext("disabled") or "no"

        if not grep_row(grep, name, peer_ip, local_ip, local_iface, auth_type, ike_version):
            continue

        table.add_row(name, peer_ip, local_ip, local_iface, auth_type, ike_version, disabled)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No IKE gateways found.[/dim]")


def render_ike_crypto(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="IKE Crypto Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Encryption", min_width=20)
    table.add_column("Hash", min_width=16)
    table.add_column("DH Group", min_width=16)
    table.add_column("Lifetime", min_width=12)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("ike/crypto-profiles/ike-crypto-profiles")
    if container is None:
        console.print("[dim]No IKE crypto profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"),
                        key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        encryption = ", ".join(get_members(entry, "encryption/member"))
        hash_ = ", ".join(get_members(entry, "hash/member"))
        dh_group = ", ".join(get_members(entry, "dh-group/member"))
        lifetime = _lifetime_str(entry)

        if not grep_row(grep, name, encryption, hash_, dh_group, lifetime):
            continue

        table.add_row(name, encryption, hash_, dh_group, lifetime)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No IKE crypto profiles found.[/dim]")


def render_ipsec_crypto(network_root: Element | None, console, grep=None) -> None:
    table = Table(title="IPSec Crypto Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("ESP Encryption", min_width=20)
    table.add_column("ESP Auth", min_width=16)
    table.add_column("DH Group", min_width=12)
    table.add_column("Lifetime", min_width=12)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("ike/crypto-profiles/ipsec-crypto-profiles")
    if container is None:
        console.print("[dim]No IPSec crypto profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"),
                        key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        esp_encryption = ", ".join(get_members(entry, "esp/encryption/member"))
        esp_auth = ", ".join(get_members(entry, "esp/authentication/member"))
        dh_group = entry.findtext("dh-group") or ""
        lifetime = _lifetime_str(entry)

        if not grep_row(grep, name, esp_encryption, esp_auth, dh_group, lifetime):
            continue

        table.add_row(name, esp_encryption, esp_auth, dh_group, lifetime)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No IPSec crypto profiles found.[/dim]")
