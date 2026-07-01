#!/usr/bin/env python3
"""PAN-OS XML config parser and viewer."""
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich import box

from parsers.addresses import render_addresses, render_address_groups
from parsers.services import render_services, render_service_groups
from parsers.security import render_security_rules
from parsers.nat import render_nat_rules
from parsers.zones import render_zones
from parsers.interfaces import render_interfaces
from parsers.dhcp import render_dhcp_servers
from parsers.routing import render_routing
from parsers.tags import render_tags
from parsers.profiles import render_profiles
from parsers.applications import (
    render_applications, render_application_groups, render_application_filters
)
from parsers.dos import render_dos_rules
from parsers.certificates import render_certificates
from parsers.auth_profiles import render_auth_profiles
from parsers.ssl_profiles import render_ssl_profiles
from parsers.zone_protection import render_zone_protection
from parsers.globalprotect import render_gp_gateways, render_gp_portals
from parsers.decryption import render_decryption_rules
from parsers.pbf import render_pbf_rules
from parsers.app_override import render_app_override_rules
from parsers.auth_rules import render_auth_rules
from parsers.qos_rules import render_qos_rules
from parsers.url_categories import render_url_categories
from parsers.server_profiles import render_server_profiles
from parsers.ike import render_ike_gateways, render_ike_crypto, render_ipsec_crypto
from parsers.ipsec import render_ipsec_tunnels
from parsers.bgp import render_bgp_peers
from parsers.ospf import render_ospf_areas
from parsers.redist import render_redist_profiles

SECTIONS = [
    "addresses",
    "address-groups",
    "services",
    "service-groups",
    "security-rules",
    "nat-rules",
    "dos-rules",
    "zones",
    "interfaces",
    "dhcp-servers",
    "routing",
    "tags",
    "profiles",
    "applications",
    "app-groups",
    "app-filters",
    "certificates",
    "auth-profiles",
    "ssl-profiles",
    "zone-protection",
    "gp-gateways",
    "gp-portals",
    "decryption",
    "pbf",
    "app-override",
    "auth-rules",
    "qos-rules",
    "url-categories",
    "server-profiles",
    "ike-gateways",
    "ike-crypto",
    "ipsec-crypto",
    "ipsec-tunnels",
    "bgp-peers",
    "ospf-areas",
    "redist-profiles",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="panparser",
        description="Parse and display PAN-OS XML configuration files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available sections:\n  " + "\n  ".join(SECTIONS),
    )
    parser.add_argument("config", help="Path to PAN-OS XML config file")
    parser.add_argument(
        "-s", "--section", dest="sections", action="append",
        metavar="SECTION",
        help="Section(s) to display (default: all). May be specified multiple times.",
    )
    parser.add_argument(
        "--vsys", default="vsys1",
        help="Target vsys name (default: vsys1)",
    )
    parser.add_argument(
        "-g", "--grep",
        metavar="TEXT",
        help="Filter output to rows containing TEXT (case-insensitive)",
    )
    parser.add_argument(
        "--no-shared", action="store_true",
        help="Skip shared-scope objects",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable color output",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write structured JSON export to FILE (skips display; use with scm-mcp).",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite output file if it already exists (used with --output).",
    )
    return parser.parse_args()


def load_config(path: str) -> Element:
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: XML parse error: {e}", file=sys.stderr)
        sys.exit(1)
    return tree.getroot()


def find_roots(root: Element, vsys_name: str, include_shared: bool):
    """Return (vsys_root, shared_root, network_root) from the config root.

    Handles both running-config and 'show config all' formats, as well as
    configs that use a <response> wrapper from the API.
    """
    # Some API responses wrap the config in <response><result><config>
    if root.tag == "response":
        result = root.find("result")
        if result is not None:
            config = result.find("config")
            if config is not None:
                root = config

    # Find the device entry — try the standard path first
    device_entry = root.find("devices/entry")
    if device_entry is None:
        # Some minimal exports omit the devices wrapper
        device_entry = root

    vsys_root = None
    vsys_container = device_entry.find("vsys")
    if vsys_container is not None:
        vsys_root = vsys_container.find(f"entry[@name='{vsys_name}']")
        if vsys_root is None and len(vsys_container) > 0:
            # Fall back to first vsys
            vsys_root = vsys_container[0]

    shared_root = root.find("shared") if include_shared else None
    network_root = device_entry.find("network")

    return vsys_root, shared_root, network_root


def section_header(console: Console, title: str) -> None:
    console.print()
    console.rule(f"[bold]{title}[/bold]", style="dim cyan")


def main() -> None:
    args = parse_args()

    root = load_config(args.config)
    vsys_root, shared_root, network_root = find_roots(
        root, args.vsys, include_shared=not args.no_shared
    )

    # --output: write JSON export and exit; do not start the display pipeline
    if args.output:
        import os
        from export.writer import build_export, write_export
        if os.path.exists(args.output) and not args.force:
            print(
                f"Error: '{args.output}' already exists. Use --force to overwrite.",
                file=sys.stderr,
            )
            sys.exit(1)
        data = build_export(
            root, vsys_root, shared_root, network_root,
            source_file=args.config, vsys=args.vsys,
        )
        write_export(data, args.output)
        sys.exit(0)

    sections = args.sections or SECTIONS
    unknown = [s for s in sections if s not in SECTIONS]
    if unknown:
        print(f"Unknown section(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"Valid sections: {', '.join(SECTIONS)}", file=sys.stderr)
        sys.exit(1)

    console = Console(highlight=False, no_color=args.no_color)

    is_full_config = root.find("defaults") is not None
    grep = args.grep

    console.print(Panel(
        f"[bold]PAN-OS Config:[/bold] {args.config}\n"
        f"[dim]vsys:[/dim] {args.vsys}  |  "
        f"[dim]shared:[/dim] {'yes' if shared_root is not None else 'no'}  |  "
        f"[dim]format:[/dim] {'full (show config all)' if is_full_config else 'running-config'}"
        + (f"  |  [dim]grep:[/dim] {grep}" if grep else ""),
        box=box.ROUNDED, style="bold blue",
    ))

    dispatch = {
        "addresses":      lambda: (section_header(console, "Address Objects"),
                                   render_addresses(vsys_root, shared_root, console, grep)),
        "address-groups": lambda: (section_header(console, "Address Groups"),
                                   render_address_groups(vsys_root, shared_root, console, grep)),
        "services":       lambda: (section_header(console, "Service Objects"),
                                   render_services(vsys_root, shared_root, console, grep)),
        "service-groups": lambda: (section_header(console, "Service Groups"),
                                   render_service_groups(vsys_root, shared_root, console, grep)),
        "security-rules": lambda: (section_header(console, "Security Policy"),
                                   render_security_rules(vsys_root, console, grep)),
        "nat-rules":      lambda: (section_header(console, "NAT Policy"),
                                   render_nat_rules(vsys_root, console, grep)),
        "dos-rules":      lambda: (section_header(console, "DoS Protection Rules"),
                                   render_dos_rules(vsys_root, console, grep)),
        "zones":          lambda: (section_header(console, "Security Zones"),
                                   render_zones(network_root, console, grep)),
        "interfaces":     lambda: (section_header(console, "Interfaces"),
                                   render_interfaces(network_root, console, grep)),
        "dhcp-servers":   lambda: (section_header(console, "DHCP Servers"),
                                   render_dhcp_servers(network_root, console, grep)),
        "routing":        lambda: (section_header(console, "Static Routes"),
                                   render_routing(network_root, console, grep)),
        "tags":           lambda: (section_header(console, "Tags"),
                                   render_tags(vsys_root, shared_root, console, grep)),
        "profiles":       lambda: (section_header(console, "Security Profiles"),
                                   render_profiles(vsys_root, shared_root, console, grep)),
        "applications":   lambda: (section_header(console, "Custom Applications"),
                                   render_applications(vsys_root, shared_root, console, grep)),
        "app-groups":     lambda: (section_header(console, "Application Groups"),
                                   render_application_groups(vsys_root, shared_root, console, grep)),
        "app-filters":    lambda: (section_header(console, "Application Filters"),
                                   render_application_filters(vsys_root, shared_root, console, grep)),
        "certificates":   lambda: (section_header(console, "Certificates"),
                                   render_certificates(shared_root, console, grep)),
        "auth-profiles":  lambda: (section_header(console, "Authentication Profiles"),
                                   render_auth_profiles(shared_root, console, grep)),
        "ssl-profiles":   lambda: (section_header(console, "SSL/TLS Service Profiles"),
                                   render_ssl_profiles(shared_root, console, grep)),
        "zone-protection": lambda: (section_header(console, "Zone Protection Profiles"),
                                    render_zone_protection(network_root, console, grep)),
        "gp-gateways":    lambda: (section_header(console, "GlobalProtect Gateways"),
                                   render_gp_gateways(vsys_root, console, grep)),
        "gp-portals":     lambda: (section_header(console, "GlobalProtect Portals"),
                                   render_gp_portals(vsys_root, console, grep)),
        "decryption":     lambda: (section_header(console, "Decryption Rules"),
                                   render_decryption_rules(vsys_root, console, grep)),
        "pbf":            lambda: (section_header(console, "Policy Based Forwarding Rules"),
                                   render_pbf_rules(vsys_root, console, grep)),
        "app-override":   lambda: (section_header(console, "Application Override Rules"),
                                   render_app_override_rules(vsys_root, console, grep)),
        "auth-rules":     lambda: (section_header(console, "Authentication Rules"),
                                   render_auth_rules(vsys_root, console, grep)),
        "qos-rules":      lambda: (section_header(console, "QoS Rules"),
                                   render_qos_rules(vsys_root, console, grep)),
        "url-categories": lambda: (section_header(console, "Custom URL Categories"),
                                   render_url_categories(vsys_root, console, grep)),
        "server-profiles": lambda: (section_header(console, "Server Profiles"),
                                    render_server_profiles(shared_root, console, grep)),
        "ike-gateways":   lambda: (section_header(console, "IKE Gateways"),
                                   render_ike_gateways(network_root, console, grep)),
        "ike-crypto":     lambda: (section_header(console, "IKE Crypto Profiles"),
                                   render_ike_crypto(network_root, console, grep)),
        "ipsec-crypto":   lambda: (section_header(console, "IPSec Crypto Profiles"),
                                   render_ipsec_crypto(network_root, console, grep)),
        "ipsec-tunnels":  lambda: (section_header(console, "IPSec Tunnels"),
                                   render_ipsec_tunnels(network_root, console, grep)),
        "bgp-peers":      lambda: (section_header(console, "BGP Peers"),
                                   render_bgp_peers(network_root, console, grep)),
        "ospf-areas":     lambda: (section_header(console, "OSPF Areas"),
                                   render_ospf_areas(network_root, console, grep)),
        "redist-profiles": lambda: (section_header(console, "Redistribution Profiles"),
                                    render_redist_profiles(network_root, console, grep)),
    }

    for section in sections:
        dispatch[section]()

    console.print()


if __name__ == "__main__":
    main()
