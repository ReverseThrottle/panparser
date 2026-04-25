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
from parsers.routing import render_routing
from parsers.tags import render_tags
from parsers.profiles import render_profiles
from parsers.applications import (
    render_applications, render_application_groups, render_application_filters
)

SECTIONS = [
    "addresses",
    "address-groups",
    "services",
    "service-groups",
    "security-rules",
    "nat-rules",
    "zones",
    "interfaces",
    "routing",
    "tags",
    "profiles",
    "applications",
    "app-groups",
    "app-filters",
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
    sections = args.sections or SECTIONS
    unknown = [s for s in sections if s not in SECTIONS]
    if unknown:
        print(f"Unknown section(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"Valid sections: {', '.join(SECTIONS)}", file=sys.stderr)
        sys.exit(1)

    console = Console(highlight=False, no_color=args.no_color)

    root = load_config(args.config)
    vsys_root, shared_root, network_root = find_roots(
        root, args.vsys, include_shared=not args.no_shared
    )

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
        "zones":          lambda: (section_header(console, "Security Zones"),
                                   render_zones(network_root, console, grep)),
        "interfaces":     lambda: (section_header(console, "Interfaces"),
                                   render_interfaces(network_root, console, grep)),
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
    }

    for section in sections:
        dispatch[section]()

    console.print()


if __name__ == "__main__":
    main()
