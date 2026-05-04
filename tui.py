#!/usr/bin/env python3
"""PAN-OS XML config viewer — interactive Textual TUI."""
from __future__ import annotations

import argparse
import sys
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Label, Static, TabbedContent, TabPane

from panparser import load_config, find_roots
from parsers._data import (
    get_address_groups,
    get_addresses,
    get_app_override_rules,
    get_application_filters,
    get_application_groups,
    get_applications,
    get_auth_profiles,
    get_auth_rules,
    get_bgp_peers,
    get_certificates,
    get_decryption_rules,
    get_dos_rules,
    get_gp_gateways,
    get_gp_portals,
    get_ike_crypto,
    get_ike_gateways,
    get_interfaces,
    get_ipsec_crypto,
    get_ipsec_tunnels,
    get_nat_rules,
    get_ospf_areas,
    get_pbf_rules,
    get_profiles,
    get_qos_rules,
    get_redist_profiles,
    get_routing,
    get_security_rules,
    get_server_profiles,
    get_service_groups,
    get_services,
    get_ssl_profiles,
    get_tags,
    get_url_categories,
    get_zone_protection,
    get_zones,
)

ACTION_STYLES = {
    "allow": "green", "deny": "bold red", "drop": "bold red",
    "reset-client": "yellow", "reset-server": "yellow", "reset-both": "yellow",
}

SECTIONS: list[dict[str, Any]] = [
    {
        "id": "addresses",
        "title": "Addresses",
        "columns": ["#", "Name", "Scope", "Type", "Value", "Description"],
        "getter": "get_addresses",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (
            str(i + 1), r[1], r[0], r[2], r[3], r[4]
        ),
        "detail_keys": ["Name", "Scope", "Type", "Value", "Description"],
    },
    {
        "id": "addr-groups",
        "title": "Addr Groups",
        "columns": ["#", "Name", "Scope", "Type", "Members", "Description"],
        "getter": "get_address_groups",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (
            str(i + 1), r[1], r[0], r[2], r[3], r[4]
        ),
        "detail_keys": ["Name", "Scope", "Type", "Members", "Description"],
    },
    {
        "id": "services",
        "title": "Services",
        "columns": ["#", "Name", "Scope", "Protocol", "Dst Port", "Src Port", "Description"],
        "getter": "get_services",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (
            str(i + 1), r[1], r[0], r[2], r[3], r[4], r[5]
        ),
        "detail_keys": ["Name", "Scope", "Protocol", "Dst Port", "Src Port", "Description"],
    },
    {
        "id": "svc-groups",
        "title": "Svc Groups",
        "columns": ["#", "Name", "Scope", "Members", "Description"],
        "getter": "get_service_groups",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (
            str(i + 1), r[1], r[0], r[2], r[3]
        ),
        "detail_keys": ["Name", "Scope", "Members", "Description"],
    },
    {
        "id": "security",
        "title": "Security Rules",
        "columns": ["#", "Name", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "App", "Service", "Action", "Profile"],
        "getter": "get_security_rules",
        "roots": "vsys",
        "row_fn": None,  # custom — see _security_row
        "detail_keys": ["#", "Name", "Disabled", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "App", "Service", "Action", "Profile"],
    },
    {
        "id": "nat",
        "title": "NAT Rules",
        "columns": ["#", "Name", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "Dst Iface", "Type", "Translated To"],
        "getter": "get_nat_rules",
        "roots": "vsys",
        "row_fn": None,  # custom — see _nat_row
        "detail_keys": ["#", "Name", "Disabled", "Src Zone", "Dst Zone", "Src Addr", "Dst Addr", "Dst Iface", "NAT Type", "Translated"],
    },
    {
        "id": "dos",
        "title": "DoS Rules",
        "columns": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Service", "Protection", "Action", "Log Setting"],
        "getter": "get_dos_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(i + 1), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]),
        "detail_keys": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Service", "Protection Type", "Action", "Log Setting", "Description"],
    },
    {
        "id": "zones",
        "title": "Zones",
        "columns": ["Name", "Type", "Interfaces", "Zone Protect Profile", "Log Setting"],
        "getter": "get_zones",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Type", "Interfaces", "Zone Protection Profile", "Log Setting"],
    },
    {
        "id": "interfaces",
        "title": "Interfaces",
        "columns": ["Name", "Type", "IP / Mode", "Subinterfaces", "Comment"],
        "getter": "get_interfaces",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Type", "IP / Mode", "Subinterfaces", "Comment"],
    },
    {
        "id": "routing",
        "title": "Routing",
        "columns": ["VR", "Route Name", "Destination", "Next Hop", "Interface", "Metric", "Admin Dist"],
        "getter": "get_routing",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["Virtual Router", "Route Name", "Destination", "Next Hop", "Interface", "Metric", "Admin Dist"],
    },
    {
        "id": "tags",
        "title": "Tags",
        "columns": ["#", "Name", "Scope", "Color", "Comments"],
        "getter": "get_tags",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (str(i + 1), r[1], r[0], r[2], r[3]),
        "detail_keys": ["Name", "Scope", "Color", "Comments"],
    },
    {
        "id": "profiles",
        "title": "Profiles",
        "columns": ["Profile Type", "Scope", "Name", "Summary", "Description"],
        "getter": "get_profiles",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Profile Type", "Scope", "Name", "Summary", "Description"],
    },
    {
        "id": "applications",
        "title": "Applications",
        "columns": ["#", "Name", "Scope", "Category", "Subcategory", "Technology", "Risk", "Default Ports"],
        "getter": "get_applications",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (str(i + 1), r[1], r[0], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["Name", "Scope", "Category", "Subcategory", "Technology", "Risk", "Default Ports"],
    },
    {
        "id": "app-groups",
        "title": "App Groups",
        "columns": ["#", "Name", "Scope", "Members"],
        "getter": "get_application_groups",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (str(i + 1), r[1], r[0], r[2]),
        "detail_keys": ["Name", "Scope", "Members"],
    },
    {
        "id": "app-filters",
        "title": "App Filters",
        "columns": ["Name", "Scope", "Category", "Subcategory", "Technology", "Risk", "Characteristic"],
        "getter": "get_application_filters",
        "roots": "vsys_shared",
        "row_fn": lambda i, r: (r[1], r[0], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["Name", "Scope", "Category", "Subcategory", "Technology", "Risk", "Characteristic"],
    },
    {
        "id": "certificates",
        "title": "Certificates",
        "columns": ["Name", "Common Name", "Issuer", "Valid From", "Valid Until", "CA", "Algorithm"],
        "getter": "get_certificates",
        "roots": "shared",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["Name", "Common Name", "Issuer", "Valid From", "Valid Until", "CA", "Algorithm"],
    },
    {
        "id": "auth-profiles",
        "title": "Auth Profiles",
        "columns": ["Name", "Method", "MFA", "Allow List", "User Domain"],
        "getter": "get_auth_profiles",
        "roots": "shared",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Method", "MFA Enabled", "Allow List", "User Domain"],
    },
    {
        "id": "ssl-profiles",
        "title": "SSL Profiles",
        "columns": ["Name", "Certificate", "Min Version", "Max Version"],
        "getter": "get_ssl_profiles",
        "roots": "shared",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3]),
        "detail_keys": ["Name", "Certificate", "Min Version", "Max Version"],
    },
    {
        "id": "zone-protection",
        "title": "Zone Protection",
        "columns": ["Name", "Flood Protection", "Discard IP Spoof", "Discard IP Frag", "Strict IP Check"],
        "getter": "get_zone_protection",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Flood Protection", "Discard IP Spoof", "Discard IP Frag", "Strict IP Check"],
    },
    {
        "id": "gp-gateways",
        "title": "GP Gateways",
        "columns": ["Name", "SSL/TLS Profile", "Tunnel Mode", "Tunnel Interface", "Client Auth"],
        "getter": "get_gp_gateways",
        "roots": "vsys",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "SSL/TLS Profile", "Tunnel Mode", "Tunnel Interface", "Client Auth Entries"],
    },
    {
        "id": "gp-portals",
        "title": "GP Portals",
        "columns": ["Name", "Local Address", "SSL/TLS Profile", "Client Auth"],
        "getter": "get_gp_portals",
        "roots": "vsys",
        "row_fn": lambda i, r: (r[0], r[1], r[3], r[2]),
        "detail_keys": ["Name", "Local Address", "Client Auth Entries", "SSL/TLS Profile"],
    },
    {
        "id": "decryption",
        "title": "Decryption",
        "columns": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Type", "Profile", "Action", "Disabled"],
        "getter": "get_decryption_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], "yes" if r[9] else ""),
        "detail_keys": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Type", "Profile", "Action", "Disabled"],
    },
    {
        "id": "pbf",
        "title": "PBF Rules",
        "columns": ["#", "Name", "From Zone", "Src Addr", "Dst Addr", "App", "Service", "Action", "Egress Iface", "Nexthop"],
        "getter": "get_pbf_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]),
        "detail_keys": ["#", "Name", "From Zone", "Src Addr", "Dst Addr", "App", "Service", "Action", "Egress Iface", "Nexthop"],
    },
    {
        "id": "app-override",
        "title": "App Override",
        "columns": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Protocol", "Port", "Application", "Disabled"],
        "getter": "get_app_override_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], "yes" if r[9] else ""),
        "detail_keys": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Protocol", "Port", "Application", "Disabled"],
    },
    {
        "id": "auth-rules",
        "title": "Auth Rules",
        "columns": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Src User", "Service", "Auth Enforcement", "Log Setting", "Disabled"],
        "getter": "get_auth_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], "yes" if r[10] else ""),
        "detail_keys": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "Src User", "Service", "Auth Enforcement", "Log Setting", "Disabled"],
    },
    {
        "id": "qos-rules",
        "title": "QoS Rules",
        "columns": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "App", "Service", "Class", "Schedule"],
        "getter": "get_qos_rules",
        "roots": "vsys",
        "row_fn": lambda i, r: (str(r[0]), r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]),
        "detail_keys": ["#", "Name", "From Zone", "To Zone", "Src Addr", "Dst Addr", "App", "Service", "Class", "Schedule"],
    },
    {
        "id": "url-categories",
        "title": "URL Categories",
        "columns": ["Name", "Type", "URL Count", "Description"],
        "getter": "get_url_categories",
        "roots": "vsys",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3]),
        "detail_keys": ["Name", "Type", "URL Count", "Description"],
    },
    {
        "id": "server-profiles",
        "title": "Server Profiles",
        "columns": ["Type", "Name", "Servers", "Details"],
        "getter": "get_server_profiles",
        "roots": "shared",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3]),
        "detail_keys": ["Profile Type", "Name", "Server Count", "Details"],
    },
    {
        "id": "ike-gateways",
        "title": "IKE Gateways",
        "columns": ["Name", "Peer IP", "Local IP", "Local Iface", "Auth Type", "IKE Version", "Disabled"],
        "getter": "get_ike_gateways",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4], r[5], "yes" if r[6] else ""),
        "detail_keys": ["Name", "Peer IP", "Local IP", "Local Iface", "Auth Type", "IKE Version", "Disabled"],
    },
    {
        "id": "ike-crypto",
        "title": "IKE Crypto",
        "columns": ["Name", "Encryption", "Hash", "DH Group", "Lifetime"],
        "getter": "get_ike_crypto",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Encryption", "Hash", "DH Group", "Lifetime"],
    },
    {
        "id": "ipsec-crypto",
        "title": "IPSec Crypto",
        "columns": ["Name", "ESP Encryption", "ESP Auth", "DH Group", "Lifetime"],
        "getter": "get_ipsec_crypto",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "ESP Encryption", "ESP Auth", "DH Group", "Lifetime"],
    },
    {
        "id": "ipsec-tunnels",
        "title": "IPSec Tunnels",
        "columns": ["Name", "Tunnel Iface", "IKE Gateway", "IPSec Crypto Profile", "Tunnel Monitor"],
        "getter": "get_ipsec_tunnels",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["Name", "Tunnel Interface", "IKE Gateway", "IPSec Crypto Profile", "Tunnel Monitor"],
    },
    {
        "id": "bgp-peers",
        "title": "BGP Peers",
        "columns": ["VR", "Peer Group", "Peer Name", "Peer AS", "Local IP", "Peer IP", "Enabled"],
        "getter": "get_bgp_peers",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["VR", "Peer Group", "Peer Name", "Peer AS", "Local IP", "Peer IP", "Enabled"],
    },
    {
        "id": "ospf-areas",
        "title": "OSPF Areas",
        "columns": ["VR", "Area ID", "Interface", "Enabled", "Passive", "Metric", "Link Type"],
        "getter": "get_ospf_areas",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4], r[5], r[6]),
        "detail_keys": ["VR", "Area ID", "Interface", "Enabled", "Passive", "Metric", "Link Type"],
    },
    {
        "id": "redist-profiles",
        "title": "Redist Profiles",
        "columns": ["VR", "Name", "Action", "Filter Type", "Filter Value"],
        "getter": "get_redist_profiles",
        "roots": "network",
        "row_fn": lambda i, r: (r[0], r[1], r[2], r[3], r[4]),
        "detail_keys": ["VR", "Name", "Action", "Filter Type", "Filter Value"],
    },
]

GETTERS = {
    "get_addresses": get_addresses,
    "get_address_groups": get_address_groups,
    "get_services": get_services,
    "get_service_groups": get_service_groups,
    "get_security_rules": get_security_rules,
    "get_nat_rules": get_nat_rules,
    "get_dos_rules": get_dos_rules,
    "get_zones": get_zones,
    "get_interfaces": get_interfaces,
    "get_routing": get_routing,
    "get_tags": get_tags,
    "get_profiles": get_profiles,
    "get_applications": get_applications,
    "get_application_groups": get_application_groups,
    "get_application_filters": get_application_filters,
    "get_certificates": get_certificates,
    "get_auth_profiles": get_auth_profiles,
    "get_ssl_profiles": get_ssl_profiles,
    "get_zone_protection": get_zone_protection,
    "get_gp_gateways": get_gp_gateways,
    "get_gp_portals": get_gp_portals,
    "get_decryption_rules": get_decryption_rules,
    "get_pbf_rules": get_pbf_rules,
    "get_app_override_rules": get_app_override_rules,
    "get_auth_rules": get_auth_rules,
    "get_qos_rules": get_qos_rules,
    "get_url_categories": get_url_categories,
    "get_server_profiles": get_server_profiles,
    "get_ike_gateways": get_ike_gateways,
    "get_ike_crypto": get_ike_crypto,
    "get_ipsec_crypto": get_ipsec_crypto,
    "get_ipsec_tunnels": get_ipsec_tunnels,
    "get_bgp_peers": get_bgp_peers,
    "get_ospf_areas": get_ospf_areas,
    "get_redist_profiles": get_redist_profiles,
}


def _security_row(i: int, r: tuple) -> tuple:
    num, name, disabled, src_z, dst_z, src_a, dst_a, apps, svcs, action, profile = r
    name_text = Text(f"{name} [disabled]" if disabled else name,
                     style="dim" if disabled else "")
    action_style = ACTION_STYLES.get(action, "")
    action_text = Text(action, style=action_style)
    return (Text(str(num), style="dim"), name_text, src_z, dst_z, src_a, dst_a,
            apps, svcs, action_text, profile)


def _nat_row(i: int, r: tuple) -> tuple:
    num, name, disabled, src_z, dst_z, src_a, dst_a, dst_iface, nat_type, translated = r
    name_text = Text(f"{name} [disabled]" if disabled else name,
                     style="dim" if disabled else "")
    return (Text(str(num), style="dim"), name_text, src_z, dst_z, src_a, dst_a,
            dst_iface, nat_type, translated)


CUSTOM_ROW_FNS = {
    "security": _security_row,
    "nat": _nat_row,
}


class PanosViewerApp(App):
    CSS = """
    Screen { layout: vertical; }

    #filter-bar {
        height: 3;
        layout: horizontal;
        background: $surface;
        padding: 0 1;
        border-bottom: solid $primary-darken-2;
    }
    #filter-label { width: auto; padding: 1 1; color: $text-muted; }
    #filter-input { width: 1fr; }
    #row-count { width: 14; padding: 1 1; color: $text-muted; text-align: right; }

    TabbedContent { height: 1fr; }
    TabPane { padding: 0; }
    DataTable { height: 1fr; }

    #detail-bar {
        height: 4;
        background: $surface-darken-1;
        border-top: solid $primary-darken-2;
        padding: 0 1;
        overflow-x: auto;
        overflow-y: auto;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_filter", "Filter", key_display="/"),
        Binding("r", "reset_filter", "Reset filter"),
        Binding("escape", "unfocus_filter", "Unfocus", show=False),
    ]

    def __init__(self, vsys_root, shared_root, network_root, config_path: str, vsys: str):
        super().__init__()
        self._roots = (vsys_root, shared_root, network_root)
        self._config_path = config_path
        self._vsys = vsys
        self._section_data: dict[str, list] = {}
        self._active_section_id = SECTIONS[0]["id"]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="filter-bar"):
            yield Label("Filter:", id="filter-label")
            yield Input(placeholder="type to filter rows...", id="filter-input")
            yield Label("", id="row-count")
        with TabbedContent():
            for sec in SECTIONS:
                with TabPane(sec["title"], id=f"tab-{sec['id']}"):
                    yield DataTable(id=f"dt-{sec['id']}", cursor_type="row",
                                    zebra_stripes=True)
        yield Static("", id="detail-bar", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"PAN-OS Config Viewer — {self._config_path}  (vsys: {self._vsys})"
        vsys_root, shared_root, network_root = self._roots

        # Load all data up front
        roots_map = {
            "vsys":        (vsys_root,),
            "shared":      (shared_root,),
            "network":     (network_root,),
            "vsys_shared": (vsys_root, shared_root),
        }
        for sec in SECTIONS:
            getter_fn = GETTERS[sec["getter"]]
            args = roots_map[sec.get("roots", "vsys_shared")]
            self._section_data[sec["id"]] = getter_fn(*args)

        # Set up columns and populate all tables
        for sec in SECTIONS:
            dt = self.query_one(f"#dt-{sec['id']}", DataTable)
            for col in sec["columns"]:
                dt.add_column(col, key=col)
            self._populate_table(sec["id"], "")

    # ── table population ──────────────────────────────────────────────────────

    def _populate_table(self, section_id: str, filter_text: str) -> None:
        sec = self._get_section(section_id)
        dt = self.query_one(f"#dt-{section_id}", DataTable)
        dt.clear()

        full_rows = self._section_data[section_id]
        needle = filter_text.strip().lower()
        row_fn = CUSTOM_ROW_FNS.get(section_id) or sec["row_fn"]

        added = 0
        for i, raw in enumerate(full_rows):
            # Filter against plain-string representation of the row
            if needle and not any(needle in str(v).lower() for v in raw):
                continue
            display = row_fn(i, raw)
            dt.add_row(*display, key=str(i))
            added += 1

        if section_id == self._active_section_id:
            self._update_count(added, len(full_rows))

    def _update_count(self, shown: int, total: int) -> None:
        self.query_one("#row-count", Label).update(
            f"{shown}/{total} rows" if shown != total else f"{total} rows"
        )

    # ── events ────────────────────────────────────────────────────────────────

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if event.tab is None:
            return
        # tab id is "tab-{section_id}"
        section_id = event.pane.id.removeprefix("tab-")
        self._active_section_id = section_id
        full = self._section_data.get(section_id, [])
        dt = self.query_one(f"#dt-{section_id}", DataTable)
        self._update_count(dt.row_count, len(full))
        self.query_one("#detail-bar", Static).update("")

    def on_input_changed(self, event: Input.Changed) -> None:
        self._populate_table(self._active_section_id, event.value)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        sec = self._get_section(self._active_section_id)
        raw_index = int(event.row_key.value)
        full_rows = self._section_data[self._active_section_id]
        if raw_index >= len(full_rows):
            return
        raw = full_rows[raw_index]
        keys = sec["detail_keys"]
        parts = [f"{k}: {v}" for k, v in zip(keys, raw)]
        self.query_one("#detail-bar", Static).update("  |  ".join(parts))

    # ── actions ───────────────────────────────────────────────────────────────

    def action_focus_filter(self) -> None:
        self.query_one("#filter-input", Input).focus()

    def action_reset_filter(self) -> None:
        inp = self.query_one("#filter-input", Input)
        inp.value = ""
        inp.focus()

    def action_unfocus_filter(self) -> None:
        dt = self.query_one(f"#dt-{self._active_section_id}", DataTable)
        dt.focus()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_section(self, section_id: str) -> dict:
        return next(s for s in SECTIONS if s["id"] == section_id)


# ── CLI entry ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tui",
        description="Interactive PAN-OS config viewer (Textual TUI).",
    )
    parser.add_argument("config", help="Path to PAN-OS XML config file")
    parser.add_argument("--vsys", default="vsys1", help="Target vsys (default: vsys1)")
    parser.add_argument("--no-shared", action="store_true",
                        help="Skip shared-scope objects")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = load_config(args.config)
    vsys_root, shared_root, network_root = find_roots(
        root, args.vsys, include_shared=not args.no_shared
    )
    app = PanosViewerApp(vsys_root, shared_root, network_root, args.config, args.vsys)
    app.run()


if __name__ == "__main__":
    main()
