"""Unit tests for parsers/_data.py TUI getters + VR export getters (issue #80).

AC1: every one of the 36 TUI sections (enumerated from tui.SECTIONS, the same
registry the app dispatches through) has a populated-fixture getter test,
empty-container tests, and exact-row assertions for extraction/merge/sort
behavior. The VR export getters (get_virtual_routers_export and helpers) are
also covered — they live in _data.py and are required for the ≥80% target;
export/objects.py itself belongs to sibling issue #79 and is untouched.
"""

import xml.etree.ElementTree as ET

import pytest

import tui
from parsers import _data
from viewer_harness import roots_for, sample_roots

# One expected marker per TUI section: a substring that must appear in the
# stringified getter rows when run against the shared sample config.
SECTION_MARKERS = {
    "addresses": "host-web",
    "addr-groups": "grp-static",
    "services": "svc-https",
    "svc-groups": "svc-grp-web",
    "security": "allow-web",
    "nat": "nat-dipp-iface",
    "dos": "dos-protect",
    "zones": "trust",
    "interfaces": "ethernet1/1",
    "vlans": "vlan-blue",
    "routing": "vr-default",
    "tags": "tag-prod",
    "profiles": "av-default",
    "applications": "app-custom",
    "app-groups": "app-grp-custom",
    "app-filters": "app-filter-risky",
    "certificates": "vpn-cert",
    "auth-profiles": "auth-local",
    "ssl-profiles": "ssl-default",
    "zone-protection": "zpp-strict",
    "gp-gateways": "gp-gw-1",
    "gp-portals": "gp-portal-1",
    "decryption": "decrypt-web",
    "pbf": "pbf-forward",
    "app-override": "app-ov-1",
    "auth-rules": "auth-rule-1",
    "qos-rules": "qos-rule-1",
    "url-categories": "url-custom",
    "server-profiles": "ldap-main",
    "ike-gateways": "ike-gw-1",
    "ike-crypto": "ike-crypto-1",
    "ipsec-crypto": "ipsec-crypto-1",
    "ipsec-tunnels": "ipsec-vpn-1",
    "bgp-peers": "peer-1",
    "ospf-areas": "0.0.0.0",
    "redist-profiles": "rp-static",
}

def _section_params():
    return [pytest.param(sec, id=sec["id"]) for sec in tui.SECTIONS]


@pytest.fixture(scope="module")
def roots():
    return sample_roots()


def test_registry_matches_issue_contract():
    """AC1 premise: 36 sections, every getter name resolves in _data."""
    assert len(tui.SECTIONS) == 36
    assert set(SECTION_MARKERS) == {s["id"] for s in tui.SECTIONS}
    for sec in tui.SECTIONS:
        assert sec["getter"] in tui.GETTERS
        assert hasattr(_data, sec["getter"])
        assert sec["roots"] in ("vsys", "network", "vsys_shared", "shared")


@pytest.mark.parametrize("sec", _section_params())
def test_section_getter_populated(sec, roots):
    """Every TUI section extracts rows from the shared sample config."""
    vsys, shared, network = roots
    getter = getattr(_data, sec["getter"])
    rows = getter(*roots_for(sec["roots"], vsys, shared, network))
    assert isinstance(rows, list)
    assert rows, f"{sec['id']} getter returned no rows on populated fixture"
    # TUI feeds rows straight into DataTable.add_row(*row): cells must be
    # str/int/bool, never None or nested containers.
    for row in rows:
        assert isinstance(row, tuple)
        assert all(isinstance(cell, (str, int, bool)) for cell in row)
    assert SECTION_MARKERS[sec["id"]] in repr(rows)


@pytest.mark.parametrize("sec", _section_params())
def test_section_getter_none_roots(sec):
    """Empty-container handling: None roots must yield [], never raise."""
    getter = getattr(_data, sec["getter"])
    n_args = 2 if sec["roots"] == "vsys_shared" else 1
    assert getter(*(None,) * n_args) == []


@pytest.mark.parametrize("sec", _section_params())
def test_section_getter_empty_roots(sec):
    """Empty-container handling: present-but-empty roots must yield []."""
    getter = getattr(_data, sec["getter"])
    n_args = 2 if sec["roots"] == "vsys_shared" else 1
    assert getter(*(ET.Element("empty") for _ in range(n_args))) == []


# ---------------------------------------------------------------------------
# Exact-row assertions: extraction, shared/vsys merge, ordering
# ---------------------------------------------------------------------------


def test_addresses_exact_rows_and_merge(roots):
    vsys, shared, _ = roots
    rows = _data.get_addresses(vsys, shared)
    assert len(rows) == 6  # 5 vsys + 1 shared, sorted by name
    assert [r[1] for r in rows] == [
        "fqdn-updates", "host-web", "mystery-obj", "range-printers",
        "shared-dns", "wildcard-mask",
    ]
    assert rows[1] == ("vsys", "host-web", "ip-netmask", "10.1.1.10/32", "web server")
    assert ("vsys", "range-printers", "ip-range", "10.1.2.10-10.1.2.20", "") in rows
    assert ("vsys", "fqdn-updates", "fqdn", "updates.example.com", "") in rows
    assert ("vsys", "wildcard-mask", "ip-wildcard", "10.0.0.0/0.255.255.255", "") in rows
    # entry with no recognized type falls back to unknown
    assert ("vsys", "mystery-obj", "unknown", "", "") in rows
    # shared-scope entry merged in with scope="shared"
    assert ("shared", "shared-dns", "ip-netmask", "8.8.8.8/32", "shared resolver") in rows


def test_services_exact_rows(roots):
    vsys, shared, _ = roots
    rows = _data.get_services(vsys, shared)
    assert ("vsys", "svc-https", "TCP", "443", "1024-65535", "HTTPS") in rows
    assert ("vsys", "svc-dns", "UDP", "53", "", "") in rows
    assert ("vsys", "svc-sctp", "SCTP", "3868", "", "") in rows
    assert ("vsys", "svc-unknown", "unknown", "", "", "") in rows
    assert ("shared", "svc-shared-ntp", "UDP", "123", "", "") in rows


def test_service_groups_merge(roots):
    vsys, shared, _ = roots
    rows = _data.get_service_groups(vsys, shared)
    assert ("vsys", "svc-grp-web", "svc-https, svc-dns", "") in rows
    assert ("shared", "svc-grp-shared", "svc-shared-ntp", "") in rows


def test_security_rules_profiles_and_disabled(roots):
    vsys, _, _ = roots
    rows = _data.get_security_rules(vsys)
    assert len(rows) == 3
    assert rows[0] == (
        1, "allow-web", False, "trust", "untrust", "host-web", "any",
        "app-custom", "svc-https", "allow", "profile-grp-1",
    )
    assert rows[1] == (
        2, "deny-all", True, "any", "any", "any", "any", "any", "any",
        "deny", "(custom)",
    )
    assert rows[2][10] == ""  # no profile-setting -> empty profile column


def test_nat_rules_translation_modes(roots):
    vsys, _, _ = roots
    rows = {r[1]: r for r in _data.get_nat_rules(vsys)}
    assert rows["nat-dipp-iface"][8:10] == ("src-nat", "DIPP (ethernet1/2)")
    assert rows["nat-dipp-iface"][7] == "ethernet1/2"  # to-interface
    assert rows["nat-dipp-pool"][9] == "DIPP 10.1.1.100, 10.1.1.101"
    assert rows["nat-dynamic-ip"][8:10] == ("src-nat", "dynamic-ip 10.1.1.200")
    assert rows["nat-static"][8:10] == ("src-nat", "static → 10.1.1.10")
    assert rows["nat-dst"][8:10] == ("dst-nat", "dst-nat → 10.1.1.10:8443")
    both = rows["nat-both"]
    assert both[2] is True  # disabled
    assert both[8] == "src+dst"
    assert both[9] == "dst-nat → 10.1.1.50\nDIPP (ethernet1/2)"
    assert rows["nat-none"][8:10] == ("none", "")


def test_dos_rules_protection_and_action(roots):
    vsys, _, _ = roots
    rows = {r[1]: r for r in _data.get_dos_rules(vsys)}
    assert rows["dos-protect"][2:4] == ("untrust", "trust")  # from/zone/member
    assert rows["dos-protect"][7:9] == ("aggregate", "protect")
    assert rows["dos-classified"][7:9] == ("classified", "deny")
    assert rows["dos-bare"][7:9] == ("", "")


def test_interfaces_types_subinterfaces_and_bare_parents(roots):
    _, _, network = roots
    rows = _data.get_interfaces(network)
    by_name = {r[0]: r for r in rows}
    assert by_name["ethernet1/1"] == (
        "ethernet1/1", "ethernet", "10.1.1.1/24",
        "ethernet1/1.10: 10.1.10.1/24", "uplink",
    )
    assert by_name["ethernet1/2"][2] == "dhcp"
    assert by_name["ethernet1/3"][2] == "layer2"
    assert by_name["ethernet1/4"][1:3] == ("ethernet", "")  # virtual-wire: no ip/mode
    assert by_name["ae1"] == ("ae1", "ae", "10.2.2.1/24", "", "aggregate uplink")
    # loopback parent has a mgmt profile and no loopback.1 unit -> bare row,
    # then the real loopback.5 unit
    assert ("loopback", "loopback", "", "", "") in rows
    assert by_name["loopback.5"] == ("loopback.5", "loopback", "10.255.255.5/32", "", "router id")
    # tunnel parent has top-level IP and no units -> bare synthesized row
    assert ("tunnel", "tunnel", "10.3.3.1/30", "", "") in rows
    assert by_name["vlan.100"] == ("vlan.100", "vlan", "10.30.30.1/24", "", "")
    # natural sort: ae1 < ethernet1/* < loopback < loopback.5 < tunnel < vlan.100
    assert [r[0] for r in rows] == [
        "ae1", "ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4",
        "ethernet1/6", "loopback", "loopback.5", "tunnel", "vlan.100",
    ]


def test_routing_sorted_by_vr_then_address(roots):
    _, _, network = roots
    rows = _data.get_routing(network)
    assert [r[2] for r in rows] == [
        "0.0.0.0/0", "10.5.0.0/16", "10.9.0.0/16", "172.16.0.0/16", "192.0.2.0/24",
    ]
    by_name = {r[1]: r for r in rows}
    assert by_name["default"] == ("vr-default", "default", "0.0.0.0/0", "10.1.1.254", "", "10", "1")
    assert by_name["blackhole"][3] == "discard"  # markup stripped
    assert by_name["to-vr-branch"][3] == "vr:vr-branch"
    assert by_name["via-tunnel"][3] == "tunnel"
    assert by_name["iface-only"][3:5] == ("", "ethernet1/1")
    # vr-empty has no routing-table -> contributes no rows
    assert all(r[0] == "vr-default" for r in rows)


def test_bgp_peers(roots):
    _, _, network = roots
    rows = _data.get_bgp_peers(network)
    assert rows[0] == ("vr-default", "pg-external", "peer-1", "65002", "10.1.1.1", "10.1.1.254", "yes")
    # peer-2 has no <enable> -> defaults "yes"; local-address has only iface
    assert rows[1] == ("vr-default", "pg-internal", "peer-2", "65001", "", "10.255.255.2", "yes")


def test_ospf_areas_interface_rows(roots):
    _, _, network = roots
    rows = _data.get_ospf_areas(network)
    assert ("vr-default", "0.0.0.0", "ethernet1/1", "yes", "no", "10", "broadcast") in rows
    # loopback.5 uses child-tag <link-type><p2p/></link-type>; findtext sees ""
    assert ("vr-default", "0.0.0.0", "loopback.5", "yes", "yes", "", "") in rows
    # area 0.0.0.1 has no interfaces -> contributes no rows
    assert all(r[1] != "0.0.0.1" for r in rows)


def test_tags_color_labels_and_merge(roots):
    vsys, shared, _ = roots
    rows = _data.get_tags(vsys, shared)
    assert ("vsys", "tag-prod", "red", "production") in rows
    assert ("vsys", "tag-nocolor", "", "") in rows
    assert ("shared", "tag-global", "blue", "shared scope tag") in rows


def test_profiles_summaries_and_merge(roots):
    vsys, shared, _ = roots
    rows = _data.get_profiles(vsys, shared)
    by_key = {(r[0], r[2]): r for r in rows}
    av = by_key[("Antivirus", "av-default")]
    assert av[1] == "vsys"
    assert av[3] == "1 rule(s), default:drop"
    assert by_key[("URL Filtering", "url-default")][3] == "block:2 allow:1 alert:1"
    assert by_key[("Vulnerability Protection", "vp-default")][3] == "2 rule(s)"
    assert by_key[("File Blocking", "fb-default")][3] == "1 rule(s)"
    assert by_key[("WildFire Analysis", "wf-default")][3] == "1 rule(s)"
    assert by_key[("DoS Protection", "dos-profile")][3] == "flood-protection, resource-protection"
    assert by_key[("Data Filtering", "df-default")][3] == ""
    assert by_key[("Antivirus", "av-shared")][1] == "shared"
    assert {r[0] for r in rows} == {
        "Antivirus", "Anti-Spyware", "Vulnerability Protection", "URL Filtering",
        "File Blocking", "WildFire Analysis", "Data Filtering", "DoS Protection",
    }


def test_address_groups_static_and_dynamic(roots):
    vsys, shared, _ = roots
    rows = _data.get_address_groups(vsys, shared)
    assert ("vsys", "grp-static", "static", "host-web, shared-dns", "static group") in rows
    assert ("vsys", "grp-dynamic", "dynamic", "'tag-prod'", "") in rows
    assert ("shared", "grp-shared", "static", "shared-dns", "") in rows


def test_applications_default_ports(roots):
    vsys, shared, _ = roots
    rows = _data.get_applications(vsys, shared)
    # ident-by-ip-protocol members are listed before port members
    assert ("vsys", "app-custom", "business-systems", "general-business", "client-server", "4", "ip/6, tcp/8443") in rows
    assert ("shared", "app-shared", "networking", "routing", "network-protocol", "2", "") in rows


def test_application_groups_and_filters(roots):
    vsys, shared, _ = roots
    assert ("vsys", "app-grp-custom", "app-custom, app-shared") in _data.get_application_groups(vsys, shared)
    assert ("shared", "app-grp-shared", "app-shared") in _data.get_application_groups(vsys, shared)
    rows = _data.get_application_filters(vsys, shared)
    assert ("vsys", "app-filter-risky", "business-systems", "general-business", "client-server", "4, 5", "evades") in rows
    assert ("shared", "app-filter-shared", "networking", "", "", "", "") in rows


def test_certificates(roots):
    _, shared, _ = roots
    rows = _data.get_certificates(shared)
    assert rows[0] == ("ca-cert", "Example CA", "Example CA", "", "", "yes", "ECDSA")
    assert rows[1] == (
        "vpn-cert", "vpn.example.com", "Example CA",
        "Jan  1 00:00:00 2026 GMT", "Jan  1 00:00:00 2028 GMT", "no", "RSA",
    )


def test_auth_profiles_method_child_tag(roots):
    _, shared, _ = roots
    rows = _data.get_auth_profiles(shared)
    assert ("auth-local", "local-database", "yes", "all", "example.local") in rows
    # no method / no mfa -> method "", mfa defaults "no"
    assert ("auth-nomethod", "", "no", "", "") in rows


def test_ssl_profiles(roots):
    _, shared, _ = roots
    assert _data.get_ssl_profiles(shared) == [("ssl-default", "vpn-cert", "tls1-0", "tls1-2")]


def test_server_profiles_details(roots):
    _, shared, _ = roots
    rows = {(r[0], r[1]): r for r in _data.get_server_profiles(shared)}
    assert rows[("ldap", "ldap-main")] == ("ldap", "ldap-main", "2", "dc=example,dc=local")
    # no <base> -> falls back to ldap-type
    assert rows[("ldap", "ldap-nobase")][2:] == ("0", "sun")
    assert rows[("radius", "radius-main")][2:] == ("1", "CHAP")
    assert rows[("syslog", "syslog-main")][2:] == ("1", "10.0.0.30")
    assert {t for t, _ in rows} == {"ldap", "radius", "syslog", "snmptrap", "email", "http"}


def test_url_categories(roots):
    vsys, _, _ = roots
    assert _data.get_url_categories(vsys) == [("url-custom", "URL List", "3", "custom list")]


def test_zone_protection_flood_list(roots):
    _, _, network = roots
    rows = {r[0]: r for r in _data.get_zone_protection(network)}
    assert rows["zpp-strict"] == ("zpp-strict", "tcp-syn, udp, icmp", "yes", "yes", "yes")
    # missing flags default to "no"
    assert rows["zpp-loose"] == ("zpp-loose", "", "no", "no", "no")


def test_ike_gateways_auth_detection(roots):
    _, _, network = roots
    rows = {r[0]: r for r in _data.get_ike_gateways(network)}
    assert rows["ike-gw-1"] == ("ike-gw-1", "203.0.113.1", "10.1.1.1", "ethernet1/1", "pre-shared-key", "ikev2", False)
    assert rows["ike-gw-cert"] == ("ike-gw-cert", "203.0.113.2", "10.1.1.1", "", "certificate", "ikev1", True)


def test_ike_crypto_lifetime_units(roots):
    _, _, network = roots
    rows = {r[0]: r for r in _data.get_ike_crypto(network)}
    assert rows["ike-crypto-1"] == ("ike-crypto-1", "aes-256-cbc, aes-128-cbc", "sha256", "group14", "8 hours")
    assert rows["ike-crypto-nolife"][4] == ""


def test_ipsec_crypto_and_tunnels(roots):
    _, _, network = roots
    assert _data.get_ipsec_crypto(network) == [("ipsec-crypto-1", "aes-256-gcm", "sha256", "group14", "3600 seconds")]
    rows = _data.get_ipsec_tunnels(network)
    assert ("ipsec-vpn-1", "tunnel.1", "ike-gw-1", "ipsec-crypto-1", "yes") in rows
    # no tunnel-monitor element -> "no"
    assert ("ipsec-vpn-2", "tunnel.2", "ike-gw-cert", "", "no") in rows


def test_globalprotect(roots):
    vsys, _, _ = roots
    assert _data.get_gp_gateways(vsys) == [("gp-gw-1", "ssl-default", "yes", "tunnel.1", "2")]
    assert _data.get_gp_portals(vsys) == [("gp-portal-1", "10.1.1.100", "1", "ssl-default")]


def test_decryption_pbf_app_override_auth_qos_rules(roots):
    vsys, _, _ = roots
    assert _data.get_decryption_rules(vsys)[0] == (
        1, "decrypt-web", "trust", "untrust", "any", "any",
        "ssl-forward-proxy", "decrypt-profile", "decrypt", False,
    )
    assert _data.get_pbf_rules(vsys)[0] == (
        1, "pbf-forward", "trust", "host-web", "any", "app-custom", "svc-https",
        "forward", "ethernet1/2", "10.1.1.254",
    )
    assert _data.get_pbf_rules(vsys)[1][7:10] == ("discard", "", "")
    assert _data.get_pbf_rules(vsys)[2][7:10] == ("", "", "")
    assert _data.get_app_override_rules(vsys)[0] == (
        1, "app-ov-1", "trust", "untrust", "any", "host-web",
        "tcp", "8080", "app-custom", False,
    )
    assert _data.get_auth_rules(vsys)[0] == (
        1, "auth-rule-1", "trust", "untrust", "any", "any", "example\\users",
        "svc-https", "auth-local", "auth-log", False,
    )
    qos = {r[1]: r for r in _data.get_qos_rules(vsys)}
    assert qos["qos-rule-1"][8:10] == ("1", "business-hours")
    # <action><class/></action>: empty class text falls back to child tag
    assert qos["qos-rule-emptyclass"][8] == "class"
    assert qos["qos-rule-noaction"][8:10] == ("", "")


def test_vlans(roots):
    _, _, network = roots
    assert _data.get_vlans(network) == [("vlan-blue", "vlan.100", "ethernet1/3")]


def test_redist_profiles_filter_extraction(roots):
    _, _, network = roots
    rows = {r[1]: r for r in _data.get_redist_profiles(network)}
    # rp-static uses child-tag <action><redist/></action>; findtext sees no text
    assert rows["rp-static"] == ("vr-default", "rp-static", "", "type", "static")
    assert rows["rp-connected"] == ("vr-default", "rp-connected", "no-redist", "", "")


def test_ip_sort_key_invalid_address():
    from parsers.routing import _ip_sort_key

    assert _ip_sort_key("not-an-ip") == (999, 999, 999, 999, 999)
    assert _ip_sort_key("10.0.0.1/8") < _ip_sort_key("10.0.0.2/8")
    assert _ip_sort_key("10.0.0.1") == (10, 0, 0, 1, 32)


def test_get_zones_extraction_contract():
    """get_zones extracts rows from a vsys root (zone entries -> rows).

    The getter itself is root-agnostic; the #89 defect was in the SECTIONS
    wiring (roots="network" while real configs keep zones under vsys), fixed
    by routing the zones section to the vsys root.
    """
    vsys = ET.fromstring(
        "<vsys><zone>"
        "<entry name='z1'><network><layer3><member>ethernet1/1</member></layer3></network>"
        "<zone-protection-profile>zpp</zone-protection-profile><log-setting>ls</log-setting></entry>"
        "<entry name='z2'><network><tap/></network></entry>"
        "</zone></vsys>"
    )
    rows = _data.get_zones(vsys)
    assert rows[0] == ("z1", "layer3", "ethernet1/1", "zpp", "ls")
    assert rows[1][0] == "z2"


def test_get_interfaces_missing_containers():
    """interface root present but every type container absent -> [] (no raise)."""
    net = ET.fromstring("<network><interface/></network>")
    assert _data.get_interfaces(net) == []


def test_bgp_peer_group_without_peers():
    net = ET.fromstring(
        "<network><virtual-router><entry name='vr'><protocol><bgp>"
        "<peer-group><entry name='pg-empty'/></peer-group>"
        "</bgp></protocol></entry></virtual-router></network>"
    )
    assert _data.get_bgp_peers(net) == []


def test_redist_profiles_filter_forms():
    net = ET.fromstring(
        "<network><virtual-router><entry name='vr'><protocol><redist-profile>"
        "<entry name='rp-emptyfilter'><action>redist</action><filter/></entry>"
        "<entry name='rp-texttype'><action>no-redist</action>"
        "<filter><type>static</type></filter></entry>"
        "<entry name='rp-membertype'><action>redist</action>"
        "<filter><type><member>connected</member></type></filter></entry>"
        "<entry name='rp-nofilter'><action>redist</action></entry>"
        "</redist-profile></protocol></entry></virtual-router></network>"
    )
    rows = {r[1]: r for r in _data.get_redist_profiles(net)}
    assert rows["rp-emptyfilter"][3:5] == ("", "")
    assert rows["rp-texttype"][3:5] == ("type", "static")
    assert rows["rp-membertype"][3:5] == ("type", "connected")
    assert rows["rp-nofilter"][3:5] == ("", "")


# ---------------------------------------------------------------------------
# VR export getters (parsers/_data.py; export/objects.py belongs to #79)
# ---------------------------------------------------------------------------


def test_vr_export_full(roots):
    _, _, network = roots
    vrs = _data.get_virtual_routers_export(network)
    # vr-empty has no protocol but is still emitted with defaults
    assert [vr["name"] for vr in vrs] == ["vr-default", "vr-empty"]
    vr = vrs[0]
    assert vr["interfaces"] == ["ethernet1/1", "loopback.5"]

    routes = {r["name"]: r for r in vr["static_routes"]}
    assert len(routes) == 5
    assert routes["default"] == {
        "name": "default", "destination": "0.0.0.0/0", "metric": 10,
        "admin_dist": 1, "nexthop_type": "ip_address", "nexthop_value": "10.1.1.254",
    }
    assert routes["blackhole"]["nexthop_type"] == "discard"
    assert "nexthop_value" not in routes["blackhole"]
    assert routes["to-vr-branch"]["nexthop_type"] == "next_vr"
    assert routes["to-vr-branch"]["nexthop_value"] == "vr-branch"
    assert routes["via-tunnel"]["nexthop_type"] == "tunnel"
    assert "nexthop_value" not in routes["via-tunnel"]
    assert routes["iface-only"]["interface"] == "ethernet1/1"
    assert "nexthop_type" not in routes["iface-only"]
    assert "metric" not in routes["iface-only"]
    notes = vr["_migration_notes"]
    assert any("next-vr 'vr-branch'" in n for n in notes)

    bgp = vr["bgp"]
    assert bgp["enable"] is True
    assert bgp["router_id"] == "10.255.255.5"
    assert bgp["local_as"] == "65001"
    assert bgp["install_route"] is True
    pgs = {pg["name"]: pg for pg in bgp["peer_groups"]}
    assert pgs["pg-external"]["type"] == "ebgp"
    assert pgs["pg-external"]["enable"] is True
    assert pgs["pg-external"]["peers"][0] == {
        "name": "peer-1", "enable": True, "peer_as": "65002",
        "peer_ip": "10.1.1.254", "local_ip": "10.1.1.1",
        "local_interface": "ethernet1/1", "max_prefixes": "", "reflector_client": "",
    }
    assert pgs["pg-internal"]["type"] == "ibgp"
    assert pgs["pg-internal"]["enable"] is False
    peer2 = pgs["pg-internal"]["peers"][0]
    assert peer2["enable"] is True  # no <enable> -> != "no"
    assert peer2["local_ip"] == "" and peer2["local_interface"] == "loopback.5"
    # interface-only local binding (not bare "loopback") emits a migration note
    assert any("peer-2" in n and "local_ip" in n for n in notes)
    assert bgp["redist_rules"] == [{
        "name": "rr-static", "address_family_identifier": "ipv4",
        "route_table": "unicast", "enable": True, "set_origin": "igp",
        "set_med": "", "metric": "5",
    }]
    rps = {p["name"]: p for p in bgp["redist_profiles"]}
    assert rps["rp-static"] == {
        "name": "rp-static", "priority": 1, "action": "redist",
        "filter_types": ["static"], "filter_destinations": ["0.0.0.0/0"],
    }
    assert rps["rp-connected"]["priority"] == 2
    assert rps["rp-connected"]["filter_types"] == []
    assert any("rp-static" in n and "bgp_redistribution_profile" in n for n in notes)

    ospf = vr["ospf"]
    assert ospf["enable"] is True
    assert ospf["router_id"] == "10.255.255.5"
    areas = {a["id"]: a for a in ospf["areas"]}
    assert areas["0.0.0.0"]["type"] == "normal"
    assert areas["0.0.0.1"]["type"] == "stub"
    assert areas["0.0.0.1"]["interfaces"] == []
    ifaces = {i["name"]: i for i in areas["0.0.0.0"]["interfaces"]}
    assert ifaces["ethernet1/1"] == {
        "name": "ethernet1/1", "enable": True, "passive": False,
        "link_type": "broadcast", "metric": 10,
    }
    lb = ifaces["loopback.5"]
    assert lb["passive"] is True
    assert lb["link_type"] == "p2p"  # child-tag form
    assert lb["authentication"] == "ospf-auth"
    assert "metric" not in lb
    assert any("ospf_auth_profile" in n for n in notes)
    assert ospf["export_rules"] == [{"name": "er-1", "new_path_type": "ext-2", "metric": "20"}]

    assert vr["ecmp"] == {"enable": True, "max_paths": 4, "algorithm": "ip_modulo"}

    empty = vrs[1]
    assert empty["interfaces"] == [] and empty["static_routes"] == []
    assert empty["bgp"]["enable"] is False and empty["bgp"]["peer_groups"] == []
    assert empty["ospf"]["areas"] == []
    assert empty["ecmp"] == {"enable": False, "max_paths": None, "algorithm": "ip_modulo"}
    assert empty["_migration_notes"] == []


def test_vr_export_empty_and_none():
    assert _data.get_virtual_routers_export(None) == []
    assert _data.get_virtual_routers_export(ET.Element("network")) == []
    # helpers tolerate a VR entry with no protocol/routing subtrees
    bare = ET.Element("entry")
    notes: list = []
    assert _data._get_static_routes_export(bare, notes) == []
    assert _data._get_bgp_export(bare, notes)["enable"] is False
    assert _data._get_ospf_export(bare, notes)["areas"] == []
    assert _data._get_ecmp_export(bare) == {"enable": False, "max_paths": None, "algorithm": "ip_modulo"}
    assert notes == []


def test_vr_export_invalid_numbers_and_edge_forms():
    net = ET.fromstring(
        "<network><virtual-router><entry name='vr-edge'>"
        "<routing-table><ip><static-route>"
        "<entry name='bad-nums'><destination>10.0.0.0/8</destination>"
        "<metric>abc</metric><admin-dist>x</admin-dist>"
        "<nexthop><next-vr/></nexthop></entry>"
        "<entry name='zero-metric'><destination>10.1.0.0/16</destination>"
        "<metric>0</metric><admin-dist>0</admin-dist></entry>"
        "</static-route></ip></routing-table>"
        "<protocol>"
        "<bgp><peer-group><entry name='pg-notype'>"
        "<peer><entry name='p'><peer-as>abc</peer-as></entry></peer>"
        "</entry></peer-group></bgp>"
        "<redist-profile><entry name='rp-nofilter'><priority>9</priority></entry></redist-profile>"
        "<ospf><area><entry name='0.0.0.0'>"
        "<interface><entry name='ethernet1/1'><metric>abc</metric>"
        "<link-type><p2mp/></link-type></entry></interface>"
        "</entry></area></ospf>"
        "</protocol>"
        "<ecmp><enable>yes</enable><max-path>abc</max-path>"
        "<algorithm>ip-hash</algorithm></ecmp>"
        "</entry></virtual-router></network>"
    )
    vr = _data.get_virtual_routers_export(net)[0]
    routes = {r["name"]: r for r in vr["static_routes"]}
    bad = routes["bad-nums"]
    assert "metric" not in bad and "admin_dist" not in bad
    # empty <next-vr/> -> no nexthop recorded, no migration note
    assert "nexthop_type" not in bad
    assert not any("bad-nums" in n for n in vr["_migration_notes"])
    # metric/admin-dist of 0 normalize to absent (int(...) or None)
    assert "metric" not in routes["zero-metric"]
    assert "admin_dist" not in routes["zero-metric"]
    pg = vr["bgp"]["peer_groups"][0]
    assert pg["type"] == "ebgp"  # missing type defaults to ebgp
    assert pg["peers"][0]["peer_as"] == "abc"  # kept as string, not parsed
    rp = vr["bgp"]["redist_profiles"][0]
    assert rp["action"] == "redist" and rp["filter_types"] == [] and rp["priority"] == 9
    area = vr["ospf"]["areas"][0]
    assert area["type"] == "normal"  # missing type defaults to normal
    iface = area["interfaces"][0]
    assert "metric" not in iface  # invalid metric dropped
    assert iface["link_type"] == "p2mp"  # child-tag form
    # text-form algorithm is ignored; default ip_modulo kept, invalid max-path dropped
    assert vr["ecmp"] == {"enable": True, "max_paths": None, "algorithm": "ip_modulo"}


def test_vr_export_ecmp_child_tag_algorithm():
    net = ET.fromstring(
        "<network><virtual-router><entry name='vr'>"
        "<protocol><bgp><enable>yes</enable></bgp></protocol>"
        "<ecmp><algorithm><balanced-round-robin/></algorithm></ecmp>"
        "</entry></virtual-router></network>"
    )
    vr = _data.get_virtual_routers_export(net)[0]
    # no <enable> under ecmp -> != "no" -> True; hyphens normalized
    assert vr["ecmp"] == {"enable": True, "max_paths": None, "algorithm": "balanced_round_robin"}
