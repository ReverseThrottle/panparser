"""Per-renderer happy-path render assertions (issue #80, AC3).

Every renderer module in parsers/ (33 modules, 40 render functions) gets at
least one populated-fixture render assertion, so a wrong-root/missing-field
regression like #9 fails the suite instead of silently rendering an empty
table. Each render function is also exercised with None roots (empty
containers) and must emit its documented empty-state message.

The RENDERERS table is the contract: a structural test asserts it covers
every renderer module, so adding a new module without a test fails CI.

Root conventions (mirrors panparser.load_config/find_roots):
- v  = vsys root   (rulebase/*, address, zone, profiles/*, global-protect, ...)
- s  = shared root (shared objects: certificates, server profiles, ...)
- n  = network root (devices/entry/network: interfaces, VRs, tunnels, ...)
- vs = merged vsys+shared renderers

zones is rendered from the VSYS root here — the CLI path fixed by #9. The
TUI's zones tab is wired to the network root and stays empty; that defect is
tracked separately (xfail in test_data_getters.py, reported on #80).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from parsers import (
    addresses,
    app_override,
    applications,
    auth_profiles,
    auth_rules,
    bgp,
    certificates,
    decryption,
    dhcp,
    dos,
    globalprotect,
    ike,
    interfaces,
    ipsec,
    monitor_profiles,
    nat,
    ospf,
    pbf,
    profiles,
    qos_profiles,
    qos_rules,
    redist,
    routing,
    security,
    server_profiles,
    services,
    ssl_profiles,
    tags,
    url_categories,
    virtual_wire,
    vlans,
    zone_protection,
    zones,
)
from viewer_harness import render_text, sample_roots_for

# (module, render_fn, roots spec, populated markers, empty-state message)
RENDERERS = [
    (addresses, addresses.render_addresses, "vs",
     ["host-web", "shared-dns", "range-printers", "updates.example.com"],
     "No address objects found."),
    (addresses, addresses.render_address_groups, "vs",
     ["grp-static", "grp-dynamic", "grp-shared"],
     "No address groups found."),
    (applications, applications.render_applications, "vs",
     ["app-custom", "app-shared"],
     "No custom applications found."),
    (applications, applications.render_application_groups, "vs",
     ["app-grp-custom", "app-grp-shared"],
     "No application groups found."),
    (applications, applications.render_application_filters, "vs",
     ["app-filter-risky", "app-filter-shared"],
     "No application filters found."),
    (app_override, app_override.render_app_override_rules, "v",
     ["app-ov-1", "app-ov-off"],
     "No vsys configuration found."),
    (auth_profiles, auth_profiles.render_auth_profiles, "s",
     ["auth-local", "auth-nomethod"],
     "No shared configuration found."),
    (auth_rules, auth_rules.render_auth_rules, "v",
     ["auth-rule-1", "auth-rule-off"],
     "No vsys configuration found."),
    (bgp, bgp.render_bgp_peers, "n",
     ["vr-default", "pg-external", "peer-1"],
     "No network configuration found."),
    (certificates, certificates.render_certificates, "s",
     ["vpn-cert", "ca-cert"],
     "No shared configuration found."),
    (decryption, decryption.render_decryption_rules, "v",
     ["decrypt-web", "decrypt-off"],
     "No vsys configuration found."),
    (dhcp, dhcp.render_dhcp_servers, "n",
     ["ethernet1/3", "10.30.30.10-10.30.30.100"],
     "No network configuration found."),
    (dos, dos.render_dos_rules, "v",
     ["dos-protect", "dos-classified", "dos-bare"],
     "No vsys configuration found."),
    (globalprotect, globalprotect.render_gp_gateways, "v",
     ["gp-gw-1"],
     "No vsys configuration found."),
    (globalprotect, globalprotect.render_gp_portals, "v",
     ["gp-portal-1"],
     "No vsys configuration found."),
    (ike, ike.render_ike_gateways, "n",
     ["ike-gw-1", "ike-gw-cert"],
     "No network configuration found."),
    (ike, ike.render_ike_crypto, "n",
     ["ike-crypto-1", "ike-crypto-nolife"],
     "No network configuration found."),
    (ike, ike.render_ipsec_crypto, "n",
     ["ipsec-crypto-1"],
     "No network configuration found."),
    (interfaces, interfaces.render_interfaces, "n",
     ["ethernet1/1", "ethernet1/1.10", "loopback.5", "ae1", "vlan.100"],
     "No network configuration found."),
    (ipsec, ipsec.render_ipsec_tunnels, "n",
     ["ipsec-vpn-1", "ipsec-vpn-2"],
     "No network configuration found."),
    (monitor_profiles, monitor_profiles.render_monitor_profiles, "n",
     ["mon-default"],
     "No network configuration found."),
    (nat, nat.render_nat_rules, "v",
     ["nat-dipp-iface", "nat-static", "nat-dst", "nat-none"],
     "No vsys configuration found."),
    (ospf, ospf.render_ospf_areas, "n",
     ["vr-default", "0.0.0.0", "ethernet1/1", "loopback.5"],
     "No network configuration found."),
    (pbf, pbf.render_pbf_rules, "v",
     ["pbf-forward", "pbf-discard", "pbf-noaction"],
     "No vsys configuration found."),
    (profiles, profiles.render_profiles, "vs",
     ["av-default", "av-shared", "as-default", "vp-default", "wf-default"],
     "No security profiles found."),
    (qos_profiles, qos_profiles.render_qos_interface_profiles, "n",
     ["qos-egress", "class1"],
     "No network configuration found."),
    (qos_rules, qos_rules.render_qos_rules, "v",
     ["qos-rule-1", "qos-rule-noaction"],
     "No vsys configuration found."),
    (redist, redist.render_redist_profiles, "n",
     ["rp-static", "rp-connected"],
     "No network configuration found."),
    (routing, routing.render_routing, "n",
     ["vr-default", "blackhole", "to-vr-branch", "via-tunnel"],
     "No network configuration found."),
    (security, security.render_security_rules, "v",
     ["allow-web", "deny-all", "allow-open"],
     "No vsys configuration found."),
    (server_profiles, server_profiles.render_server_profiles, "s",
     ["ldap-main", "radius-main", "syslog-main", "snmp-main", "email-main", "http-main"],
     "No shared configuration found."),
    (services, services.render_services, "vs",
     ["svc-https", "svc-shared-ntp", "svc-sctp"],
     "No service objects found."),
    (services, services.render_service_groups, "vs",
     ["svc-grp-web", "svc-grp-shared"],
     "No service groups found."),
    (ssl_profiles, ssl_profiles.render_ssl_profiles, "s",
     ["ssl-default"],
     "No shared configuration found."),
    (tags, tags.render_tags, "vs",
     ["tag-prod", "tag-global", "tag-nocolor"],
     "No tags found."),
    (url_categories, url_categories.render_url_categories, "v",
     ["url-custom"],
     "No vsys configuration found."),
    (virtual_wire, virtual_wire.render_virtual_wires, "n",
     ["vw-1", "ethernet1/4"],
     "No network configuration found."),
    (vlans, vlans.render_vlans, "n",
     ["vlan-blue", "vlan.100"],
     "No network configuration found."),
    (zone_protection, zone_protection.render_zone_protection, "n",
     ["zpp-strict", "zpp-loose"],
     "No network configuration found."),
    (zones, zones.render_zones, "v",
     ["trust", "untrust", "ethernet1/1", "zpp-strict"],
     "No vsys configuration found."),
]

_IDS = [f"{mod.__name__.split('.')[-1]}:{fn.__name__}" for mod, fn, *_ in RENDERERS]


@pytest.mark.parametrize("mod,fn,roots_spec,markers,empty_msg", RENDERERS, ids=_IDS)
def test_renderer_populated(mod, fn, roots_spec, markers, empty_msg):
    """Happy path: every marker from the sample fixture appears in output."""
    text = render_text(fn, *sample_roots_for(roots_spec))
    for marker in markers:
        assert marker in text, f"{fn.__name__}: missing {marker!r}\n{text}"
    assert empty_msg not in text


@pytest.mark.parametrize("mod,fn,roots_spec,markers,empty_msg", RENDERERS, ids=_IDS)
def test_renderer_empty_roots(mod, fn, roots_spec, markers, empty_msg):
    """None roots (absent containers) render the documented empty state."""
    text = render_text(fn, *([None] * len(roots_spec)))
    assert empty_msg in text
    for marker in markers:
        assert marker not in text


def test_every_renderer_module_has_a_test():
    """Structural guard: a new parsers/ renderer module without a RENDERERS
    entry fails here, keeping AC3's per-module coverage honest."""
    parsers_dir = Path(__file__).resolve().parent.parent / "parsers"
    modules = {
        p.stem for p in parsers_dir.glob("*.py")
        if p.stem not in ("__init__", "_data", "_helpers")
    }
    covered = {mod.__name__.split(".")[-1] for mod, *_ in RENDERERS}
    assert covered == modules, f"untested renderer modules: {modules - covered}"
    assert len(modules) == 33


def test_grep_narrows_rendered_rows():
    """The shared grep filter keeps matching rows and drops the rest."""
    text = render_text(addresses.render_addresses, *sample_roots_for("vs"), grep="host-web")
    assert "host-web" in text
    assert "shared-dns" not in text
    assert "range-printers" not in text
    # Case-insensitive match on any cell (here: the address value).
    text = render_text(security.render_security_rules, *sample_roots_for("v"), grep="DENY")
    assert "deny-all" in text
    assert "allow-web" not in text


def test_grep_matching_nothing_renders_empty_state():
    text = render_text(addresses.render_addresses, *sample_roots_for("vs"), grep="zzz-no-match")
    assert "No address objects found." in text
    assert "host-web" not in text


def test_zones_renderer_reads_vsys_root_not_network():
    """#9 regression guard: zones live under vsys. Rendering with only the
    network root must NOT show zones; rendering with the vsys root must."""
    vsys, shared, network = sample_roots_for("vsn")
    assert "trust" in render_text(zones.render_zones, vsys)
    assert "trust" not in render_text(zones.render_zones, network)


def test_renderer_modules_importable():
    """All renderer modules import cleanly (no side effects at import)."""
    for mod, *_ in RENDERERS:
        assert importlib.import_module(mod.__name__) is mod
