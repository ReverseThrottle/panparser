"""Export PAN-OS config to SCM-shaped JSON."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from xml.etree.ElementTree import Element

from parsers._data import get_virtual_routers_export
from parsers._devicegroup import DeviceGroupScope
from export.objects import (
    export_tags,
    export_addresses,
    export_address_groups,
    export_profile_groups,
    export_services,
    export_service_groups,
    export_application_groups,
    export_url_categories,
    export_zones,
    export_gp_portals,
    export_security_rules,
    export_nat_rules,
    export_decryption_rules,
    export_authentication_rules,
    export_pbf_rules,
    export_qos_rules,
    export_qos_interface_profiles,
    export_ike_crypto_profiles,
    export_gp_app_crypto_profiles,
    export_ipsec_crypto_profiles,
    export_ike_gateways,
    export_ipsec_tunnels,
    export_interface_management_profiles,
    export_monitor_profiles,
    export_loopback_interfaces,
    export_tunnel_interfaces,
    export_vlan_interfaces,
    export_vlan_objects,
    export_ethernet_interfaces,
    export_aggregate_interfaces,
    export_layer2_subinterfaces,
    export_anti_spyware_profiles,
    export_wildfire_antivirus_profiles,
    list_antivirus_profile_names,
    list_wildfire_profile_names,
    find_profile_groups_dropping_wildfire,
    find_profile_groups_with_data_filtering,
    export_vulnerability_protection_profiles,
    export_url_access_profiles,
    export_decryption_profiles,
    export_dns_security_profiles,
    export_file_blocking_profiles,
    export_lldp_profiles,
    export_virtual_wires,
    export_dhcp_servers,
    export_zone_protection_profiles,
    export_dos_protection_profiles,
    export_dos_protection_rules,
    export_custom_applications,
    export_application_filters,
    export_schedules,
    export_edls,
    export_log_forwarding_profiles,
    export_syslog_server_profiles,
    export_http_server_profiles,
    export_snmp_trap_server_profiles,
    export_email_server_profiles,
    export_authentication_profiles,
    export_radius_server_profiles,
    export_ldap_server_profiles,
    export_kerberos_server_profiles,
    export_saml_server_profiles,
    export_tacacs_server_profiles,
    export_gp_gateways,
    export_ssl_profiles,
    export_device_setup,
    export_high_availability,
    export_botnet_report,
    export_certificates,
)


def _normalize_name(name: str) -> str:
    """Strip trailing underscores from an object name.

    Opt-in only (``build_export(normalize_names=True)`` / ``--normalize-names``),
    for tenants or workflows that want trailing underscores removed. Not applied
    by default: SCM accepts trailing underscores, and in source configs they can
    deliberately distinguish otherwise-duplicate names.
    """
    return name.rstrip("_")


class NameCollisionError(ValueError):
    """--normalize-names would map two or more distinct names to one name.

    ``collisions`` maps each normalized name to the sorted list of
    ``(source_name, collection_path)`` pairs that produce it.
    """

    def __init__(self, collisions: dict[str, list[tuple[str, str]]]):
        self.collisions = collisions
        lines = [
            f"--normalize-names would merge distinct names "
            f"({len(collisions)} collision group(s)):"
        ]
        for target, sources in sorted(collisions.items()):
            shown = repr(target) if target else "<empty name>"
            lines.append(f"  {shown} <- " + ", ".join(
                f"{name!r} ({path})" for name, path in sources))
        super().__init__("\n".join(lines))


def _iter_named_objects_at(data, path: str = ""):
    """Like _iter_named_objects, but yields (collection_path, item)."""
    if isinstance(data, dict):
        for key, value in data.items():
            yield from _iter_named_objects_at(
                value, f"{path}/{key}" if path else key)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                yield path, item


def _find_name_collisions(pairs) -> dict[str, list[tuple[str, str]]]:
    """Group (collection_path, item) pairs by normalized name.

    A collision is a normalized name produced by two or more DISTINCT source
    names (e.g. 'foo' and 'foo_'), or an empty normalized name. The same
    source name appearing in several collections (address + address-group)
    is not itself a collision, but those entries are listed alongside any
    real one because SCM shares a namespace between them. Names are compared
    export-wide, matching how _apply_renames rewrites references.
    """
    by_target: dict[str, set[tuple[str, str]]] = {}
    for path, item in pairs:
        by_target.setdefault(_normalize_name(item["name"]), set()).add(
            (item["name"], path))
    return {
        target: sorted(sources)
        for target, sources in by_target.items()
        if not target or len({n for n, _ in sources}) > 1
    }


def _iter_named_objects(data):
    """Yield every named collection item in the export (#93).

    A named object is a dict with a string 'name' that is an element of a
    list anywhere in the export (addresses, services, rules, zones, ...).
    Structural scope: new exporters participate automatically. Nested
    sub-entities that also carry 'name' keys (interface IP entries, BGP
    peers, syslog servers inside a profile) are NOT standalone SCM objects
    and are deliberately not yielded — we never descend into items.
    """
    if isinstance(data, dict):
        for value in data.values():
            yield from _iter_named_objects(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                yield item


def _build_rename_map(items: list[dict]) -> tuple[dict[str, str], list[str]]:
    """Map original name → normalized name for objects with trailing underscores.

    Returns (rename_map, skipped). A candidate rename is skipped — the name
    keeps its original spelling — when normalizing it would create a
    duplicate SCM name: the target already exists among the exported names,
    another candidate normalizes to the same target, or the target would be
    empty. Skipped names are returned so the caller can warn about them.
    """
    candidates = {
        item["name"]: _normalize_name(item["name"])
        for item in items
        if item["name"] != _normalize_name(item["name"])
    }
    existing = {item["name"] for item in items}
    target_counts: dict[str, int] = {}
    for target in candidates.values():
        target_counts[target] = target_counts.get(target, 0) + 1
    rename_map: dict[str, str] = {}
    skipped: list[str] = []
    for old, new in candidates.items():
        if not new or new in existing or target_counts[new] > 1:
            skipped.append(old)
        else:
            rename_map[old] = new
    return rename_map, skipped


def _apply_renames(data: dict, rename_map: dict[str, str]) -> dict:
    """Walk the full export dict and replace old names with normalized ones everywhere.

    Contract (#93): any string VALUE exactly equal to a renamed name is
    rewritten — including free-text fields such as descriptions. Dict keys
    and non-string values are never touched, and partial matches are left
    alone. The collision guard in _build_rename_map keeps every rewrite
    unambiguous.
    """
    if not rename_map:
        return data

    def fix(obj):
        if isinstance(obj, str):
            return rename_map.get(obj, obj)
        if isinstance(obj, list):
            return [fix(v) for v in obj]
        if isinstance(obj, dict):
            # Rebuild values only — keys (including 'name') are never rewritten;
            # an object's own name is renamed because its VALUE matches.
            result = {}
            for k, v in obj.items():
                result[k] = fix(v)
            return result
        return obj

    return fix(data)


def _reconcile_interface_members(
    owners: list[dict],
    known_interfaces: set[str],
    normalized_bare_interfaces: set[str],
    owner_type: str,
    object_path_prefix: str,
) -> list[dict]:
    """Validate zone/VR members against interfaces produced by the exporter."""
    warnings = []
    for owner in owners:
        if "interfaces" not in owner:
            continue

        owner_name = owner["name"]
        reconciled = []
        for interface_name in owner["interfaces"]:
            if interface_name in known_interfaces or (
                interface_name == "vlan" and "vlan" not in normalized_bare_interfaces
            ):
                reconciled.append(interface_name)
                continue

            object_path = f"{object_path_prefix}/{owner_name}"
            if interface_name in normalized_bare_interfaces:
                normalized_name = f"{interface_name}.1"
                reconciled.append(normalized_name)
                warnings.append({
                    "severity": "info",
                    "object_path": object_path,
                    "message": (
                        f"Rewrote normalized bare parent interface member "
                        f"'{interface_name}' to '{normalized_name}' on {owner_type} "
                        f"'{owner_name}' so it references the exported interface."
                    ),
                })
                continue

            if interface_name in {"tunnel", "loopback"}:
                warnings.append({
                    "severity": "warn",
                    "object_path": object_path,
                    "message": (
                        f"Dropped bare parent interface member '{interface_name}' from "
                        f"{owner_type} '{owner_name}' because no corresponding interface "
                        "was exported."
                    ),
                })
                continue

            reconciled.append(interface_name)
            warnings.append({
                "severity": "warn",
                "object_path": object_path,
                "message": (
                    f"Kept interface member '{interface_name}' on {owner_type} "
                    f"'{owner_name}', but it doesn't match any exported interface; "
                    "verify it manually."
                ),
            })

        owner["interfaces"] = reconciled

    return warnings


_PREDEFINED_SERVICES = frozenset({"service-http", "service-https"})
_PREDEFINED_PROFILES = frozenset({"default", "strict"})


def _count_unresolved_refs(addresses, address_groups, services, service_groups,
                           profile_groups, spyware, wildfire, vuln, url,
                           file_blocking, dns) -> int:
    """Count group/profile-group references with no target in the export."""
    def names(items):
        return {i["name"] for i in items}

    addr_names = names(addresses) | names(address_groups)
    svc_names = names(services) | names(service_groups) | _PREDEFINED_SERVICES
    n = 0
    for g in address_groups:
        n += sum(1 for m in g.get("static", []) if m not in addr_names)
    for g in service_groups:
        n += sum(1 for m in g.get("members", []) if m not in svc_names)
    by_field = {
        "spyware": names(spyware),
        "virus_and_wildfire_analysis": names(wildfire),
        "vulnerability": names(vuln),
        "url_filtering": names(url),
        "file_blocking": names(file_blocking),
        "dns_security": names(dns),
    }
    for g in profile_groups:
        for field, known in by_field.items():
            n += sum(1 for m in g.get(field, [])
                     if m not in known and m not in _PREDEFINED_PROFILES)
    return n


def build_export(
    root: Element,
    vsys_root: Element | None,
    shared_root: Element | None,
    network_root: Element | None,
    source_file: str,
    vsys: str,
    normalize_names: bool = False,
    device_group: DeviceGroupScope | None = None,
    allow_name_collisions: bool = False,
) -> dict:
    """Assemble the full export dict from all getter functions.

    Object names are preserved exactly as in the source config. With
    ``normalize_names=True``, trailing underscores are stripped from named
    objects and references are rewritten export-wide (see #93). If two or
    more distinct names would normalize to the same name, NameCollisionError
    is raised listing every group; ``allow_name_collisions=True`` instead
    keeps the colliding names unchanged and adds a 'warn' migration warning.

    ``device_group`` (a parsers._devicegroup.DeviceGroupScope) switches to
    Panorama device-group mode: ``vsys_root`` is the merged device-group
    object root, and only object collections are populated. Policy, zones,
    network, device setup and HA stay present but empty.
    """
    dg = device_group is not None
    if dg:
        network_root = None
        shared_root = None
    virtual_routers = get_virtual_routers_export(network_root)

    # Collect all migration warnings from VR notes
    warnings = []
    for vr in virtual_routers:
        for note in vr.get("_migration_notes", []):
            warnings.append({
                "severity": "warn",
                "object_path": f"network/virtual_routers/{vr['name']}",
                "message": note,
            })

    hostname = root.findtext(".//deviceconfig/system/hostname") or ""
    sw_version = root.get("version") or ""

    tags               = export_tags(vsys_root, shared_root)
    addresses          = export_addresses(vsys_root, shared_root)
    address_groups     = export_address_groups(vsys_root, shared_root)
    profile_groups     = export_profile_groups(vsys_root, shared_root)
    services           = export_services(vsys_root, shared_root)
    service_groups     = export_service_groups(vsys_root, shared_root)
    application_groups = export_application_groups(vsys_root, shared_root)
    url_categories     = [c for c in export_url_categories(vsys_root, shared_root)
                          if c.get("list")]   # skip empty URL lists — invalid in SCM
    # Device-group mode is objects-only: rulebases live under pre/post-rulebase
    # (not rulebase) and zones/GP are template/firewall scoped.
    zones              = [] if dg else export_zones(vsys_root)
    gp_portals         = [] if dg else export_gp_portals(vsys_root)
    security_rules     = [] if dg else export_security_rules(vsys_root)
    nat_rules          = [] if dg else export_nat_rules(vsys_root)
    decryption_rules   = [] if dg else export_decryption_rules(vsys_root)
    authentication_rules = [] if dg else export_authentication_rules(vsys_root)
    pbf_rules          = [] if dg else export_pbf_rules(vsys_root)
    qos_rules          = [] if dg else export_qos_rules(vsys_root)

    ike_crypto_profiles   = export_ike_crypto_profiles(network_root)
    gp_app_crypto_profiles = export_gp_app_crypto_profiles(network_root)
    ipsec_crypto_profiles = export_ipsec_crypto_profiles(network_root)
    ike_gateways          = export_ike_gateways(network_root)
    ipsec_tunnels         = export_ipsec_tunnels(network_root)
    lldp_profiles           = export_lldp_profiles(network_root)
    virtual_wires           = export_virtual_wires(network_root)
    vlan_objects            = export_vlan_objects(network_root)
    qos_profiles            = export_qos_interface_profiles(network_root)
    dhcp_servers            = export_dhcp_servers(network_root)
    interface_mgmt_profiles = export_interface_management_profiles(network_root)
    monitor_profiles        = export_monitor_profiles(network_root)
    loopback_interfaces, loopback_notes = export_loopback_interfaces(network_root)
    tunnel_interfaces, tunnel_notes     = export_tunnel_interfaces(network_root)
    vlan_interfaces, vlan_notes         = export_vlan_interfaces(network_root)
    ethernet_parents, ethernet_subinterfaces, ethernet_notes = export_ethernet_interfaces(network_root)
    aggregate_parents, aggregate_subinterfaces, aggregate_notes = export_aggregate_interfaces(network_root)
    ethernet_layer2_subinterfaces = export_layer2_subinterfaces(network_root, "ethernet")
    aggregate_layer2_subinterfaces = export_layer2_subinterfaces(network_root, "aggregate-ethernet")

    interface_groups = (
        loopback_interfaces,
        tunnel_interfaces,
        vlan_interfaces,
        ethernet_parents,
        ethernet_subinterfaces,
        aggregate_parents,
        aggregate_subinterfaces,
        ethernet_layer2_subinterfaces,
        aggregate_layer2_subinterfaces,
    )
    known_interfaces = {
        interface["name"]
        for interface_group in interface_groups
        for interface in interface_group
    }
    normalized_bare_interfaces = set()
    if any(note.startswith("Bare 'loopback' parent interface") for note in loopback_notes):
        normalized_bare_interfaces.add("loopback")
    if any(note.startswith("Bare 'tunnel' parent interface") for note in tunnel_notes):
        normalized_bare_interfaces.add("tunnel")
    if any(note.startswith("Bare 'vlan' parent interface") for note in vlan_notes):
        normalized_bare_interfaces.add("vlan")

    warnings.extend(_reconcile_interface_members(
        zones,
        known_interfaces,
        normalized_bare_interfaces,
        "zone",
        "zones",
    ))
    warnings.extend(_reconcile_interface_members(
        virtual_routers,
        known_interfaces,
        normalized_bare_interfaces,
        "virtual router",
        "network/virtual_routers",
    ))
    warnings.extend(_reconcile_interface_members(
        vlan_objects,
        known_interfaces,
        normalized_bare_interfaces,
        "vlan",
        "network/vlans",
    ))
    # Reconcile each VLAN object's SVI reference through the same shared
    # machinery (single-member probe), so bare-parent normalization — e.g.
    # the bare 'vlan' → 'vlan.1' rewrite from #58 — applies here identically
    # to zone/VR members without duplicating that logic.
    for vlan in vlan_objects:
        svi = vlan.get("virtual_interface")
        if not svi:
            continue
        probe = {"name": vlan["name"], "interfaces": [svi]}
        warnings.extend(_reconcile_interface_members(
            [probe],
            known_interfaces,
            normalized_bare_interfaces,
            "vlan object",
            "network/vlans",
        ))
        if probe["interfaces"]:
            vlan["virtual_interface"] = probe["interfaces"][0]
        else:
            del vlan["virtual_interface"]

    # Security-profile content merges vsys + shared scopes (issue #107), the
    # same iter_entries pattern export_profile_groups and the viewer use.
    # Zone protection stays network-rooted; DoS rules stay vsys rulebase-only.
    anti_spyware_profiles           = export_anti_spyware_profiles(vsys_root, shared_root)
    wildfire_antivirus_profiles     = export_wildfire_antivirus_profiles(vsys_root, shared_root)
    vulnerability_protection_profiles = export_vulnerability_protection_profiles(vsys_root, shared_root)
    url_access_profiles             = export_url_access_profiles(vsys_root, shared_root)
    decryption_profiles             = export_decryption_profiles(vsys_root, shared_root)
    dns_security_profiles           = export_dns_security_profiles(vsys_root, shared_root)
    file_blocking_profiles          = export_file_blocking_profiles(vsys_root, shared_root)
    zone_protection_profiles        = export_zone_protection_profiles(network_root)
    dos_protection_profiles         = export_dos_protection_profiles(vsys_root, shared_root)
    dos_protection_rules            = [] if dg else export_dos_protection_rules(vsys_root)

    # Surface profile content SCM cannot represent (issue #67) the same way
    # virtual-router notes are surfaced above.
    for export_key, profiles in (
        ("anti_spyware", anti_spyware_profiles),
        ("url_access", url_access_profiles),
        ("decryption", decryption_profiles),
        ("dns_security", dns_security_profiles),
        ("zone_protection", zone_protection_profiles),
    ):
        for profile in profiles:
            for note in profile.get("_migration_notes", []):
                warnings.append({
                    "severity": "warn",
                    "object_path": f"security_profiles/{export_key}/{profile['name']}",
                    "message": note,
                })

    custom_applications     = export_custom_applications(vsys_root, shared_root)
    application_filters     = export_application_filters(vsys_root, shared_root)
    schedules               = export_schedules(vsys_root, shared_root)
    edls                    = export_edls(vsys_root, shared_root)
    log_forwarding_profiles  = export_log_forwarding_profiles(vsys_root, shared_root)
    # Auth/server profiles merge vsys + shared scopes (#122, #107 convention):
    # the viewers show both scopes, so the export must carry both.
    syslog_server_profiles   = export_syslog_server_profiles(vsys_root, shared_root)
    http_server_profiles     = export_http_server_profiles(vsys_root, shared_root)
    snmp_v2c_server_profiles, snmp_v3_server_profiles = export_snmp_trap_server_profiles(vsys_root, shared_root)
    email_server_profiles    = export_email_server_profiles(vsys_root, shared_root)
    authentication_profiles  = export_authentication_profiles(vsys_root, shared_root)
    radius_server_profiles   = export_radius_server_profiles(vsys_root, shared_root)
    ldap_server_profiles     = export_ldap_server_profiles(vsys_root, shared_root)
    kerberos_server_profiles = export_kerberos_server_profiles(vsys_root, shared_root)
    saml_server_profiles     = export_saml_server_profiles(vsys_root, shared_root)
    tacacs_server_profiles   = export_tacacs_server_profiles(vsys_root, shared_root)
    gp_gateways              = [] if dg else export_gp_gateways(vsys_root)
    ssl_profiles             = export_ssl_profiles(shared_root)

    # Device Setup — device-scoped, requires serial at push time
    mgmt_interface, service_settings, service_routes = (
        ({}, {}, []) if dg else export_device_setup(root)
    )

    # High Availability — device-scoped, no SCM push path for HA pairing
    high_availability = {} if dg else export_high_availability(root)

    # Botnet/C2 traffic report config — reporting/analytics, not pushable to SCM
    botnet_report = export_botnet_report(shared_root)

    # Certificates — public cert material is exported; private-key VALUES are
    # never read/exported, only their presence is flagged for a warning.
    certificates, certificates_with_private_key = export_certificates(shared_root)
    if certificates_with_private_key:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/certificates",
            "message": (
                f"{len(certificates_with_private_key)} certificate(s) have a private key "
                "in the source PAN-OS config. Private key material is never read or "
                "exported by this tool. These certificates must have their private key "
                "re-imported into SCM through a secure/manual channel: "
                + ", ".join(certificates_with_private_key)
            ),
        })

    # Identity server profiles with encrypted secrets — flag placeholder values
    for _items, _path, _label in [(r, p, l) for r, p, l in [
        (radius_server_profiles,   "objects/radius_server_profiles",   "RADIUS"),
        (ldap_server_profiles,     "objects/ldap_server_profiles",     "LDAP"),
        (tacacs_server_profiles,   "objects/tacacs_server_profiles",   "TACACS+"),
    ] if r]:
        warnings.append({
            "severity": "warn",
            "object_path": _path,
            "message": (
                f"{len(_items)} {_label} server profile(s) exported with "
                "'MIGRATION-PLACEHOLDER-SECRET' replacing the encrypted shared secret. "
                "Update each profile's secret in SCM after migration."
            ),
        })
    if saml_server_profiles:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/saml_server_profiles",
            "message": (
                f"{len(saml_server_profiles)} SAML server profile(s) exported. "
                "The referenced certificate object must exist in SCM before the push will succeed. "
                "Create or import the certificate in SCM first."
            ),
        })
    if gp_portals:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/gp_portals",
            "message": (
                f"{len(gp_portals)} GlobalProtect portal(s) exported. Each portal's "
                "referenced ssl_tls_service_profile must exist in SCM before the push "
                "will succeed. Create the SSL/TLS service profile in SCM first. Note: "
                "client-config (agent/app behavior) and satellite-config (site-to-site) "
                "subtrees are not exported in this pass and must be reconfigured "
                "manually in SCM after migration."
            ),
        })
    if ssl_profiles:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/ssl_profiles",
            "message": (
                f"{len(ssl_profiles)} SSL/TLS service profile(s) exported. "
                "The referenced certificate object must exist in SCM before the push will succeed. "
                "Create or import the certificate in SCM first. Cipher suite restriction flags "
                "(keyxchg-algo-*/enc-algo-*/auth-algo-* under protocol-settings) are not exported — "
                "the scm-mcp SDK has no SSL/TLS Service Profile model to push them into; "
                "recreate cipher suite restrictions manually in SCM if needed."
            ),
        })
    if snmp_v2c_server_profiles:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/snmp_v2c_server_profiles",
            "message": (
                f"{len(snmp_v2c_server_profiles)} SNMPv2c server profile(s) exported with "
                "'MIGRATION-PLACEHOLDER-COMMUNITY' replacing the encrypted community string. "
                "Update each profile's community string in SCM after migration."
            ),
        })
    if snmp_v3_server_profiles:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/snmp_v3_server_profiles",
            "message": (
                f"{len(snmp_v3_server_profiles)} SNMPv3 server profile(s) exported with "
                "placeholder auth/priv passwords "
                "('MIGRATION-PLACEHOLDER-AUTHPWD', 'MIGRATION-PLACEHOLDER-PRIVPWD'). "
                "Update each profile's credentials in SCM after migration."
            ),
        })
    if email_server_profiles:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/email_server_profiles",
            "message": (
                f"{len(email_server_profiles)} email server profile(s) exported with "
                "'MIGRATION-PLACEHOLDER-SECRET' replacing any encrypted SMTP auth "
                "password. Update each profile's credentials after migration. "
                "The pan-scm-sdk has no Email Server Profile model to push them "
                "into; recreate email server profiles manually in SCM if needed."
            ),
        })

    antivirus_names = list_antivirus_profile_names(vsys_root, shared_root)
    if antivirus_names:
        # Reconcile the warning's name sets with the exporter's #65 collision
        # policy: a same-named WildFire Analysis definition wins, so the virus
        # entry is skipped and NO default-rule export happens for that name
        # (#108). Only non-colliding names may be claimed as default-rule
        # exports; colliding names get an accurate note instead — their
        # per-decoder antivirus actions are still dropped (the tail below).
        # Both name sets merge vsys + shared scopes (#107) so the
        # reconciliation stays accurate for shared collisions.
        wildfire_names = set(list_wildfire_profile_names(vsys_root, shared_root))
        default_rule_names = [n for n in antivirus_names if n not in wildfire_names]
        collision_names = [n for n in antivirus_names if n in wildfire_names]
        message = ""
        if default_rule_names:
            message += (
                f"{len(default_rule_names)} Antivirus profile(s) exported as SCM "
                "WildFire and Antivirus profile(s) with a default WildFire rule: "
                + ", ".join(default_rule_names) + ". "
            )
        if collision_names:
            message += (
                f"{len(collision_names)} Antivirus profile(s) share a name with a "
                "WildFire Analysis profile; the WildFire definition was exported "
                "instead (the Antivirus entry was skipped): "
                + ", ".join(collision_names) + ". "
            )
        message += (
            "SCM has no equivalent of the PAN-OS per-decoder antivirus "
            "actions (e.g. reset-both), so those settings are not migrated. "
            "Review each profile in SCM."
        )
        warnings.append({
            "severity": "warn",
            "object_path": "security_profiles/wildfire_antivirus",
            "message": message,
        })
    for group in find_profile_groups_dropping_wildfire(vsys_root, shared_root):
        warnings.append({
            "severity": "warn",
            "object_path": f"objects/profile_groups/{group['name']}",
            "message": (
                f"Profile group '{group['name']}' references Antivirus profile "
                f"'{group['virus']}' and WildFire Analysis profile "
                f"'{group['wildfire']}'. SCM has one combined slot per group, so "
                f"the group keeps only the '{group['virus']}' reference; the "
                f"'{group['wildfire']}' reference is dropped from the group. "
                f"A '{group['wildfire']}' profile defined in vsys or shared scope "
                "is still exported as a standalone WildFire and Antivirus profile."
            ),
        })
    # #111: Data Filtering profiles have no SCM equivalent at the pinned
    # pan-scm-sdk, so they are never exported. The group's data_filtering
    # reference is kept for documentation only (see export_profile_groups);
    # warn per referencing group so the dangling reference is never silent.
    for group in find_profile_groups_with_data_filtering(vsys_root, shared_root):
        warnings.append({
            "severity": "warn",
            "object_path": f"objects/profile_groups/{group['name']}",
            "message": (
                f"Profile group '{group['name']}' references Data Filtering "
                f"profile '{group['data_filtering']}'. Data Filtering profiles "
                "are not exported: the pinned pan-scm-sdk has no Data "
                "Filtering profile model (no SCM equivalent), so the "
                "referenced profile is not migrated. The group's "
                "'data_filtering' reference is kept in the export for "
                "documentation only; recreate the data-filtering settings "
                "manually after migration."
            ),
        })

    if dos_protection_profiles or dos_protection_rules:
        warnings.append({
            "severity": "info",
            "object_path": "security_profiles/dos_protection",
            "message": (
                f"{len(dos_protection_profiles)} DoS protection profile(s) and "
                f"{len(dos_protection_rules)} DoS protection rule(s) exported and will be "
                "pushed to SCM via direct REST API during migration."
            ),
        })
    if lldp_profiles:
        warnings.append({
            "severity": "info",
            "object_path": "network/lldp_profiles",
            "message": (
                f"{len(lldp_profiles)} LLDP profile(s) exported and will be pushed to SCM "
                "via direct REST API during migration."
            ),
        })
    if virtual_wires:
        warnings.append({
            "severity": "warn",
            "object_path": "network/virtual_wires",
            "message": (
                f"{len(virtual_wires)} virtual wire(s) exported. SCM's folder-scoped API "
                "does not support creating virtual-wire interface pairings the way this tool "
                "handles other network objects — configure the vwire pairing manually in SCM "
                "device management after migration."
            ),
        })
    if vlan_objects:
        _vlan_mappings = "; ".join(
            f"{v['name']} → SVI {v.get('virtual_interface', 'none')}, "
            f"members: {', '.join(v['interfaces']) or 'none'}"
            for v in vlan_objects
        )
        warnings.append({
            "severity": "warn",
            "object_path": "network/vlans",
            "message": (
                f"{len(vlan_objects)} VLAN object(s) exported for reference "
                f"({_vlan_mappings}). SCM's folder-scoped API has no VLAN-object "
                "equivalent — the VLAN-to-SVI and Layer2 member bindings are "
                "device-scoped. Recreate these mappings manually in SCM device "
                "management after migration."
            ),
        })
    if qos_profiles:
        warnings.append({
            "severity": "info",
            "object_path": "network/qos_profiles",
            "message": (
                f"{len(qos_profiles)} QoS interface bandwidth/priority profile(s) exported "
                "(network/qos/profile — distinct from policy QoS rules) and will be pushed "
                "to SCM via direct REST API during migration."
            ),
        })
    if dhcp_servers:
        warnings.append({
            "severity": "warn",
            "object_path": "network/dhcp_servers",
            "message": (
                f"{len(dhcp_servers)} DHCP server configuration(s) exported for reference "
                f"({', '.join(d['interface'] for d in dhcp_servers)}). "
                "SCM has no native DHCP server object — recreate these settings manually "
                "(leases, IP pool, reservations, DNS/gateway options) on the target "
                "device or in SCM device management after migration."
            ),
        })
    if botnet_report:
        warnings.append({
            "severity": "warn",
            "object_path": "shared/botnet_report",
            "message": (
                "Botnet/C2 traffic report configuration (Monitor > PDF Reports > Botnet) "
                "exported for reference only. SCM/Strata Logging Service has no direct "
                "equivalent object for these thresholds and report settings — recreate "
                "the equivalent alerting/reporting manually in SCM after migration."
            ),
        })
    if gp_gateways:
        warnings.append({
            "severity": "warn",
            "object_path": "objects/gp_gateways",
            "message": (
                f"{len(gp_gateways)} GlobalProtect gateway(s) exported. The referenced "
                "ssl_tls_service_profile and remote_user_tunnel (tunnel interface) must "
                "already exist in SCM before this push will succeed. v1 export scope "
                "covers name, ssl_tls_service_profile, tunnel_mode, remote_user_tunnel, "
                "and client_auth entries only — roles, remote-user-tunnel-configs, and "
                "gp-gw-dhcp (DHCP pool / login-lifetime / per-tunnel auth-override, "
                "source-address/user, and OS restrictions) are not exported and must be "
                "configured manually in SCM after migration."
            ),
        })

    _device_setup_sections = []
    if mgmt_interface:
        _device_setup_sections.append("management_interface")
    if service_settings:
        _device_setup_sections.append("service_settings")
    if service_routes:
        _device_setup_sections.append(f"service_routes ({len(service_routes)} entries)")
    if _device_setup_sections:
        warnings.append({
            "severity": "warn",
            "object_path": "device_setup",
            "message": (
                f"Device Setup sections exported: {', '.join(_device_setup_sections)}. "
                "These are device-scoped and cannot be pushed without a device serial number. "
                "Pass device_serial to scm_migrate_panparser_export to push them, "
                "or configure manually in SCM Device Management."
            ),
        })

    if high_availability:
        _ha_group = high_availability.get("group_id", "?")
        _ha_peer = high_availability.get("peer_ip", "unknown peer")
        warnings.append({
            "severity": "warn",
            "object_path": "high_availability",
            "message": (
                f"High Availability is enabled on the source device (group {_ha_group}, "
                f"peer {_ha_peer}). SCM/folder-scoped migration has no path to push HA "
                "pairing — HA must be reconfigured manually on the destination."
            ),
        })

    # Migration warnings for VPN/interface known limitations
    if ike_gateways:
        warnings.append({
            "severity": "warn",
            "object_path": "network/ike_gateways",
            "message": (
                f"{len(ike_gateways)} IKE gateway(s) exported with placeholder PSK "
                "('MIGRATION-PLACEHOLDER-PSK'). Update each gateway's pre-shared key "
                "in SCM after migration."
            ),
        })
        for gw in ike_gateways:
            local_ip    = gw.pop("_local_ip", "")
            local_iface = gw.pop("_local_iface", "")
            if local_ip or local_iface:
                binding = local_iface or local_ip
                warnings.append({
                    "severity": "warn",
                    "object_path": f"network/ike_gateways/{gw['name']}",
                    "message": (
                        f"IKE gateway '{gw['name']}' had local-address binding "
                        f"({binding}) which is not supported by the SCM SDK and was "
                        "skipped. Configure the local address binding in SCM after migration."
                    ),
                })
    total_ifaces = (
        len(loopback_interfaces) + len(tunnel_interfaces) + len(vlan_interfaces)
        + len(ethernet_parents) + len(ethernet_subinterfaces)
        + len(aggregate_parents) + len(aggregate_subinterfaces)
    )
    if total_ifaces:
        warnings.append({
            "severity": "info",
            "object_path": "network/interfaces",
            "message": (
                f"{total_ifaces} interface(s) exported as SCM $variable templates "
                f"({len(ethernet_parents)} ethernet + {len(ethernet_subinterfaces)} eth-subs, "
                f"{len(aggregate_parents)} aggregate + {len(aggregate_subinterfaces)} ae-subs, "
                f"{len(loopback_interfaces)} loopback, {len(tunnel_interfaces)} tunnel, "
                f"{len(vlan_interfaces)} vlan). "
                "Bind each $variable to the real device interface in SCM device management."
            ),
        })
    for note in loopback_notes + tunnel_notes + vlan_notes + ethernet_notes + aggregate_notes:
        warnings.append({
            "severity": "warn",
            "object_path": "network/interfaces",
            "message": note,
        })

    if dg:
        for _msg in device_group.warnings:
            warnings.append({
                "severity": "warn",
                "object_path": "meta/device_group",
                "message": _msg,
            })
        warnings.append({
            "severity": "info",
            "object_path": "meta/device_group",
            "message": (
                f"Device-group export of '{device_group.name}' is objects-only "
                f"(objects merged from: {' > '.join(device_group.chain)} > shared, "
                "nearest group wins). Policy rules (pre/post-rulebase), zones, "
                "network and device setup are not exported and the corresponding "
                "sections are empty."
            ),
        })

    if dg and device_group.unexported:
        warnings.append({
            "severity": "info",
            "object_path": "meta/device_group",
            "message": (
                "Containers present in the device group but not exported: "
                + ", ".join(device_group.unexported) + "."
            ),
        })
    if dg and not device_group.include_ancestors:
        _n_unresolved = _count_unresolved_refs(
            addresses, address_groups, services, service_groups, profile_groups,
            anti_spyware_profiles, wildfire_antivirus_profiles,
            vulnerability_protection_profiles, url_access_profiles,
            file_blocking_profiles, dns_security_profiles,
        )
        if _n_unresolved:
            warnings.append({
                "severity": "warn",
                "object_path": "meta/device_group",
                "message": (
                    f"--no-ancestors: {_n_unresolved} reference(s) (address-group "
                    "members, service-group members, profile-group profiles) do "
                    "not resolve to any object in the exported scope (group "
                    "itself + shared, unless --no-shared is also given); they "
                    "probably point at parent device groups. Predefined "
                    "services/profiles are not counted."
                ),
            })

    data = {
        "meta": {
            "schema_version": "1.2",
            "source_file": source_file,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "hostname": hostname,
            "sw_version": sw_version,
            "vsys": None if dg else vsys,
            **({"device_group": device_group.name,
                "device_group_chain": device_group.chain} if dg else {}),
        },
        "migration_warnings": warnings,
        "network": {
            "virtual_routers": virtual_routers,
            "ike_crypto_profiles": ike_crypto_profiles,
            "gp_app_crypto_profiles": gp_app_crypto_profiles,
            "ipsec_crypto_profiles": ipsec_crypto_profiles,
            "ike_gateways": ike_gateways,
            "ipsec_tunnels": ipsec_tunnels,
            "lldp_profiles": lldp_profiles,
            "virtual_wires": virtual_wires,
            "vlans": vlan_objects,
            "qos_profiles": qos_profiles,
            "dhcp_servers": dhcp_servers,
            "interface_management_profiles": interface_mgmt_profiles,
            "monitor_profiles": monitor_profiles,
            "interfaces": {
                "loopback": loopback_interfaces,
                "tunnel": tunnel_interfaces,
                "vlan": vlan_interfaces,
                "ethernet": ethernet_parents,
                "ethernet_subinterfaces": ethernet_subinterfaces,
                "aggregate": aggregate_parents,
                "aggregate_subinterfaces": aggregate_subinterfaces,
                "ethernet_layer2_subinterfaces": ethernet_layer2_subinterfaces,
                "aggregate_layer2_subinterfaces": aggregate_layer2_subinterfaces,
            },
        },
        "objects": {
            "tags": tags,
            "addresses": addresses,
            "address_groups": address_groups,
            "profile_groups": profile_groups,
            "services": services,
            "service_groups": service_groups,
            "application_groups": application_groups,
            "url_categories": url_categories,
            "custom_applications": custom_applications,
            "application_filters": application_filters,
            "schedules": schedules,
            "edls": edls,
            "log_forwarding_profiles": log_forwarding_profiles,
            "syslog_server_profiles": syslog_server_profiles,
            "http_server_profiles": http_server_profiles,
            "snmp_v2c_server_profiles": snmp_v2c_server_profiles,
            "snmp_v3_server_profiles": snmp_v3_server_profiles,
            "email_server_profiles": email_server_profiles,
            "authentication_profiles": authentication_profiles,
            "radius_server_profiles": radius_server_profiles,
            "ldap_server_profiles": ldap_server_profiles,
            "kerberos_server_profiles": kerberos_server_profiles,
            "saml_server_profiles": saml_server_profiles,
            "tacacs_server_profiles": tacacs_server_profiles,
            "certificates": certificates,
            "gp_portals": gp_portals,
            "gp_gateways": gp_gateways,
            "ssl_profiles": ssl_profiles,
        },
        "policy": {
            "security_rules": security_rules,
            "nat_rules": nat_rules,
            "decryption_rules": decryption_rules,
            "authentication_rules": authentication_rules,
            "pbf_rules": pbf_rules,
            "qos_rules": qos_rules,
            "dos_protection_rules": dos_protection_rules,
        },
        "zones": zones,
        "security_profiles": {
            "anti_spyware": anti_spyware_profiles,
            "wildfire_antivirus": wildfire_antivirus_profiles,
            "vulnerability_protection": vulnerability_protection_profiles,
            "url_access": url_access_profiles,
            "decryption": decryption_profiles,
            "dns_security": dns_security_profiles,
            "file_blocking": file_blocking_profiles,
            "zone_protection": zone_protection_profiles,
            "dos_protection": dos_protection_profiles,
        },
    }

    if mgmt_interface or service_settings or service_routes:
        data["device_setup"] = {
            "management_interface": mgmt_interface,
            "service_settings": service_settings,
            "service_routes": service_routes,
        }

    if high_availability:
        data["high_availability"] = high_availability
    if botnet_report:
        data["shared"] = {"botnet_report": botnet_report}

    # Trailing-underscore normalization (#93), opt-in via normalize_names:
    # every named object in every exported collection participates, and
    # references are rewritten export-wide. Warnings must be appended BEFORE
    # _apply_renames, which rebuilds every list/dict — appending to
    # `warnings` afterwards would orphan them from the returned data.
    rename_map: dict[str, str] = {}
    skipped: list[str] = []
    if normalize_names:
        collisions = _find_name_collisions(_iter_named_objects_at(data))
        if collisions and not allow_name_collisions:
            raise NameCollisionError(collisions)
        rename_map, skipped = _build_rename_map(list(_iter_named_objects(data)))
    if rename_map:
        warnings.append({
            "severity": "info",
            "object_path": "names",
            "message": (
                f"Normalized {len(rename_map)} object name(s) with trailing underscores "
                f"(stripped '_' suffix): {', '.join(sorted(rename_map.keys())[:10])}"
                + ("..." if len(rename_map) > 10 else "")
            ),
        })
    if skipped:
        warnings.append({
            "severity": "warn",
            "object_path": "names",
            "message": (
                f"{len(skipped)} object name(s) with trailing underscores were left "
                "unchanged because the normalized name already exists or is "
                f"ambiguous: {', '.join(sorted(skipped))}. Rename them manually "
                "if your workflow requires names without trailing underscores."
            ),
        })
    if rename_map:
        data = _apply_renames(data, rename_map)

    return data


def write_export(data: dict, output_path: str) -> None:
    """Write the export dict as indented JSON to output_path."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    meta = data.get("meta", {})
    objs = data.get("objects", {})
    pol  = data.get("policy", {})
    sec_profiles = data.get("security_profiles", {})
    vrs  = data.get("network", {}).get("virtual_routers", [])
    warns = data.get("migration_warnings", [])
    dev_setup = data.get("device_setup", {})
    ha = data.get("high_availability", {})
    shared = data.get("shared", {})

    print(
        f"Exported to {output_path}  "
        f"[{meta.get('hostname', '?')}  PAN-OS {meta.get('sw_version', '?')}]",
        file=sys.stderr,
    )
    if meta.get("device_group"):
        print(
            f"  scope   : device group {meta['device_group']} "
            f"(merged: {' > '.join(meta.get('device_group_chain', []))} > shared)  "
            "OBJECTS ONLY",
            file=sys.stderr,
        )
    net = data.get("network", {})
    ifaces = net.get("interfaces", {})
    print(
        f"  network : {len(vrs)} virtual_router(s)  "
        f"{len(net.get('ike_crypto_profiles', []))} ike_crypto  "
        f"{len(net.get('gp_app_crypto_profiles', []))} gp_app_crypto  "
        f"{len(net.get('ipsec_crypto_profiles', []))} ipsec_crypto  "
        f"{len(net.get('ike_gateways', []))} ike_gw  "
        f"{len(net.get('ipsec_tunnels', []))} ipsec_tunnel  "
        f"{len(net.get('lldp_profiles', []))} lldp_profile  "
        f"{len(net.get('virtual_wires', []))} virtual_wire  "
        f"{len(net.get('vlans', []))} vlan_obj  "
        f"{len(net.get('qos_profiles', []))} qos_profile  "
        f"{len(net.get('dhcp_servers', []))} dhcp_server  "
        f"{len(ifaces.get('loopback', []))} loopback  "
        f"{len(ifaces.get('tunnel', []))} tunnel  "
        f"{len(ifaces.get('vlan', []))} vlan  "
        f"{len(ifaces.get('ethernet', []))} eth({len(ifaces.get('ethernet_subinterfaces', []))} subs)  "
        f"{len(ifaces.get('aggregate', []))} ae({len(ifaces.get('aggregate_subinterfaces', []))} subs)  "
        f"{len(ifaces.get('ethernet_layer2_subinterfaces', []))} eth-l2-subs  "
        f"{len(ifaces.get('aggregate_layer2_subinterfaces', []))} ae-l2-subs",
        file=sys.stderr,
    )
    print(
        f"  objects : {len(objs.get('tags',[]))} tags  "
        f"{len(objs.get('addresses',[]))} addresses  "
        f"{len(objs.get('address_groups',[]))} addr_groups  "
        f"{len(objs.get('services',[]))} services  "
        f"{len(objs.get('service_groups',[]))} svc_groups  "
        f"{len(objs.get('application_groups',[]))} app_groups  "
        f"{len(objs.get('url_categories',[]))} url_cats  "
        f"{len(objs.get('profile_groups',[]))} profile_groups",
        file=sys.stderr,
    )
    print(
        f"  extras  : {len(objs.get('custom_applications',[]))} custom_apps  "
        f"{len(objs.get('application_filters',[]))} app_filters  "
        f"{len(objs.get('schedules',[]))} schedules  "
        f"{len(objs.get('edls',[]))} edls  "
        f"{len(objs.get('log_forwarding_profiles',[]))} lfps  "
        f"{len(objs.get('syslog_server_profiles',[]))} syslog_profiles  "
        f"{len(objs.get('http_server_profiles',[]))} http_profiles  "
        f"{len(objs.get('snmp_v2c_server_profiles',[]))} snmp_v2c  "
        f"{len(objs.get('snmp_v3_server_profiles',[]))} snmp_v3  "
        f"{len(objs.get('email_server_profiles',[]))} email_profiles  "
        f"{len(objs.get('authentication_profiles',[]))} auth_profiles",
        file=sys.stderr,
    )
    print(
        f"  id svrs : {len(objs.get('radius_server_profiles',[]))} radius  "
        f"{len(objs.get('ldap_server_profiles',[]))} ldap  "
        f"{len(objs.get('kerberos_server_profiles',[]))} kerberos  "
        f"{len(objs.get('saml_server_profiles',[]))} saml  "
        f"{len(objs.get('tacacs_server_profiles',[]))} tacacs  "
        f"{len(objs.get('gp_gateways',[]))} gp_gateways  "
        f"{len(objs.get('gp_portals',[]))} gp_portals  "
        f"{len(objs.get('ssl_profiles',[]))} ssl_profiles",
        file=sys.stderr,
    )
    print(
        f"  certs   : {len(objs.get('certificates',[]))} certificates",
        file=sys.stderr,
    )
    print(
        f"  zones   : {len(data.get('zones', []))}",
        file=sys.stderr,
    )
    print(
        f"  policy  : {len(pol.get('security_rules',[]))} security_rules  "
        f"{len(pol.get('nat_rules',[]))} nat_rules  "
        f"{len(pol.get('decryption_rules',[]))} decryption_rules  "
        f"{len(pol.get('authentication_rules',[]))} auth_rules  "
        f"{len(pol.get('pbf_rules',[]))} pbf_rules  "
        f"{len(pol.get('qos_rules',[]))} qos_rules",
        file=sys.stderr,
    )
    print(
        f"  profiles: {len(sec_profiles.get('anti_spyware',[]))} anti_spyware  "
        f"{len(sec_profiles.get('wildfire_antivirus',[]))} wildfire  "
        f"{len(sec_profiles.get('vulnerability_protection',[]))} vuln  "
        f"{len(sec_profiles.get('url_access',[]))} url_access  "
        f"{len(sec_profiles.get('decryption',[]))} decryption  "
        f"{len(sec_profiles.get('dns_security',[]))} dns_sec  "
        f"{len(sec_profiles.get('file_blocking',[]))} file_block  "
        f"{len(sec_profiles.get('zone_protection',[]))} zone_prot  "
        f"{len(sec_profiles.get('dos_protection',[]))} dos_prot  "
        f"{len(pol.get('dos_protection_rules',[]))} dos_rules",
        file=sys.stderr,
    )
    ds_parts = []
    if dev_setup.get("management_interface"):
        ds_parts.append("mgmt_iface")
    if dev_setup.get("service_settings"):
        ds_parts.append("svc_settings")
    if dev_setup.get("service_routes"):
        ds_parts.append(f"{len(dev_setup['service_routes'])} svc_routes")
    if ds_parts:
        print(
            f"  device  : {' | '.join(ds_parts)}  (device-scoped — needs device_serial to push)",
            file=sys.stderr,
        )
    if ha:
        print(
            f"  ha      : group {ha.get('group_id', '?')}  mode {ha.get('mode', '?')}  "
            f"peer {ha.get('peer_ip', '?')}  (must be reconfigured manually — no SCM push path)",
            file=sys.stderr,
        )
    if shared.get("botnet_report"):
        print(
            "  shared  : botnet_report present  (reference only — no SCM equivalent object)",
            file=sys.stderr,
        )
    if warns:
        print(
            f"  {len(warns)} migration warning(s) — review 'migration_warnings' in the output",
            file=sys.stderr,
        )
