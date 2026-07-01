"""Export PAN-OS config to SCM-shaped JSON."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from xml.etree.ElementTree import Element

from parsers._data import get_virtual_routers_export
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
    export_security_rules,
    export_nat_rules,
    export_decryption_rules,
    export_authentication_rules,
    export_pbf_rules,
    export_qos_rules,
    export_ike_crypto_profiles,
    export_ipsec_crypto_profiles,
    export_ike_gateways,
    export_ipsec_tunnels,
    export_interface_management_profiles,
    export_loopback_interfaces,
    export_tunnel_interfaces,
    export_vlan_interfaces,
    export_ethernet_interfaces,
    export_aggregate_interfaces,
    export_anti_spyware_profiles,
    export_wildfire_antivirus_profiles,
    export_vulnerability_protection_profiles,
    export_url_access_profiles,
    export_decryption_profiles,
    export_dns_security_profiles,
    export_file_blocking_profiles,
    export_lldp_profiles,
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
    export_authentication_profiles,
    export_radius_server_profiles,
    export_ldap_server_profiles,
    export_kerberos_server_profiles,
    export_saml_server_profiles,
    export_tacacs_server_profiles,
    export_device_setup,
)


def _normalize_name(name: str) -> str:
    """Strip trailing underscores from object names — SCM rejects them."""
    return name.rstrip("_")


def _build_rename_map(items: list[dict]) -> dict[str, str]:
    """Map original name → normalized name for objects with trailing underscores."""
    return {
        item["name"]: _normalize_name(item["name"])
        for item in items
        if item["name"] != _normalize_name(item["name"])
    }


def _apply_renames(data: dict, rename_map: dict[str, str]) -> dict:
    """Walk the full export dict and replace old names with normalized ones everywhere."""
    if not rename_map:
        return data

    def fix(obj):
        if isinstance(obj, str):
            return rename_map.get(obj, obj)
        if isinstance(obj, list):
            return [fix(v) for v in obj]
        if isinstance(obj, dict):
            # 'name' key is the object's own name — rename it
            result = {}
            for k, v in obj.items():
                result[k] = fix(v)
            return result
        return obj

    return fix(data)


def build_export(
    root: Element,
    vsys_root: Element | None,
    shared_root: Element | None,
    network_root: Element | None,
    source_file: str,
    vsys: str,
) -> dict:
    """Assemble the full export dict from all getter functions."""
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
    zones              = export_zones(vsys_root)
    security_rules     = export_security_rules(vsys_root)
    nat_rules          = export_nat_rules(vsys_root)
    decryption_rules   = export_decryption_rules(vsys_root)
    authentication_rules = export_authentication_rules(vsys_root)
    pbf_rules          = export_pbf_rules(vsys_root)
    qos_rules          = export_qos_rules(vsys_root)

    ike_crypto_profiles   = export_ike_crypto_profiles(network_root)
    ipsec_crypto_profiles = export_ipsec_crypto_profiles(network_root)
    ike_gateways          = export_ike_gateways(network_root)
    ipsec_tunnels         = export_ipsec_tunnels(network_root)
    lldp_profiles           = export_lldp_profiles(network_root)
    dhcp_servers            = export_dhcp_servers(network_root)
    interface_mgmt_profiles = export_interface_management_profiles(network_root)
    loopback_interfaces, loopback_notes = export_loopback_interfaces(network_root)
    tunnel_interfaces, tunnel_notes     = export_tunnel_interfaces(network_root)
    vlan_interfaces, vlan_notes         = export_vlan_interfaces(network_root)
    ethernet_parents, ethernet_subinterfaces = export_ethernet_interfaces(network_root)
    aggregate_parents, aggregate_subinterfaces = export_aggregate_interfaces(network_root)

    anti_spyware_profiles           = export_anti_spyware_profiles(vsys_root)
    wildfire_antivirus_profiles     = export_wildfire_antivirus_profiles(vsys_root)
    vulnerability_protection_profiles = export_vulnerability_protection_profiles(vsys_root)
    url_access_profiles             = export_url_access_profiles(vsys_root)
    decryption_profiles             = export_decryption_profiles(vsys_root)
    dns_security_profiles           = export_dns_security_profiles(vsys_root)
    file_blocking_profiles          = export_file_blocking_profiles(vsys_root)
    zone_protection_profiles        = export_zone_protection_profiles(network_root)
    dos_protection_profiles         = export_dos_protection_profiles(vsys_root)
    dos_protection_rules            = export_dos_protection_rules(vsys_root)

    custom_applications     = export_custom_applications(vsys_root)
    application_filters     = export_application_filters(vsys_root)
    schedules               = export_schedules(vsys_root)
    edls                    = export_edls(vsys_root)
    log_forwarding_profiles  = export_log_forwarding_profiles(vsys_root)
    syslog_server_profiles   = export_syslog_server_profiles(vsys_root)
    http_server_profiles     = export_http_server_profiles(vsys_root)
    snmp_v2c_server_profiles, snmp_v3_server_profiles = export_snmp_trap_server_profiles(vsys_root)
    authentication_profiles  = export_authentication_profiles(vsys_root)
    radius_server_profiles   = export_radius_server_profiles(vsys_root)
    ldap_server_profiles     = export_ldap_server_profiles(vsys_root)
    kerberos_server_profiles = export_kerberos_server_profiles(vsys_root)
    saml_server_profiles     = export_saml_server_profiles(vsys_root)
    tacacs_server_profiles   = export_tacacs_server_profiles(vsys_root)

    # Device Setup — device-scoped, requires serial at push time
    mgmt_interface, service_settings, service_routes = export_device_setup(root)

    # Identity server profiles with encrypted secrets — flag placeholder values
    _secret_profiles = (
        [(radius_server_profiles, "objects/radius_server_profiles", "RADIUS")]
        + [(ldap_server_profiles,   "objects/ldap_server_profiles",   "LDAP") if ldap_server_profiles else []]
        + [(tacacs_server_profiles, "objects/tacacs_server_profiles", "TACACS+") if tacacs_server_profiles else []]
    )
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
    for note in loopback_notes + tunnel_notes + vlan_notes:
        warnings.append({
            "severity": "warn",
            "object_path": "network/interfaces",
            "message": note,
        })

    # Build a unified rename map for all objects with trailing underscores
    all_named = addresses + address_groups + service_groups + tags
    rename_map = _build_rename_map(all_named)

    data = {
        "meta": {
            "schema_version": "1.2",
            "source_file": source_file,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "hostname": hostname,
            "sw_version": sw_version,
            "vsys": vsys,
        },
        "migration_warnings": warnings,
        "network": {
            "virtual_routers": virtual_routers,
            "ike_crypto_profiles": ike_crypto_profiles,
            "ipsec_crypto_profiles": ipsec_crypto_profiles,
            "ike_gateways": ike_gateways,
            "ipsec_tunnels": ipsec_tunnels,
            "lldp_profiles": lldp_profiles,
            "dhcp_servers": dhcp_servers,
            "interface_management_profiles": interface_mgmt_profiles,
            "interfaces": {
                "loopback": loopback_interfaces,
                "tunnel": tunnel_interfaces,
                "vlan": vlan_interfaces,
                "ethernet": ethernet_parents,
                "ethernet_subinterfaces": ethernet_subinterfaces,
                "aggregate": aggregate_parents,
                "aggregate_subinterfaces": aggregate_subinterfaces,
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
            "authentication_profiles": authentication_profiles,
            "radius_server_profiles": radius_server_profiles,
            "ldap_server_profiles": ldap_server_profiles,
            "kerberos_server_profiles": kerberos_server_profiles,
            "saml_server_profiles": saml_server_profiles,
            "tacacs_server_profiles": tacacs_server_profiles,
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

    # Apply trailing-underscore normalization across all names and references
    if rename_map:
        data = _apply_renames(data, rename_map)
        warnings.append({
            "severity": "info",
            "object_path": "names",
            "message": (
                f"Normalized {len(rename_map)} object name(s) with trailing underscores "
                f"(stripped '_' suffix): {', '.join(sorted(rename_map.keys())[:10])}"
                + ("..." if len(rename_map) > 10 else "")
            ),
        })

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

    print(
        f"Exported to {output_path}  "
        f"[{meta.get('hostname', '?')}  PAN-OS {meta.get('sw_version', '?')}]",
        file=sys.stderr,
    )
    net = data.get("network", {})
    ifaces = net.get("interfaces", {})
    print(
        f"  network : {len(vrs)} virtual_router(s)  "
        f"{len(net.get('ike_crypto_profiles', []))} ike_crypto  "
        f"{len(net.get('ipsec_crypto_profiles', []))} ipsec_crypto  "
        f"{len(net.get('ike_gateways', []))} ike_gw  "
        f"{len(net.get('ipsec_tunnels', []))} ipsec_tunnel  "
        f"{len(net.get('lldp_profiles', []))} lldp_profile  "
        f"{len(net.get('dhcp_servers', []))} dhcp_server  "
        f"{len(ifaces.get('loopback', []))} loopback  "
        f"{len(ifaces.get('tunnel', []))} tunnel  "
        f"{len(ifaces.get('vlan', []))} vlan  "
        f"{len(ifaces.get('ethernet', []))} eth({len(ifaces.get('ethernet_subinterfaces', []))} subs)  "
        f"{len(ifaces.get('aggregate', []))} ae({len(ifaces.get('aggregate_subinterfaces', []))} subs)",
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
        f"{len(objs.get('authentication_profiles',[]))} auth_profiles",
        file=sys.stderr,
    )
    print(
        f"  id svrs : {len(objs.get('radius_server_profiles',[]))} radius  "
        f"{len(objs.get('ldap_server_profiles',[]))} ldap  "
        f"{len(objs.get('kerberos_server_profiles',[]))} kerberos  "
        f"{len(objs.get('saml_server_profiles',[]))} saml  "
        f"{len(objs.get('tacacs_server_profiles',[]))} tacacs",
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
    if warns:
        print(
            f"  {len(warns)} migration warning(s) — review 'migration_warnings' in the output",
            file=sys.stderr,
        )
