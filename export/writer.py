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
    export_ike_crypto_profiles,
    export_ipsec_crypto_profiles,
    export_ike_gateways,
    export_ipsec_tunnels,
    export_loopback_interfaces,
    export_tunnel_interfaces,
    export_ethernet_interfaces,
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

    ike_crypto_profiles   = export_ike_crypto_profiles(network_root)
    ipsec_crypto_profiles = export_ipsec_crypto_profiles(network_root)
    ike_gateways          = export_ike_gateways(network_root)
    ipsec_tunnels         = export_ipsec_tunnels(network_root)
    loopback_interfaces   = export_loopback_interfaces(network_root)
    tunnel_interfaces     = export_tunnel_interfaces(network_root)
    ethernet_parents, ethernet_subinterfaces = export_ethernet_interfaces(network_root)

    # Migration warnings for VPN/interface known limitations
    if ike_gateways:
        warnings.append({
            "severity": "warn",
            "object_path": "network/ike_gateways",
            "message": (
                f"{len(ike_gateways)} IKE gateway(s) exported with placeholder PSK "
                "('MIGRATION-PLACEHOLDER-PSK'). Update each gateway's pre-shared key "
                "in SCM after migration. The local-address field is also not supported "
                "by the SCM SDK and was skipped."
            ),
        })
    if ipsec_tunnels:
        warnings.append({
            "severity": "warn",
            "object_path": "network/ipsec_tunnels",
            "message": (
                f"{len(ipsec_tunnels)} IPSec tunnel(s) exported without tunnel-interface "
                "binding — the SCM SDK does not support this field. Link each tunnel "
                "to its tunnel interface manually after migration."
            ),
        })
    total_ifaces = (
        len(loopback_interfaces) + len(tunnel_interfaces)
        + len(ethernet_parents) + len(ethernet_subinterfaces)
    )
    if total_ifaces:
        warnings.append({
            "severity": "info",
            "object_path": "network/interfaces",
            "message": (
                f"{total_ifaces} physical interface(s) exported for reference "
                f"({len(ethernet_parents)} ethernet + {len(ethernet_subinterfaces)} subinterfaces, "
                f"{len(loopback_interfaces)} loopback, {len(tunnel_interfaces)} tunnel). "
                "Physical interfaces are device-scoped in SCM and cannot be pushed to a folder — "
                "they must be configured per-device in SCM device management. "
                "Interface data is preserved in the export JSON under network.interfaces."
            ),
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
            "interfaces": {
                "loopback": loopback_interfaces,
                "tunnel": tunnel_interfaces,
                "ethernet": ethernet_parents,
                "ethernet_subinterfaces": ethernet_subinterfaces,
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
        },
        "policy": {
            "security_rules": security_rules,
            "nat_rules": nat_rules,
        },
        "zones": zones,
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
    vrs  = data.get("network", {}).get("virtual_routers", [])
    warns = data.get("migration_warnings", [])

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
        f"{len(ifaces.get('loopback', []))} loopback  "
        f"{len(ifaces.get('tunnel', []))} tunnel  "
        f"{len(ifaces.get('ethernet', []))} eth({len(ifaces.get('ethernet_subinterfaces', []))} subs)",
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
        f"  zones   : {len(data.get('zones', []))}",
        file=sys.stderr,
    )
    print(
        f"  policy  : {len(pol.get('security_rules',[]))} security_rules  "
        f"{len(pol.get('nat_rules',[]))} nat_rules",
        file=sys.stderr,
    )
    if warns:
        print(
            f"  {len(warns)} migration warning(s) — review 'migration_warnings' in the output",
            file=sys.stderr,
        )
