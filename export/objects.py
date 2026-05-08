"""Dict-returning exporters for all PAN-OS object types.

Each function returns a list of dicts shaped to match scm-mcp create function params.
The 'folder' key is intentionally omitted — the migration script supplies it at push time.
"""
from __future__ import annotations
from xml.etree.ElementTree import Element

from parsers._helpers import iter_entries, get_members

# ── PAN-OS color token → SCM color name ──────────────────────────────────────
# SCM valid colors: Azure Blue, Black, Blue, Blue Gray, Blue Violet, Brown,
# Burnt Sienna, Cerulean Blue, Chestnut, Cobalt Blue, Copper, Cyan, Forest Green,
# Gold, Gray, Green, Lavender, Light Gray, Light Green, Lime, Magenta, Mahogany,
# Maroon, Medium Blue, Medium Rose, Medium Violet, Midnight Blue, Olive, Orange,
# Orchid, Peach, Purple, Red, Red Violet, Red-Orange, Salmon, Thistle,
# Turquoise Blue, Violet Blue, Yellow, Yellow-Orange
_PANOS_COLORS = {
    "color1":  "Red",
    "color2":  "Orange",
    "color3":  "Yellow",
    "color4":  "Green",
    "color5":  "Blue",
    "color6":  "Purple",
    "color7":  "Brown",
    "color8":  "Cyan",        # PAN-OS "Teal" → closest SCM match
    "color9":  "Olive",
    "color10": "Maroon",
    "color11": "Cyan",
    "color12": "Gold",
    "color13": "Forest Green",
    "color14": "Cobalt Blue",  # PAN-OS "Blue (Phishing)" → closest SCM match
    "color15": "Midnight Blue",
    "color16": "Orchid",
    "color17": "Gray",
}

# ── PAN-OS addr-type → SCM field name ────────────────────────────────────────
_ADDR_TYPE_MAP = {
    "ip-netmask": "ip_netmask",
    "ip-range":   "ip_range",
    "ip-wildcard": "ip_wildcard",
    "fqdn":       "fqdn",
}


def export_tags(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "tag"):
        name = entry.get("name", "")
        color_raw = entry.findtext("color") or ""
        comments = entry.findtext("comments") or ""
        d: dict = {"name": name}
        scm_color = _PANOS_COLORS.get(color_raw)
        if scm_color:
            d["color"] = scm_color
        if comments:
            d["comments"] = comments
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_addresses(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "address"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        tags = get_members(entry, "tag/member")
        d: dict = {"name": name}
        for panos_key, scm_key in _ADDR_TYPE_MAP.items():
            val = entry.findtext(panos_key)
            if val is not None:
                d[scm_key] = val
                break
        if desc:
            d["description"] = desc
        if tags:
            d["tag"] = tags
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_address_groups(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "address-group"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        tags = get_members(entry, "tag/member")
        static = get_members(entry, "static/member")
        dyn_filter = entry.findtext("dynamic/filter") or ""
        d: dict = {"name": name}
        if static:
            d["static"] = static
        elif dyn_filter:
            d["dynamic_filter"] = dyn_filter
        if desc:
            d["description"] = desc
        if tags:
            d["tag"] = tags
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_services(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "service"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        tags = get_members(entry, "tag/member")
        d: dict = {"name": name}
        for proto in ("tcp", "udp", "sctp"):
            proto_el = entry.find(f"protocol/{proto}")
            if proto_el is not None:
                dst = proto_el.findtext("port") or ""
                src = proto_el.findtext("source-port") or ""
                d["protocol"] = proto
                d["destination_port"] = dst
                if src:
                    d["source_port"] = src
                break
        if desc:
            d["description"] = desc
        if tags:
            d["tag"] = tags
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_service_groups(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "service-group"):
        name = entry.get("name", "")
        members = get_members(entry, "members/member")
        tags = get_members(entry, "tag/member")
        d: dict = {"name": name, "members": members}
        if tags:
            d["tag"] = tags
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_application_groups(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "application-group"):
        name = entry.get("name", "")
        members = get_members(entry, "members/member")
        out.append({"name": name, "members": members})
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_profile_groups(vsys_root, shared_root) -> list[dict]:
    """Export security profile groups.

    PAN-OS field → SCM field:
      virus        → virus_and_wildfire_analysis
      spyware      → spyware
      vulnerability → vulnerability
      url-filtering → url_filtering
      wildfire-analysis → virus_and_wildfire_analysis (merged with virus in SCM)
      file-blocking → file_blocking
      dns-security  → dns_security
      data-filtering → data_filtering
    """
    _FIELD_MAP = {
        "virus":              "virus_and_wildfire_analysis",
        "spyware":            "spyware",
        "vulnerability":      "vulnerability",
        "url-filtering":      "url_filtering",
        "wildfire-analysis":  "virus_and_wildfire_analysis",
        "file-blocking":      "file_blocking",
        "dns-security":       "dns_security",
        "data-filtering":     "data_filtering",
    }
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "profile-group"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        for panos_field, scm_field in _FIELD_MAP.items():
            val = entry.findtext(f"{panos_field}/member")
            if val and scm_field not in d:   # first match wins for merged fields
                d[scm_field] = [val]
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_url_categories(vsys_root, shared_root) -> list[dict]:
    out = []
    for entry, _ in iter_entries(vsys_root, shared_root, "profiles/custom-url-category"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        cat_type = entry.findtext("type") or "URL List"
        urls = get_members(entry, "list/member")
        d: dict = {"name": name, "type": cat_type, "list": urls}
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_zones(vsys_root) -> list[dict]:
    """Zones live under vsys, not network, in PAN-OS."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("zone")
    if container is None:
        return out
    for zone in container.findall("entry"):
        name = zone.get("name", "")
        # Determine zone type
        for ztype in ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"):
            el = zone.find(f"network/{ztype}")
            if el is not None:
                ifaces = get_members(el, "member")
                break
        else:
            ztype = "layer3"
            ifaces = []
        enable_uid = zone.findtext("enable-user-identification") == "yes"
        zpp = zone.findtext("zone-protection-profile") or ""
        log_setting = zone.findtext("log-setting") or ""
        d: dict = {
            "name": name,
            "zone_type": ztype.replace("-", "_"),
        }
        if ifaces:
            d["interfaces"] = ifaces
        if enable_uid:
            d["enable_user_identification"] = True
        if zpp:
            d["zone_protection_profile"] = zpp
        if log_setting:
            d["log_setting"] = log_setting
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def _extract_profile_setting(rule: Element) -> dict | None:
    pg = rule.findtext("profile-setting/group/member")
    if pg:
        return {"group": [pg]}
    profiles_el = rule.find("profile-setting/profiles")
    if profiles_el is not None:
        ps: dict = {}
        for ptype in ("virus", "spyware", "vulnerability", "url-filtering",
                      "file-blocking", "wildfire-analysis", "data-filtering"):
            val = profiles_el.findtext(f"{ptype}/member")
            if val:
                # SCM uses underscores
                ps[ptype.replace("-", "_")] = [val]
        if ps:
            return ps
    return None


def export_security_rules(vsys_root) -> list[dict]:
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/security/rules") or vsys_root.find("security/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        action = rule.findtext("action") or "allow"
        src_zones = get_members(rule, "from/member")
        dst_zones = get_members(rule, "to/member")
        src_addrs = get_members(rule, "source/member")
        dst_addrs = get_members(rule, "destination/member")
        apps = get_members(rule, "application/member")
        services = get_members(rule, "service/member")
        tags = get_members(rule, "tag/member")
        desc = rule.findtext("description") or ""
        log_setting = rule.findtext("log-setting") or ""
        negate_src = rule.findtext("negate-source") == "yes"
        negate_dst = rule.findtext("negate-destination") == "yes"
        profile_setting = _extract_profile_setting(rule)

        categories = get_members(rule, "category/member")
        source_users = get_members(rule, "source-user/member")

        d: dict = {
            "name": name,
            "action": action,
            "source_zone": src_zones or ["any"],
            "destination_zone": dst_zones or ["any"],
            "source": src_addrs or ["any"],
            "destination": dst_addrs or ["any"],
            "application": apps or ["any"],
            "service": services or ["application-default"],
            "category": categories or ["any"],
            "source_user": source_users or ["any"],
        }
        if disabled:
            d["disabled"] = True
        if tags:
            d["tag"] = tags
        if desc:
            d["description"] = desc
        if log_setting:
            d["log_setting"] = log_setting
        if negate_src:
            d["negate_source"] = True
        if negate_dst:
            d["negate_destination"] = True
        if profile_setting:
            d["profile_setting"] = profile_setting
        out.append(d)
    return out


def _extract_source_translation(rule: Element) -> dict | None:
    src_nat = rule.find("source-translation")
    if src_nat is None:
        return None
    # dynamic-ip-and-port
    dipap = src_nat.find("dynamic-ip-and-port")
    if dipap is not None:
        iface_el = dipap.find("interface-address")
        if iface_el is not None:
            iface = iface_el.findtext("interface") or ""
            ip = iface_el.findtext("ip") or ""
            ia: dict = {"interface": iface}
            if ip:
                ia["ip"] = ip
            return {"dynamic_ip_and_port": {"interface_address": ia}}
        translated = get_members(dipap, "translated-address/member")
        if translated:
            return {"dynamic_ip_and_port": {"translated_address": translated}}
    # dynamic-ip
    dip = src_nat.find("dynamic-ip")
    if dip is not None:
        translated = get_members(dip, "translated-address/member")
        return {"dynamic_ip": {"translated_address": translated}}
    # static-ip
    sip = src_nat.find("static-ip")
    if sip is not None:
        translated = sip.findtext("translated-address") or ""
        d: dict = {"static_ip": {"translated_address": translated}}
        if sip.findtext("bi-directional") == "yes":
            d["static_ip"]["bi_directional"] = "yes"
        return d
    return None


def _extract_destination_translation(rule: Element) -> dict | None:
    dst_nat = rule.find("destination-translation")
    if dst_nat is None:
        return None
    d: dict = {}
    addr = dst_nat.findtext("translated-address")
    port = dst_nat.findtext("translated-port")
    if addr:
        d["translated_address"] = addr
    if port:
        d["translated_port"] = int(port)
    return d if d else None


def export_ike_crypto_profiles(network_root: Element | None) -> list[dict]:
    if network_root is None:
        return []
    container = network_root.find("ike/crypto-profiles/ike-crypto-profiles")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {
            "name": name,
            "hash": get_members(entry, "hash/member"),
            "encryption": get_members(entry, "encryption/member"),
            "dh_group": get_members(entry, "dh-group/member"),
        }
        lt = entry.find("lifetime")
        if lt is not None:
            child = next(iter(lt), None)
            if child is not None and child.text:
                d["lifetime"] = {child.tag: int(child.text)}
        out.append(d)
    return out


def export_ipsec_crypto_profiles(network_root: Element | None) -> list[dict]:
    if network_root is None:
        return []
    container = network_root.find("ike/crypto-profiles/ipsec-crypto-profiles")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        esp = entry.find("esp")
        if esp is not None:
            d["esp"] = {
                "encryption": get_members(esp, "encryption/member"),
                "authentication": get_members(esp, "authentication/member"),
            }
        dh = entry.findtext("dh-group")
        if dh:
            d["dh_group"] = dh
        lt = entry.find("lifetime")
        if lt is not None:
            child = next(iter(lt), None)
            if child is not None and child.text:
                d["lifetime"] = {child.tag: int(child.text)}
        out.append(d)
    return out


def export_ike_gateways(network_root: Element | None) -> list[dict]:
    """PSK keys are encrypted in PAN-OS XML — replaced with a placeholder.

    Admin must update each IKE gateway's PSK (or certificate) after migration.
    The local-address field is also skipped — not supported in the SCM SDK.
    """
    if network_root is None:
        return []
    container = network_root.find("ike/gateway")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {
            "name": name,
            "authentication": {"pre_shared_key": {"key": "MIGRATION-PLACEHOLDER-PSK"}},
        }

        # Peer address
        peer_ip = entry.findtext("peer-address/ip")
        peer_fqdn = entry.findtext("peer-address/fqdn")
        if peer_ip:
            d["peer_address"] = {"ip": peer_ip}
        elif peer_fqdn:
            d["peer_address"] = {"fqdn": peer_fqdn}
        else:
            d["peer_address"] = {"dynamic": {}}

        # Protocol version + per-version settings
        proto: dict = {}
        version = entry.findtext("protocol/version")
        if version:
            proto["version"] = version
        for ver in ("ikev1", "ikev2"):
            el = entry.find(f"protocol/{ver}")
            if el is None:
                continue
            ver_d: dict = {}
            cp = el.findtext("ike-crypto-profile")
            if cp:
                ver_d["ike_crypto_profile"] = cp
            dpd = el.find("dpd")
            if dpd is not None:
                ver_d["dpd"] = {"enable": dpd.findtext("enable") == "yes"}
            if ver_d:
                proto[ver] = ver_d
        if proto:
            d["protocol"] = proto

        # protocol-common
        pc = entry.find("protocol-common")
        if pc is not None:
            pc_d: dict = {}
            nat_trav = pc.find("nat-traversal")
            if nat_trav is not None:
                pc_d["nat_traversal"] = {"enable": nat_trav.findtext("enable") == "yes"}
            frag = pc.find("fragmentation")
            if frag is not None:
                pc_d["fragmentation"] = {"enable": frag.findtext("enable") == "yes"}
            if pc_d:
                d["protocol_common"] = pc_d

        out.append(d)
    return out


def export_ipsec_tunnels(network_root: Element | None) -> list[dict]:
    """The tunnel-interface binding is skipped — not supported in the SCM SDK.

    Admin must link the IPSec tunnel to its tunnel interface after migration.
    """
    if network_root is None:
        return []
    container = network_root.find("tunnel/ipsec")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}

        ak = entry.find("auto-key")
        if ak is not None:
            auto_key: dict = {}
            gws = [e.get("name", "") for e in ak.findall("ike-gateway/entry") if e.get("name")]
            if gws:
                auto_key["ike_gateway"] = [{"name": g} for g in gws]
            cp = ak.findtext("ipsec-crypto-profile")
            if cp:
                auto_key["ipsec_crypto_profile"] = cp
            proxy_ids = []
            for px in ak.findall("proxy-id/entry"):
                px_d: dict = {"name": px.get("name", "")}
                local = px.findtext("local")
                remote = px.findtext("remote")
                if local:
                    px_d["local"] = local
                if remote:
                    px_d["remote"] = remote
                proto_el = px.find("protocol")
                if proto_el is not None:
                    if proto_el.find("tcp") is not None:
                        px_d["protocol"] = {"tcp": {}}
                    elif proto_el.find("udp") is not None:
                        px_d["protocol"] = {"udp": {}}
                    # <any/> → omit protocol (SCM default = any)
                proxy_ids.append(px_d)
            if proxy_ids:
                auto_key["proxy_id"] = proxy_ids
            d["auto_key"] = auto_key

        out.append(d)
    return out


def export_loopback_interfaces(network_root: Element | None) -> list[dict]:
    """Loopback subinterfaces live at interface/loopback/units/entry."""
    if network_root is None:
        return []
    units = network_root.find("interface/loopback/units")
    if units is None:
        return []
    out = []
    for entry in units.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        comment = entry.findtext("comment")
        if comment:
            d["comment"] = comment
        mtu = entry.findtext("mtu")
        if mtu:
            d["mtu"] = int(mtu)
        mgmt = entry.findtext("interface-management-profile")
        if mgmt:
            d["interface_management_profile"] = mgmt
        ips = [e.get("name", "") for e in entry.findall("ip/entry") if e.get("name")]
        if ips:
            d["ip"] = [{"name": ip} for ip in ips]
        out.append(d)
    return out


def export_tunnel_interfaces(network_root: Element | None) -> list[dict]:
    """Tunnel subinterfaces live at interface/tunnel/units/entry."""
    if network_root is None:
        return []
    units = network_root.find("interface/tunnel/units")
    if units is None:
        return []
    out = []
    for entry in units.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        comment = entry.findtext("comment")
        if comment:
            d["comment"] = comment
        ips = [e.get("name", "") for e in entry.findall("ip/entry") if e.get("name")]
        if ips:
            d["ip"] = [{"name": ip} for ip in ips]
        out.append(d)
    return out


def export_ethernet_interfaces(
    network_root: Element | None,
) -> tuple[list[dict], list[dict]]:
    """Return (parent_interfaces, layer3_subinterfaces).

    Parent ethernet interfaces are pushed as layer3 mode with no IP.
    Subinterfaces (units) carry the IP/VLAN config and are pushed separately.
    """
    if network_root is None:
        return [], []
    container = network_root.find("interface/ethernet")
    if container is None:
        return [], []
    parents: list[dict] = []
    subinterfaces: list[dict] = []

    for entry in container.findall("entry"):
        name = entry.get("name", "")
        layer3 = entry.find("layer3")
        layer2 = entry.find("layer2")

        parent: dict = {"name": name}
        comment = entry.findtext("comment")
        if comment:
            parent["comment"] = comment

        if layer3 is not None:
            layer3_d: dict = {}
            ips = [e.get("name", "") for e in layer3.findall("ip/entry") if e.get("name")]
            if ips:
                layer3_d["ip"] = [{"name": ip} for ip in ips]
            parent["layer3"] = layer3_d

            for unit in layer3.findall("units/entry"):
                sub: dict = {"name": unit.get("name", ""), "parent_interface": name}
                tag = unit.findtext("tag")
                if tag:
                    sub["tag"] = int(tag)
                sub_comment = unit.findtext("comment")
                if sub_comment:
                    sub["comment"] = sub_comment
                mtu = unit.findtext("mtu")
                if mtu:
                    sub["mtu"] = int(mtu)
                mgmt = unit.findtext("interface-management-profile")
                if mgmt:
                    sub["interface_management_profile"] = mgmt
                sub_ips = [e.get("name", "") for e in unit.findall("ip/entry") if e.get("name")]
                if sub_ips:
                    sub["ip"] = [{"name": ip} for ip in sub_ips]
                subinterfaces.append(sub)
        elif layer2 is not None:
            parent["layer2"] = {}

        parents.append(parent)

    return parents, subinterfaces


def export_decryption_rules(vsys_root) -> list[dict]:
    """Export SSL/TLS decryption policy rules."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/decryption/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        action = rule.findtext("action") or "no-decrypt"
        src_zones = get_members(rule, "from/member")
        dst_zones = get_members(rule, "to/member")
        src_addrs = get_members(rule, "source/member")
        dst_addrs = get_members(rule, "destination/member")
        src_users = get_members(rule, "source-user/member")
        categories = get_members(rule, "category/member")
        services = get_members(rule, "service/member")
        profile = rule.findtext("profile") or ""
        desc = rule.findtext("description") or ""
        log_setting = rule.findtext("log-setting") or ""
        disabled = rule.findtext("disabled") == "yes"
        tags = get_members(rule, "tag/member")

        # PAN-OS <type> element maps to SCM type dict
        # e.g. ssl-forward-proxy → {"ssl_forward_proxy": {}}
        _type_map = {
            "ssl-forward-proxy":      "ssl_forward_proxy",
            "ssl-inbound-inspection": "ssl_inbound_inspection",
            "ssl-no-proxy":           "ssl_no_proxy",
            "ssh-proxy":              "ssh_proxy",
        }
        rule_type_el = rule.find("type")
        rule_type: dict | None = None
        if rule_type_el is not None:
            # The type element may be a text value or a child element tag
            type_text = rule_type_el.text or ""
            type_child = next(iter(rule_type_el), None)
            raw_type = type_child.tag if type_child is not None else type_text.strip()
            scm_type_key = _type_map.get(raw_type, raw_type.replace("-", "_"))
            rule_type = {scm_type_key: {}}

        d: dict = {
            "name": name,
            "action": action,
            "from": src_zones or ["any"],
            "to": dst_zones or ["any"],
            "source": src_addrs or ["any"],
            "destination": dst_addrs or ["any"],
            "source_user": src_users or ["any"],
            "category": categories or ["any"],
            "service": services or ["any"],
        }
        if rule_type:
            d["type"] = rule_type
        if profile:
            d["profile"] = profile
        if disabled:
            d["disabled"] = True
        if tags:
            d["tag"] = tags
        if desc:
            d["description"] = desc
        if log_setting and log_setting != "Panorama":
            d["log_setting"] = log_setting
        out.append(d)
    return out


def export_authentication_rules(vsys_root) -> list[dict]:
    """Export authentication policy rules."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/authentication/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        src_zones = get_members(rule, "from/member")
        dst_zones = get_members(rule, "to/member")
        src_addrs = get_members(rule, "source/member")
        dst_addrs = get_members(rule, "destination/member")
        src_users = get_members(rule, "source-user/member")
        categories = get_members(rule, "category/member")
        services = get_members(rule, "service/member")
        auth_profile = rule.findtext("authentication-enforcement") or ""
        desc = rule.findtext("description") or ""
        log_setting = rule.findtext("log-setting") or ""
        disabled = rule.findtext("disabled") == "yes"
        tags = get_members(rule, "tag/member")
        timeout = rule.findtext("timeout")

        d: dict = {
            "name": name,
            "from": src_zones or ["any"],
            "to": dst_zones or ["any"],
            "source": src_addrs or ["any"],
            "destination": dst_addrs or ["any"],
            "source_user": src_users or ["any"],
            "category": categories or ["any"],
            "service": services or ["any"],
        }
        if auth_profile:
            d["authentication_enforcement"] = auth_profile
        if disabled:
            d["disabled"] = True
        if tags:
            d["tag"] = tags
        if desc:
            d["description"] = desc
        if log_setting and log_setting != "Panorama":
            d["log_setting"] = log_setting
        if timeout:
            try:
                d["timeout"] = int(timeout)
            except ValueError:
                pass
        out.append(d)
    return out


def export_pbf_rules(vsys_root) -> list[dict]:
    """Export policy-based forwarding rules."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/pbf/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        src_zones = get_members(rule, "from/member")
        src_addrs = get_members(rule, "source/member")
        dst_addrs = get_members(rule, "destination/member")
        apps = get_members(rule, "application/member")
        services = get_members(rule, "service/member")
        desc = rule.findtext("description") or ""
        disabled = rule.findtext("disabled") == "yes"
        tags = get_members(rule, "tag/member")

        # Determine action: forward, discard, or no-pbf
        action: dict = {}
        fwd = rule.find("action/forward")
        if fwd is not None:
            nexthop_ip = fwd.findtext("nexthop/ip-address")
            egress_iface = fwd.findtext("egress-interface")
            fwd_d: dict = {}
            if egress_iface:
                fwd_d["egress_interface"] = egress_iface
            if nexthop_ip:
                fwd_d["nexthop"] = {"ip_address": nexthop_ip}
            action = {"forward": fwd_d}
        elif rule.find("action/discard") is not None:
            action = {"discard": {}}
        elif rule.find("action/no-pbf") is not None:
            action = {"no_pbf": {}}

        d: dict = {
            "name": name,
            "from_": {"zone": src_zones} if src_zones else {"zone": ["any"]},
            "source": src_addrs or ["any"],
            "destination": dst_addrs or ["any"],
            "application": apps or ["any"],
            "service": services or ["any"],
        }
        if action:
            d["action"] = action
        if disabled:
            d["disabled"] = True
        if tags:
            d["tag"] = tags
        if desc:
            d["description"] = desc
        out.append(d)
    return out


def export_qos_rules(vsys_root) -> list[dict]:
    """Export QoS policy rules.

    SCM QoS rule model only supports name, description, action, schedule,
    and dscp_tos. Match criteria (from/to/source/destination/app/service)
    are not supported in SCM and are silently dropped.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/qos/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        desc = rule.findtext("description") or ""

        # SCM action: {"class": "1"} through {"class": "8"}
        qos_class = rule.findtext("action/class") or ""
        action: dict = {}
        if qos_class:
            action = {"class": qos_class}

        d: dict = {"name": name}
        if action:
            d["action"] = action
        if desc:
            d["description"] = desc
        out.append(d)
    return out


def export_nat_rules(vsys_root) -> list[dict]:
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/nat/rules") or vsys_root.find("nat/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        nat_type = rule.findtext("nat-type") or "ipv4"
        src_zones = get_members(rule, "from/member")
        dst_zones = get_members(rule, "to/member")
        src_addrs = get_members(rule, "source/member")
        dst_addrs = get_members(rule, "destination/member")
        service = rule.findtext("service") or "any"
        desc = rule.findtext("description") or ""
        tags = get_members(rule, "tag/member")
        src_translation = _extract_source_translation(rule)
        dst_translation = _extract_destination_translation(rule)

        d: dict = {
            "name": name,
            "nat_type": nat_type,
            "source_zone": src_zones or ["any"],
            "destination_zone": dst_zones or ["any"],
            "source": src_addrs or ["any"],
            "destination": dst_addrs or ["any"],
            "service": service,
        }
        if disabled:
            d["disabled"] = True
        if src_translation:
            d["source_translation"] = src_translation
        if dst_translation:
            d["destination_translation"] = dst_translation
        if desc:
            d["description"] = desc
        if tags:
            d["tag"] = tags
        out.append(d)
    return out


# ── Security Profiles (Chunk 2) ───────────────────────────────────────────────

def _export_named_profiles(vsys_root, path: str) -> list[dict]:
    """Export profiles that only need name + description (complex rule bodies are skipped)."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find(f"profiles/{path}")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        d: dict = {"name": name}
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_anti_spyware_profiles(vsys_root) -> list[dict]:
    return _export_named_profiles(vsys_root, "spyware")


def export_wildfire_antivirus_profiles(vsys_root) -> list[dict]:
    """Export WildFire antivirus profiles including rules (name, direction, analysis, app, file_type).

    SCM WildfireAvProfileCreateModel requires at least one rule; a default is added if none found.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("profiles/wildfire-analysis")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        rules = []
        for rule_el in entry.findall("rules/entry"):
            rule: dict = {
                "name": rule_el.get("name", "default"),
                "direction": rule_el.findtext("direction") or "both",
            }
            apps = get_members(rule_el, "application/member")
            ftypes = get_members(rule_el, "file-type/member")
            analysis = rule_el.findtext("analysis") or ""
            if apps:
                rule["application"] = apps
            if ftypes:
                rule["file_type"] = ftypes
            if analysis:
                rule["analysis"] = analysis
            rules.append(rule)
        if not rules:
            rules = [{"name": "default", "direction": "both",
                      "application": ["any"], "file_type": ["any"],
                      "analysis": "public-cloud"}]
        d: dict = {"name": name, "rules": rules}
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_vulnerability_protection_profiles(vsys_root) -> list[dict]:
    """Export vulnerability protection profiles including rules.

    SCM requires: name, severity, host, cve, vendor_id, category, threat_name per rule.
    A default rule is added if none found. Complex action fields are skipped — review in SCM.
    """
    _DEFAULT_VULN_RULE = {
        "name": "default", "severity": ["any"], "host": "any",
        "cve": ["any"], "vendor_id": ["any"], "category": "any", "threat_name": "any",
    }
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("profiles/vulnerability")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        rules = []
        for rule_el in entry.findall("rules/entry"):
            rule_name = rule_el.get("name", "default")
            severities = get_members(rule_el, "severity/member")
            host = rule_el.findtext("host") or "any"
            cves = get_members(rule_el, "cve/member")
            vendor_ids = get_members(rule_el, "vendor-id/member")
            category = rule_el.findtext("category") or "any"
            threat_name = rule_el.findtext("threat-name") or "any"
            rule: dict = {
                "name": rule_name,
                "severity": severities if severities else ["any"],
                "host": host if host in ("any", "client", "server") else "any",
                "cve": cves if cves else ["any"],
                "vendor_id": vendor_ids if vendor_ids else ["any"],
                "category": category,
                "threat_name": threat_name,
            }
            rules.append(rule)
        if not rules:
            rules = [dict(_DEFAULT_VULN_RULE)]
        d: dict = {"name": name, "rules": rules}
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_url_access_profiles(vsys_root) -> list[dict]:
    """Export URL filtering profiles (mapped to URL Access profiles in SCM)."""
    return _export_named_profiles(vsys_root, "url-filtering")


def export_decryption_profiles(vsys_root) -> list[dict]:
    return _export_named_profiles(vsys_root, "decryption")


def export_dns_security_profiles(vsys_root) -> list[dict]:
    return _export_named_profiles(vsys_root, "dns-security")


def export_file_blocking_profiles(vsys_root) -> list[dict]:
    """Export file blocking profiles including rules (rules are simple enough to extract)."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("profiles/file-blocking")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        rules = []
        for rule_el in entry.findall("rules/entry"):
            rule: dict = {"name": rule_el.get("name", "")}
            apps = get_members(rule_el, "application/member")
            ftypes = get_members(rule_el, "file-type/member")
            direction = rule_el.findtext("direction") or "both"
            action = rule_el.findtext("action") or "alert"
            if apps:
                rule["application"] = apps
            if ftypes:
                rule["file_type"] = ftypes
            rule["direction"] = direction
            rule["action"] = action
            rules.append(rule)
        d: dict = {"name": name}
        if desc:
            d["description"] = desc
        if rules:
            d["rules"] = rules
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_zone_protection_profiles(network_root) -> list[dict]:
    """Export zone protection profiles from network/profiles/zone-protection."""
    out = []
    if network_root is None:
        return out
    container = network_root.find("profiles/zone-protection")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        d: dict = {"name": name}
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_dos_protection_profiles(vsys_root) -> list[dict]:
    """Export DoS protection profiles — exported for reference only, no SDK push."""
    return _export_named_profiles(vsys_root, "dos-protection")
