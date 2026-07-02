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


def export_gp_app_crypto_profiles(network_root: Element | None) -> list[dict]:
    """GlobalProtect app crypto profiles — sibling of ike-crypto-profiles under
    ike/crypto-profiles. Same entry shape (name/encryption/authentication
    member lists) but no hash/dh-group/lifetime fields."""
    if network_root is None:
        return []
    container = network_root.find("ike/crypto-profiles/global-protect-app-crypto-profiles")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {
            "name": name,
            "encryption": get_members(entry, "encryption/member"),
            "authentication": get_members(entry, "authentication/member"),
        }
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
    Local-address bindings are captured as _local_ip/_local_iface metadata keys
    so writer.py can emit per-gateway warnings; writer.py pops them before
    serializing the list to JSON.
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

        # Capture local-address binding as writer metadata (underscore-prefixed).
        # These keys are stripped in writer.py before the list is serialized to JSON.
        local_ip    = entry.findtext("local-address/ip") or ""
        local_iface = entry.findtext("local-address/interface") or ""
        if local_ip or local_iface:
            d["_local_ip"]    = local_ip
            d["_local_iface"] = local_iface

        out.append(d)
    return out


def export_ipsec_tunnels(network_root: Element | None) -> list[dict]:
    if network_root is None:
        return []
    container = network_root.find("tunnel/ipsec")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}

        tunnel_iface = entry.findtext("tunnel-interface")
        if tunnel_iface:
            d["tunnel_interface"] = tunnel_iface

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


def export_interface_management_profiles(network_root: Element | None) -> list[dict]:
    """Locally-defined interface management profiles at network/profiles/interface-management-profile."""
    if network_root is None:
        return []
    container = network_root.find("profiles/interface-management-profile")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        p: dict = {"name": name}
        for field in ("http", "https", "telnet", "ssh", "ping", "snmp"):
            if entry.find(field) is not None:
                p[field] = True
        for alias, tag in (("http_ocsp", "http-ocsp"), ("response_pages", "response-pages"),
                           ("userid_service", "userid-service"),
                           ("userid_syslog_listener_ssl", "userid-syslog-listener-ssl"),
                           ("userid_syslog_listener_udp", "userid-syslog-listener-udp")):
            if entry.find(tag) is not None:
                p[alias] = True
        permitted = [e.get("name", "") for e in entry.findall("permitted-ip/entry") if e.get("name")]
        if permitted:
            p["permitted_ip"] = permitted
        out.append(p)
    return out


def export_monitor_profiles(network_root: Element | None) -> list[dict]:
    """Locally-defined monitor profiles at network/profiles/monitor-profile.

    Used for IKE gateway / static-route path monitoring.
    """
    if network_root is None:
        return []
    container = network_root.find("profiles/monitor-profile")
    if container is None:
        return []
    out = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        p: dict = {"name": name}
        interval = entry.findtext("interval")
        if interval:
            p["interval"] = int(interval)
        threshold = entry.findtext("threshold")
        if threshold:
            p["threshold"] = int(threshold)
        action = entry.findtext("action")
        if action:
            p["action"] = action
        out.append(p)
    return out


def export_loopback_interfaces(network_root: Element | None) -> tuple[list[dict], list[str]]:
    """Loopback interfaces: numbered units at interface/loopback/units/entry.

    Also detects the bare 'loopback' parent when it carries IPs or a management
    profile directly (no unit number). Exports it as 'loopback.1' and emits a
    migration note. Skipped if 'loopback.1' already exists as a numbered unit.
    """
    if network_root is None:
        return [], []
    lo_root = network_root.find("interface/loopback")
    if lo_root is None:
        return [], []

    notes: list[str] = []
    out: list[dict] = []

    units = lo_root.find("units")
    unit_names = {e.get("name", "") for e in units.findall("entry")} if units is not None else set()

    parent_ips = [e.get("name", "") for e in lo_root.findall("ip/entry") if e.get("name")]
    parent_mgmt = lo_root.findtext("interface-management-profile")
    if (parent_ips or parent_mgmt) and "loopback.1" not in unit_names:
        d: dict = {"name": "loopback.1"}
        if parent_mgmt:
            d["interface_management_profile"] = parent_mgmt
        if parent_ips:
            d["ip"] = [{"name": ip} for ip in parent_ips]
        out.append(d)
        notes.append(
            "Bare 'loopback' parent interface (no unit number) normalized to 'loopback.1' "
            "— IPs and management profile carried over. Verify unit assignment in SCM."
        )

    if units is not None:
        for entry in units.findall("entry"):
            name = entry.get("name", "")
            d = {"name": name}
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

    return out, notes


def export_tunnel_interfaces(network_root: Element | None) -> tuple[list[dict], list[str]]:
    """Tunnel interfaces: numbered units at interface/tunnel/units/entry.

    Also detects the bare 'tunnel' parent when it carries IPs directly.
    Exports it as 'tunnel.1' and emits a migration note.
    Skipped if 'tunnel.1' already exists as a numbered unit.
    """
    if network_root is None:
        return [], []
    tun_root = network_root.find("interface/tunnel")
    if tun_root is None:
        return [], []

    notes: list[str] = []
    out: list[dict] = []

    units = tun_root.find("units")
    unit_names = {e.get("name", "") for e in units.findall("entry")} if units is not None else set()

    parent_ips = [e.get("name", "") for e in tun_root.findall("ip/entry") if e.get("name")]
    if parent_ips and "tunnel.1" not in unit_names:
        d: dict = {"name": "tunnel.1", "ip": [{"name": ip} for ip in parent_ips]}
        out.append(d)
        notes.append(
            "Bare 'tunnel' parent interface (no unit number) normalized to 'tunnel.1' "
            "— IPs carried over. Verify unit assignment in SCM."
        )

    if units is not None:
        for entry in units.findall("entry"):
            name = entry.get("name", "")
            d = {"name": name}
            comment = entry.findtext("comment")
            if comment:
                d["comment"] = comment
            ips = [e.get("name", "") for e in entry.findall("ip/entry") if e.get("name")]
            if ips:
                d["ip"] = [{"name": ip} for ip in ips]
            out.append(d)

    return out, notes


def export_vlan_interfaces(network_root: Element | None) -> tuple[list[dict], list[str]]:
    """VLAN interfaces: numbered units at interface/vlan/units/entry.

    Also detects the bare 'vlan' parent when it carries IPs or a management
    profile directly. Exports it as 'vlan.1' and emits a migration note.
    Skipped if 'vlan.1' already exists as a numbered unit.
    """
    if network_root is None:
        return [], []
    vlan_root = network_root.find("interface/vlan")
    if vlan_root is None:
        return [], []

    notes: list[str] = []
    out: list[dict] = []

    units = vlan_root.find("units")
    unit_names = {e.get("name", "") for e in units.findall("entry")} if units is not None else set()

    parent_ips = [e.get("name", "") for e in vlan_root.findall("ip/entry") if e.get("name")]
    parent_mgmt = vlan_root.findtext("interface-management-profile")
    if (parent_ips or parent_mgmt) and "vlan.1" not in unit_names:
        d: dict = {"name": "vlan.1"}
        if parent_mgmt:
            d["interface_management_profile"] = parent_mgmt
        if parent_ips:
            d["ip"] = [{"name": ip} for ip in parent_ips]
        out.append(d)
        notes.append(
            "Bare 'vlan' parent interface (no unit number) normalized to 'vlan.1' "
            "— IPs and management profile carried over. Verify unit assignment in SCM."
        )

    if units is not None:
        for entry in units.findall("entry"):
            name = entry.get("name", "")
            d = {"name": name}
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

    return out, notes


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
            dhcp_client = _export_dhcp_client(layer3)
            if dhcp_client is not None:
                layer3_d["dhcp_client"] = dhcp_client
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


def _export_dhcp_client(layer3: Element) -> dict | None:
    """Return the ``dhcp_client`` block for a ``<layer3>`` element, or None.

    PAN-OS interfaces configured for DHCP addressing carry a
    ``<dhcp-client>`` element under ``<layer3>`` with no ``<ip>`` entries.
    Without reading it, the exported ``layer3`` dict comes out empty —
    indistinguishable from an interface with no addressing configured at
    all — and the interface silently loses its DHCP assignment downstream.
    """
    dhcp_el = layer3.find("dhcp-client")
    if dhcp_el is None:
        return None
    dhcp: dict = {}
    create_default_route = dhcp_el.findtext("create-default-route")
    if create_default_route is not None:
        dhcp["create_default_route"] = create_default_route == "yes"
    default_route_metric = dhcp_el.findtext("default-route-metric")
    if default_route_metric:
        dhcp["default_route_metric"] = int(default_route_metric)
    return dhcp


def export_aggregate_interfaces(
    network_root: Element | None,
) -> tuple[list[dict], list[dict]]:
    """Return (parent_ae_interfaces, layer3_subinterfaces).

    Parent aggregate interfaces (ae1, ae2…) are pushed as $ae-N variables.
    Subinterfaces (ae1.1, ae1.2…) carry IP/VLAN config and are pushed separately.
    """
    if network_root is None:
        return [], []
    container = network_root.find("interface/aggregate-ethernet")
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
            dhcp_client = _export_dhcp_client(layer3)
            if dhcp_client is not None:
                layer3_d["dhcp_client"] = dhcp_client
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
    # SCM SDK VulnerabilityProfileCategory enum — values outside this set map to "any"
    _VALID_VULN_CATEGORIES = {
        "any", "brute-force", "code-execution", "code-obfuscation", "command-execution",
        "dos", "exploit-kit", "info-leak", "insecure-credentials", "overflow",
        "phishing", "protocol-anomaly", "scan", "sql-injection",
    }
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("profiles/vulnerability")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "").replace(" ", "-")
        desc = entry.findtext("description") or ""
        rules = []
        for rule_el in entry.findall("rules/entry"):
            rule_name = rule_el.get("name", "default")
            severities = get_members(rule_el, "severity/member")
            host = rule_el.findtext("host") or "any"
            cves = get_members(rule_el, "cve/member")
            vendor_ids = get_members(rule_el, "vendor-id/member")
            category = rule_el.findtext("category") or "any"
            if category not in _VALID_VULN_CATEGORIES:
                category = "any"
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


def export_lldp_profiles(network_root) -> list[dict]:
    """Export LLDP profiles from network/profiles/lldp-profile."""
    out = []
    if network_root is None:
        return out
    container = network_root.find("profiles/lldp-profile")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        mode = entry.findtext("mode")
        if mode:
            d["mode"] = mode
        snmp = entry.findtext("snmp-syslog-notification")
        if snmp is not None:
            d["snmp_syslog_notification"] = snmp.lower() == "yes"
        tlvs_el = entry.find("option-tlvs")
        if tlvs_el is not None:
            tlvs: dict = {}
            for scm_key, xml_tag in (
                ("port_description", "port-description"),
                ("system_name", "system-name"),
                ("system_description", "system-description"),
                ("system_capabilities", "system-capabilities"),
            ):
                val = tlvs_el.findtext(xml_tag)
                if val is not None:
                    tlvs[scm_key] = val.lower() == "yes"
            mgmt_el = tlvs_el.find("management-address")
            if mgmt_el is not None:
                mgmt: dict = {}
                enabled_text = mgmt_el.findtext("enabled")
                if enabled_text is not None:
                    mgmt["enabled"] = enabled_text.lower() == "yes"
                iplist_el = mgmt_el.find("iplist")
                if iplist_el is not None:
                    mgmt["iplist"] = [
                        {k: e.findtext(k) or "" for k in ("name", "interface", "ipv4", "ipv6")}
                        for e in iplist_el.findall("entry")
                    ]
                if mgmt:
                    tlvs["management_address"] = mgmt
            if tlvs:
                d["option_tlvs"] = tlvs
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_dhcp_servers(network_root) -> list[dict]:
    """Export DHCP server configuration from network/dhcp/interface.

    Covers an interface acting as a DHCP *server* (leases, IP pool,
    reservations, DNS/gateway options). Separate from DHCP *client*
    configuration on layer3 interfaces (network/interface/.../dhcp-client).
    """
    out = []
    if network_root is None:
        return out
    container = network_root.find("dhcp/interface")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        if not name:
            continue
        server = entry.find("server")
        if server is None:
            continue

        d: dict = {"interface": name}

        mode = server.findtext("mode")
        if mode:
            d["mode"] = mode

        probe_ip = server.findtext("probe-ip")
        if probe_ip is not None:
            d["probe_ip"] = probe_ip.lower() == "yes"

        option = server.find("option")
        if option is not None:
            gateway = option.findtext("gateway")
            if gateway:
                d["gateway"] = gateway
            subnet_mask = option.findtext("subnet-mask")
            if subnet_mask:
                d["subnet_mask"] = subnet_mask
            dns_primary = option.findtext("dns/primary")
            if dns_primary:
                d["dns_primary"] = dns_primary
            dns_secondary = option.findtext("dns/secondary")
            if dns_secondary:
                d["dns_secondary"] = dns_secondary
            lease_timeout = option.findtext("lease/timeout")
            if lease_timeout is not None:
                try:
                    d["lease_timeout"] = int(lease_timeout)
                except ValueError:
                    pass

        ip_pool = [m.text for m in server.findall("ip-pool/member") if m.text]
        if ip_pool:
            d["ip_pool"] = ip_pool

        reserved = []
        for r in server.findall("reserved/entry"):
            ip = r.get("name", "")
            if not ip:
                continue
            reserved.append({"ip": ip, "mac": r.findtext("mac") or ""})
        if reserved:
            d["reserved"] = reserved

        out.append(d)
    out.sort(key=lambda x: x["interface"].lower())
    return out


def _parse_flood_proto(el: Element) -> dict:
    """Parse a single flood protocol element (tcp-syn, udp, icmp, icmpv6, other-ip)."""
    out: dict = {}
    enable_text = el.findtext("enable")
    if enable_text is not None:
        out["enable"] = enable_text.lower() == "yes"
    for section in ("red", "syn-cookies"):
        sec_el = el.find(section)
        if sec_el is None:
            continue
        sec: dict = {}
        for rate_key in ("alarm-rate", "activate-rate", "maximal-rate"):
            val = sec_el.findtext(rate_key)
            if val is not None:
                try:
                    sec[rate_key] = int(val)
                except ValueError:
                    pass
        block_el = sec_el.find("block")
        if block_el is not None:
            dur = block_el.findtext("duration")
            if dur is not None:
                try:
                    sec["block"] = {"duration": int(dur)}
                except ValueError:
                    pass
        if sec:
            out[section] = sec
    return out


def export_dos_protection_profiles(vsys_root) -> list[dict]:
    """Export DoS protection profiles with full flood and resource settings."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("profiles/dos-protection")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        desc = entry.findtext("description")
        if desc:
            d["description"] = desc

        # type: aggregate or classified — SCM requires this field; PAN-OS defaults to aggregate
        type_el = entry.find("type")
        if type_el is not None and type_el.find("classified") is not None:
            d["type"] = "classified"
        else:
            d["type"] = "aggregate"

        # flood protection settings
        flood_el = entry.find("flood")
        if flood_el is not None:
            flood: dict = {}
            for proto in ("tcp-syn", "udp", "icmp", "icmpv6", "other-ip"):
                proto_el = flood_el.find(proto)
                if proto_el is not None:
                    parsed = _parse_flood_proto(proto_el)
                    if parsed:
                        flood[proto] = parsed
            if flood:
                d["flood"] = flood

        # resource protection settings
        resource_el = entry.find("resource")
        if resource_el is not None:
            sessions_el = resource_el.find("sessions")
            if sessions_el is not None:
                sessions: dict = {}
                enabled_text = sessions_el.findtext("enabled")
                if enabled_text is not None:
                    sessions["enabled"] = enabled_text.lower() == "yes"
                limit = sessions_el.findtext("max-concurrent-limit")
                if limit is not None:
                    try:
                        sessions["max-concurrent-limit"] = int(limit)
                    except ValueError:
                        pass
                if sessions:
                    d["resource"] = {"sessions": sessions}

        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_dos_protection_rules(vsys_root) -> list[dict]:
    """Export DoS protection rules from the vsys rulebase."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("rulebase/dos/rules") or vsys_root.find("dos/rules")
    if container is None:
        return out
    for rule in container.findall("entry"):
        name = rule.get("name", "")
        d: dict = {"name": name}

        disabled_text = rule.findtext("disabled")
        d["disabled"] = disabled_text is not None and disabled_text.lower() == "yes"

        # Zones: from/zone/member and to/zone/member
        from_zones = get_members(rule, "from/zone/member")
        d["from"] = from_zones if from_zones else ["any"]
        to_zones = get_members(rule, "to/zone/member")
        d["to"] = to_zones if to_zones else ["any"]

        src = get_members(rule, "source/member")
        d["source"] = src if src else ["any"]
        dst = get_members(rule, "destination/member")
        d["destination"] = dst if dst else ["any"]
        src_user = get_members(rule, "source-user/member")
        d["source_user"] = src_user if src_user else ["any"]
        svc = get_members(rule, "service/member")
        d["service"] = svc if svc else ["any"]

        # action: deny / allow / protect
        action_el = rule.find("action")
        if action_el is not None:
            action_tag = next((c.tag for c in action_el), None)
            if action_tag:
                d["action"] = {action_tag: {}}
        else:
            d["action"] = {"deny": {}}

        # protection: aggregate or classified
        prot_el = rule.find("protection")
        if prot_el is not None:
            agg_el = prot_el.find("aggregate")
            cls_el = prot_el.find("classified")
            if agg_el is not None:
                profile_name = agg_el.findtext("profile") or ""
                prot: dict = {"aggregate": {}}
                if profile_name:
                    prot["aggregate"]["profile"] = profile_name
                d["protection"] = prot
            elif cls_el is not None:
                profile_name = cls_el.findtext("profile") or ""
                prot = {"classified": {}}
                if profile_name:
                    prot["classified"]["profile"] = profile_name
                for rate_key in ("alarm-rate", "activate-rate", "maximal-rate"):
                    val = cls_el.findtext(rate_key)
                    if val is not None:
                        try:
                            prot["classified"][rate_key] = int(val)
                        except ValueError:
                            pass
                d["protection"] = prot

        log_setting = rule.findtext("log-setting")
        if log_setting:
            d["log_setting"] = log_setting
        schedule = rule.findtext("schedule")
        if schedule:
            d["schedule"] = schedule
        tags = get_members(rule, "tag/member")
        if tags:
            d["tag"] = tags

        out.append(d)
    return out


# ── Chunk 3: Applications, Schedules, EDLs, Server Profiles, Auth Profiles ───

def export_custom_applications(vsys_root) -> list[dict]:
    """Export custom application definitions from vsys/application."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("application")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        risk_raw = entry.findtext("risk")
        try:
            risk = int(risk_raw) if risk_raw else 1
        except ValueError:
            risk = 1
        d: dict = {
            "name": name,
            "category": entry.findtext("category") or "business-systems",
            "subcategory": entry.findtext("subcategory") or "other",
            "technology": entry.findtext("technology") or "client-server",
            "risk": risk,
        }
        desc = entry.findtext("description") or ""
        if desc:
            d["description"] = desc
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_application_filters(vsys_root) -> list[dict]:
    """Export application filter definitions from vsys/application-filter."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("application-filter")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        d: dict = {"name": name}
        categories = get_members(entry, "category/member")
        subcategories = get_members(entry, "subcategory/member")
        technologies = get_members(entry, "technology/member")
        risk_strs = get_members(entry, "risk/member")
        risks = []
        for r in risk_strs:
            try:
                risks.append(int(r))
            except ValueError:
                pass
        if categories:
            d["category"] = categories
        if subcategories:
            d["subcategory"] = subcategories
        if technologies:
            d["technology"] = technologies
        if risks:
            d["risk"] = risks
        new_appid = entry.findtext("new-appid")
        if new_appid == "yes":
            d["new_appid"] = True
        excludes = get_members(entry, "exclude/member")
        if excludes:
            d["exclude"] = excludes
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_schedules(vsys_root) -> list[dict]:
    """Export schedule objects from vsys/schedule.

    PAN-OS weekly days use text content (e.g. <monday>09:00-17:00</monday>),
    not member elements. Multiple ranges within a day are comma-separated.
    """
    _DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("schedule")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        sched_type: dict = {}

        recurring_el = entry.find("schedule-type/recurring")
        non_rec_el = entry.find("schedule-type/non-recurring")

        if recurring_el is not None:
            weekly_el = recurring_el.find("weekly")
            daily_el = recurring_el.find("daily")
            if weekly_el is not None:
                weekly: dict = {}
                for day in _DAYS:
                    day_text = (weekly_el.findtext(day) or "").strip()
                    if day_text:
                        weekly[day] = [t.strip() for t in day_text.split(",") if t.strip()]
                if weekly:
                    sched_type = {"recurring": {"weekly": weekly}}
            elif daily_el is not None:
                times = get_members(daily_el, "member")
                if times:
                    sched_type = {"recurring": {"daily": times}}
        elif non_rec_el is not None:
            times = get_members(non_rec_el, "member")
            if times:
                sched_type = {"non_recurring": times}

        d: dict = {"name": name}
        if sched_type:
            d["schedule_type"] = sched_type
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_edls(vsys_root) -> list[dict]:
    """Export External Dynamic List (EDL) objects from vsys/external-list.

    Supports ip, domain, and url EDL types with recurring schedules.
    Exception lists are preserved. Predefined EDLs are skipped (read-only in SCM).
    """
    _EDL_TYPES = ("ip", "domain", "url")
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("external-list")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        type_el = entry.find("type")
        if type_el is None:
            continue
        edl_type: dict = {}
        for type_name in _EDL_TYPES:
            child = type_el.find(type_name)
            if child is None:
                continue
            type_dict: dict = {}
            url_text = child.findtext("url") or ""
            if url_text:
                type_dict["url"] = url_text
            recurring_el = child.find("recurring")
            if recurring_el is not None:
                rec: dict = {}
                if recurring_el.find("five-minute") is not None:
                    rec["five_minute"] = {}
                if recurring_el.find("hourly") is not None:
                    rec["hourly"] = {}
                daily_el = recurring_el.find("daily")
                if daily_el is not None:
                    at = daily_el.findtext("at") or ""
                    rec["daily"] = {"at": at} if at else {}
                weekly_el = recurring_el.find("weekly")
                if weekly_el is not None:
                    w: dict = {}
                    dow = weekly_el.findtext("day-of-week")
                    if dow:
                        w["day_of_week"] = dow
                    at = weekly_el.findtext("at")
                    if at:
                        w["at"] = at
                    rec["weekly"] = w
                monthly_el = recurring_el.find("monthly")
                if monthly_el is not None:
                    m: dict = {}
                    dom = monthly_el.findtext("day-of-month")
                    if dom:
                        m["day_of_month"] = dom
                    at = monthly_el.findtext("at")
                    if at:
                        m["at"] = at
                    rec["monthly"] = m
                if rec:
                    type_dict["recurring"] = rec
            exceptions = get_members(child, "exception-list/member")
            if exceptions:
                type_dict["exception_list"] = exceptions
            edl_type[type_name] = type_dict
            break
        if not edl_type:
            continue
        out.append({"name": name, "type": edl_type})
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_log_forwarding_profiles(vsys_root) -> list[dict]:
    """Export log forwarding profiles from vsys/log-settings/profiles.

    The send_syslog / send_http forwarding destinations are exported by name
    for reference but not included in the push payload — those server profile
    references must be wired up manually in SCM after migration.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("log-settings/profiles")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        d: dict = {"name": name}
        if desc:
            d["description"] = desc
        match_list = []
        for ml_entry in entry.findall("match-list/entry"):
            ml: dict = {"name": ml_entry.get("name", "")}
            log_type = ml_entry.findtext("log-type")
            if log_type:
                ml["log_type"] = log_type
            ml["filter"] = ml_entry.findtext("filter") or "All Logs"
            # Store forwarding targets as reference — not pushed (server profiles
            # may not exist yet in SCM)
            syslog_refs = get_members(ml_entry, "send-syslog/using-syslog-setting/member")
            if syslog_refs:
                ml["_syslog_refs"] = syslog_refs
            http_refs = get_members(ml_entry, "send-http/using-http-setting/member")
            if http_refs:
                ml["_http_refs"] = http_refs
            snmp_refs = get_members(ml_entry, "send-snmptrap/using-snmptrap-setting/member")
            if snmp_refs:
                ml["_snmp_refs"] = snmp_refs
            match_list.append(ml)
        if match_list:
            d["match_list"] = match_list
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_syslog_server_profiles(vsys_root) -> list[dict]:
    """Export syslog server profiles from vsys/log-settings/syslog."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("log-settings/syslog")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "514"
            try:
                port = int(port_raw)
            except ValueError:
                port = 514
            servers.append({
                "name": srv_name,
                "server": srv.findtext("server") or "",
                "transport": srv.findtext("transport") or "UDP",
                "port": port,
                "format": srv.findtext("format") or "BSD",
                "facility": srv.findtext("facility") or "LOG_USER",
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_http_server_profiles(vsys_root) -> list[dict]:
    """Export HTTP server profiles from vsys/log-settings/http."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("log-settings/http")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "443"
            try:
                port = int(port_raw)
            except ValueError:
                port = 443
            servers.append({
                "name": srv_name,
                "address": srv.findtext("address") or "",
                "protocol": srv.findtext("protocol") or "HTTPS",
                "port": port,
                "http_method": srv.findtext("http-method") or "POST",
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_snmp_trap_server_profiles(vsys_root) -> tuple[list[dict], list[dict]]:
    """Export SNMP trap server profiles from vsys/log-settings/snmptrap.

    Splits profiles into SNMPv2c and SNMPv3 lists based on the <version> child
    tag.  Encrypted secrets (community / authpwd / privpwd) are replaced with
    MIGRATION-PLACEHOLDER-* values; callers should emit a migration_warning.

    Returns (snmp_v2c_server_profiles, snmp_v3_server_profiles).
    """
    v2c_out: list[dict] = []
    v3_out: list[dict] = []
    if vsys_root is None:
        return v2c_out, v3_out
    container = vsys_root.find("log-settings/snmptrap")
    if container is None:
        return v2c_out, v3_out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        version_el = entry.find("version")
        if version_el is None:
            continue
        if version_el.find("v2c") is not None:
            servers = []
            for srv in version_el.findall("v2c/server/entry"):
                servers.append({
                    "name": srv.get("name", ""),
                    "manager": srv.findtext("manager") or "",
                    "community": "MIGRATION-PLACEHOLDER-COMMUNITY",
                })
            d: dict = {"name": name}
            if servers:
                d["server"] = servers
            v2c_out.append(d)
        elif version_el.find("v3") is not None:
            servers = []
            for srv in version_el.findall("v3/server/entry"):
                servers.append({
                    "name": srv.get("name", ""),
                    "manager": srv.findtext("manager") or "",
                    "user": srv.findtext("user") or "",
                    "engineid": srv.findtext("engineid") or "",
                    "authpwd": "MIGRATION-PLACEHOLDER-AUTHPWD",
                    "privpwd": "MIGRATION-PLACEHOLDER-PRIVPWD",
                })
            d = {"name": name}
            if servers:
                d["server"] = servers
            v3_out.append(d)
    v2c_out.sort(key=lambda x: x["name"].lower())
    v3_out.sort(key=lambda x: x["name"].lower())
    return v2c_out, v3_out


def export_authentication_profiles(vsys_root) -> list[dict]:
    """Export authentication profiles from vsys/authentication-profile.

    Exports name, allow_list, and method type. LDAP/RADIUS profiles reference
    server profiles that may not exist in SCM — push will fail gracefully for
    those and require manual configuration after migration.
    """
    _METHOD_MAP = {
        "local-database": "local_database",
        "ldap": "ldap",
        "radius": "radius",
        "saml-idp": "saml_idp",
        "tacplus": "tacplus",
        "kerberos": "kerberos",
    }
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("authentication-profile")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        allow_list = get_members(entry, "allow-list/member")
        method: dict | None = None
        method_el = entry.find("method")
        if method_el is not None:
            for panos_method, scm_method in _METHOD_MAP.items():
                child = method_el.find(panos_method)
                if child is None:
                    continue
                if panos_method == "local-database":
                    method = {"local_database": {}}
                elif panos_method == "ldap":
                    m: dict = {}
                    sp = child.findtext("server-profile")
                    if sp:
                        m["server_profile"] = sp
                    la = child.findtext("login-attribute")
                    if la:
                        m["login_attribute"] = la
                    method = {"ldap": m}
                elif panos_method == "radius":
                    m = {}
                    sp = child.findtext("server-profile")
                    if sp:
                        m["server_profile"] = sp
                    method = {"radius": m}
                else:
                    method = {scm_method: {}}
                break
        d: dict = {"name": name}
        if desc:
            d["description"] = desc
        if allow_list:
            d["allow_list"] = allow_list
        if method:
            d["method"] = method
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_radius_server_profiles(vsys_root) -> list[dict]:
    """Export RADIUS server profiles from vsys/server-profile/radius.

    Secrets are encrypted in PAN-OS XML — replaced with MIGRATION-PLACEHOLDER-SECRET.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("server-profile/radius")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "1812"
            try:
                port = int(port_raw)
            except ValueError:
                port = 1812
            servers.append({
                "name": srv_name,
                "ip_address": srv.findtext("server") or "",
                "port": port,
                "secret": "MIGRATION-PLACEHOLDER-SECRET",
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        proto_el = entry.find("protocol")
        if proto_el is not None:
            for child in proto_el:
                tag = child.tag
                if tag == "CHAP":
                    d["protocol"] = {"CHAP": {}}
                elif tag == "PAP":
                    d["protocol"] = {"PAP": {}}
                elif tag == "PEAP-MSCHAPv2":
                    d["protocol"] = {"PEAP_MSCHAPv2": {}}
                elif tag == "PEAP-with-GTC":
                    d["protocol"] = {"PEAP_with_GTC": {}}
                elif tag == "EAP-TTLS-with-PAP":
                    d["protocol"] = {"EAP_TTLS_with_PAP": {}}
                break
        retries_raw = entry.findtext("retries")
        if retries_raw:
            try:
                d["retries"] = int(retries_raw)
            except ValueError:
                pass
        timeout_raw = entry.findtext("timeout")
        if timeout_raw:
            try:
                d["timeout"] = int(timeout_raw)
            except ValueError:
                pass
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_ldap_server_profiles(vsys_root) -> list[dict]:
    """Export LDAP server profiles from vsys/server-profile/ldap.

    bind-password is encrypted in PAN-OS XML — replaced with MIGRATION-PLACEHOLDER-SECRET.
    """
    _LDAP_TYPE_MAP = {
        "active-directory": "active-directory",
        "e-directory": "e-directory",
        "sun": "sun",
        "other": "other",
    }
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("server-profile/ldap")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "389"
            try:
                port = int(port_raw)
            except ValueError:
                port = 389
            servers.append({
                "name": srv_name,
                "address": srv.findtext("server") or "",
                "port": port,
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        base = entry.findtext("base")
        if base:
            d["base"] = base
        bind_dn = entry.findtext("bind-dn")
        if bind_dn:
            d["bind_dn"] = bind_dn
        bind_password = entry.findtext("bind-password")
        if bind_password:
            d["bind_password"] = "MIGRATION-PLACEHOLDER-SECRET"
        bind_timelimit = entry.findtext("bind-timelimit")
        if bind_timelimit:
            d["bind_timelimit"] = bind_timelimit
        ldap_type = entry.findtext("ldap-type") or entry.findtext("type")
        if ldap_type and ldap_type in _LDAP_TYPE_MAP:
            d["ldap_type"] = _LDAP_TYPE_MAP[ldap_type]
        timelimit_raw = entry.findtext("timelimit")
        if timelimit_raw:
            try:
                d["timelimit"] = int(timelimit_raw)
            except ValueError:
                pass
        retry_raw = entry.findtext("retry-interval")
        if retry_raw:
            try:
                d["retry_interval"] = int(retry_raw)
            except ValueError:
                pass
        ssl_raw = entry.findtext("ssl")
        if ssl_raw is not None:
            d["ssl"] = ssl_raw.lower() == "yes"
        verify_raw = entry.findtext("verify-server-certificate")
        if verify_raw is not None:
            d["verify_server_certificate"] = verify_raw.lower() == "yes"
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_kerberos_server_profiles(vsys_root) -> list[dict]:
    """Export Kerberos server profiles from vsys/server-profile/kerberos."""
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("server-profile/kerberos")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "88"
            try:
                port = int(port_raw)
            except ValueError:
                port = 88
            servers.append({
                "name": srv_name,
                "host": srv.findtext("host") or srv.findtext("server") or "",
                "port": port,
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def export_saml_server_profiles(vsys_root) -> list[dict]:
    """Export SAML IdP server profiles from vsys/server-profile/saml.

    Requires entity_id, certificate, sso_url, and sso_bindings in SCM.
    Profiles missing required fields are included as-is; push will fail
    gracefully if the SCM certificate object doesn't exist.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("server-profile/saml")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        entity_id = entry.findtext("entity-id") or ""
        certificate = entry.findtext("certificate") or ""
        sso_url = entry.findtext("sso-url") or ""
        sso_bindings_raw = entry.findtext("sso-bindings") or "post"
        sso_bindings = sso_bindings_raw if sso_bindings_raw in ("post", "redirect") else "post"
        slo_bindings_raw = entry.findtext("slo-bindings")
        d: dict = {"name": name}
        if entity_id:
            d["entity_id"] = entity_id
        if certificate:
            d["certificate"] = certificate
        if sso_url:
            d["sso_url"] = sso_url
        d["sso_bindings"] = sso_bindings
        if slo_bindings_raw and slo_bindings_raw in ("post", "redirect"):
            d["slo_bindings"] = slo_bindings_raw
        max_skew_raw = entry.findtext("max-clock-skew")
        if max_skew_raw:
            try:
                d["max_clock_skew"] = int(max_skew_raw)
            except ValueError:
                pass
        validate_raw = entry.findtext("validate-idp-certificate")
        if validate_raw is not None:
            d["validate_idp_certificate"] = validate_raw.lower() == "yes"
        want_signed_raw = entry.findtext("want-auth-requests-signed")
        if want_signed_raw is not None:
            d["want_auth_requests_signed"] = want_signed_raw.lower() == "yes"
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


_DEVICE_SYSTEM_PATH = "devices/entry/deviceconfig/system"


def _mgmt_from_el(sys_el) -> dict:
    d: dict = {}

    ip = sys_el.findtext("ip-address")
    if ip:
        d["ip_address"] = ip.strip()
    netmask = sys_el.findtext("netmask")
    if netmask:
        d["netmask"] = netmask.strip()
    gateway = sys_el.findtext("default-gateway")
    if gateway:
        d["default_gateway"] = gateway.strip()
    if sys_el.find("type/static") is not None:
        d["type"] = "static"
    elif sys_el.find("type/dhcp-client") is not None:
        d["type"] = "dhcp-client"

    # permitted_ip stays a flat list of strings for backward compatibility with
    # downstream consumers (e.g. scm-mcp's device-setup push, which forwards
    # this list verbatim to the SCM management-interface API). Per-entry
    # descriptions are exported separately so operationally useful context
    # isn't silently dropped.
    permitted = []
    descriptions = {}
    for e in sys_el.findall("permitted-ip/entry"):
        name = e.get("name", "")
        if not name:
            continue
        permitted.append(name)
        desc = e.findtext("description")
        if desc and desc.strip():
            descriptions[name] = desc.strip()
    if permitted:
        d["permitted_ip"] = permitted
    if descriptions:
        d["permitted_ip_descriptions"] = descriptions

    for flag, xml_flag in (
        ("ssh", "disable-ssh"),
        ("https", "disable-https"),
        ("telnet", "disable-telnet"),
        ("http", "disable-http"),
    ):
        val = sys_el.findtext(f"service/{xml_flag}")
        if val is not None:
            d[flag] = val.strip().lower() != "yes"

    for xml_field, key in (("ssh-port", "ssh_port"), ("https-port", "https_port")):
        raw = sys_el.findtext(xml_field)
        if raw:
            try:
                d[key] = int(raw)
            except ValueError:
                pass
    return d


def _svc_from_el(sys_el) -> dict:
    d: dict = {}
    ntp_primary = sys_el.findtext("ntp-servers/primary-ntp-server/ntp-server-address")
    if ntp_primary:
        d["ntp_primary"] = ntp_primary.strip()
    ntp_secondary = sys_el.findtext("ntp-servers/secondary-ntp-server/ntp-server-address")
    if ntp_secondary:
        d["ntp_secondary"] = ntp_secondary.strip()
    dns_primary = sys_el.findtext("dns-setting/servers/primary")
    if dns_primary:
        d["dns_primary"] = dns_primary.strip()
    dns_secondary = sys_el.findtext("dns-setting/servers/secondary")
    if dns_secondary:
        d["dns_secondary"] = dns_secondary.strip()
    banner = sys_el.findtext("login-banner")
    if banner:
        d["login_banner"] = banner.strip()
    update_server = sys_el.findtext("update-server")
    if update_server:
        d["update_server"] = update_server.strip()
    return d


def _routes_from_el(sys_el) -> list[dict]:
    out = []
    for entry in sys_el.findall("route/service/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        iface = entry.findtext("source/interface") or ""
        src_ip = entry.findtext("source/address") or ""
        d: dict = {"service": name}
        if iface:
            d["interface"] = iface
        if src_ip:
            d["source_ip"] = src_ip
        out.append(d)
    for entry in sys_el.findall("route/destination/entry"):
        name = entry.get("name", "")
        if not name:
            continue
        iface = entry.findtext("source/interface") or ""
        src_ip = entry.findtext("source/address") or ""
        d = {"destination": name}
        if iface:
            d["interface"] = iface
        if src_ip:
            d["source_ip"] = src_ip
        out.append(d)
    return out


def export_management_interface(root) -> dict:
    """Export management interface config from deviceconfig/system."""
    sys_el = root.find(_DEVICE_SYSTEM_PATH)
    if sys_el is None:
        return {}
    return _mgmt_from_el(sys_el)


def export_service_settings(root) -> dict:
    """Export NTP, DNS, login-banner, and update-server from deviceconfig/system."""
    sys_el = root.find(_DEVICE_SYSTEM_PATH)
    if sys_el is None:
        return {}
    return _svc_from_el(sys_el)


def export_service_routes(root) -> list[dict]:
    """Export per-service routing entries from deviceconfig/system/route."""
    sys_el = root.find(_DEVICE_SYSTEM_PATH)
    if sys_el is None:
        return []
    return _routes_from_el(sys_el)


def export_device_setup(root) -> tuple[dict, dict, list[dict]]:
    """Export all three device setup sections with a single XPath traversal.

    Returns (management_interface, service_settings, service_routes).
    """
    sys_el = root.find(_DEVICE_SYSTEM_PATH)
    if sys_el is None:
        return {}, {}, []
    return _mgmt_from_el(sys_el), _svc_from_el(sys_el), _routes_from_el(sys_el)


_HA_PATH = "devices/entry/deviceconfig/high-availability"

_HA_INTERFACE_TAGS = ("ha1", "ha1-backup", "ha2", "ha2-backup", "ha3")


def _ha_iface_from_el(iface_el) -> dict:
    d: dict = {}
    port = iface_el.findtext("port")
    if port:
        d["port"] = port.strip()
    ip_address = iface_el.findtext("ip-address")
    if ip_address:
        d["ip_address"] = ip_address.strip()
    netmask = iface_el.findtext("netmask")
    if netmask:
        d["netmask"] = netmask.strip()
    return d


def export_high_availability(root) -> dict:
    """Export HA pairing config from deviceconfig/high-availability.

    Only returns data when HA is enabled — the goal is visibility into the
    fact that this firewall is HA-paired (group id, peer, mode, election
    priority, HA1/HA2/HA3 interface bindings), not a full push path. SCM's
    folder-scoped migration has no mechanism to configure HA pairing, so
    the caller is expected to always surface a migration_warning alongside
    this data.
    """
    ha_el = root.find(_HA_PATH)
    if ha_el is None:
        return {}
    if (ha_el.findtext("enabled") or "").strip().lower() != "yes":
        return {}

    d: dict = {"enabled": True}

    group_el = ha_el.find("group")
    if group_el is not None:
        group_id_raw = group_el.findtext("group-id")
        if group_id_raw:
            try:
                d["group_id"] = int(group_id_raw)
            except ValueError:
                d["group_id"] = group_id_raw.strip()
        description = group_el.findtext("description")
        if description:
            d["description"] = description.strip()
        peer_ip = group_el.findtext("peer-ip")
        if peer_ip:
            d["peer_ip"] = peer_ip.strip()
        mode_el = group_el.find("mode")
        if mode_el is not None and len(mode_el):
            d["mode"] = mode_el[0].tag
        priority_raw = group_el.findtext("election-option/device-priority")
        if priority_raw:
            try:
                d["election_priority"] = int(priority_raw)
            except ValueError:
                d["election_priority"] = priority_raw.strip()

    interface_el = ha_el.find("interface")
    interfaces: dict = {}
    if interface_el is not None:
        for tag in _HA_INTERFACE_TAGS:
            iface_el = interface_el.find(tag)
            if iface_el is None:
                continue
            iface = _ha_iface_from_el(iface_el)
            if iface:
                interfaces[tag.replace("-", "_")] = iface
    if interfaces:
        d["interfaces"] = interfaces

    return d


def export_tacacs_server_profiles(vsys_root) -> list[dict]:
    """Export TACACS+ server profiles from vsys/server-profile/tacacs-plus.

    Secrets are encrypted in PAN-OS XML — replaced with MIGRATION-PLACEHOLDER-SECRET.
    """
    out = []
    if vsys_root is None:
        return out
    container = vsys_root.find("server-profile/tacacs-plus")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        servers = []
        for srv in entry.findall("server/entry"):
            srv_name = srv.get("name", "")
            port_raw = srv.findtext("port") or "49"
            try:
                port = int(port_raw)
            except ValueError:
                port = 49
            servers.append({
                "name": srv_name,
                "address": srv.findtext("server") or "",
                "port": port,
                "secret": "MIGRATION-PLACEHOLDER-SECRET",
            })
        d: dict = {"name": name}
        if servers:
            d["server"] = servers
        proto_raw = entry.findtext("protocol")
        if proto_raw:
            proto_upper = proto_raw.upper()
            if proto_upper in ("CHAP", "PAP"):
                d["protocol"] = proto_upper
        timeout_raw = entry.findtext("timeout")
        if timeout_raw:
            try:
                d["timeout"] = int(timeout_raw)
            except ValueError:
                pass
        single_conn_raw = entry.findtext("use-single-connection")
        if single_conn_raw is not None:
            d["use_single_connection"] = single_conn_raw.lower() == "yes"
        out.append(d)
    out.sort(key=lambda x: x["name"].lower())
    return out


def _threshold_entry(el) -> dict:
    """Read an <enabled>/<threshold> pair from a botnet http-detection element."""
    d: dict = {}
    enabled_raw = el.findtext("enabled")
    if enabled_raw is not None:
        d["enabled"] = enabled_raw.strip().lower() == "yes"
    threshold_raw = el.findtext("threshold")
    if threshold_raw:
        try:
            d["threshold"] = int(threshold_raw)
        except ValueError:
            pass
    return d


def _unknown_proto_entry(el) -> dict:
    """Read destinations/sessions-per-hour and session-length from a botnet
    unknown-tcp/unknown-udp element."""
    d: dict = {}
    for xml_field, key in (
        ("destinations-per-hour", "destinations_per_hour"),
        ("sessions-per-hour", "sessions_per_hour"),
    ):
        raw = el.findtext(xml_field)
        if raw:
            try:
                d[key] = int(raw)
            except ValueError:
                pass
    length_el = el.find("session-length")
    if length_el is not None:
        length: dict = {}
        for xml_field, key in (
            ("maximum-bytes", "maximum_bytes"),
            ("minimum-bytes", "minimum_bytes"),
        ):
            raw = length_el.findtext(xml_field)
            if raw:
                try:
                    length[key] = int(raw)
                except ValueError:
                    pass
        if length:
            d["session_length"] = length
    return d


def export_botnet_report(shared_root) -> dict:
    """Export the Botnet/C2 traffic report config from shared/botnet.

    Corresponds to Monitor > PDF Reports > Botnet in PAN-OS. SCM/Strata Logging
    Service has no direct equivalent object for this — exported for reference
    only, not as a pushable object (see the migration_warning emitted by
    build_export(), which follows the same pattern as dos_protection profiles).
    """
    if shared_root is None:
        return {}
    botnet_el = shared_root.find("botnet")
    if botnet_el is None:
        return {}

    d: dict = {}

    config_el = botnet_el.find("configuration")
    if config_el is not None:
        config: dict = {}

        http_el = config_el.find("http")
        if http_el is not None:
            http: dict = {}
            for xml_field, key in (
                ("dynamic-dns", "dynamic_dns"),
                ("malware-sites", "malware_sites"),
                ("recent-domains", "recent_domains"),
                ("ip-domains", "ip_domains"),
                ("executables-from-unknown-sites", "executables_from_unknown_sites"),
            ):
                el = http_el.find(xml_field)
                if el is None:
                    continue
                entry = _threshold_entry(el)
                if entry:
                    http[key] = entry
            if http:
                config["http"] = http

        irc_raw = config_el.findtext("other-applications/irc")
        if irc_raw is not None:
            config["other_applications"] = {"irc": irc_raw.strip().lower() == "yes"}

        unknown_el = config_el.find("unknown-applications")
        if unknown_el is not None:
            unknown: dict = {}
            for xml_field, key in (
                ("unknown-tcp", "unknown_tcp"),
                ("unknown-udp", "unknown_udp"),
            ):
                proto_el = unknown_el.find(xml_field)
                if proto_el is None:
                    continue
                proto = _unknown_proto_entry(proto_el)
                if proto:
                    unknown[key] = proto
            if unknown:
                config["unknown_applications"] = unknown

        if config:
            d["configuration"] = config

    report_el = botnet_el.find("report")
    if report_el is not None:
        report: dict = {}
        topn_raw = report_el.findtext("topn")
        if topn_raw:
            try:
                report["topn"] = int(topn_raw)
            except ValueError:
                pass
        scheduled_raw = report_el.findtext("scheduled")
        if scheduled_raw is not None:
            report["scheduled"] = scheduled_raw.strip().lower() == "yes"
        if report:
            d["report"] = report

    return d
