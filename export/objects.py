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
