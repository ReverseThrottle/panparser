"""Pure data extraction — no rendering. Returns plain Python tuples for the TUI."""
from __future__ import annotations
from xml.etree.ElementTree import Element
from ._helpers import iter_entries, get_members

from .addresses import _extract_addr
from .services import _extract_service
from .zones import _extract_zone_type
from .interfaces import _extract_iface_detail, _iface_sort_key
from .routing import _extract_nexthop, _ip_sort_key
from .profiles import PROFILE_TYPES, _summarize_profile
from .applications import _extract_default_ports, _risk_color
from .nat import _extract_nat_translation
from .tags import PANOS_TAG_COLORS


def get_addresses(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, addr_type, value, desc)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "address"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        addr_type, value = _extract_addr(entry)
        rows.append((scope, name, addr_type, value, desc))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_address_groups(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, group_type, members_str, desc)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "address-group"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        static = get_members(entry, "static/member")
        dyn = entry.findtext("dynamic/filter") or ""
        if static:
            rows.append((scope, name, "static", ", ".join(static), desc))
        else:
            rows.append((scope, name, "dynamic", dyn, desc))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_services(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, proto, dst_port, src_port, desc)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "service"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        proto, dst, src = _extract_service(entry)
        rows.append((scope, name, proto, dst, src, desc))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_service_groups(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, members_str, desc)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "service-group"):
        name = entry.get("name", "")
        desc = entry.findtext("description") or ""
        members = get_members(entry, "members/member")
        rows.append((scope, name, ", ".join(members), desc))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_security_rules(vsys_root) -> list[tuple]:
    """(num, name, disabled, src_zones, dst_zones, src_addrs, dst_addrs, apps, services, action, profile)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("security/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        action = rule.findtext("action") or ""
        src_zones = ", ".join(get_members(rule, "from/member"))
        dst_zones = ", ".join(get_members(rule, "to/member"))
        src_addrs = ", ".join(get_members(rule, "source/member"))
        dst_addrs = ", ".join(get_members(rule, "destination/member"))
        apps = ", ".join(get_members(rule, "application/member"))
        services = ", ".join(get_members(rule, "service/member"))
        profile = _get_profile_group(rule)
        rows.append((i, name, disabled, src_zones, dst_zones, src_addrs,
                     dst_addrs, apps, services, action, profile))
    return rows


def get_nat_rules(vsys_root) -> list[tuple]:
    """(num, name, disabled, src_zones, dst_zones, src_addrs, dst_addrs, dst_iface, nat_type, translated)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("nat/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        src_zones = ", ".join(get_members(rule, "from/member"))
        dst_zones = ", ".join(get_members(rule, "to/member"))
        src_addrs = ", ".join(get_members(rule, "source/member"))
        dst_addrs = ", ".join(get_members(rule, "destination/member"))
        dst_iface = rule.findtext("to-interface") or ""
        nat_type, translated = _extract_nat_translation(rule)
        import re
        translated_plain = re.sub(r"\[.*?\]", "", translated).strip()
        rows.append((i, name, disabled, src_zones, dst_zones, src_addrs,
                     dst_addrs, dst_iface, nat_type, translated_plain))
    return rows


def get_zones(network_root) -> list[tuple]:
    """(name, zone_type, ifaces_str, zpp, log_setting)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("zone")
    if container is None:
        return rows
    for zone in container.findall("entry"):
        name = zone.get("name", "")
        zone_type, ifaces = _extract_zone_type(zone)
        zpp = zone.findtext("zone-protection-profile") or ""
        log_setting = zone.findtext("log-setting") or ""
        rows.append((name, zone_type, ", ".join(ifaces), zpp, log_setting))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_interfaces(network_root) -> list[tuple]:
    """(name, itype, ip_or_mode, subs_str, comment)"""
    rows = []
    if network_root is None:
        return rows
    iface_root = network_root.find("interface")
    if iface_root is None:
        return rows
    for itype, label in (("ethernet", "ethernet"), ("loopback", "loopback"),
                          ("tunnel", "tunnel"), ("vlan", "vlan"),
                          ("aggregate-ethernet", "ae")):
        container = iface_root.find(itype)
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name", "")
            ip, mode, subs = _extract_iface_detail(entry)
            comment = entry.findtext("comment") or ""
            ip_or_mode = ip if ip else mode
            rows.append((name, label, ip_or_mode, "; ".join(subs), comment))
    rows.sort(key=lambda r: _iface_sort_key(r[0]))
    return rows


def get_routing(network_root) -> list[tuple]:
    """(vr_name, route_name, dest, nexthop, iface, metric, admin_dist)"""
    rows = []
    if network_root is None:
        return rows
    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        return rows
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        sr = vr.find("routing-table/ip/static-route")
        if sr is None:
            continue
        for route in sr.findall("entry"):
            rname = route.get("name", "")
            dest = route.findtext("destination") or ""
            nexthop, iface = _extract_nexthop(route)
            import re
            nexthop = re.sub(r"\[.*?\]", "", nexthop).strip()
            metric = route.findtext("metric") or ""
            admin_dist = route.findtext("admin-dist") or ""
            rows.append((vr_name, rname, dest, nexthop, iface, metric, admin_dist))
    rows.sort(key=lambda r: (r[0].lower(), _ip_sort_key(r[2])))
    return rows


def get_tags(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, color_label, comments)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "tag"):
        name = entry.get("name", "")
        color_val = entry.findtext("color") or ""
        color_label = PANOS_TAG_COLORS.get(color_val, color_val)
        comments = entry.findtext("comments") or ""
        rows.append((scope, name, color_label, comments))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_profiles(vsys_root, shared_root) -> list[tuple]:
    """(profile_type_label, scope, name, summary, desc)"""
    rows = []
    for xml_key, label in PROFILE_TYPES:
        for entry, scope in iter_entries(vsys_root, shared_root, f"profiles/{xml_key}"):
            name = entry.get("name", "")
            desc = entry.findtext("description") or ""
            summary = _summarize_profile(entry, xml_key)
            rows.append((label, scope, name, summary, desc))
    rows.sort(key=lambda r: (r[0], r[2].lower()))
    return rows


def get_applications(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, category, subcategory, technology, risk, ports)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application"):
        name = entry.get("name", "")
        cat = entry.findtext("category") or ""
        subcat = entry.findtext("subcategory") or ""
        tech = entry.findtext("technology") or ""
        risk = entry.findtext("risk") or ""
        ports = _extract_default_ports(entry)
        rows.append((scope, name, cat, subcat, tech, risk, ports))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_application_groups(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, members_str)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application-group"):
        name = entry.get("name", "")
        members = get_members(entry, "members/member")
        rows.append((scope, name, ", ".join(members)))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def get_application_filters(vsys_root, shared_root) -> list[tuple]:
    """(scope, name, categories, subcategories, technologies, risks, characteristics)"""
    rows = []
    for entry, scope in iter_entries(vsys_root, shared_root, "application-filter"):
        name = entry.get("name", "")
        cat = ", ".join(get_members(entry, "category/member"))
        subcat = ", ".join(get_members(entry, "subcategory/member"))
        tech = ", ".join(get_members(entry, "technology/member"))
        risk = ", ".join(get_members(entry, "risk/member"))
        char = ", ".join(get_members(entry, "characteristic/member"))
        rows.append((scope, name, cat, subcat, tech, risk, char))
    rows.sort(key=lambda r: r[1].lower())
    return rows


def _get_profile_group(rule) -> str:
    pg = rule.findtext("profile-setting/group/member")
    if pg:
        return pg
    if rule.find("profile-setting/profiles") is not None:
        return "(custom)"
    return ""
