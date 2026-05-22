"""Pure data extraction — no rendering. Returns plain Python tuples for the TUI."""
from __future__ import annotations
from xml.etree.ElementTree import Element
from ._helpers import iter_entries, get_members

from .addresses import _extract_addr
from .services import _extract_service
from .zones import _extract_zone_type
from .interfaces import _extract_iface_detail, _iface_sort_key, _get_first_ip
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
    container = vsys_root.find("rulebase/security/rules") or vsys_root.find("security/rules")
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
    container = vsys_root.find("rulebase/nat/rules") or vsys_root.find("nat/rules")
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
    # Ethernet and AE: named entries are direct children of the container
    for itype, label in (("ethernet", "ethernet"), ("aggregate-ethernet", "ae")):
        container = iface_root.find(itype)
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name", "")
            ip, mode, subs = _extract_iface_detail(entry)
            comment = entry.findtext("comment") or ""
            ip_or_mode = ip if ip else mode
            rows.append((name, label, ip_or_mode, "; ".join(subs), comment))

    # Loopback, tunnel, vlan: named entries are under <units/entry>;
    # bare parent may also carry IPs/management profile directly.
    for itype, label, bare_name in (
        ("loopback", "loopback", "loopback"),
        ("tunnel",   "tunnel",   "tunnel"),
        ("vlan",     "vlan",     "vlan"),
    ):
        container = iface_root.find(itype)
        if container is None:
            continue
        unit_names = {e.get("name", "") for e in container.findall("units/entry")}
        parent_ip = _get_first_ip(container)
        parent_mgmt = container.findtext("interface-management-profile")
        if (parent_ip or parent_mgmt) and f"{bare_name}.1" not in unit_names:
            rows.append((bare_name, label, parent_ip or "", "", ""))
        for entry in container.findall("units/entry"):
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


def get_dos_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, to_zone, src_addr, dst_addr, service, protection_type, action, log_setting, description)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("rulebase/dos/rules") or vsys_root.find("dos/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = ", ".join(get_members(rule, "from/zone/member"))
        to_zone = ", ".join(get_members(rule, "to/zone/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        service = ", ".join(get_members(rule, "service/member"))
        prot = rule.find("protection")
        if prot is not None:
            protection_type = "aggregate" if prot.find("aggregate") is not None else "classified"
        else:
            protection_type = ""
        action_el = rule.find("action")
        if action_el is not None:
            action = next((c.tag for c in action_el), "")
        else:
            action = ""
        log_setting = rule.findtext("log-setting") or ""
        description = rule.findtext("description") or ""
        rows.append((i, name, from_zone, to_zone, src_addr, dst_addr, service,
                     protection_type, action, log_setting, description))
    return rows


def get_certificates(shared_root) -> list[tuple]:
    """(name, common_name, issuer, not_valid_before, not_valid_after, ca, algorithm)"""
    rows = []
    if shared_root is None:
        return rows
    container = shared_root.find("certificate")
    if container is None:
        return rows
    for cert in container.findall("entry"):
        name = cert.get("name", "")
        common_name = cert.findtext("common-name") or ""
        issuer = cert.findtext("issuer") or ""
        not_before = cert.findtext("not-valid-before") or ""
        not_after = cert.findtext("not-valid-after") or ""
        ca = cert.findtext("ca") or "no"
        algorithm = cert.findtext("algorithm") or ""
        rows.append((name, common_name, issuer, not_before, not_after, ca, algorithm))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_auth_profiles(shared_root) -> list[tuple]:
    """(name, method, mfa_enabled, allow_list, user_domain)"""
    rows = []
    if shared_root is None:
        return rows
    container = shared_root.find("authentication-profile")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        method_el = entry.find("method")
        if method_el is not None:
            method = next((c.tag for c in method_el), "")
        else:
            method = ""
        mfa_enabled = entry.findtext("multi-factor-auth/mfa-enable") or "no"
        allow_list = ", ".join(get_members(entry, "allow-list/member"))
        user_domain = entry.findtext("user-domain") or ""
        rows.append((name, method, mfa_enabled, allow_list, user_domain))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_ssl_profiles(shared_root) -> list[tuple]:
    """(name, certificate, min_version, max_version)"""
    rows = []
    if shared_root is None:
        return rows
    container = shared_root.find("ssl-tls-service-profile")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        certificate = entry.findtext("certificate") or ""
        min_ver = entry.findtext("protocol-settings/min-version") or ""
        max_ver = entry.findtext("protocol-settings/max-version") or ""
        rows.append((name, certificate, min_ver, max_ver))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_zone_protection(network_root) -> list[tuple]:
    """(name, flood_protections, discard_ip_spoof, discard_ip_frag, strict_ip_check)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("profiles/zone-protection-profile")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        flood_el = entry.find("flood")
        flood_types = ", ".join(c.tag for c in flood_el) if flood_el is not None else ""
        discard_spoof = entry.findtext("discard-ip-spoof") or "no"
        discard_frag = entry.findtext("discard-ip-frag") or "no"
        strict_ip = entry.findtext("strict-ip-check") or "no"
        rows.append((name, flood_types, discard_spoof, discard_frag, strict_ip))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_gp_gateways(vsys_root) -> list[tuple]:
    """(name, ssl_profile, tunnel_mode, tunnel_iface, client_auth_count)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("global-protect/global-protect-gateway")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        ssl_profile = entry.findtext("ssl-tls-service-profile") or ""
        tunnel_mode = entry.findtext("tunnel-mode") or "no"
        tunnel_iface = entry.findtext("remote-user-tunnel") or ""
        client_auth_count = len(entry.findall("client-auth/entry"))
        rows.append((name, ssl_profile, tunnel_mode, tunnel_iface, str(client_auth_count)))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_decryption_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, to_zone, src_addr, dst_addr, decrypt_type, profile, action, disabled)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("rulebase/decryption/rules") or vsys_root.find("decryption/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        from_zone = ", ".join(get_members(rule, "from/member"))
        to_zone = ", ".join(get_members(rule, "to/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        decrypt_type = rule.findtext("type") or ""
        profile = rule.findtext("profile") or ""
        action = rule.findtext("action") or ""
        rows.append((i, name, from_zone, to_zone, src_addr, dst_addr, decrypt_type, profile, action, disabled))
    return rows


def get_pbf_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, src_addr, dst_addr, app, service, action, egress_iface, nexthop)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("rulebase/pbf/rules") or vsys_root.find("pbf/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = ", ".join(get_members(rule, "from/zone/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        app = ", ".join(get_members(rule, "application/member"))
        service = ", ".join(get_members(rule, "service/member"))
        action_el = rule.find("action")
        if action_el is not None:
            action = next((c.tag for c in action_el), "")
            fwd = action_el.find("forward")
            egress_iface = fwd.findtext("egress-interface") if fwd is not None else ""
            nh_el = fwd.find("nexthop") if fwd is not None else None
            nexthop = next((c.text or "" for c in nh_el), "") if nh_el is not None else ""
        else:
            action = ""
            egress_iface = ""
            nexthop = ""
        rows.append((i, name, from_zone, src_addr, dst_addr, app, service, action,
                     egress_iface or "", nexthop or ""))
    return rows


def get_app_override_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, to_zone, src_addr, dst_addr, protocol, port, application, disabled)"""
    rows = []
    if vsys_root is None:
        return rows
    container = (vsys_root.find("rulebase/application-override/rules")
                 or vsys_root.find("application-override/rules"))
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        from_zone = ", ".join(get_members(rule, "from/member"))
        to_zone = ", ".join(get_members(rule, "to/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        protocol = rule.findtext("protocol") or ""
        port = rule.findtext("port") or ""
        application = rule.findtext("application") or ""
        rows.append((i, name, from_zone, to_zone, src_addr, dst_addr, protocol, port, application, disabled))
    return rows


def get_auth_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, to_zone, src_addr, dst_addr, src_user, service, auth_enforcement, log_setting, disabled)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("rulebase/authentication/rules") or vsys_root.find("authentication/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        from_zone = ", ".join(get_members(rule, "from/member"))
        to_zone = ", ".join(get_members(rule, "to/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        src_user = ", ".join(get_members(rule, "source-user/member"))
        service = ", ".join(get_members(rule, "service/member"))
        auth_enforcement = rule.findtext("authentication-enforcement") or ""
        log_setting = rule.findtext("log-setting") or ""
        rows.append((i, name, from_zone, to_zone, src_addr, dst_addr, src_user, service,
                     auth_enforcement, log_setting, disabled))
    return rows


def get_qos_rules(vsys_root) -> list[tuple]:
    """(num, name, from_zone, to_zone, src_addr, dst_addr, app, service, action_class, schedule)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("rulebase/qos/rules") or vsys_root.find("qos/rules")
    if container is None:
        return rows
    for i, rule in enumerate(container.findall("entry"), 1):
        name = rule.get("name", "")
        from_zone = ", ".join(get_members(rule, "from/member"))
        to_zone = ", ".join(get_members(rule, "to/member"))
        src_addr = ", ".join(get_members(rule, "source/member"))
        dst_addr = ", ".join(get_members(rule, "destination/member"))
        app = ", ".join(get_members(rule, "application/member"))
        service = ", ".join(get_members(rule, "service/member"))
        action_el = rule.find("action")
        if action_el is not None:
            action_class = rule.findtext("action/class") or next((c.tag for c in action_el), "")
        else:
            action_class = ""
        schedule = rule.findtext("schedule") or ""
        rows.append((i, name, from_zone, to_zone, src_addr, dst_addr, app, service, action_class, schedule))
    return rows


def get_url_categories(vsys_root) -> list[tuple]:
    """(name, url_type, member_count, description)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("profiles/custom-url-category")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        url_type = entry.findtext("type") or ""
        member_count = str(len(entry.findall("list/member")))
        description = entry.findtext("description") or ""
        rows.append((name, url_type, member_count, description))
    rows.sort(key=lambda r: r[0].lower())
    return rows


_SERVER_PROFILE_TYPES = ["ldap", "radius", "syslog", "snmptrap", "email", "http"]


def get_server_profiles(shared_root) -> list[tuple]:
    """(profile_type, name, server_count, details)"""
    rows = []
    if shared_root is None:
        return rows
    for ptype in _SERVER_PROFILE_TYPES:
        container = shared_root.find(f"server-profile/{ptype}")
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name", "")
            server_count = str(len(entry.findall("server/entry")))
            if ptype == "ldap":
                details = entry.findtext("base") or entry.findtext("ldap-type") or ""
            elif ptype == "radius":
                details = entry.findtext("server/entry/protocol") or ""
            else:
                details = entry.findtext("server/entry/address") or ""
            rows.append((ptype, name, server_count, details))
    return rows


def get_ike_gateways(network_root) -> list[tuple]:
    """(name, peer_ip, local_ip, local_iface, auth_type, ike_version, disabled)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("ike/gateway")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        peer_ip = entry.findtext("peer-address/ip") or ""
        local_ip = entry.findtext("local-address/ip") or ""
        local_iface = entry.findtext("local-address/interface") or ""
        auth_type = ("pre-shared-key"
                     if entry.find("authentication/pre-shared-key") is not None
                     else "certificate")
        ike_version = entry.findtext("protocol/version") or ""
        disabled = entry.findtext("disabled") == "yes"
        rows.append((name, peer_ip, local_ip, local_iface, auth_type, ike_version, disabled))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def _lifetime_str(entry) -> str:
    el = entry.find("lifetime")
    if el is None:
        return ""
    child = next(iter(el), None)
    return f"{child.text} {child.tag}" if child is not None else ""


def get_ike_crypto(network_root) -> list[tuple]:
    """(name, encryption, hash, dh_group, lifetime)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("ike/crypto-profiles/ike-crypto-profiles")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        encryption = ", ".join(get_members(entry, "encryption/member"))
        hash_ = ", ".join(get_members(entry, "hash/member"))
        dh_group = ", ".join(get_members(entry, "dh-group/member"))
        lifetime = _lifetime_str(entry)
        rows.append((name, encryption, hash_, dh_group, lifetime))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_ipsec_crypto(network_root) -> list[tuple]:
    """(name, esp_encryption, esp_auth, dh_group, lifetime)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("ike/crypto-profiles/ipsec-crypto-profiles")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        esp_encryption = ", ".join(get_members(entry, "esp/encryption/member"))
        esp_auth = ", ".join(get_members(entry, "esp/authentication/member"))
        dh_group = entry.findtext("dh-group") or ""
        lifetime = _lifetime_str(entry)
        rows.append((name, esp_encryption, esp_auth, dh_group, lifetime))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_ipsec_tunnels(network_root) -> list[tuple]:
    """(name, tunnel_iface, ike_gateway, ipsec_crypto_profile, tunnel_monitor_enabled)"""
    rows = []
    if network_root is None:
        return rows
    container = network_root.find("tunnel/ipsec")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        tunnel_iface = entry.findtext("tunnel-interface") or ""
        gw_entry = entry.find("auto-key/ike-gateway/entry")
        ike_gateway = gw_entry.get("name", "") if gw_entry is not None else ""
        ipsec_crypto = entry.findtext("auto-key/ipsec-crypto-profile") or ""
        monitor_enabled = "yes" if entry.find("tunnel-monitor") is not None else "no"
        rows.append((name, tunnel_iface, ike_gateway, ipsec_crypto, monitor_enabled))
    rows.sort(key=lambda r: r[0].lower())
    return rows


def get_bgp_peers(network_root) -> list[tuple]:
    """(vr_name, peer_group, peer_name, peer_as, local_ip, peer_ip, enabled)"""
    rows = []
    if network_root is None:
        return rows
    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        return rows
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        pg_container = vr.find("protocol/bgp/peer-group")
        if pg_container is None:
            continue
        for pg in pg_container.findall("entry"):
            pg_name = pg.get("name", "")
            peer_container = pg.find("peer")
            if peer_container is None:
                continue
            for peer in peer_container.findall("entry"):
                peer_name = peer.get("name", "")
                peer_as = peer.findtext("peer-as") or ""
                local_ip = peer.findtext("local-address/ip") or ""
                peer_ip = peer.findtext("peer-address/ip") or ""
                enabled = peer.findtext("enable") or "yes"
                rows.append((vr_name, pg_name, peer_name, peer_as, local_ip, peer_ip, enabled))
    return rows


def get_ospf_areas(network_root) -> list[tuple]:
    """(vr_name, area_id, interface, enabled, passive, metric, link_type)"""
    rows = []
    if network_root is None:
        return rows
    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        return rows
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        area_container = vr.find("protocol/ospf/area")
        if area_container is None:
            continue
        for area in area_container.findall("entry"):
            area_id = area.get("name", "")
            iface_container = area.find("interface")
            if iface_container is None:
                continue
            for iface in iface_container.findall("entry"):
                iface_name = iface.get("name", "")
                enabled = iface.findtext("enable") or "yes"
                passive = iface.findtext("passive") or "no"
                metric = iface.findtext("metric") or ""
                link_type = iface.findtext("link-type") or ""
                rows.append((vr_name, area_id, iface_name, enabled, passive, metric, link_type))
    return rows


def get_redist_profiles(network_root) -> list[tuple]:
    """(vr_name, name, action, filter_type, filter_value)"""
    rows = []
    if network_root is None:
        return rows
    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        return rows
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        rp_container = vr.find("protocol/redist-profile")
        if rp_container is None:
            continue
        for entry in rp_container.findall("entry"):
            name = entry.get("name", "")
            action = entry.findtext("action") or ""
            filter_el = entry.find("filter")
            if filter_el is not None:
                type_child = next(iter(filter_el), None)
                if type_child is not None:
                    filter_type = type_child.tag
                    val_child = next(iter(type_child), None)
                    filter_value = val_child.text if val_child is not None else (type_child.text or "")
                else:
                    filter_type = ""
                    filter_value = ""
            else:
                filter_type = ""
                filter_value = ""
            rows.append((vr_name, name, action, filter_type, filter_value or ""))
    return rows


def get_gp_portals(vsys_root) -> list[tuple]:
    """(name, local_address, client_auth_count, ssl_profile)"""
    rows = []
    if vsys_root is None:
        return rows
    container = vsys_root.find("global-protect/global-protect-portal")
    if container is None:
        return rows
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        local_addr = entry.findtext("portal-config/local-address/ip/ipv4") or ""
        ssl_profile = entry.findtext("portal-config/ssl-tls-service-profile") or ""
        client_auth_count = len(entry.findall("portal-config/client-auth/entry"))
        rows.append((name, local_addr, str(client_auth_count), ssl_profile))
    rows.sort(key=lambda r: r[0].lower())
    return rows


# ---------------------------------------------------------------------------
# Export getters — return plain dicts suitable for JSON serialization.
# These do NOT modify or replace the tuple-returning getters above.
# ---------------------------------------------------------------------------

def get_virtual_routers_export(network_root: Element | None) -> list[dict]:
    """Return VR configs as SCM-shaped dicts for JSON export.

    Each dict maps directly to the parameters expected by scm_create_logical_router,
    with routing config structured to fit inside a single VRF.

    Returns [] when network_root is None or no virtual-routers are found.
    """
    if network_root is None:
        return []
    vr_container = network_root.find("virtual-router")
    if vr_container is None:
        return []

    results = []
    for vr in vr_container.findall("entry"):
        vr_name = vr.get("name", "")
        notes: list[str] = []

        interfaces = get_members(vr, "interface/member")
        static_routes = _get_static_routes_export(vr, notes)
        bgp = _get_bgp_export(vr, notes)
        ospf = _get_ospf_export(vr, notes)
        ecmp = _get_ecmp_export(vr)

        results.append({
            "name": vr_name,
            "interfaces": interfaces,
            "static_routes": static_routes,
            "bgp": bgp,
            "ospf": ospf,
            "ecmp": ecmp,
            "_migration_notes": notes,
        })

    return results


def _get_static_routes_export(vr_entry: Element, notes: list[str]) -> list[dict]:
    """Extract static routes from a VR entry as SCM-shaped dicts."""
    routes = []
    sr_container = vr_entry.find("routing-table/ip/static-route")
    if sr_container is None:
        return routes

    for route in sr_container.findall("entry"):
        name = route.get("name", "")
        destination = route.findtext("destination") or ""
        interface = route.findtext("interface") or ""

        try:
            metric = int(route.findtext("metric") or 0) or None
        except ValueError:
            metric = None
        try:
            admin_dist = int(route.findtext("admin-dist") or 0) or None
        except ValueError:
            admin_dist = None

        nexthop_type, nexthop_value = _extract_nexthop_export(route)

        if nexthop_type == "next_vr":
            notes.append(
                f"static-route '{name}': next-vr '{nexthop_value}' mapped to "
                f"next_lr — verify logical router name exists in SCM"
            )

        entry: dict = {"name": name, "destination": destination}
        if interface:
            entry["interface"] = interface
        if metric is not None:
            entry["metric"] = metric
        if admin_dist is not None:
            entry["admin_dist"] = admin_dist
        if nexthop_type and nexthop_type != "none":
            entry["nexthop_type"] = nexthop_type
            if nexthop_value is not None:
                entry["nexthop_value"] = nexthop_value

        routes.append(entry)

    return routes


def _extract_nexthop_export(route: Element) -> tuple[str, str | None]:
    """Return (nexthop_type, nexthop_value) for a static route entry."""
    nh = route.find("nexthop")
    if nh is None:
        return "none", None
    ip = nh.findtext("ip-address")
    if ip:
        return "ip_address", ip
    if nh.find("discard") is not None:
        return "discard", None
    next_vr = nh.findtext("next-vr")
    if next_vr:
        return "next_vr", next_vr
    if nh.find("tunnel") is not None:
        return "tunnel", None
    return "none", None


def _get_bgp_export(vr_entry: Element, notes: list[str]) -> dict:
    """Extract BGP configuration from a VR entry as an SCM-shaped dict."""
    bgp_el = vr_entry.find("protocol/bgp")
    base: dict = {
        "enable": False,
        "router_id": "",
        "local_as": "",
        "install_route": False,
        "reject_default_route": False,
        "allow_redist_default_route": False,
        "peer_groups": [],
        "redist_rules": [],
        "redist_profiles": [],
    }
    if bgp_el is None:
        return base

    base["enable"] = bgp_el.findtext("enable") == "yes"
    base["router_id"] = bgp_el.findtext("router-id") or ""
    base["local_as"] = bgp_el.findtext("local-as") or ""
    base["install_route"] = bgp_el.findtext("install-route") == "yes"
    base["reject_default_route"] = bgp_el.findtext("reject-default-route") == "yes"
    base["allow_redist_default_route"] = (
        bgp_el.findtext("allow-redist-default-route") == "yes"
    )

    # Peer groups
    pg_container = bgp_el.find("peer-group")
    if pg_container is not None:
        for pg in pg_container.findall("entry"):
            pg_name = pg.get("name", "")
            type_el = pg.find("type")
            pg_type = next((c.tag for c in type_el), "ebgp") if type_el is not None else "ebgp"
            # Normalize hyphen variant from XML
            pg_type = pg_type.replace("-", "_")

            peers = []
            peer_container = pg.find("peer")
            if peer_container is not None:
                for peer in peer_container.findall("entry"):
                    peers.append({
                        "name": peer.get("name", ""),
                        "enable": peer.findtext("enable") != "no",
                        "peer_as": peer.findtext("peer-as") or "",
                        "peer_ip": peer.findtext("peer-address/ip") or "",
                        "local_ip": peer.findtext("local-address/ip") or "",
                        "local_interface": peer.findtext("local-address/interface") or "",
                        "max_prefixes": peer.findtext("max-prefixes") or "",
                        "reflector_client": peer.findtext("reflector-client") or "",
                    })

            base["peer_groups"].append({
                "name": pg_name,
                "enable": pg.findtext("enable") != "no",
                "type": pg_type,
                "aggregated_confed_as_path": (
                    pg.findtext("aggregated-confed-as-path") == "yes"
                ),
                "soft_reset_with_stored_info": (
                    pg.findtext("soft-reset-with-stored-info") == "yes"
                ),
                "peers": peers,
            })

    # BGP redistribution rules (redist-rules — maps to BgpRedistRule in SDK)
    rr_container = bgp_el.find("redist-rules")
    if rr_container is not None:
        for rr in rr_container.findall("entry"):
            base["redist_rules"].append({
                "name": rr.get("name", ""),
                "address_family_identifier": (
                    rr.findtext("address-family-identifier") or "ipv4"
                ),
                "route_table": rr.findtext("route-table") or "unicast",
                "enable": rr.findtext("enable") != "no",
                "set_origin": rr.findtext("set-origin") or "",
                "set_med": rr.findtext("set-med") or "",
                "metric": rr.findtext("metric") or "",
            })

    # VR-level redistribution profiles — must become separate SCM objects
    rp_container = vr_entry.find("protocol/redist-profile")
    if rp_container is not None:
        for rp in rp_container.findall("entry"):
            rp_name = rp.get("name", "")
            action_el = rp.find("action")
            action = (
                next((c.tag for c in action_el), "redist")
                if action_el is not None else "redist"
            )
            filter_el = rp.find("filter")
            filter_types = []
            filter_destinations = []
            if filter_el is not None:
                filter_types = get_members(filter_el, "type/member")
                filter_destinations = get_members(filter_el, "destination/member")

            base["redist_profiles"].append({
                "name": rp_name,
                "priority": int(rp.findtext("priority") or 0),
                "action": action,
                "filter_types": filter_types,
                "filter_destinations": filter_destinations,
            })
            notes.append(
                f"bgp redist-profile '{rp_name}': must be created as a separate "
                f"bgp_redistribution_profile object in SCM — cannot be migrated inline"
            )

    return base


def _get_ospf_export(vr_entry: Element, notes: list[str]) -> dict:
    """Extract OSPF configuration from a VR entry as an SCM-shaped dict."""
    ospf_el = vr_entry.find("protocol/ospf")
    base: dict = {
        "enable": False,
        "router_id": "",
        "reject_default_route": False,
        "allow_redist_default_route": False,
        "areas": [],
        "export_rules": [],
    }
    if ospf_el is None:
        return base

    base["enable"] = ospf_el.findtext("enable") == "yes"
    base["router_id"] = ospf_el.findtext("router-id") or ""
    base["reject_default_route"] = ospf_el.findtext("reject-default-route") == "yes"
    base["allow_redist_default_route"] = (
        ospf_el.findtext("allow-redist-default-route") == "yes"
    )

    # Areas
    area_container = ospf_el.find("area")
    if area_container is not None:
        for area in area_container.findall("entry"):
            area_id = area.get("name", "")
            type_el = area.find("type")
            area_type = (
                next((c.tag for c in type_el), "normal")
                if type_el is not None else "normal"
            )

            interfaces = []
            iface_container = area.find("interface")
            if iface_container is not None:
                for iface in iface_container.findall("entry"):
                    iface_name = iface.get("name", "")
                    link_type_el = iface.find("link-type")
                    link_type = (
                        next((c.tag for c in link_type_el), "broadcast")
                        if link_type_el is not None else "broadcast"
                    )
                    auth = iface.findtext("authentication") or ""
                    if auth:
                        notes.append(
                            f"ospf area '{area_id}' interface '{iface_name}': "
                            f"auth profile '{auth}' must be created as a separate "
                            f"ospf_auth_profile object in SCM"
                        )
                    entry: dict = {
                        "name": iface_name,
                        "enable": iface.findtext("enable") != "no",
                        "passive": iface.findtext("passive") == "yes",
                        "link_type": link_type,
                    }
                    metric_str = iface.findtext("metric")
                    if metric_str:
                        try:
                            entry["metric"] = int(metric_str)
                        except ValueError:
                            pass
                    if auth:
                        entry["authentication"] = auth
                    interfaces.append(entry)

            base["areas"].append({
                "id": area_id,
                "type": area_type,
                "interfaces": interfaces,
            })

    # Export rules
    er_container = ospf_el.find("export-rules")
    if er_container is not None:
        for er in er_container.findall("entry"):
            base["export_rules"].append({
                "name": er.get("name", ""),
                "new_path_type": er.findtext("new-path-type") or "",
                "metric": er.findtext("metric") or "",
            })

    return base


def _get_ecmp_export(vr_entry: Element) -> dict:
    """Extract ECMP configuration from a VR entry as an SCM-shaped dict."""
    base: dict = {"enable": False, "max_paths": None, "algorithm": "ip_modulo"}
    ecmp_el = vr_entry.find("ecmp")
    if ecmp_el is None:
        return base

    base["enable"] = ecmp_el.findtext("enable") != "no"
    max_path = ecmp_el.findtext("max-path")
    if max_path:
        try:
            base["max_paths"] = int(max_path)
        except ValueError:
            pass

    algo_el = ecmp_el.find("algorithm")
    if algo_el is not None:
        algo_child = next((c.tag for c in algo_el), None)
        if algo_child:
            # XML uses hyphens, we normalise to underscores for Python/JSON
            base["algorithm"] = algo_child.replace("-", "_")

    return base
