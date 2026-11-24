"""Panorama device-group scope resolution.

A device group's objects live in ``devices/entry/device-group/entry[@name=X]``
using the same relative paths a firewall vsys uses (``address``, ``service``,
``tag``, ``profiles/...``), so a device-group entry can stand in for
``vsys_root`` in every object parser. Policy lives under ``pre-rulebase`` /
``post-rulebase`` (not ``rulebase``) and is deliberately out of scope.

Panorama inheritance is flattened here into one synthetic root so no parser
changes are needed. Precedence, highest first: the named group, its parent,
the parent's parent ..., then ``<shared>``. A name defined at a higher level
shadows the same name at every lower level (it appears once in the result).
"""
from __future__ import annotations

import copy
from typing import NamedTuple
from xml.etree.ElementTree import Element, SubElement

# Containers the exporter reads (parser-relative top-level names). Anything
# else present in a device group is reported as not exported.
_EXPORTED_TAGS = frozenset({
    "address", "address-group", "tag", "service", "service-group",
    "application-group", "application", "application-filter", "schedule",
    "external-list", "profile-group", "profiles", "log-settings",
    "authentication-profile", "server-profile",
})

# Children of a device-group entry that are not object containers.
_NON_OBJECT_TAGS = frozenset({
    "devices", "parent-dg", "description", "id", "reference-templates",
    "pre-rulebase", "post-rulebase",
})


class DeviceGroupNotFoundError(Exception):
    """Requested device group does not exist (mirrors VsysNotFoundError)."""

    def __init__(self, name: str, available: list[str]):
        self.device_group = name
        self.available = available
        listing = ", ".join(available) if available else "(none: no device groups in this config)"
        super().__init__(f"device group '{name}' not found; available: {listing}")


class DeviceGroupScope(NamedTuple):
    root: Element          # synthetic object root (group + ancestors + shared)
    name: str
    chain: list[str]       # [name, parent, grandparent, ...] actually merged
    warnings: list[str]    # hierarchy problems (unknown parent, cycle, conflict)
    unexported: tuple | list = ()   # "Group/container" present but not exported
    include_ancestors: bool = True


def _merge(dst: Element, src: Element, top: bool) -> None:
    """Merge src's object containers into dst; entries already in dst win."""
    have = {e.get("name") for e in dst if e.tag == "entry"}
    for child in src:
        if top and child.tag in _NON_OBJECT_TAGS:
            continue
        if child.tag == "entry":
            if child.get("name") not in have:
                dst.append(copy.deepcopy(child))
                have.add(child.get("name"))
        elif len(child):
            sub = dst.find(child.tag)
            if sub is None:
                sub = SubElement(dst, child.tag)
            _merge(sub, child, False)
        elif dst.find(child.tag) is None:
            dst.append(copy.deepcopy(child))


def list_device_groups(config_root: Element) -> list[str]:
    dgs = _dg_container(config_root)
    return [e.get("name", "") for e in dgs] if dgs is not None else []


def _dg_container(config_root: Element) -> Element | None:
    device_entry = config_root.find("devices/entry")
    if device_entry is None:
        device_entry = config_root
    return device_entry.find("device-group")


def _parent_of(config_root: Element, dg: Element,
               warnings: list[str]) -> str | None:
    """Parent group name. <readonly> (Panorama's maintained hierarchy) wins
    over an inline <parent-dg>; a disagreement adds a warning."""
    inline = (dg.findtext("parent-dg") or "").strip() or None
    readonly = None
    for entry in config_root.findall(
        "readonly/devices/entry/device-group/entry"
    ):
        if entry.get("name") == dg.get("name"):
            readonly = (entry.findtext("parent-dg") or "").strip() or None
            break
    if inline and readonly and inline != readonly:
        warnings.append(
            f"Device group '{dg.get('name')}' has conflicting parents: inline "
            f"parent-dg '{inline}' vs readonly '{readonly}'; using the "
            f"readonly value '{readonly}'."
        )
    return readonly or inline


def resolve_device_group(config_root: Element, name: str,
                         shared_root: Element | None,
                         include_ancestors: bool = True) -> DeviceGroupScope:
    """Build the merged object root for device group ``name``.

    ``config_root`` must already be unwrapped from any API ``<response>``.
    Raises DeviceGroupNotFoundError for an unknown group. An unknown or
    cyclic ``parent-dg`` is not fatal: the chain stops there and a warning
    is returned. With ``include_ancestors=False`` only the named group (plus
    shared) is merged. The source tree is never modified or aliased.
    """
    container = _dg_container(config_root)
    groups = {e.get("name"): e for e in container} if container is not None else {}
    if name not in groups:
        raise DeviceGroupNotFoundError(name, list(
            e.get("name", "") for e in container) if container is not None else [])

    chain: list[str] = []
    warnings: list[str] = []
    unexported: list[str] = []
    merged = Element("entry", {"name": name})
    current: str | None = name
    while current is not None:
        if current in chain:
            warnings.append(
                f"Device group hierarchy cycle at '{current}'; ancestors "
                "above it were not included."
            )
            break
        dg = groups.get(current)
        if dg is None:
            warnings.append(
                f"Parent device group '{current}' (of '{chain[-1]}') was not "
                "found in the config; its objects (and its ancestors') were "
                "not included."
            )
            break
        chain.append(current)
        _merge(merged, dg, True)
        for child in dg:
            if child.tag not in _EXPORTED_TAGS and child.tag not in (
                "devices", "parent-dg", "description", "id",
                "reference-templates",
            ):
                unexported.append(f"{current}/{child.tag}")
        parent = _parent_of(config_root, dg, warnings)
        current = parent if include_ancestors else None
    if shared_root is not None:
        _merge(merged, shared_root, True)
    return DeviceGroupScope(merged, name, chain, warnings, unexported,
                            include_ancestors)
