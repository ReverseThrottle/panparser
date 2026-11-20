"""Viewer/export parity regression guard for shared security profiles (#107 AC4).

The viewer (parsers/profiles.py::render_profiles) merges vsys + shared via
iter_entries for its PROFILE_TYPES; the export must carry every shared
profile the exporter family supports — no silent drops. The guard is keyed on
the UNION of exporter-supported types, not on render_profiles output alone.

Since #112 every profiles/-keyed exporter type (including decryption and
dns-security) has a shared-scope profile viewer, so parity is asserted
directly against the rendered output for all of them.

- data-filtering is viewer-only (no exporter) — a pre-existing separate gap,
  explicitly out of #107 scope. Its presence in the viewer is pinned so the
  exclusion stays a documented decision, not an accident.
- zone-protection IS exported, but from the NETWORK root
  (network/profiles/zone-protection-profile), not profiles/ — and it has its
  own dedicated viewer surfaces (render_zone_protection / get_zone_protection,
  TUI "zone-protection" section). It is intentionally outside this
  profiles/-keyed matrix; NETWORK_ROOT_ONLY pins that exclusion and
  test_zone_protection_exclusion_is_backed_by_network_path proves the
  alternative export + viewer paths actually carry it (#112 guard hygiene).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.writer import build_export
from export.objects import export_zone_protection_profiles
from parsers._data import get_zone_protection
from parsers._helpers import iter_entries
from parsers.profiles import PROFILE_TYPES, render_profiles
from parsers.zone_protection import render_zone_protection
from export_fixtures import network_root, shared_root, vsys_root
from viewer_harness import render_text

# XML path key -> security_profiles export key, for all 8 exporter types
# (virus and wildfire-analysis share SCM's combined profile type).
EXPORTER_TYPES = {
    "virus": "wildfire_antivirus",
    "wildfire-analysis": "wildfire_antivirus",
    "spyware": "anti_spyware",
    "vulnerability": "vulnerability_protection",
    "url-filtering": "url_access",
    "decryption": "decryption",
    "dns-security": "dns_security",
    "file-blocking": "file_blocking",
    "dos-protection": "dos_protection",
}
# Viewer-only type with no exporter (out of #107 scope).
VIEWER_ONLY = {"data-filtering"}
# Exported from the network root with dedicated viewer surfaces — excluded
# from this profiles/-keyed matrix by design (see module docstring).
NETWORK_ROOT_ONLY = {"zone-protection"}


def test_guard_keys_cover_exporter_and_viewer_union():
    """Structural pin: if either side's type list drifts, this guard must be
    revisited — a guard keyed strictly on render_profiles would silently miss
    exporter types the viewer omits."""
    viewer_keys = {xml_key for xml_key, _ in PROFILE_TYPES}
    assert viewer_keys - VIEWER_ONLY == set(EXPORTER_TYPES)
    assert not set(EXPORTER_TYPES) & VIEWER_ONLY
    # The network-root exclusion must stay disjoint from both sides of the
    # profiles/ matrix — if zone-protection ever moves into profiles/, this
    # pin forces the guard to be revisited instead of silently missing it.
    assert not NETWORK_ROOT_ONLY & (set(EXPORTER_TYPES) | viewer_keys)


def test_zone_protection_exclusion_is_backed_by_network_path():
    """The documented zone-protection exclusion is only honest if the
    alternative paths really carry it: the network-root exporter exports it
    and the dedicated viewer surfaces (CLI renderer + TUI getter) show it."""
    net = network_root(
        "<profiles><zone-protection-profile>"
        '<entry name="Parity-zpp"><flood><tcp-syn/></flood></entry>'
        "</zone-protection-profile></profiles>"
    )
    assert [p["name"] for p in export_zone_protection_profiles(net)] == ["Parity-zpp"]
    assert [r[0] for r in get_zone_protection(net)] == ["Parity-zpp"]
    assert "Parity-zpp" in render_text(render_zone_protection, net)


def test_shared_profiles_viewer_shows_are_exported():
    """Every shared profile name the viewer shows for a supported type is
    present in build_export's security_profiles — for ALL exporter types,
    since #112 gave decryption and dns-security their viewer entries."""
    xml_keys = [*EXPORTER_TYPES, *VIEWER_ONLY]
    shared_xml = "<profiles>" + "".join(
        f'<{key}><entry name="Parity-{key}"/></{key}>' for key in xml_keys
    ) + "</profiles>"
    vsys = vsys_root("")
    shared = shared_root(shared_xml)
    data = build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        vsys, shared, None, "fixture.xml", "vsys1",
    )
    text = render_text(render_profiles, vsys, shared)

    for xml_key, export_key in EXPORTER_TYPES.items():
        expected = [
            e.get("name", "")
            for e, _ in iter_entries(None, shared, f"profiles/{xml_key}")
        ]
        assert expected, f"fixture must plant a shared {xml_key} profile"
        exported = [p["name"] for p in data["security_profiles"][export_key]]
        for name in expected:
            assert name in exported, (
                f"shared {xml_key} profile '{name}' silently dropped by export"
            )
            # Parity proper: the viewer shows it, so the export carries it.
            assert name in text, (
                f"shared {xml_key} profile '{name}' exported but not shown "
                f"by the viewer"
            )

    # Viewer-only type: shown by the viewer, no exporter exists (#107 scope
    # boundary — the data-filtering export gap is a separate issue).
    assert "Parity-data-filtering" in text
