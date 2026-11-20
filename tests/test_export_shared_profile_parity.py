"""Viewer/export parity regression guard for shared security profiles (#107 AC4).

The viewer (parsers/profiles.py::render_profiles) merges vsys + shared via
iter_entries for its PROFILE_TYPES; the export must carry every shared
profile the exporter family supports — no silent drops. The guard is keyed on
the UNION of exporter-supported types, not on render_profiles output alone:

- decryption and dns-security have NO shared-scope profile viewer
  (PROFILE_TYPES omits them; parsers/decryption.py renders only vsys
  decryption rules). Their parity is asserted against iter_entries — the
  same source render_profiles uses — and the viewer-side exclusion is pinned
  so the guard notices if the viewer ever adds them.
- data-filtering is viewer-only (no exporter) — no SCM equivalent at the
  pinned pan-scm-sdk. #111 closed the silent-dangling-reference half of the
  gap: profile-group data_filtering references are KEPT in the export for
  documentation and now emit a per-group migration warning. The profile
  exporter itself remains out of scope; its viewer presence is pinned so
  the exclusion stays a documented decision, not an accident.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.writer import build_export
from parsers._helpers import iter_entries
from parsers.profiles import PROFILE_TYPES, render_profiles
from export_fixtures import shared_root, vsys_root
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
# Exporter types with no shared-scope profile viewer (documented exclusion).
NO_VIEWER = {"decryption", "dns-security"}
# Viewer-only type with no exporter: no SCM equivalent at the pinned
# pan-scm-sdk. #111 chose the migration-warning path — profile-group
# data_filtering references are kept for documentation and warned about
# (tests/test_export_data_filtering_warning.py); no profile exporter exists.
VIEWER_ONLY = {"data-filtering"}


def test_guard_keys_cover_exporter_and_viewer_union():
    """Structural pin: if either side's type list drifts, this guard must be
    revisited — a guard keyed strictly on render_profiles would silently miss
    the NO_VIEWER exporters."""
    viewer_keys = {xml_key for xml_key, _ in PROFILE_TYPES}
    assert viewer_keys - VIEWER_ONLY == set(EXPORTER_TYPES) - NO_VIEWER
    assert not set(EXPORTER_TYPES) & VIEWER_ONLY
    assert NO_VIEWER <= set(EXPORTER_TYPES)


def test_shared_profiles_viewer_shows_are_exported():
    """Every shared profile name the viewer shows for a supported type is
    present in build_export's security_profiles; NO_VIEWER types are checked
    against iter_entries directly."""
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
            if xml_key not in NO_VIEWER:
                # Parity proper: the viewer shows it, so the export carries it.
                assert name in text

    # Documented viewer-side exclusions stay excluded (and stay exported).
    for xml_key in NO_VIEWER:
        assert f"Parity-{xml_key}" not in text
    # Viewer-only type: shown by the viewer, no exporter exists (#111 —
    # no SCM equivalent at the pinned SDK; the migration-warning path was
    # chosen instead of a 9th exporter).
    assert "Parity-data-filtering" in text
    assert "data_filtering" not in data["security_profiles"]
