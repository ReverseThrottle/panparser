"""Shared-scope applications/filters export regression + parity guard (#121).

Before #121, export_custom_applications / export_application_filters read
vsys only while both viewers merge vsys + shared via iter_entries — so the
canonical sample's export dropped `app-shared` and `app-filter-shared` while
still exporting application groups that reference `app-shared`: dangling
member references on an SCM push. Same bug class as #107 (security profiles).

Guards here (issue #121 AC3/AC4):
- the canonical sample's export carries the shared entries;
- export ⊇ viewer rows for both families (name-list equality pins full
  parity including same-name-in-both-scopes multiplicity — both sides merge
  via iter_entries and sort case-insensitively by name);
- every exported application-group member resolves to an exported custom
  application, another exported group (nested groups), or a predefined
  application (built-ins are not custom objects and are never exported);
- the resolution guard has teeth: replaying the #121 drop (removing
  `app-shared` from the export) makes it flag both referencing groups.

Viewer output itself is untouched by #121 — the existing viewer suites
(test_data_getters / test_renderers / test_tui_smoke) pin it; the parity
assertions below additionally prove the export now matches what they show.
"""
from __future__ import annotations

import copy
import xml.etree.ElementTree as ET

from export.writer import build_export
from export_fixtures import shared_root, vsys_root
from parsers._data import get_application_filters, get_applications
from parsers.applications import render_application_filters, render_applications
from tests.sample_config import SAMPLE_CONFIG_XML
from viewer_harness import render_text, sample_roots

# PAN-OS predefined applications (web-browsing, ssl, dns, ...) are built into
# the firewall, not custom objects — the export intentionally never carries
# them, so group members naming them are exempt from the resolution guard.
# This is the documented built-in sample used by the fixtures (the same names
# tests/test_export_application_groups.py plants); the canonical sample's
# groups reference only custom applications.
PREDEFINED_APPLICATIONS = {"any", "dns", "ntp", "ssl", "web-browsing"}


def _sample_export() -> dict:
    vsys, shared, network = sample_roots()
    return build_export(
        ET.fromstring(SAMPLE_CONFIG_XML), vsys, shared, network,
        "sample.xml", "vsys1",
    )


def _dangling_members(data: dict) -> list[tuple[str, str]]:
    """(group, member) pairs whose member resolves to nothing exportable.

    A member resolves if it names an exported custom application, another
    exported application group (nested groups), or a predefined application.
    ``data`` is the full build_export dict; the families live under objects.
    """
    objects = data["objects"]
    app_names = {a["name"] for a in objects["custom_applications"]}
    group_names = {g["name"] for g in objects["application_groups"]}
    dangling = []
    for group in objects["application_groups"]:
        for member in group["members"]:
            if (member not in app_names
                    and member not in group_names
                    and member not in PREDEFINED_APPLICATIONS):
                dangling.append((group["name"], member))
    return dangling


def test_canonical_sample_shared_entries_exported():
    """AC3: the export carries the shared app + filter, not just vsys ones."""
    data = _sample_export()
    app_names = [a["name"] for a in data["objects"]["custom_applications"]]
    filter_names = [f["name"] for f in data["objects"]["application_filters"]]
    assert "app-shared" in app_names, "shared custom application dropped (#121)"
    assert "app-custom" in app_names
    assert "app-filter-shared" in filter_names, "shared application filter dropped (#121)"
    assert "app-filter-risky" in filter_names


def test_export_matches_viewer_rows():
    """AC3/AC4 parity: export name lists equal the merged viewer rows for
    both families — same scopes, same multiplicity, same sort order."""
    vsys, shared, _ = sample_roots()
    data = _sample_export()
    assert [a["name"] for a in data["objects"]["custom_applications"]] == [
        r[1] for r in get_applications(vsys, shared)
    ]
    assert [f["name"] for f in data["objects"]["application_filters"]] == [
        r[1] for r in get_application_filters(vsys, shared)
    ]
    # The rendered viewer surfaces show the shared entries too (unchanged by
    # #121) — the export now carries exactly what the user sees.
    assert "app-shared" in render_text(render_applications, vsys, shared)
    assert "app-filter-shared" in render_text(render_application_filters, vsys, shared)


def test_group_members_resolve_no_dangling_references():
    """AC3: every exported group member naming a custom application resolves
    to a custom_applications entry — the #121 dangling-reference shape."""
    data = _sample_export()
    assert _dangling_members(data) == []
    # Pin the concrete cross-scope reference the bug dangled: app-grp-custom
    # (vsys) references app-shared (shared scope).
    grp = next(g for g in data["objects"]["application_groups"] if g["name"] == "app-grp-custom")
    assert "app-shared" in grp["members"]
    assert "app-shared" in {a["name"] for a in data["objects"]["custom_applications"]}


def test_predefined_members_are_exempt():
    """Group members naming predefined built-ins resolve by exception —
    they are not custom objects and are never exported."""
    vsys = vsys_root(
        '<application><entry name="corp-app"/></application>'
        '<application-group><entry name="web-apps">'
        '<members><member>ssl</member><member>web-browsing</member>'
        '<member>corp-app</member></members>'
        '</entry></application-group>')
    data = build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        vsys, shared_root(""), None, "fixture.xml", "vsys1",
    )
    assert _dangling_members(data) == []


def test_guard_flags_the_121_drop():
    """Sabotage teeth: replaying the pre-#121 export (shared app dropped)
    makes the guard flag BOTH groups that reference app-shared."""
    data = _sample_export()
    dropped = copy.deepcopy(data)
    dropped["objects"]["custom_applications"] = [
        a for a in dropped["objects"]["custom_applications"] if a["name"] != "app-shared"
    ]
    assert _dangling_members(dropped) == [
        ("app-grp-custom", "app-shared"),
        ("app-grp-shared", "app-shared"),
    ]
