"""Data Filtering migration warning for profile-group references — #111.

Profile groups may reference a Data Filtering profile, but Data Filtering
profiles are never exported (no SCM equivalent at the pinned
pan-scm-sdk==0.14.0). build_export() must warn per referencing group —
vsys OR shared scope — naming the group and the referenced profile, so
the dangling reference is never silent (the gap #107 deferred).

Keep-vs-drop pin (#111 AC2): export_profile_groups KEEPS the group's
``data_filtering`` reference for documentation only; the warning text
must state that choice accurately. Inline XML fragments follow the suite
convention (the repo gitignores *.xml).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import find_profile_groups_with_data_filtering
from export.writer import build_export
from export_fixtures import shared_root, vsys_root

PG_PATH_PREFIX = "objects/profile_groups/"


def _group_xml(name: str, inner: str = "") -> str:
    return f'<profile-group><entry name="{name}">{inner}</entry></profile-group>'


def _df_member(profile: str) -> str:
    return f"<data-filtering><member>{profile}</member></data-filtering>"


def _export(vsys_inner: str = "", shared_inner: str | None = None) -> dict:
    root = ET.fromstring("<config version='11.1.0'/>")
    return build_export(
        root,
        vsys_root(vsys_inner),
        shared_root(shared_inner) if shared_inner is not None else None,
        None,
        "df-warning.xml",
        "vsys1",
    )


def _pg_warnings(data: dict) -> list[dict]:
    return [
        w for w in data["migration_warnings"]
        if w["object_path"].startswith(PG_PATH_PREFIX)
    ]


def _df_warnings(data: dict) -> list[dict]:
    return [w for w in _pg_warnings(data) if "Data Filtering" in w["message"]]


def _df_message(group: str, profile: str) -> str:
    """The exact warning text — pins the keep-for-documentation choice."""
    return (
        f"Profile group '{group}' references Data Filtering "
        f"profile '{profile}'. Data Filtering profiles "
        "are not exported: the pinned pan-scm-sdk has no Data "
        "Filtering profile model (no SCM equivalent), so the "
        "referenced profile is not migrated. The group's "
        "'data_filtering' reference is kept in the export for "
        "documentation only; recreate the data-filtering settings "
        "manually after migration."
    )


class TestVsysOnly:
    def test_warning_names_group_and_profile(self):
        data = _export(_group_xml("g-vsys", _df_member("df-v")))
        warnings = _df_warnings(data)
        assert len(warnings) == 1
        w = warnings[0]
        assert w["severity"] == "warn"
        assert w["object_path"] == "objects/profile_groups/g-vsys"
        assert w["message"] == _df_message("g-vsys", "df-v")

    def test_export_keeps_data_filtering_reference(self):
        # Keep-vs-drop pin (#111 AC2): the reference stays in the artifact.
        data = _export(_group_xml("g-vsys", _df_member("df-v")))
        assert data["objects"]["profile_groups"] == [
            {"name": "g-vsys", "data_filtering": ["df-v"]},
        ]


class TestSharedOnly:
    def test_warning_names_group_and_profile(self):
        data = _export("", _group_xml("g-shared", _df_member("df-s")))
        warnings = _df_warnings(data)
        assert len(warnings) == 1
        w = warnings[0]
        assert w["severity"] == "warn"
        assert w["object_path"] == "objects/profile_groups/g-shared"
        assert w["message"] == _df_message("g-shared", "df-s")

    def test_export_keeps_data_filtering_reference(self):
        data = _export("", _group_xml("g-shared", _df_member("df-s")))
        assert data["objects"]["profile_groups"] == [
            {"name": "g-shared", "data_filtering": ["df-s"]},
        ]


class TestMixedScope:
    def test_one_warning_per_referencing_group_sorted(self):
        data = _export(
            _group_xml("b-vsys", _df_member("df-v"))
            + _group_xml("c-no-df", "<spyware><member>as-1</member></spyware>"),
            _group_xml("a-shared", _df_member("df-s")),
        )
        warnings = _df_warnings(data)
        assert len(warnings) == 2
        assert [w["object_path"] for w in warnings] == [
            "objects/profile_groups/a-shared",
            "objects/profile_groups/b-vsys",
        ]
        assert warnings[0]["message"] == _df_message("a-shared", "df-s")
        assert warnings[1]["message"] == _df_message("b-vsys", "df-v")
        # The group without a data-filtering reference adds no warning.
        assert len(_pg_warnings(data)) == 2

    def test_export_keeps_both_references(self):
        data = _export(
            _group_xml("b-vsys", _df_member("df-v")),
            _group_xml("a-shared", _df_member("df-s")),
        )
        assert data["objects"]["profile_groups"] == [
            {"name": "a-shared", "data_filtering": ["df-s"]},
            {"name": "b-vsys", "data_filtering": ["df-v"]},
        ]


class TestNoReferenceNoWarning:
    def test_group_without_data_filtering(self):
        data = _export(_group_xml(
            "plain",
            "<spyware><member>as-1</member></spyware>"
            "<virus><member>av-1</member></virus>",
        ))
        assert _pg_warnings(data) == []

    def test_empty_roots(self):
        assert _pg_warnings(_export()) == []


class TestExistingBehaviorUnchanged:
    FULL_GROUP = (
        "<virus><member>av-1</member></virus>"
        "<spyware><member>as-1</member></spyware>"
        "<vulnerability><member>vp-1</member></vulnerability>"
        "<url-filtering><member>url-1</member></url-filtering>"
        "<file-blocking><member>fb-1</member></file-blocking>"
        "<dns-security><member>dns-1</member></dns-security>"
        "<wildfire-analysis><member>wf-1</member></wildfire-analysis>"
        + _df_member("df-1")
    )

    def test_all_eight_field_mappings_unchanged(self):
        # Same full-map pin as tests/test_export_profile_groups.py, at the
        # build_export level: the other 7 mappings are untouched by #111.
        data = _export(_group_xml("full", self.FULL_GROUP))
        assert data["objects"]["profile_groups"] == [{
            "name": "full",
            "virus_and_wildfire_analysis": ["av-1"],
            "spyware": ["as-1"],
            "vulnerability": ["vp-1"],
            "url_filtering": ["url-1"],
            "file_blocking": ["fb-1"],
            "dns_security": ["dns-1"],
            "data_filtering": ["df-1"],
        }]

    def test_wildfire_drop_warning_unchanged_alongside_df_warning(self):
        data = _export(_group_xml("full", self.FULL_GROUP))
        warnings = _pg_warnings(data)
        assert len(warnings) == 2
        wildfire = [w for w in warnings if "WildFire Analysis" in w["message"]]
        assert len(wildfire) == 1
        assert wildfire[0]["severity"] == "warn"
        assert wildfire[0]["object_path"] == "objects/profile_groups/full"
        assert wildfire[0]["message"] == (
            "Profile group 'full' references Antivirus profile "
            "'av-1' and WildFire Analysis profile "
            "'wf-1'. SCM has one combined slot per group, so "
            "the group keeps only the 'av-1' reference; the "
            "'wf-1' reference is dropped from the group. "
            "A 'wf-1' profile defined in vsys or shared scope "
            "is still exported as a standalone WildFire and Antivirus profile."
        )
        assert _df_warnings(data)[0]["message"] == _df_message("full", "df-1")


class TestFinder:
    def test_merges_scopes_and_sorts(self):
        vsys = vsys_root(
            _group_xml("Z-group", _df_member("df-v"))
            + _group_xml("no-df", "<spyware><member>as</member></spyware>")
        )
        shared = shared_root(_group_xml("a-group", _df_member("df-s")))
        assert find_profile_groups_with_data_filtering(vsys, shared) == [
            {"name": "a-group", "data_filtering": "df-s"},
            {"name": "Z-group", "data_filtering": "df-v"},
        ]

    def test_empty_roots(self):
        assert find_profile_groups_with_data_filtering(None, None) == []
