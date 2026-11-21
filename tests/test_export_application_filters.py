"""Field-asserting tests for export_application_filters() — issue #92 backfill.

Shared-scope merge coverage added for #121: vsys + shared via iter_entries,
the #107 convention (same-name entries in both scopes are BOTH kept).
"""
from __future__ import annotations

from export.objects import export_application_filters
from export_fixtures import shared_root, vsys_root


class TestExportApplicationFilters:
    def test_none_root(self):
        assert export_application_filters(None) == []

    def test_missing_container(self):
        assert export_application_filters(vsys_root("<application/>")) == []

    def test_full_filter(self):
        root = vsys_root("""
        <application-filter>
          <entry name="risky-business">
            <category><member>business-systems</member><member>networking</member></category>
            <subcategory><member>erp</member></subcategory>
            <technology><member>client-server</member></technology>
            <risk><member>4</member><member>5</member></risk>
            <new-appid>yes</new-appid>
            <exclude><member>corp-erp</member></exclude>
          </entry>
        </application-filter>""")
        assert export_application_filters(root) == [{
            "name": "risky-business",
            "category": ["business-systems", "networking"],
            "subcategory": ["erp"],
            "technology": ["client-server"],
            "risk": [4, 5],
            "new_appid": True,
            "exclude": ["corp-erp"],
        }]

    def test_invalid_risk_members_skipped(self):
        root = vsys_root("""
        <application-filter>
          <entry name="mixed-risk"><risk><member>3</member><member>high</member><member>5</member></risk></entry>
        </application-filter>""")
        assert export_application_filters(root) == [{"name": "mixed-risk", "risk": [3, 5]}]

    def test_bare_entry_and_new_appid_no(self):
        root = vsys_root("""
        <application-filter>
          <entry name="bare"/>
          <entry name="old-appid"><new-appid>no</new-appid></entry>
        </application-filter>""")
        assert export_application_filters(root) == [
            {"name": "bare"},
            {"name": "old-appid"},
        ]

    def test_all_invalid_risks_omits_key(self):
        root = vsys_root("""
        <application-filter>
          <entry name="no-valid-risk"><risk><member>high</member></risk></entry>
        </application-filter>""")
        assert export_application_filters(root) == [{"name": "no-valid-risk"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root('<application-filter><entry name="Z-filter"/><entry name="a-filter"/></application-filter>')
        assert [f["name"] for f in export_application_filters(root)] == ["a-filter", "Z-filter"]

    def test_both_roots_none(self):
        assert export_application_filters(None, None) == []

    def test_shared_only(self):
        shared = shared_root(
            '<application-filter><entry name="s-filter">'
            '<category><member>networking</member></category>'
            '</entry></application-filter>')
        assert export_application_filters(None, shared) == [
            {"name": "s-filter", "category": ["networking"]},
        ]

    def test_vsys_and_shared_merged_sorted(self):
        vsys = vsys_root('<application-filter><entry name="Z-filter"/></application-filter>')
        shared = shared_root('<application-filter><entry name="a-filter"/></application-filter>')
        assert [f["name"] for f in export_application_filters(vsys, shared)] == ["a-filter", "Z-filter"]

    def test_same_name_both_scopes_kept_twice(self):
        """#107 convention: no dedupe — one entry per scope, vsys first."""
        vsys = vsys_root(
            '<application-filter><entry name="dup">'
            '<category><member>networking</member></category>'
            '</entry></application-filter>')
        shared = shared_root(
            '<application-filter><entry name="dup">'
            '<category><member>business-systems</member></category>'
            '</entry></application-filter>')
        out = export_application_filters(vsys, shared)
        assert [f["name"] for f in out] == ["dup", "dup"]
        assert [f["category"] for f in out] == [["networking"], ["business-systems"]]
