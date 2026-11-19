"""Field-asserting tests for export_application_filters() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_application_filters
from export_fixtures import vsys_root


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
