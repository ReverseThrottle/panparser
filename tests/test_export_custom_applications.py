"""Field-asserting tests for export_custom_applications() — issue #92 backfill.

Shared-scope merge coverage added for #121: vsys + shared via iter_entries,
the #107 convention (same-name entries in both scopes are BOTH kept).
"""
from __future__ import annotations

from export.objects import export_custom_applications
from export_fixtures import shared_root, vsys_root


class TestExportCustomApplications:
    def test_none_root(self):
        assert export_custom_applications(None) == []

    def test_missing_container(self):
        assert export_custom_applications(vsys_root("<application-filter/>")) == []

    def test_full_application(self):
        root = vsys_root("""
        <application>
          <entry name="corp-erp">
            <category>business-systems</category>
            <subcategory>erp</subcategory>
            <technology>client-server</technology>
            <risk>5</risk>
            <description>internal ERP</description>
          </entry>
        </application>""")
        assert export_custom_applications(root) == [{
            "name": "corp-erp",
            "category": "business-systems",
            "subcategory": "erp",
            "technology": "client-server",
            "risk": 5,
            "description": "internal ERP",
        }]

    def test_defaults_for_bare_entry(self):
        root = vsys_root('<application><entry name="bare"/></application>')
        assert export_custom_applications(root) == [{
            "name": "bare",
            "category": "business-systems",
            "subcategory": "other",
            "technology": "client-server",
            "risk": 1,
        }]

    def test_invalid_risk_falls_back_to_one(self):
        root = vsys_root('<application><entry name="bad-risk"><risk>high</risk></entry></application>')
        assert export_custom_applications(root)[0]["risk"] == 1

    def test_sorted_case_insensitive(self):
        root = vsys_root('<application><entry name="Z-app"/><entry name="a-app"/></application>')
        assert [a["name"] for a in export_custom_applications(root)] == ["a-app", "Z-app"]

    def test_both_roots_none(self):
        assert export_custom_applications(None, None) == []

    def test_shared_only(self):
        shared = shared_root('<application><entry name="s-app"><risk>3</risk></entry></application>')
        assert export_custom_applications(None, shared) == [{
            "name": "s-app",
            "category": "business-systems",
            "subcategory": "other",
            "technology": "client-server",
            "risk": 3,
        }]

    def test_vsys_and_shared_merged_sorted(self):
        vsys = vsys_root('<application><entry name="Z-app"/></application>')
        shared = shared_root('<application><entry name="a-app"/></application>')
        assert [a["name"] for a in export_custom_applications(vsys, shared)] == ["a-app", "Z-app"]

    def test_same_name_both_scopes_kept_twice(self):
        """#107 convention: no dedupe — one entry per scope, vsys first."""
        vsys = vsys_root('<application><entry name="dup"><risk>2</risk></entry></application>')
        shared = shared_root('<application><entry name="dup"><risk>5</risk></entry></application>')
        out = export_custom_applications(vsys, shared)
        assert [a["name"] for a in out] == ["dup", "dup"]
        assert [a["risk"] for a in out] == [2, 5]
