"""Field-asserting tests for export_custom_applications() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_custom_applications
from export_fixtures import vsys_root


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
