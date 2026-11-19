"""Field-asserting tests for export_wildfire_antivirus_profiles() — #92 backfill."""
from __future__ import annotations

from export.objects import export_wildfire_antivirus_profiles
from export_fixtures import vsys_root


def _profiles(inner: str) -> str:
    return f"<profiles><wildfire-analysis>{inner}</wildfire-analysis></profiles>"


class TestExportWildfireAntivirusProfiles:
    def test_none_root(self):
        assert export_wildfire_antivirus_profiles(None) == []

    def test_missing_container(self):
        assert export_wildfire_antivirus_profiles(vsys_root("<profiles><virus/></profiles>")) == []

    def test_full_rules(self):
        root = vsys_root(_profiles("""
        <entry name="wf-strict">
          <description>upload inspection</description>
          <rules>
            <entry name="pe-upload">
              <direction>upload</direction>
              <application><member>web-browsing</member></application>
              <file-type><member>pe</member><member>pdf</member></file-type>
              <analysis>public-cloud</analysis>
            </entry>
          </rules>
        </entry>
        """))
        assert export_wildfire_antivirus_profiles(root) == [{
            "name": "wf-strict",
            "rules": [{
                "name": "pe-upload",
                "direction": "upload",
                "application": ["web-browsing"],
                "file_type": ["pe", "pdf"],
                "analysis": "public-cloud",
            }],
            "description": "upload inspection",
        }]

    def test_rule_defaults(self):
        root = vsys_root(_profiles("""
        <entry name="wf-defaults"><rules><entry/></rules></entry>
        """))
        assert export_wildfire_antivirus_profiles(root) == [{
            "name": "wf-defaults",
            "rules": [{"name": "default", "direction": "both"}],
        }]

    def test_no_rules_synthesizes_scm_required_default(self):
        root = vsys_root(_profiles('<entry name="wf-empty"/>'))
        assert export_wildfire_antivirus_profiles(root) == [{
            "name": "wf-empty",
            "rules": [{"name": "default", "direction": "both",
                       "application": ["any"], "file_type": ["any"],
                       "analysis": "public-cloud"}],
        }]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-wf"/><entry name="a-wf"/>'))
        assert [p["name"] for p in export_wildfire_antivirus_profiles(root)] == ["a-wf", "Z-wf"]
