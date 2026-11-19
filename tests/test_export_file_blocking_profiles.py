"""Field-asserting tests for export_file_blocking_profiles() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_file_blocking_profiles
from export_fixtures import vsys_root


def _profiles(inner: str) -> str:
    return f"<profiles><file-blocking>{inner}</file-blocking></profiles>"


class TestExportFileBlockingProfiles:
    def test_none_root(self):
        assert export_file_blocking_profiles(None) == []

    def test_missing_container(self):
        assert export_file_blocking_profiles(vsys_root("<profiles><virus/></profiles>")) == []

    def test_full_rules(self):
        root = vsys_root(_profiles("""
        <entry name="block-executables">
          <description>no PE downloads</description>
          <rules>
            <entry name="pe-block">
              <application><member>web-browsing</member><member>ftp</member></application>
              <file-type><member>pe</member><member>elf</member></file-type>
              <direction>download</direction>
              <action>block</action>
            </entry>
          </rules>
        </entry>
        """))
        assert export_file_blocking_profiles(root) == [{
            "name": "block-executables",
            "description": "no PE downloads",
            "rules": [{
                "name": "pe-block",
                "application": ["web-browsing", "ftp"],
                "file_type": ["pe", "elf"],
                "direction": "download",
                "action": "block",
            }],
        }]

    def test_rule_defaults(self):
        root = vsys_root(_profiles('<entry name="defaults"><rules><entry name="r"/></rules></entry>'))
        assert export_file_blocking_profiles(root) == [{
            "name": "defaults",
            "rules": [{"name": "r", "direction": "both", "action": "alert"}],
        }]

    def test_no_rules_omits_rules_key(self):
        root = vsys_root(_profiles('<entry name="empty"/>'))
        assert export_file_blocking_profiles(root) == [{"name": "empty"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-fb"/><entry name="a-fb"/>'))
        assert [p["name"] for p in export_file_blocking_profiles(root)] == ["a-fb", "Z-fb"]
