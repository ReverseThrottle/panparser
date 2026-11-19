"""Field-asserting tests for export_application_groups() — issue #92 backfill.

The 25th sub-60% exporter flagged by triage (attack-the-premise): not in the
issue's named table but measured below 60% on the CI matrix, so it is covered
in the same pass with the same pattern rather than silently excluded.
"""
from __future__ import annotations

from export.objects import export_application_groups
from export_fixtures import shared_root, vsys_root


class TestExportApplicationGroups:
    def test_empty_roots(self):
        assert export_application_groups(None, None) == []

    def test_populated_members_and_empty_group(self):
        root = vsys_root("""
        <application-group>
          <entry name="web-apps">
            <members><member>ssl</member><member>web-browsing</member></members>
          </entry>
          <entry name="empty-group"/>
        </application-group>""")
        assert export_application_groups(root, None) == [
            {"name": "empty-group", "members": []},
            {"name": "web-apps", "members": ["ssl", "web-browsing"]},
        ]

    def test_shared_merge_sorted_case_insensitive(self):
        vsys = vsys_root('<application-group><entry name="Z-grp"><members><member>dns</member></members></entry></application-group>')
        shared = shared_root('<application-group><entry name="a-grp"><members><member>ntp</member></members></entry></application-group>')
        assert export_application_groups(vsys, shared) == [
            {"name": "a-grp", "members": ["ntp"]},
            {"name": "Z-grp", "members": ["dns"]},
        ]
