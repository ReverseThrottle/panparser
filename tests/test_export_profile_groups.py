"""Field-asserting tests for export_profile_groups() — issue #92 backfill.

Covers the PAN-OS → SCM field map, including the virus/wildfire-analysis
merge where first match wins.
"""
from __future__ import annotations

from export.objects import export_profile_groups
from export_fixtures import shared_root, vsys_root


class TestExportProfileGroups:
    def test_empty_roots(self):
        assert export_profile_groups(None, None) == []

    def test_full_field_map(self):
        root = vsys_root("""
        <profile-group>
          <entry name="full">
            <virus><member>av-1</member></virus>
            <spyware><member>as-1</member></spyware>
            <vulnerability><member>vp-1</member></vulnerability>
            <url-filtering><member>url-1</member></url-filtering>
            <file-blocking><member>fb-1</member></file-blocking>
            <dns-security><member>dns-1</member></dns-security>
            <data-filtering><member>df-1</member></data-filtering>
          </entry>
        </profile-group>""")
        assert export_profile_groups(root, None) == [{
            "name": "full",
            "virus_and_wildfire_analysis": ["av-1"],
            "spyware": ["as-1"],
            "vulnerability": ["vp-1"],
            "url_filtering": ["url-1"],
            "file_blocking": ["fb-1"],
            "dns_security": ["dns-1"],
            "data_filtering": ["df-1"],
        }]

    def test_virus_wins_merge_with_wildfire(self):
        root = vsys_root("""
        <profile-group>
          <entry name="merged">
            <virus><member>av-first</member></virus>
            <wildfire-analysis><member>wf-second</member></wildfire-analysis>
          </entry>
        </profile-group>""")
        assert export_profile_groups(root, None) == [
            {"name": "merged", "virus_and_wildfire_analysis": ["av-first"]},
        ]

    def test_wildfire_only_maps_to_merged_field(self):
        root = vsys_root("""
        <profile-group>
          <entry name="wf-only"><wildfire-analysis><member>wf-1</member></wildfire-analysis></entry>
          <entry name="empty"/>
        </profile-group>""")
        assert export_profile_groups(root, None) == [
            {"name": "empty"},
            {"name": "wf-only", "virus_and_wildfire_analysis": ["wf-1"]},
        ]

    def test_shared_merge_sorted(self):
        vsys = vsys_root('<profile-group><entry name="Z-group"/></profile-group>')
        shared = shared_root('<profile-group><entry name="a-group"><spyware><member>s</member></spyware></entry></profile-group>')
        assert export_profile_groups(vsys, shared) == [
            {"name": "a-group", "spyware": ["s"]},
            {"name": "Z-group"},
        ]
