"""Field-asserting tests for export_tags() — issue #92 coverage backfill."""
from __future__ import annotations

from export.objects import export_tags
from export_fixtures import shared_root, vsys_root


class TestExportTags:
    def test_empty_roots(self):
        assert export_tags(None, None) == []

    def test_populated_fields_and_omissions(self):
        root = vsys_root("""
        <tag>
          <entry name="prod"><color>color1</color><comments>production</comments></entry>
          <entry name="plain"/>
          <entry name="weird"><color>color99</color></entry>
        </tag>""")
        assert export_tags(root, None) == [
            {"name": "plain"},
            {"name": "prod", "color": "Red", "comments": "production"},
            {"name": "weird"},  # unknown color token → no color key
        ]

    def test_color_token_mapping(self):
        for token, scm_color in (("color5", "Blue"), ("color14", "Cobalt Blue"),
                                 ("color17", "Gray")):
            root = vsys_root(f'<tag><entry name="t"><color>{token}</color></entry></tag>')
            assert export_tags(root, None) == [{"name": "t", "color": scm_color}]

    def test_vsys_and_shared_merge_sorted_case_insensitive(self):
        vsys = vsys_root('<tag><entry name="Zebra"><color>color2</color></entry></tag>')
        shared = shared_root(
            '<tag><entry name="apple"><color>color3</color><comments>shared</comments></entry></tag>')
        assert export_tags(vsys, shared) == [
            {"name": "apple", "color": "Yellow", "comments": "shared"},
            {"name": "Zebra", "color": "Orange"},
        ]
