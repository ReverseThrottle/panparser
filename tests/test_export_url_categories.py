"""Field-asserting tests for export_url_categories() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_url_categories
from export_fixtures import shared_root, vsys_root


def _categories(inner: str) -> str:
    return f"<profiles><custom-url-category>{inner}</custom-url-category></profiles>"


class TestExportUrlCategories:
    def test_empty_roots(self):
        assert export_url_categories(None, None) == []

    def test_populated_fields_and_type_default(self):
        root = vsys_root(_categories("""
        <entry name="block-list">
          <description>bad sites</description>
          <type>URL List</type>
          <list><member>example.com</member><member>*.evil.test</member></list>
        </entry>
        <entry name="bare"><list><member>a.test</member></list></entry>
        """))
        assert export_url_categories(root, None) == [
            {"name": "bare", "type": "URL List", "list": ["a.test"]},
            {"name": "block-list", "type": "URL List",
             "list": ["example.com", "*.evil.test"], "description": "bad sites"},
        ]

    def test_explicit_type_and_empty_list(self):
        root = vsys_root(_categories("""
        <entry name="cat-match"><type>Category Match</type></entry>
        """))
        assert export_url_categories(root, None) == [
            {"name": "cat-match", "type": "Category Match", "list": []},
        ]

    def test_shared_merge_sorted(self):
        vsys = vsys_root(_categories('<entry name="z-local"><list><member>z.test</member></list></entry>'))
        shared = shared_root(_categories('<entry name="a-shared"/>'))
        assert export_url_categories(vsys, shared) == [
            {"name": "a-shared", "type": "URL List", "list": []},
            {"name": "z-local", "type": "URL List", "list": ["z.test"]},
        ]
