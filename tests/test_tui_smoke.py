"""Headless TUI smoke tests (issue #80, AC2).

Drives tui.PanosViewerApp through Textual's App.run_test pilot — no display,
no terminal, CI-safe. The async pilot is wrapped in asyncio.run by
viewer_harness.run_app_test so these stay plain sync pytest functions (CI
installs pytest only, no pytest-asyncio).

Contract under test (tui.py at current main):
- compose(): Header, filter bar (#filter-input, #row-count), TabbedContent
  with one TabPane/DataTable per SECTIONS entry, #detail-bar, Footer.
- on_mount(): every section's data loaded and table populated up front.
- Tab activation switches the active section and updates the row count.
- Bindings: q quit, / focus_filter, r reset_filter, escape unfocus_filter.
- Input.Changed filters the active table against every raw cell.

The zones-tab empty-data defect (#89, one #9-class twin) is FIXED:
SECTIONS routes zones to the vsys root, guarded by
test_zones_tab_populated_from_vsys_root below.

Fixed by #90 (the other #9-class twin): the detail bar labels the RAW
getter row positionally — detail_keys is the getter's schema, not the
display order. The 8 vsys_shared object sections had authored
detail_keys in display order, so Name/Scope values came out swapped;
their key lists now follow the same raw-record contract as every other
section (cf. profiles, which lists Scope before Name). Pinned by the
alignment, width-invariant, and hidden-field tests below.

Focus model (verified against textual 8.x): the filter Input is auto-focused
on startup, so printable keys (including q/r//) are typed into it while it
has focus. The app bindings fire from table focus — press escape first.
"""

from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input, Static, TabbedContent, TabPane

import tui
from viewer_harness import roots_for, run_app_test, sample_roots


def _app_factory():
    vsys, shared, network = sample_roots()
    return tui.PanosViewerApp(vsys, shared, network, "sample_config.xml", "vsys1")


def test_app_composes_and_populates_every_section():
    async def body(app, pilot):
        await pilot.pause()
        # One tab pane + data table per registry entry, columns match.
        panes = app.query(TabPane)
        assert len(panes) == len(tui.SECTIONS) == 36
        for sec in tui.SECTIONS:
            dt = app.query_one(f"#dt-{sec['id']}", DataTable)
            assert len(dt.columns) == len(sec["columns"])
            # on_mount populated every table from the sample config
            assert dt.row_count == len(app._section_data[sec["id"]])
        # Default active section is the first registry entry (addresses).
        assert app._active_section_id == "addresses"
        # str() normalizes render(): textual 0.80 returns a rich Text, 8.x a
        # str — same style as the detail-bar assertions below (#101).
        assert str(app.query_one("#row-count", Static).render()) == "6 rows"
        assert "vsys1" in app.title
        # Textual auto-focuses the first focusable widget: the filter input.
        assert app.focused is app.query_one("#filter-input", Input)

    run_app_test(_app_factory, body)


def test_every_tab_activates_without_exception():
    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        for sec in tui.SECTIONS:
            tc.active = f"tab-{sec['id']}"
            await pilot.pause()
            assert app._active_section_id == sec["id"]
            dt = app.query_one(f"#dt-{sec['id']}", DataTable)
            n = len(app._section_data[sec["id"]])
            assert dt.row_count == n
            assert str(app.query_one("#row-count", Static).render()) == f"{n} rows"

    run_app_test(_app_factory, body)


def test_zones_tab_populated_from_vsys_root():
    """#89 regression guard: PAN-OS zones live under vsys, not the device
    network root. The zones tab must list the selected vsys's zones on the
    populated fixture — a wrong-root wiring (roots="network") silently
    empties it, so assert real rows, not just "renders without exception".
    """

    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        tc.active = "tab-zones"
        await pilot.pause()
        dt = app.query_one("#dt-zones", DataTable)
        assert dt.row_count > 0
        assert str(app.query_one("#row-count", Static).render()) == f"{dt.row_count} rows"
        # Exact rows from the sample config's vsys1 (sorted by name).
        assert dt.row_count == 2
        assert [str(c) for c in dt.get_row_at(0)] == [
            "trust", "layer3", "ethernet1/1", "zpp-strict", "default",
        ]
        assert [str(c) for c in dt.get_row_at(1)] == [
            "untrust", "layer3", "ethernet1/2", "", "",
        ]

    run_app_test(_app_factory, body)


def test_profiles_tab_shows_decryption_and_dns_security():
    """#112: the Profiles tab lists decryption + dns-security from vsys AND
    shared with non-empty summaries, and the detail bar labels the RAW
    getter row in getter order (#90 contract: Profile Type, Scope, Name,
    Summary, Description — row_fn must stay aligned with detail_keys)."""

    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        tc.active = "tab-profiles"
        await pilot.pause()
        rows = app._section_data["profiles"]
        new_rows = [r for r in rows if r[0] in ("Decryption", "DNS Security")]
        assert {(r[0], r[1], r[2]) for r in new_rows} == {
            ("Decryption", "vsys", "decrypt-profile"),
            ("Decryption", "shared", "decrypt-shared"),
            ("DNS Security", "vsys", "dns-default"),
            ("DNS Security", "shared", "dns-shared"),
        }
        # Populated profiles must not render an empty summary.
        assert all(r[3] for r in new_rows)
        dt = app.query_one("#dt-profiles", DataTable)
        assert dt.row_count == len(rows)
        # Highlight the vsys decryption row; check display + detail-bar
        # alignment against the raw getter schema, independent of detail_keys.
        idx = next(i for i, r in enumerate(rows) if r[2] == "decrypt-profile")
        await pilot.press("escape")  # focus the profiles table
        for _ in range(idx):
            await pilot.press("down")
        await pilot.pause()
        raw = rows[idx]
        assert [str(c) for c in dt.get_row_at(idx)] == list(raw)
        detail = str(app.query_one("#detail-bar", Static).render())
        assert detail.startswith(
            "Profile Type: Decryption  |  Scope: vsys  |  Name: decrypt-profile"
        )
        assert f"Summary: {raw[3]}" in detail
        assert f"Description: {raw[4]}" in detail
        # A scope/type swap (the #90 bug class) must not pass silently.
        assert "Scope: Decryption" not in detail
        assert "Name: vsys" not in detail

    run_app_test(_app_factory, body)


def test_filter_binding_narrows_rows_and_r_resets():
    async def body(app, pilot):
        await pilot.pause()
        dt = app.query_one("#dt-addresses", DataTable)
        assert dt.row_count == 6

        # Bindings fire from table focus (the input auto-focuses on startup
        # and consumes printable keys while focused).
        await pilot.press("escape")
        assert app.focused is dt

        # "/" focuses the filter input without inserting a literal "/".
        await pilot.press("/")
        assert app.focused is app.query_one("#filter-input", Input)
        assert app.query_one("#filter-input", Input).value == ""

        # Typing filters the active table (matches any raw cell).
        await pilot.press(*"host-web")
        await pilot.pause()
        assert dt.row_count == 1
        assert str(app.query_one("#row-count", Static).render()) == "1/6 rows"

        # A needle matching nothing empties the table without raising.
        await pilot.press(*"zzz")
        await pilot.pause()
        assert dt.row_count == 0
        assert str(app.query_one("#row-count", Static).render()) == "0/6 rows"

        # "r" (from table focus) clears the filter and refocuses the input.
        await pilot.press("escape")
        await pilot.press("r")
        await pilot.pause()
        assert app.query_one("#filter-input", Input).value == ""
        assert dt.row_count == 6
        assert app.focused is app.query_one("#filter-input", Input)

        # escape moves focus back to the active data table.
        await pilot.press("escape")
        assert app.focused is dt

    run_app_test(_app_factory, body)


def test_filter_applies_to_active_tab_only():
    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        tc.active = "tab-security"
        await pilot.pause()
        await pilot.press("escape")  # focus the security table
        await pilot.press("/")
        await pilot.press(*"deny")
        await pilot.pause()
        sec_dt = app.query_one("#dt-security", DataTable)
        assert sec_dt.row_count == 1  # deny-all only
        assert str(app.query_one("#row-count", Static).render()) == "1/3 rows"
        # Other tabs keep their full row sets.
        assert app.query_one("#dt-addresses", DataTable).row_count == 6

    run_app_test(_app_factory, body)


def test_row_highlight_updates_detail_bar():
    async def body(app, pilot):
        await pilot.pause()
        await pilot.press("escape")  # focus the addresses table
        dt = app.query_one("#dt-addresses", DataTable)
        await pilot.press("down")
        await pilot.pause()
        detail = str(app.query_one("#detail-bar", Static).render())
        assert "Name:" in detail and "Scope:" in detail

    run_app_test(_app_factory, body)


def test_q_quits():
    async def body(app, pilot):
        await pilot.pause()
        assert app.is_running
        await pilot.press("escape")  # q is typed into the input while focused
        await pilot.press("q")
        await pilot.pause()
        # action_quit -> App.exit(): return code set, exit requested.
        assert app.return_code == 0

    run_app_test(_app_factory, body)


# The 8 vsys_shared object sections whose getters return (scope, name, ...)
# and whose row_fn swaps fields 0/1 for display. Covers both row_fn shapes:
# index-prefixed (addresses, tags, ...) and non-indexed (app-filters). (#90)
_SCOPE_NAME_SECTIONS = [
    "addresses", "addr-groups", "services", "svc-groups",
    "tags", "applications", "app-groups", "app-filters",
]


@pytest.mark.parametrize("section_id", _SCOPE_NAME_SECTIONS)
def test_detail_bar_labels_align_with_row_semantics(section_id):
    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        tc.active = f"tab-{section_id}"
        await pilot.pause()
        await pilot.press("escape")  # focus the section's table
        await pilot.press("down")    # highlight row 1 (e.g. host-web)
        await pilot.pause()
        # Oracle is the getter's documented (scope, name, ...) schema,
        # independent of detail_keys.
        scope, name = app._section_data[section_id][1][:2]
        detail = str(app.query_one("#detail-bar", Static).render())
        # The Name label must carry the object name, not the scope.
        assert f"Name: {name}" in detail
        assert f"Scope: {scope}" in detail
        assert f"Name: {scope}" not in detail
        # Raw-record order: detail_keys follows the getter, so Scope is
        # labeled first (same contract as profiles/gp-portals).
        assert detail.startswith(f"Scope: {scope}  |  Name: {name}")

    run_app_test(_app_factory, body)


def test_detail_keys_label_raw_rows_positionally():
    """#90 contract: detail_keys positionally labels the RAW getter row, so
    its width must equal the getter's row width for every section. Pins the
    single generic zip contract and catches future key/row drift."""
    vsys, shared, network = sample_roots()
    for sec in tui.SECTIONS:
        rows = tui.GETTERS[sec["getter"]](
            *roots_for(sec.get("roots", "vsys_shared"), vsys, shared, network)
        )
        for raw in rows:
            assert len(sec["detail_keys"]) == len(raw), sec["id"]


@pytest.mark.parametrize(
    "section_id, hidden_key, hidden_idx",
    [
        ("security", "Disabled", 2),
        ("nat", "Disabled", 2),
        ("dos", "Description", 10),
    ],
)
def test_detail_bar_keeps_hidden_fields_for_rule_sections(section_id, hidden_key, hidden_idx):
    """#90 AC3: rule sections whose detail_keys include fields the table
    hides (security/nat Disabled, dos Description) must keep labeling the
    full raw record — the fix must not regress them to a display-only zip."""
    async def body(app, pilot):
        await pilot.pause()
        tc = app.query_one(TabbedContent)
        tc.active = f"tab-{section_id}"
        await pilot.pause()
        await pilot.press("escape")
        await pilot.press("down")
        await pilot.pause()
        raw = app._section_data[section_id][1]
        detail = str(app.query_one("#detail-bar", Static).render())
        assert f"Name: {raw[1]}" in detail
        assert f"{hidden_key}: {raw[hidden_idx]}" in detail

    run_app_test(_app_factory, body)


def test_app_composes_on_empty_config():
    """All-None roots (empty/absent containers) must compose and render 0 rows."""

    def factory():
        return tui.PanosViewerApp(None, None, None, "empty.xml", "vsys1")

    async def body(app, pilot):
        await pilot.pause()
        for sec in tui.SECTIONS:
            dt = app.query_one(f"#dt-{sec['id']}", DataTable)
            assert dt.row_count == 0
        assert str(app.query_one("#row-count", Static).render()) == "0 rows"
        # Filter + tab switching still work with no data.
        tc = app.query_one(TabbedContent)
        tc.active = "tab-routing"
        await pilot.pause()
        await pilot.press("escape")
        await pilot.press("/")
        await pilot.press(*"anything")
        await pilot.pause()
        assert app.query_one("#dt-routing", DataTable).row_count == 0

    run_app_test(factory, body)
