"""Regression tests for vsys selection (issue #78).

An unknown --vsys must error with the available vsys names instead of
silently falling back to the first vsys and mislabeling meta.vsys.
Covers find_roots(), the CLI (display + --output export), and the TUI
entry point, which shares find_roots().
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET

import pytest

import panparser
import tui
from panparser import VsysNotFoundError, find_roots

MULTI_VSYS_CONFIG = """
<config>
  <devices>
    <entry name="localhost.localdomain">
      <network/>
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="host-a1"><ip-netmask>10.1.0.1/32</ip-netmask></entry>
          </address>
        </entry>
        <entry name="vsys2">
          <address>
            <entry name="host-b2"><ip-netmask>10.2.0.2/32</ip-netmask></entry>
          </address>
        </entry>
      </vsys>
    </entry>
  </devices>
  <shared/>
</config>
"""


@pytest.fixture
def multi_vsys_config(tmp_path):
    path = tmp_path / "multi.xml"
    path.write_text(MULTI_VSYS_CONFIG, encoding="utf-8")
    return path


def _run_cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["panparser", *argv])
    panparser.main()


# ── find_roots() contract ─────────────────────────────────────────────────────


def test_find_roots_returns_requested_vsys_not_first():
    root = ET.fromstring(MULTI_VSYS_CONFIG)
    vsys_root, _, _ = find_roots(root, "vsys2", include_shared=True)
    assert vsys_root is not None
    assert vsys_root.get("name") == "vsys2"


def test_find_roots_valid_vsys1_unchanged():
    root = ET.fromstring(MULTI_VSYS_CONFIG)
    vsys_root, shared_root, _ = find_roots(root, "vsys1", include_shared=True)
    assert vsys_root is not None
    assert vsys_root.get("name") == "vsys1"
    assert shared_root is not None


def test_find_roots_absent_vsys_raises_with_available_names():
    root = ET.fromstring(MULTI_VSYS_CONFIG)
    with pytest.raises(VsysNotFoundError) as excinfo:
        find_roots(root, "vsys99", include_shared=True)
    assert excinfo.value.vsys_name == "vsys99"
    assert excinfo.value.available == ["vsys1", "vsys2"]
    assert str(excinfo.value) == "vsys 'vsys99' not found; available: vsys1, vsys2"


def test_find_roots_absent_vsys_raises_in_response_wrapper():
    root = ET.fromstring(
        f"<response><result>{MULTI_VSYS_CONFIG}</result></response>"
    )
    with pytest.raises(VsysNotFoundError):
        find_roots(root, "vsys99", include_shared=True)


def test_find_roots_empty_vsys_container_still_yields_none():
    # Boundary decision: an empty/absent vsys container is the existing
    # empty-state case, not a mislabeled export — behavior unchanged.
    root = ET.fromstring(
        '<config><devices><entry name="d"><vsys/></entry></devices></config>'
    )
    vsys_root, _, _ = find_roots(root, "vsys1", include_shared=True)
    assert vsys_root is None


def test_find_roots_no_vsys_container_still_yields_none():
    root = ET.fromstring('<config><devices><entry name="d"/></devices></config>')
    vsys_root, _, _ = find_roots(root, "vsys1", include_shared=True)
    assert vsys_root is None


# ── CLI: --output export ──────────────────────────────────────────────────────


def test_cli_export_vsys2_stamps_matching_meta_and_content(
    tmp_path, multi_vsys_config, monkeypatch
):
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, str(multi_vsys_config), "--vsys", "vsys2",
                 "--output", str(out))
    assert excinfo.value.code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["vsys"] == "vsys2"
    names = [a["name"] for a in data["objects"]["addresses"]]
    assert "host-b2" in names
    assert "host-a1" not in names


def test_cli_export_vsys1_stamps_matching_meta_and_content(
    tmp_path, multi_vsys_config, monkeypatch
):
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, str(multi_vsys_config), "--vsys", "vsys1",
                 "--output", str(out))
    assert excinfo.value.code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["vsys"] == "vsys1"
    names = [a["name"] for a in data["objects"]["addresses"]]
    assert "host-a1" in names
    assert "host-b2" not in names


def test_cli_export_absent_vsys_errors_and_writes_nothing(
    tmp_path, multi_vsys_config, monkeypatch, capsys
):
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, str(multi_vsys_config), "--vsys", "vsys99",
                 "--output", str(out))
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Error: vsys 'vsys99' not found; available: vsys1, vsys2" in err
    assert not out.exists()


# ── CLI: display path ─────────────────────────────────────────────────────────


def test_cli_display_absent_vsys_errors(multi_vsys_config, monkeypatch, capsys):
    with pytest.raises(SystemExit) as excinfo:
        _run_cli(monkeypatch, str(multi_vsys_config), "--vsys", "vsys99",
                 "--section", "addresses", "--no-color")
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Error: vsys 'vsys99' not found; available: vsys1, vsys2" in err


def test_cli_display_valid_vsys2_shows_vsys2_content(
    multi_vsys_config, monkeypatch, capsys
):
    _run_cli(monkeypatch, str(multi_vsys_config), "--vsys", "vsys2",
             "--section", "addresses", "--no-color")
    out = capsys.readouterr().out
    assert "host-b2" in out
    assert "host-a1" not in out


# ── TUI entry point (shared find_roots) ───────────────────────────────────────


def test_tui_absent_vsys_errors_before_app_starts(
    multi_vsys_config, monkeypatch, capsys
):
    class _MustNotStart:
        def __init__(self, *args, **kwargs):
            raise AssertionError("TUI app must not start for an absent vsys")

    monkeypatch.setattr(tui, "PanosViewerApp", _MustNotStart)
    monkeypatch.setattr(
        sys, "argv", ["tui", str(multi_vsys_config), "--vsys", "vsys99"]
    )
    with pytest.raises(SystemExit) as excinfo:
        tui.main()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "Error: vsys 'vsys99' not found; available: vsys1, vsys2" in err


def test_tui_valid_vsys2_passes_vsys2_root_to_app(multi_vsys_config, monkeypatch):
    captured = {}

    class _RecordingApp:
        def __init__(self, vsys_root, shared_root, network_root, config_path, vsys):
            captured["vsys_root"] = vsys_root
            captured["vsys"] = vsys

        def run(self):
            captured["ran"] = True

    monkeypatch.setattr(tui, "PanosViewerApp", _RecordingApp)
    monkeypatch.setattr(
        sys, "argv", ["tui", str(multi_vsys_config), "--vsys", "vsys2"]
    )
    tui.main()
    assert captured["ran"] is True
    assert captured["vsys"] == "vsys2"
    assert captured["vsys_root"].get("name") == "vsys2"
