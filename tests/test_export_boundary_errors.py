"""Regression tests for the export output boundary (issue #99).

An unwritable ``--output`` destination (missing parent directory, a directory,
a permission-denied file) must produce a clean one-line ``Error: ...`` on
stderr and exit 1 — no raw traceback — mirroring the input-side boundary that
issue #81 gave ``load_config``. A directory is never an overwriteable file, so
it must be a clean error both WITH and WITHOUT ``--force``; the pre-write
exists-check must not advise ``--force`` for a directory.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_config(path: Path) -> Path:
    """Write a minimal running-config with one address object."""
    path.write_text(
        '<config version="10.2.0"><devices>'
        '<entry name="localhost.localdomain"><vsys>'
        '<entry name="vsys1"><address>'
        '<entry name="host-00000"><ip-netmask>10.0.0.1/32</ip-netmask></entry>'
        "</address></entry>"
        "</vsys></entry></devices></config>"
    )
    return path


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "panparser", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        timeout=60,
    )


def _assert_clean_boundary_error(proc: subprocess.CompletedProcess) -> str:
    """Assert exit 1 + a single-line ``Error:`` on stderr, no traceback."""
    stderr = proc.stderr.decode()
    assert proc.returncode == 1, stderr
    assert stderr.startswith("Error:"), stderr
    assert len(stderr.splitlines()) == 1, stderr
    assert "Traceback" not in stderr, stderr
    return stderr


def test_nonexistent_parent_dir_clean_error(tmp_path):
    """--output under a missing parent dir → clean error, not FileNotFoundError."""
    config = _write_config(tmp_path / "config.xml")
    target = tmp_path / "no-such-dir" / "out.json"
    proc = _run_cli(str(config), "--output", str(target))
    stderr = _assert_clean_boundary_error(proc)
    assert "cannot write export file" in stderr


def test_directory_as_output_with_force_clean_error(tmp_path):
    """A directory as --output is a clean error even WITH --force."""
    config = _write_config(tmp_path / "config.xml")
    directory = tmp_path / "somedir"
    directory.mkdir()
    proc = _run_cli(str(config), "--output", str(directory), "--force")
    stderr = _assert_clean_boundary_error(proc)
    assert "cannot write export file" in stderr


def test_directory_as_output_without_force_clean_error(tmp_path):
    """A directory as --output is a clean error WITHOUT --force too, and the
    exists-check must not advise --force (a directory is not overwriteable)."""
    config = _write_config(tmp_path / "config.xml")
    directory = tmp_path / "somedir"
    directory.mkdir()
    proc = _run_cli(str(config), "--output", str(directory))
    stderr = _assert_clean_boundary_error(proc)
    assert "cannot write export file" in stderr
    assert "--force" not in stderr


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root can write mode-444 files; PermissionError not reproducible",
)
def test_permission_denied_output_clean_error(tmp_path):
    """Forcing overwrite of a read-only file → clean PermissionError, not a
    traceback."""
    config = _write_config(tmp_path / "config.xml")
    target = tmp_path / "readonly.json"
    target.write_text("{}")
    target.chmod(0o444)
    try:
        proc = _run_cli(str(config), "--output", str(target), "--force")
        stderr = _assert_clean_boundary_error(proc)
        assert "cannot write export file" in stderr
    finally:
        target.chmod(0o644)


def test_writable_output_still_succeeds(tmp_path):
    """Happy path unchanged: a writable --output exits 0 and writes JSON."""
    config = _write_config(tmp_path / "config.xml")
    target = tmp_path / "out.json"
    proc = _run_cli(str(config), "--output", str(target))
    assert proc.returncode == 0, proc.stderr.decode()
    assert target.exists()
    assert target.read_text().lstrip().startswith("{")
