"""Regression tests for CLI boundary errors (issue #81).

1. Unreadable config paths (a directory, a permission-denied file) must produce
   a clean one-line ``Error: ...`` on stderr and a non-zero exit — no traceback,
   mirroring the existing missing-file handling.
2. Early pipe close (``| head``, quitting ``less``) must exit 0 with no stderr
   noise, so the documented ``--no-color | less`` usage does not report failure
   under ``set -o pipefail`` when the consumer simply stops reading.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import panparser

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_config(path: Path, n_addresses: int = 1) -> Path:
    """Write a minimal running-config with ``n_addresses`` address objects."""
    entries = "\n".join(
        f'<entry name="host-{i:05d}">'
        f"<ip-netmask>10.{i // 256}.{i % 256}.1/32</ip-netmask></entry>"
        for i in range(n_addresses)
    )
    path.write_text(
        '<config version="10.2.0"><devices>'
        '<entry name="localhost.localdomain"><vsys>'
        f'<entry name="vsys1"><address>{entries}</address></entry>'
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


def test_directory_as_config_clean_error(tmp_path, capsys):
    """load_config exits non-zero with a one-line Error, not a traceback."""
    with pytest.raises(SystemExit) as exc:
        panparser.load_config(str(tmp_path))
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("Error:")
    assert str(tmp_path) in err
    assert len(err.splitlines()) == 1
    assert "Traceback" not in err


def test_directory_as_config_subprocess_no_traceback(tmp_path):
    proc = _run_cli(str(tmp_path), "--no-color")
    assert proc.returncode != 0
    stderr = proc.stderr.decode()
    assert stderr.startswith("Error:")
    assert len(stderr.splitlines()) == 1
    assert "Traceback" not in stderr


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root can read mode-000 files; PermissionError not reproducible",
)
def test_unreadable_config_clean_error(tmp_path, capsys):
    config = _write_config(tmp_path / "config.xml")
    config.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as exc:
            panparser.load_config(str(config))
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert err.startswith("Error:")
        assert len(err.splitlines()) == 1
        assert "Traceback" not in err
    finally:
        config.chmod(0o644)


def test_missing_file_message_unchanged(tmp_path, capsys):
    """The pre-existing missing-file diagnostic keeps its exact format."""
    missing = str(tmp_path / "does-not-exist.xml")
    with pytest.raises(SystemExit) as exc:
        panparser.load_config(missing)
    assert exc.value.code == 1
    assert capsys.readouterr().err == f"Error: file not found: {missing}\n"


def test_early_pipe_close_exits_zero(tmp_path):
    """Closing stdout mid-render (like `| head -1`) exits 0 with empty stderr.

    The config renders far more than a pipe buffer (~64 KiB), so the child is
    guaranteed to still be writing when the read end closes. Exit 0 means the
    documented usage passes under `set -o pipefail`; empty stderr rules out a
    traceback or an 'Exception ignored' shutdown-flush diagnostic (exit 120).
    """
    config = _write_config(tmp_path / "config.xml", n_addresses=3000)
    proc = subprocess.Popen(
        [sys.executable, "-m", "panparser", str(config),
         "-s", "addresses", "--no-color"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None and proc.stderr is not None
        assert proc.stdout.readline()  # first rendered line arrives
        proc.stdout.close()  # consumer stops reading early
        stderr = proc.stderr.read()
        assert proc.wait(timeout=60) == 0
        assert stderr == b""
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
