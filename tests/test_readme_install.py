"""Regression tests for issue #71: README install path must agree with the repo.

The README's install instructions and Project Layout tree are a contract with
the repo root: an editable install is only valid if packaging metadata exists,
the documented dependency install must reference a real requirements file,
and every root-level entry in the layout tree must actually exist.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_install_instructions_match_repo():
    if "pip install -e ." in README:
        assert any(
            (ROOT / name).exists()
            for name in ("pyproject.toml", "setup.py", "setup.cfg")
        ), "README documents 'pip install -e .' but the repo has no packaging metadata"
    assert "pip install -r requirements.txt" in README, (
        "README must install runtime deps via requirements.txt"
    )
    assert (ROOT / "requirements.txt").exists()


def test_project_layout_root_entries_exist():
    block = README.split("## Project Layout", 1)[1].split("```")[1]
    entries = []
    for line in block.splitlines():
        # Depth-1 tree entries only (nested lines start with '│').
        if line.startswith(("├── ", "└── ")):
            name = line[4:].split("#", 1)[0].strip().rstrip("/")
            if name and name != "…":
                entries.append(name)
    assert entries, "expected root-level entries in the Project Layout tree"
    for name in entries:
        assert (ROOT / name).exists(), (
            f"README Project Layout lists '{name}' but it does not exist in the repo root"
        )
