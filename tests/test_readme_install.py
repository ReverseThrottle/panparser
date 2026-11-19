"""Regression tests for issue #71: README install path must agree with the repo.

The README's install instructions and Project Layout tree are a contract with
the repo root: an editable install is only valid if packaging metadata exists,
the documented dependency install must reference a real requirements file,
and every root-level entry in the layout tree must actually exist.

Extended for issue #82: the documented contributor testing recipe (SDK pin,
pytest command) must match CI, and the documented Python floor must be covered
by the CI matrix.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
TESTS_YML = ROOT / ".github" / "workflows" / "tests.yml"


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


def test_documented_test_recipe_matches_ci():
    """#82: the README's SDK pin and pytest command must match tests.yml."""
    ci = TESTS_YML.read_text(encoding="utf-8")
    ci_pin = re.search(r"pan-scm-sdk==([\w.]+)", ci)
    assert ci_pin, "tests.yml must install a pinned pan-scm-sdk"
    doc_pin = re.search(r"pan-scm-sdk==([\w.]+)", README)
    assert doc_pin, "README must document the pinned pan-scm-sdk install"
    assert doc_pin.group(1) == ci_pin.group(1), (
        f"README documents pan-scm-sdk=={doc_pin.group(1)} but tests.yml pins "
        f"pan-scm-sdk=={ci_pin.group(1)} — keep the pin in sync"
    )
    assert "python -m pytest tests/ -rs" in ci, "tests.yml must run pytest with -rs"
    assert "python -m pytest tests/ -rs" in README, (
        "README must document the same pytest command CI runs"
    )


def test_documented_python_floor_covered_by_ci_matrix():
    """#82: the README's 'Python X.Y+' floor must be a leg of the CI matrix."""
    floor = re.search(r"Python (\d+\.\d+)\+", README)
    assert floor, "README must state a minimum Python version"
    ci = TESTS_YML.read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]*)\]", ci)
    assert matrix, "tests.yml must run a python-version matrix guarding the floor"
    versions = re.findall(r"[\"'](\d+\.\d+)[\"']", matrix.group(1))
    assert floor.group(1) in versions, (
        f"README claims Python {floor.group(1)}+ but the CI matrix {versions} "
        f"does not test the floor"
    )
