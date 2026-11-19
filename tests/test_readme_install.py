"""Regression tests for issues #71 and #77: README must agree with the repo.

The README's install instructions and Project Layout tree are a contract with
the repo root (#71): an editable install is only valid if packaging metadata
exists, the documented dependency install must reference a real requirements
file, and every root-level entry in the layout tree must actually exist.

Every `python3 -m <module>` invocation example is likewise a contract with
that module's entry point (#77): the module must exist, be runnable via -m
(a `__name__ == "__main__"` guard), and accept every long flag the example
shows. Checked statically via AST so the guard needs no runtime deps.

Extended for issue #82: the documented contributor testing recipe (SDK pin,
pytest command) must match CI, and the documented Python floor must be covered
by the CI matrix.
"""
import ast
import re
import sys
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


def _module_source(module: str) -> Path | None:
    """Repo-local source file for a dotted module name, if it exists."""
    rel = module.replace(".", "/")
    for candidate in (ROOT / f"{rel}.py", ROOT / rel / "__init__.py"):
        if candidate.exists():
            return candidate
    return None


def _long_flags_accepted(source: Path) -> set[str]:
    """Long options registered via parser.add_argument(...) — static AST read."""
    flags = set()
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and arg.value.startswith("--")
                ):
                    flags.add(arg.value)
    return flags


def _has_main_guard(source: Path) -> bool:
    """True if the module has an `if __name__ == "__main__":` block (-m runnable)."""
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            left = node.test.left
            if (
                isinstance(left, ast.Name)
                and left.id == "__name__"
                and any(
                    isinstance(c, ast.Constant) and c.value == "__main__"
                    for c in node.test.comparators
                )
            ):
                return True
    return False


def test_readme_module_examples_are_valid_entry_points():
    examples = re.findall(r"^python3 -m [\w.]+[^\n]*", README, re.MULTILINE)
    assert examples, "expected 'python3 -m <module>' examples in the README"
    for line in examples:
        module = line.split()[2]
        source = _module_source(module)
        if source is None:
            # Stdlib modules (e.g. `python3 -m venv`) have no repo parser to
            # check; existence is the whole contract for them.
            assert module.split(".")[0] in sys.stdlib_module_names, (
                f"README example {line!r} references module '{module}' which "
                "exists neither in the repo nor in the stdlib"
            )
            continue
        assert _has_main_guard(source), (
            f"README documents {line!r} but {source.name} has no "
            "'if __name__ == \"__main__\"' guard — `python3 -m {module}` would not run it"
        )
        # Left boundary excludes word chars/hyphens (not just non-whitespace)
        # so bracketed synopsis flags like `[--vsys VSYS]` are checked too.
        shown = set(re.findall(r"(?<![\w-])--[A-Za-z][\w-]*", line))
        accepted = _long_flags_accepted(source)
        unknown = shown - accepted
        assert not unknown, (
            f"README example {line!r} shows flag(s) {sorted(unknown)} that "
            f"{module}'s parser does not accept (accepts: {sorted(accepted)})"
        )
