"""Regression tests for issues #71 and #77: README must agree with the repo.

The README's install instructions and Project Layout tree are a contract with
the repo root (#71): an editable install is only valid if packaging metadata
exists, the documented dependency install must reference a real requirements
file, and every root-level entry in the layout tree must actually exist.

Every `python3 -m <module>` invocation example is likewise a contract with
that module's entry point (#77): the module must exist, be runnable via -m
(a `__name__ == "__main__"` guard), and accept every long flag the example
shows. Checked statically via AST so the guard needs no runtime deps.
"""
import ast
import re
import sys
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
        shown = set(re.findall(r"(?<!\S)--[A-Za-z][\w-]*", line))
        accepted = _long_flags_accepted(source)
        unknown = shown - accepted
        assert not unknown, (
            f"README example {line!r} shows flag(s) {sorted(unknown)} that "
            f"{module}'s parser does not accept (accepts: {sorted(accepted)})"
        )
