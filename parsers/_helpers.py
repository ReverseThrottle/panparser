from __future__ import annotations
from xml.etree.ElementTree import Element


def find_first(root: Element | None, *paths: str) -> Element | None:
    """Return the first container that exists at any of `paths` under `root`.

    Selection is by presence (`is not None`), never by Element truth value:
    a present-but-empty primary container is SELECTED rather than falling
    through to a legacy fallback path (#91). Returns None when `root` is
    None or no path matches.
    """
    if root is None:
        return None
    for path in paths:
        el = root.find(path)
        if el is not None:
            return el
    return None


def iter_entries(vsys_root: Element | None, shared_root: Element | None,
                 path: str):
    """Yield (entry, scope) for all entries at `path` under vsys and shared."""
    if vsys_root is not None:
        container = vsys_root.find(path)
        if container is not None:
            for entry in container.findall("entry"):
                yield entry, "vsys"
    if shared_root is not None:
        container = shared_root.find(path)
        if container is not None:
            for entry in container.findall("entry"):
                yield entry, "shared"


def scope_label(scope: str) -> str:
    # Escape the opening bracket so Rich renders literal "[shared]" instead
    # of consuming it as an (unknown) style tag, which blanked the Scope
    # cell for shared rows in every section (#115). vsys stays "" — the
    # implicit default scope is intentionally unlabelled.
    return "[dim]\\[shared][/dim]" if scope == "shared" else ""


def get_members(el: Element, path: str) -> list[str]:
    return [m.text or "" for m in el.findall(path)]


def fmt_any(value: str) -> str:
    """Render 'any' in a distinct style."""
    if value.strip() == "any":
        return "[dim italic]any[/dim italic]"
    return value


def fmt_members(members: list[str]) -> str:
    """Join member list; return 'any' if the only member is 'any'."""
    if not members:
        return "any"
    return "\n".join(members)


def grep_row(grep: str | None, *values: str) -> bool:
    """Return True if grep is None or any value contains grep (case-insensitive)."""
    if grep is None:
        return True
    needle = grep.lower()
    return any(needle in v.lower() for v in values)
