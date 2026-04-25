from __future__ import annotations
from xml.etree.ElementTree import Element


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
    return "[dim][shared][/dim]" if scope == "shared" else ""


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
