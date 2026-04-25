from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich.panel import Panel
from rich import box
from ._helpers import iter_entries, scope_label, grep_row

PROFILE_TYPES = [
    ("virus", "Antivirus"),
    ("spyware", "Anti-Spyware"),
    ("vulnerability", "Vulnerability Protection"),
    ("url-filtering", "URL Filtering"),
    ("file-blocking", "File Blocking"),
    ("wildfire-analysis", "WildFire Analysis"),
    ("data-filtering", "Data Filtering"),
    ("dos-protection", "DoS Protection"),
]


def render_profiles(vsys_root: Element | None, shared_root: Element | None,
                    console, grep: str | None = None) -> None:
    any_found = False
    for xml_key, label in PROFILE_TYPES:
        rows = []
        for entry, scope in iter_entries(vsys_root, shared_root, f"profiles/{xml_key}"):
            name = entry.get("name", "")
            desc = entry.findtext("description") or ""
            summary = _summarize_profile(entry, xml_key)
            rows.append((scope, name, desc, summary))

        if not rows:
            continue

        rows.sort(key=lambda r: r[1].lower())
        table = Table(title=f"{label} Profiles", box=box.SIMPLE_HEAD,
                      show_lines=False, header_style="bold magenta")
        table.add_column("Name", style="bold")
        table.add_column("Scope", style="dim")
        table.add_column("Summary")
        table.add_column("Description", style="dim")

        added = 0
        for scope, name, desc, summary in rows:
            if grep_row(grep, name, desc, summary):
                table.add_row(name, scope_label(scope), summary, desc)
                added += 1

        if added:
            console.print(table)
            any_found = True

    if not any_found:
        console.print("[dim]No security profiles found.[/dim]")


def _summarize_profile(entry: Element, xml_key: str) -> str:
    if xml_key == "url-filtering":
        block = _count_categories(entry, "block/member")
        allow = _count_categories(entry, "allow/member")
        alert = _count_categories(entry, "alert/member")
        return f"block:{block} allow:{allow} alert:{alert}"
    if xml_key in ("virus", "spyware", "vulnerability"):
        rules = entry.findall("rules/entry") or entry.findall("botnet-domains") or []
        rule_count = len(entry.findall("rules/entry"))
        default_action = entry.findtext("default-action/action") or ""
        parts = []
        if rule_count:
            parts.append(f"{rule_count} rule(s)")
        if default_action:
            parts.append(f"default:{default_action}")
        return ", ".join(parts) if parts else ""
    if xml_key == "wildfire-analysis":
        rule_count = len(entry.findall("rules/entry"))
        return f"{rule_count} rule(s)" if rule_count else ""
    if xml_key == "file-blocking":
        rule_count = len(entry.findall("rules/entry"))
        return f"{rule_count} rule(s)" if rule_count else ""
    if xml_key == "dos-protection":
        flood = entry.find("flood")
        resource = entry.find("resource")
        parts = []
        if flood is not None:
            parts.append("flood-protection")
        if resource is not None:
            parts.append("resource-protection")
        return ", ".join(parts)
    return ""


def _count_categories(entry: Element, path: str) -> int:
    return len(entry.findall(path))
