from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members

ACTION_COLORS = {
    "allow": "green", "deny": "red", "drop": "red",
    "reset-client": "yellow", "reset-server": "yellow", "reset-both": "yellow",
}


def render_security_rules(vsys_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Security Policy Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("Src Zone", min_width=10)
    table.add_column("Dst Zone", min_width=10)
    table.add_column("Src Address", min_width=14)
    table.add_column("Dst Address", min_width=14)
    table.add_column("App", min_width=12)
    table.add_column("Service", min_width=10)
    table.add_column("Action", min_width=7)
    table.add_column("Profile", style="dim", min_width=8)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    rules_container = vsys_root.find("security/rules")
    if rules_container is None:
        console.print("[dim]No security rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(rules_container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"
        action = rule.findtext("action") or ""

        src_zones = fmt_members(get_members(rule, "from/member"))
        dst_zones = fmt_members(get_members(rule, "to/member"))
        src_addrs = fmt_members(get_members(rule, "source/member"))
        dst_addrs = fmt_members(get_members(rule, "destination/member"))
        apps = fmt_members(get_members(rule, "application/member"))
        services = fmt_members(get_members(rule, "service/member"))
        profile = _extract_profile_group(rule)

        all_text = " ".join([name, src_zones, dst_zones, src_addrs, dst_addrs,
                             apps, services, action, profile])
        if not grep_row(grep, all_text):
            continue

        color = ACTION_COLORS.get(action, "white")
        action_markup = f"[{color}]{action}[/{color}]"
        name_markup = f"[dim italic]{name}[/dim italic]" if disabled else name
        if disabled:
            name_markup = f"[dim italic]{name} (disabled)[/dim italic]"

        table.add_row(
            str(i), name_markup, fmt_any(src_zones), fmt_any(dst_zones),
            fmt_any(src_addrs), fmt_any(dst_addrs), fmt_any(apps),
            fmt_any(services), action_markup, profile,
        )
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No security rules found.[/dim]")


def _extract_profile_group(rule: Element) -> str:
    pg = rule.findtext("profile-setting/group/member")
    if pg:
        return pg
    profiles = rule.find("profile-setting/profiles")
    if profiles is not None:
        return "[dim]custom[/dim]"
    return ""
