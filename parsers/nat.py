from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row, get_members, fmt_any, fmt_members


def render_nat_rules(vsys_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="NAT Rules", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("#", style="dim", justify="right", width=4)
    table.add_column("Name", style="bold", min_width=18)
    table.add_column("Src Zone", min_width=10)
    table.add_column("Dst Zone", min_width=10)
    table.add_column("Src Address", min_width=14)
    table.add_column("Dst Address", min_width=14)
    table.add_column("Dst Interface", style="dim")
    table.add_column("NAT Type")
    table.add_column("Translated To", min_width=14)

    if vsys_root is None:
        console.print("[dim]No vsys configuration found.[/dim]")
        return

    rules_container = vsys_root.find("rulebase/nat/rules") or vsys_root.find("nat/rules")
    if rules_container is None:
        console.print("[dim]No NAT rules found.[/dim]")
        return

    added = 0
    for i, rule in enumerate(rules_container.findall("entry"), 1):
        name = rule.get("name", "")
        disabled = rule.findtext("disabled") == "yes"

        src_zones = fmt_members(get_members(rule, "from/member"))
        dst_zones = fmt_members(get_members(rule, "to/member"))
        src_addrs = fmt_members(get_members(rule, "source/member"))
        dst_addrs = fmt_members(get_members(rule, "destination/member"))
        dst_iface = rule.findtext("to-interface") or ""

        nat_type, translated = _extract_nat_translation(rule)

        all_text = " ".join([name, src_zones, dst_zones, src_addrs, dst_addrs,
                             nat_type, translated])
        if not grep_row(grep, all_text):
            continue

        name_markup = f"[dim italic]{name} (disabled)[/dim italic]" if disabled else name
        table.add_row(
            str(i), name_markup, fmt_any(src_zones), fmt_any(dst_zones),
            fmt_any(src_addrs), fmt_any(dst_addrs), dst_iface, nat_type, translated,
        )
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No NAT rules found.[/dim]")


def _extract_nat_translation(rule: Element) -> tuple[str, str]:
    src_nat = rule.find("source-translation")
    dst_nat = rule.find("destination-translation")

    parts = []
    if dst_nat is not None:
        addr = dst_nat.findtext("translated-address") or ""
        port = dst_nat.findtext("translated-port") or ""
        val = addr
        if port:
            val = f"{addr}:{port}" if addr else f":{port}"
        parts.append(f"[cyan]dst-nat[/cyan] → {val}")

    if src_nat is not None:
        for mode in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
            el = src_nat.find(mode)
            if el is not None:
                if mode == "dynamic-ip-and-port":
                    iface_addr = el.find("interface-address")
                    if iface_addr is not None:
                        iface = iface_addr.findtext("interface") or ""
                        parts.append(f"[green]DIPP[/green] ({iface})")
                    else:
                        pool = _get_pool(el)
                        parts.append(f"[green]DIPP[/green] {pool}")
                elif mode == "dynamic-ip":
                    pool = _get_pool(el)
                    parts.append(f"[green]dynamic-ip[/green] {pool}")
                elif mode == "static-ip":
                    translated = el.findtext("translated-address") or ""
                    parts.append(f"[green]static[/green] → {translated}")
                break

    nat_type = "src+dst" if src_nat is not None and dst_nat is not None else (
        "src-nat" if src_nat is not None else "dst-nat" if dst_nat is not None else "none"
    )
    return nat_type, "\n".join(parts) if parts else ""


def _get_pool(el: Element) -> str:
    members = [m.text or "" for m in el.findall("translated-address/member")]
    return ", ".join(members)
