"""TUI renderer for network/qos/profile — interface-level QoS bandwidth/priority
profiles.

This is a distinct PAN-OS construct from parsers/qos_rules.py
(render_qos_rules), which renders the vsys **policy** QoS rules (rulebase
match criteria -> DSCP/class marking). This module instead renders the
class-bandwidth allocation profile that gets applied to a physical
interface's QoS settings (network/qos/profile) — same "QoS" name, completely
separate object.
"""
from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_qos_interface_profiles(network_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="QoS Interface Profiles", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=16)
    table.add_column("Bandwidth Type", min_width=14)
    table.add_column("Egress Guar/Max", min_width=16)
    table.add_column("Classes (priority)", min_width=40)

    if network_root is None:
        console.print("[dim]No network configuration found.[/dim]")
        return

    container = network_root.find("qos/profile")
    if container is None:
        console.print("[dim]No QoS interface profiles found.[/dim]")
        return

    added = 0
    for entry in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = entry.get("name", "")
        bw_type = ""
        egress_guar = ""
        egress_max = ""
        class_lines: list[str] = []

        cbt_el = entry.find("class-bandwidth-type")
        if cbt_el is not None:
            for candidate in ("mbps", "percentage"):
                bw_el = cbt_el.find(candidate)
                if bw_el is None:
                    continue
                bw_type = candidate
                egress_guar = bw_el.findtext("egress-guaranteed") or ""
                egress_max = bw_el.findtext("egress-max") or ""
                class_container = bw_el.find("class")
                if class_container is not None:
                    for cls_entry in sorted(
                        class_container.findall("entry"),
                        key=lambda e: (e.get("name") or ""),
                    ):
                        cls_name = cls_entry.get("name", "")
                        priority = cls_entry.findtext("priority") or ""
                        class_lines.append(f"{cls_name}: {priority}" if priority else cls_name)
                break

        classes_str = "\n".join(class_lines)
        egress_str = f"{egress_guar or '-'} / {egress_max or '-'}" if (egress_guar or egress_max) else ""

        if not grep_row(grep, name, bw_type, egress_str, classes_str):
            continue

        table.add_row(name, bw_type, egress_str, classes_str)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No QoS interface profiles found.[/dim]")
