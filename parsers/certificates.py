from __future__ import annotations
from xml.etree.ElementTree import Element
from rich.table import Table
from rich import box
from ._helpers import grep_row


def render_certificates(shared_root: Element | None, console, grep: str | None = None) -> None:
    table = Table(title="Certificates", box=box.ROUNDED, show_lines=True,
                  header_style="bold cyan")
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Common Name", min_width=20)
    table.add_column("Issuer", min_width=20)
    table.add_column("Valid From", min_width=22)
    table.add_column("Valid Until", min_width=22)
    table.add_column("CA", justify="center", width=5)
    table.add_column("Algorithm", min_width=8)

    if shared_root is None:
        console.print("[dim]No shared configuration found.[/dim]")
        return

    container = shared_root.find("certificate")
    if container is None:
        console.print("[dim]No certificates found.[/dim]")
        return

    added = 0
    for cert in sorted(container.findall("entry"), key=lambda e: (e.get("name") or "").lower()):
        name = cert.get("name", "")
        common_name = cert.findtext("common-name") or ""
        issuer = cert.findtext("issuer") or ""
        not_before = cert.findtext("not-valid-before") or ""
        not_after = cert.findtext("not-valid-after") or ""
        ca = cert.findtext("ca") or "no"
        algorithm = cert.findtext("algorithm") or ""

        if not grep_row(grep, name, common_name, issuer, not_before, not_after, ca, algorithm):
            continue

        ca_markup = "[green]yes[/green]" if ca == "yes" else "no"
        table.add_row(name, common_name, issuer, not_before, not_after, ca_markup, algorithm)
        added += 1

    if added:
        console.print(table)
    else:
        console.print("[dim]No certificates found.[/dim]")
