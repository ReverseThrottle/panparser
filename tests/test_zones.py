"""Tests for zone rendering."""
from __future__ import annotations

import io
import sys
import xml.etree.ElementTree as ET

from rich.console import Console

import panparser
from parsers.zones import render_zones


def test_zones_section_reads_zones_from_vsys(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.xml"
    config.write_text(
        """
        <config>
          <devices>
            <entry name="localhost.localdomain">
              <network/>
              <vsys>
                <entry name="vsys1">
                  <zone>
                    <entry name="trust">
                      <network>
                        <layer3>
                          <member>ethernet1/1</member>
                        </layer3>
                      </network>
                    </entry>
                  </zone>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
        """,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["panparser", str(config), "--section", "zones", "--no-color"],
    )

    panparser.main()

    output = capsys.readouterr().out
    assert "trust" in output
    assert "No zones found." not in output


def test_missing_vsys_reports_vsys_empty_state():
    output = io.StringIO()
    console = Console(file=output, no_color=True)

    render_zones(None, console)

    assert "No vsys configuration found." in output.getvalue()


def test_vsys_without_zones_reports_zone_empty_state():
    output = io.StringIO()
    console = Console(file=output, no_color=True)
    vsys_root = ET.fromstring('<entry name="vsys1"/>')

    render_zones(vsys_root, console)

    assert "No zones found." in output.getvalue()
