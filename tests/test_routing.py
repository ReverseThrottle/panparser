"""Unit tests for _extract_nexthop()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from parsers.routing import _extract_nexthop


def _route(xml_str: str):
    """Wrap a fragment in an <entry> root and return the element."""
    return ET.fromstring(f'<entry name="r">{xml_str}</entry>')


class TestExtractNexthop:
    def test_repro_from_issue_52(self):
        xml = """
        <interface>tunnel.137</interface>
        <metric>10</metric>
        <destination>0.0.0.0/0</destination>
        """

        assert _extract_nexthop(_route(xml)) == ("", "tunnel.137")

    def test_nexthop_ip_address_with_interface(self):
        xml = """
        <nexthop><ip-address>192.168.10.1</ip-address></nexthop>
        <interface>ethernet1/8</interface>
        """

        assert _extract_nexthop(_route(xml)) == (
            "192.168.10.1",
            "ethernet1/8",
        )

    def test_nexthop_discard(self):
        xml = "<nexthop><discard/></nexthop>"

        assert _extract_nexthop(_route(xml)) == ("[dim]discard[/dim]", "")

    def test_nexthop_next_vr(self):
        xml = "<nexthop><next-vr>other-vr</next-vr></nexthop>"

        assert _extract_nexthop(_route(xml)) == ("vr:other-vr", "")

    def test_no_nexthop_and_no_interface(self):
        assert _extract_nexthop(_route("<metric>10</metric>")) == ("", "")
