"""Unit tests for export_services() — issue #79 coverage backfill.

Covers tcp/udp/sctp protocol selection, destination/source ports, and
description/tag metadata.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_services


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _shared(xml_str: str):
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportServices:
    def test_returns_empty_when_both_roots_none(self):
        assert export_services(None, None) == []

    def test_returns_empty_when_no_container(self):
        assert export_services(_vsys("<service-group/>"), None) == []

    def test_returns_empty_when_no_entries(self):
        assert export_services(_vsys("<service/>"), None) == []

    def test_tcp_service_full_fields(self):
        xml = """
        <service>
          <entry name="svc-https-alt">
            <protocol>
              <tcp>
                <port>8443</port>
                <source-port>1024-65535</source-port>
              </tcp>
            </protocol>
            <description>Alternate HTTPS</description>
            <tag><member>web</member></tag>
          </entry>
        </service>
        """
        out = export_services(_vsys(xml), None)
        assert out == [{
            "name": "svc-https-alt",
            "protocol": "tcp",
            "destination_port": "8443",
            "source_port": "1024-65535",
            "description": "Alternate HTTPS",
            "tag": ["web"],
        }]

    def test_udp_service_without_source_port(self):
        xml = """
        <service>
          <entry name="svc-dns">
            <protocol><udp><port>53</port></udp></protocol>
          </entry>
        </service>
        """
        out = export_services(_vsys(xml), None)
        assert out == [{"name": "svc-dns", "protocol": "udp", "destination_port": "53"}]
        assert "source_port" not in out[0]

    def test_sctp_service(self):
        xml = """
        <service>
          <entry name="svc-diameter">
            <protocol><sctp><port>3868</port></sctp></protocol>
          </entry>
        </service>
        """
        out = export_services(_vsys(xml), None)
        assert out == [{"name": "svc-diameter", "protocol": "sctp", "destination_port": "3868"}]

    def test_tcp_preferred_over_udp_when_both_present(self):
        xml = """
        <service>
          <entry name="svc-both">
            <protocol>
              <tcp><port>443</port></tcp>
              <udp><port>443</port></udp>
            </protocol>
          </entry>
        </service>
        """
        out = export_services(_vsys(xml), None)
        assert out[0]["protocol"] == "tcp"

    def test_service_without_protocol_keeps_name_only(self):
        xml = '<service><entry name="svc-bare"/></service>'
        assert export_services(_vsys(xml), None) == [{"name": "svc-bare"}]

    def test_missing_port_yields_empty_destination_port(self):
        xml = """
        <service>
          <entry name="svc-noport"><protocol><tcp/></protocol></entry>
        </service>
        """
        out = export_services(_vsys(xml), None)
        assert out == [{"name": "svc-noport", "protocol": "tcp", "destination_port": ""}]

    def test_shared_and_vsys_merged_sorted(self):
        vsys_xml = """
        <service>
          <entry name="z-svc"><protocol><tcp><port>9000</port></tcp></protocol></entry>
        </service>
        """
        shared_xml = """
        <service>
          <entry name="A-svc"><protocol><udp><port>514</port></udp></protocol></entry>
        </service>
        """
        out = export_services(_vsys(vsys_xml), _shared(shared_xml))
        assert [s["name"] for s in out] == ["A-svc", "z-svc"]
