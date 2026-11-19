"""Unit tests for export_radius_server_profiles() — issue #79 coverage backfill.

SECURITY NOTE: RADIUS shared secrets are encrypted in PAN-OS XML. The
exporter must replace them with MIGRATION-PLACEHOLDER-SECRET. Fixtures use
an obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) as the <secret> text;
assertions check the placeholder constant and the absence of the fake blob
anywhere in the exported dicts (same pattern as the certificate/SNMP tests).
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from export.objects import export_radius_server_profiles

PLACEHOLDER_SECRET = "MIGRATION-PLACEHOLDER-SECRET"
FAKE_SECRET_MARKER = "FAKE-TEST-SECRET-DO-NOT-USE"


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _profiles(inner: str) -> str:
    return f"<server-profile><radius>{inner}</radius></server-profile>"


class TestExportRadiusServerProfiles:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_radius_server_profiles(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_radius_server_profiles(_vsys("<server-profile><ldap/></server-profile>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_radius_server_profiles(_vsys(_profiles(""))) == []

    def test_full_profile_with_secret_placeholder(self):
        xml = _profiles(f"""
        <entry name="corp-radius">
          <server>
            <entry name="radius-1">
              <server>10.10.10.5</server>
              <port>1812</port>
              <secret>{FAKE_SECRET_MARKER}</secret>
            </entry>
            <entry name="radius-2">
              <server>10.10.10.6</server>
              <secret>{FAKE_SECRET_MARKER}</secret>
            </entry>
          </server>
          <protocol><PEAP-MSCHAPv2/></protocol>
          <retries>3</retries>
          <timeout>5</timeout>
        </entry>
        """)
        out = export_radius_server_profiles(_vsys(xml))
        assert out == [{
            "name": "corp-radius",
            "server": [
                {"name": "radius-1", "ip_address": "10.10.10.5", "port": 1812,
                 "secret": PLACEHOLDER_SECRET},
                {"name": "radius-2", "ip_address": "10.10.10.6", "port": 1812,
                 "secret": PLACEHOLDER_SECRET},
            ],
            "protocol": {"PEAP_MSCHAPv2": {}},
            "retries": 3,
            "timeout": 5,
        }]
        assert FAKE_SECRET_MARKER not in json.dumps(out)

    def test_explicit_and_invalid_ports(self):
        xml = _profiles("""
        <entry name="port-cases">
          <server>
            <entry name="custom-port"><server>10.0.0.1</server><port>1645</port></entry>
            <entry name="bad-port"><server>10.0.0.2</server><port>not-a-port</port></entry>
            <entry name="no-port"><server>10.0.0.3</server></entry>
          </server>
        </entry>
        """)
        servers = export_radius_server_profiles(_vsys(xml))[0]["server"]
        assert servers[0]["port"] == 1645
        assert servers[1]["port"] == 1812  # invalid → default
        assert servers[2]["port"] == 1812  # absent → default
        assert all(s["secret"] == PLACEHOLDER_SECRET for s in servers)

    def test_profile_without_servers_omits_server_key(self):
        xml = _profiles('<entry name="empty-radius"/>')
        out = export_radius_server_profiles(_vsys(xml))
        assert out == [{"name": "empty-radius"}]

    def test_all_protocol_mappings(self):
        for panos_tag, scm_key in (
            ("CHAP", "CHAP"),
            ("PAP", "PAP"),
            ("PEAP-MSCHAPv2", "PEAP_MSCHAPv2"),
            ("PEAP-with-GTC", "PEAP_with_GTC"),
            ("EAP-TTLS-with-PAP", "EAP_TTLS_with_PAP"),
        ):
            xml = _profiles(f'<entry name="p"><protocol><{panos_tag}/></protocol></entry>')
            profile = export_radius_server_profiles(_vsys(xml))[0]
            assert profile["protocol"] == {scm_key: {}}, panos_tag

    def test_unknown_protocol_omitted(self):
        xml = _profiles('<entry name="p-unknown"><protocol><SOMETHING-NEW/></protocol></entry>')
        profile = export_radius_server_profiles(_vsys(xml))[0]
        assert "protocol" not in profile

    def test_empty_protocol_container_omitted(self):
        xml = _profiles('<entry name="p-empty"><protocol/></entry>')
        profile = export_radius_server_profiles(_vsys(xml))[0]
        assert "protocol" not in profile

    def test_invalid_retries_and_timeout_skipped(self):
        xml = _profiles("""
        <entry name="bad-numbers">
          <retries>many</retries>
          <timeout>soon</timeout>
        </entry>
        """)
        profile = export_radius_server_profiles(_vsys(xml))[0]
        assert "retries" not in profile
        assert "timeout" not in profile

    def test_sorted_case_insensitive(self):
        xml = _profiles("""
        <entry name="Z-profile"/>
        <entry name="a-profile"/>
        """)
        out = export_radius_server_profiles(_vsys(xml))
        assert [p["name"] for p in out] == ["a-profile", "Z-profile"]
