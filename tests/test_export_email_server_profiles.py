"""Unit tests for export_email_server_profiles() — issue #122 Correction 2.

The email server-profile family had NO exporter while the viewer showed it
(export ⊇ viewer parity failed for email-main). Canonical container is
log-settings/email per pan-os-python EmailServerProfile — NOT the
server-profile/email placement the old sample/viewers used.

SECURITY NOTE: SMTP auth passwords are encrypted in PAN-OS XML. The exporter
must replace them with MIGRATION-PLACEHOLDER-SECRET. Fixtures use an
obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) as the <password> text;
assertions check the placeholder constant and the absence of the fake blob
anywhere in the exported dicts (same pattern as the radius/SNMP tests).
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from export.objects import export_email_server_profiles

PLACEHOLDER_SECRET = "MIGRATION-PLACEHOLDER-SECRET"
FAKE_SECRET_MARKER = "FAKE-TEST-SECRET-DO-NOT-USE"


def _root(xml_str: str) -> ET.Element:
    return ET.fromstring(f"<root>{xml_str}</root>")


def _profiles(inner: str) -> str:
    return f"<log-settings><email>{inner}</email></log-settings>"


class TestExportEmailServerProfiles:
    def test_returns_empty_when_roots_none(self):
        assert export_email_server_profiles(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_email_server_profiles(_root("<log-settings><syslog/></log-settings>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_email_server_profiles(_root(_profiles(""))) == []

    def test_full_profile_with_password_placeholder(self):
        xml = _profiles(f"""
        <entry name="corp-email">
          <server>
            <entry name="smtp-1">
              <gateway>10.10.10.5</gateway>
              <from>pan@example.com</from>
              <to>noc@example.com</to>
              <and-also-to>soc@example.com</and-also-to>
              <display-name>PAN Alerts</display-name>
              <protocol>SMTP</protocol>
              <port>587</port>
              <tls-version>1.2</tls-version>
              <auth>yes</auth>
              <certificate-profile>smtp-cert</certificate-profile>
              <username>smtp-user</username>
              <password>{FAKE_SECRET_MARKER}</password>
            </entry>
          </server>
        </entry>
        """)
        out = export_email_server_profiles(_root(xml))
        assert out == [{
            "name": "corp-email",
            "server": [{
                "name": "smtp-1",
                "gateway": "10.10.10.5",
                "from": "pan@example.com",
                "to": "noc@example.com",
                "protocol": "SMTP",
                "port": 587,
                "display_name": "PAN Alerts",
                "also_to": "soc@example.com",
                "tls_version": "1.2",
                "auth": "yes",
                "certificate_profile": "smtp-cert",
                "username": "smtp-user",
                "password": PLACEHOLDER_SECRET,
            }],
        }]
        assert FAKE_SECRET_MARKER not in json.dumps(out)

    def test_defaults_protocol_smtp_port_25(self):
        xml = _profiles("""
        <entry name="bare-email">
          <server>
            <entry name="smtp"><gateway>10.0.0.1</gateway></entry>
          </server>
        </entry>
        """)
        out = export_email_server_profiles(_root(xml))
        srv = out[0]["server"][0]
        assert srv["protocol"] == "SMTP"
        assert srv["port"] == 25
        assert "password" not in srv
        assert "username" not in srv

    def test_invalid_port_falls_back_to_25(self):
        xml = _profiles("""
        <entry name="bad-port">
          <server>
            <entry name="smtp"><gateway>10.0.0.1</gateway><port>not-a-number</port></entry>
          </server>
        </entry>
        """)
        assert export_email_server_profiles(_root(xml))[0]["server"][0]["port"] == 25

    def test_profile_without_servers(self):
        out = export_email_server_profiles(_root(_profiles('<entry name="empty-email"/>')))
        assert out == [{"name": "empty-email"}]

    def test_sorted_by_name(self):
        xml = _profiles('<entry name="zeta"/><entry name="Alpha"/>')
        assert [p["name"] for p in export_email_server_profiles(_root(xml))] == ["Alpha", "zeta"]

    def test_merges_vsys_and_shared_scopes(self):
        # Issue #122 / #107 convention: both scopes merged, vsys entries
        # first, same-name entries kept per scope.
        vsys = _root(_profiles('<entry name="email-vsys"/><entry name="dup"/>'))
        shared = _root(_profiles('<entry name="email-shared"/><entry name="dup"/>'))
        out = export_email_server_profiles(vsys, shared)
        assert [p["name"] for p in out] == ["dup", "dup", "email-shared", "email-vsys"]

    def test_shared_only_scope(self):
        shared = _root(_profiles('<entry name="email-shared"/>'))
        assert [p["name"] for p in export_email_server_profiles(None, shared)] == ["email-shared"]

    def test_noncanonical_container_not_read(self):
        # server-profile/email is the NON-canonical placement (#122): the
        # exporter reads log-settings/email only, matching the SDK xpath.
        xml = "<server-profile><email><entry name='wrong-place'/></email></server-profile>"
        assert export_email_server_profiles(_root(xml)) == []
