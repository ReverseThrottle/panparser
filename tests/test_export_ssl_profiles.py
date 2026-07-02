"""Unit tests for export_ssl_profiles()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_ssl_profiles


def _shared(xml_str: str):
    """Wrap fragment in a <shared> root and return the Element."""
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportSSLProfiles:
    def test_returns_empty_when_shared_root_none(self):
        assert export_ssl_profiles(None) == []

    def test_returns_empty_when_no_container_element(self):
        assert export_ssl_profiles(_shared("<certificate/>")) == []

    def test_returns_empty_when_container_self_closed(self):
        """uas-config.xml has a vsys-scoped <ssl-tls-service-profile/> with no entries."""
        assert export_ssl_profiles(_shared("<ssl-tls-service-profile/>")) == []

    def test_returns_empty_when_no_entries(self):
        xml = "<ssl-tls-service-profile></ssl-tls-service-profile>"
        assert export_ssl_profiles(_shared(xml)) == []

    def test_real_profile_shape_from_440_config(self):
        """Matches shared/ssl-tls-service-profile/entry in 440-config.xml."""
        xml = """
        <ssl-tls-service-profile>
          <entry name="Homelab PortalGW">
            <protocol-settings>
              <min-version>tls1-2</min-version>
              <max-version>tls1-3</max-version>
              <keyxchg-algo-rsa>no</keyxchg-algo-rsa>
              <keyxchg-algo-dhe>no</keyxchg-algo-dhe>
              <keyxchg-algo-ecdhe>yes</keyxchg-algo-ecdhe>
              <enc-algo-aes-128-cbc>yes</enc-algo-aes-128-cbc>
              <enc-algo-aes-128-gcm>yes</enc-algo-aes-128-gcm>
              <enc-algo-aes-chacha20-poly1305>yes</enc-algo-aes-chacha20-poly1305>
              <enc-algo-aes-256-cbc>yes</enc-algo-aes-256-cbc>
              <enc-algo-aes-256-gcm>yes</enc-algo-aes-256-gcm>
              <auth-algo-sha1>no</auth-algo-sha1>
              <auth-algo-sha256>yes</auth-algo-sha256>
              <auth-algo-sha384>yes</auth-algo-sha384>
            </protocol-settings>
            <certificate>Homlab PortalGW</certificate>
          </entry>
        </ssl-tls-service-profile>
        """
        result = export_ssl_profiles(_shared(xml))
        assert result == [{
            "name": "Homelab PortalGW",
            "certificate": "Homlab PortalGW",
            "min_version": "tls1-2",
            "max_version": "tls1-3",
        }]

    def test_real_profile_shape_from_uas_config(self):
        """Matches shared/ssl-tls-service-profile/entry in uas-config.xml.

        Note this profile has no cipher-suite flags at all under protocol-settings,
        and max-version is the literal string 'max' (not a numbered TLS version).
        """
        xml = """
        <ssl-tls-service-profile>
          <entry name="Global-Protect-SSL-TLS-Profile">
            <protocol-settings>
              <min-version>tls1-2</min-version>
              <max-version>max</max-version>
            </protocol-settings>
            <certificate>vpn-cert_2025</certificate>
          </entry>
        </ssl-tls-service-profile>
        """
        result = export_ssl_profiles(_shared(xml))
        assert result == [{
            "name": "Global-Protect-SSL-TLS-Profile",
            "certificate": "vpn-cert_2025",
            "min_version": "tls1-2",
            "max_version": "max",
        }]

    def test_cipher_suite_flags_are_not_exported(self):
        """Documented limitation: keyxchg-algo-*/enc-algo-*/auth-algo-* are dropped —
        the scm-mcp SDK has no SSL/TLS Service Profile model to push them into."""
        xml = """
        <ssl-tls-service-profile>
          <entry name="CipherTest">
            <protocol-settings>
              <min-version>tls1-2</min-version>
              <max-version>tls1-3</max-version>
              <keyxchg-algo-ecdhe>yes</keyxchg-algo-ecdhe>
              <enc-algo-aes-256-gcm>yes</enc-algo-aes-256-gcm>
            </protocol-settings>
            <certificate>some-cert</certificate>
          </entry>
        </ssl-tls-service-profile>
        """
        result = export_ssl_profiles(_shared(xml))
        assert set(result[0].keys()) == {"name", "certificate", "min_version", "max_version"}

    def test_missing_certificate_and_versions_omitted(self):
        """Fields absent from the source XML are omitted rather than emitted as empty strings."""
        xml = '<ssl-tls-service-profile><entry name="Bare"/></ssl-tls-service-profile>'
        result = export_ssl_profiles(_shared(xml))
        assert result == [{"name": "Bare"}]

    def test_entry_without_name_skipped(self):
        xml = '<ssl-tls-service-profile><entry><certificate>x</certificate></entry></ssl-tls-service-profile>'
        assert export_ssl_profiles(_shared(xml)) == []

    def test_sorted_by_name(self):
        xml = """
        <ssl-tls-service-profile>
          <entry name="Zebra"/>
          <entry name="Alpha"/>
          <entry name="Middle"/>
        </ssl-tls-service-profile>
        """
        result = export_ssl_profiles(_shared(xml))
        assert [p["name"] for p in result] == ["Alpha", "Middle", "Zebra"]

    def test_multiple_profiles(self):
        xml = """
        <ssl-tls-service-profile>
          <entry name="Profile-A">
            <protocol-settings>
              <min-version>tls1-0</min-version>
              <max-version>tls1-2</max-version>
            </protocol-settings>
            <certificate>cert-a</certificate>
          </entry>
          <entry name="Profile-B">
            <protocol-settings>
              <min-version>tls1-2</min-version>
              <max-version>max</max-version>
            </protocol-settings>
            <certificate>cert-b</certificate>
          </entry>
        </ssl-tls-service-profile>
        """
        result = export_ssl_profiles(_shared(xml))
        assert len(result) == 2
        assert result[0]["certificate"] == "cert-a"
        assert result[1]["certificate"] == "cert-b"
