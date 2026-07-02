"""Unit tests for export_certificates().

SECURITY NOTE: Some certificate entries carry a <private-key> element. The
exporter must never read, store, or expose that element's value. These tests
verify presence-only detection: a fixture uses an obviously-fake placeholder
string (FAKE-TEST-KEY-DO-NOT-USE) as the <private-key> text content, and
assertions only check for the *absence* of any private_key/private-key key
in the exported dict plus the presence of the cert's name in the returned
warning-name list. The placeholder value itself is never asserted on or
printed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_certificates


def _shared(xml_str: str):
    """Wrap fragment in a <shared> root and return the Element."""
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportCertificates:
    def test_returns_empty_when_shared_root_none(self):
        assert export_certificates(None) == ([], [])

    def test_returns_empty_when_no_certificate_element(self):
        assert export_certificates(_shared("<address/>")) == ([], [])

    def test_returns_empty_when_no_entries(self):
        assert export_certificates(_shared("<certificate/>")) == ([], [])

    def test_minimal_certificate_name_only(self):
        xml = '<certificate><entry name="Basic-Cert"/></certificate>'
        certs, warn_names = export_certificates(_shared(xml))
        assert certs == [{"name": "Basic-Cert"}]
        assert warn_names == []

    def test_full_field_mapping(self):
        xml = """
        <certificate>
          <entry name="220 Root CA">
            <common-name>220 Root CA</common-name>
            <issuer>/C=US/O=RevThrottle/CN=220 Root CA</issuer>
            <subject>/C=US/O=RevThrottle/CN=220 Root CA</subject>
            <not-valid-before>Apr 26 00:54:58 2025 GMT</not-valid-before>
            <not-valid-after>Apr 26 00:54:58 2026 GMT</not-valid-after>
            <ca>yes</ca>
            <algorithm>RSA</algorithm>
            <public-key>-----BEGIN CERTIFICATE-----FAKEPUBLICKEYDATA-----END CERTIFICATE-----</public-key>
          </entry>
        </certificate>
        """
        certs, warn_names = export_certificates(_shared(xml))
        assert len(certs) == 1
        cert = certs[0]
        assert cert["name"] == "220 Root CA"
        assert cert["common_name"] == "220 Root CA"
        assert cert["issuer"] == "/C=US/O=RevThrottle/CN=220 Root CA"
        assert cert["subject"] == "/C=US/O=RevThrottle/CN=220 Root CA"
        assert cert["not_valid_before"] == "Apr 26 00:54:58 2025 GMT"
        assert cert["not_valid_after"] == "Apr 26 00:54:58 2026 GMT"
        assert cert["ca"] is True
        assert cert["algorithm"] == "RSA"
        assert cert["public_key"] == (
            "-----BEGIN CERTIFICATE-----FAKEPUBLICKEYDATA-----END CERTIFICATE-----"
        )
        assert warn_names == []

    def test_ca_no_maps_to_false(self):
        xml = """
        <certificate>
          <entry name="Leaf-Cert">
            <ca>no</ca>
          </entry>
        </certificate>
        """
        certs, _ = export_certificates(_shared(xml))
        assert certs[0]["ca"] is False

    def test_private_key_present_is_never_captured_and_warns(self):
        """Certificate has a <private-key> element (fake placeholder text).

        The exported dict must never contain a private_key/private-key key,
        regardless of the element's content, and the certificate's name must
        appear in the returned warning-name list.
        """
        xml = """
        <certificate>
          <entry name="Locally-Generated-Cert">
            <common-name>Locally-Generated-Cert</common-name>
            <algorithm>RSA</algorithm>
            <private-key>FAKE-TEST-KEY-DO-NOT-USE</private-key>
          </entry>
        </certificate>
        """
        certs, warn_names = export_certificates(_shared(xml))
        assert len(certs) == 1
        cert = certs[0]
        assert "private_key" not in cert
        assert "private-key" not in cert
        assert warn_names == ["Locally-Generated-Cert"]

    def test_private_key_absent_does_not_warn(self):
        xml = """
        <certificate>
          <entry name="CA-Imported-Only">
            <common-name>CA-Imported-Only</common-name>
          </entry>
        </certificate>
        """
        certs, warn_names = export_certificates(_shared(xml))
        assert "private_key" not in certs[0]
        assert warn_names == []

    def test_mixed_entries_only_flags_ones_with_private_key(self):
        xml = """
        <certificate>
          <entry name="No-Key-Cert">
            <common-name>No-Key-Cert</common-name>
          </entry>
          <entry name="Has-Key-Cert">
            <common-name>Has-Key-Cert</common-name>
            <private-key>FAKE-TEST-KEY-DO-NOT-USE</private-key>
          </entry>
        </certificate>
        """
        certs, warn_names = export_certificates(_shared(xml))
        assert len(certs) == 2
        for cert in certs:
            assert "private_key" not in cert
            assert "private-key" not in cert
        assert warn_names == ["Has-Key-Cert"]

    def test_sorted_by_name(self):
        xml = """
        <certificate>
          <entry name="Zebra-Cert"/>
          <entry name="Alpha-Cert"/>
          <entry name="Middle-Cert"/>
        </certificate>
        """
        certs, _ = export_certificates(_shared(xml))
        assert [c["name"] for c in certs] == ["Alpha-Cert", "Middle-Cert", "Zebra-Cert"]

    def test_no_optional_fields_when_absent(self):
        """If optional child elements are missing, their keys are absent from the dict."""
        xml = '<certificate><entry name="Sparse-Cert"><algorithm>RSA</algorithm></entry></certificate>'
        certs, _ = export_certificates(_shared(xml))
        cert = certs[0]
        assert cert == {"name": "Sparse-Cert", "algorithm": "RSA"}
