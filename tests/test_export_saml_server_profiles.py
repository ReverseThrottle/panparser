"""Field-asserting tests for export_saml_server_profiles() — issue #92 backfill.

SECURITY NOTE: the SAML exporter references the IdP certificate by NAME
(the SCM certificate object), never by key material. The fixture plants the
obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) in a private-key element
and assertions prove it never reaches the exported dicts — same hygiene
pattern as the certificate / IKE-PSK tests.
"""
from __future__ import annotations

from export.objects import export_saml_server_profiles
from export_fixtures import FAKE_SECRET_MARKER, assert_no_secret_leak, vsys_root


def _profiles(inner: str) -> str:
    return f"<server-profile><saml>{inner}</saml></server-profile>"


class TestExportSamlServerProfiles:
    def test_none_root(self):
        assert export_saml_server_profiles(None) == []

    def test_missing_container(self):
        assert export_saml_server_profiles(vsys_root("<server-profile><ldap/></server-profile>")) == []

    def test_full_profile_certificate_is_name_reference(self):
        root = vsys_root(_profiles(f"""
        <entry name="corp-idp">
          <entity-id>https://idp.example.com/metadata</entity-id>
          <certificate>idp-cert</certificate>
          <certificate-private-key>{FAKE_SECRET_MARKER}</certificate-private-key>
          <sso-url>https://idp.example.com/sso</sso-url>
          <sso-bindings>redirect</sso-bindings>
          <slo-bindings>post</slo-bindings>
          <max-clock-skew>60</max-clock-skew>
          <validate-idp-certificate>yes</validate-idp-certificate>
          <want-auth-requests-signed>no</want-auth-requests-signed>
        </entry>
        """))
        out = export_saml_server_profiles(root)
        assert out == [{
            "name": "corp-idp",
            "entity_id": "https://idp.example.com/metadata",
            "certificate": "idp-cert",
            "sso_url": "https://idp.example.com/sso",
            "sso_bindings": "redirect",
            "slo_bindings": "post",
            "max_clock_skew": 60,
            "validate_idp_certificate": True,
            "want_auth_requests_signed": False,
        }]
        assert_no_secret_leak(out)

    def test_minimal_profile_defaults_sso_bindings_post(self):
        root = vsys_root(_profiles('<entry name="bare-idp"/>'))
        assert export_saml_server_profiles(root) == [
            {"name": "bare-idp", "sso_bindings": "post"},
        ]

    def test_invalid_bindings_and_skew(self):
        root = vsys_root(_profiles("""
        <entry name="bad-values">
          <sso-bindings>artifact</sso-bindings>
          <slo-bindings>artifact</slo-bindings>
          <max-clock-skew>lots</max-clock-skew>
        </entry>
        """))
        profile = export_saml_server_profiles(root)[0]
        assert profile["sso_bindings"] == "post"  # invalid → default
        assert "slo_bindings" not in profile      # invalid → omitted
        assert "max_clock_skew" not in profile

    def test_boolean_flags_yes_no(self):
        root = vsys_root(_profiles("""
        <entry name="flags">
          <validate-idp-certificate>no</validate-idp-certificate>
          <want-auth-requests-signed>yes</want-auth-requests-signed>
        </entry>
        """))
        profile = export_saml_server_profiles(root)[0]
        assert profile["validate_idp_certificate"] is False
        assert profile["want_auth_requests_signed"] is True

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-idp"/><entry name="a-idp"/>'))
        assert [p["name"] for p in export_saml_server_profiles(root)] == ["a-idp", "Z-idp"]
