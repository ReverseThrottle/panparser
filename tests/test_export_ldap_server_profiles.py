"""Field-asserting tests for export_ldap_server_profiles() — issue #92 backfill.

SECURITY NOTE: LDAP bind passwords are encrypted in PAN-OS XML. The exporter
must replace them with MIGRATION-PLACEHOLDER-SECRET. Fixtures plant an
obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) as <bind-password>;
assertions check the placeholder constant and the absence of the fake blob
anywhere in the exported dicts (same pattern as the RADIUS/IKE/cert tests).
"""
from __future__ import annotations

from export.objects import export_ldap_server_profiles
from export_fixtures import (
    FAKE_SECRET_MARKER,
    PLACEHOLDER_SECRET,
    assert_no_secret_leak,
    vsys_root,
)


def _profiles(inner: str) -> str:
    return f"<server-profile><ldap>{inner}</ldap></server-profile>"


class TestExportLdapServerProfiles:
    def test_none_root(self):
        assert export_ldap_server_profiles(None) == []

    def test_missing_container(self):
        assert export_ldap_server_profiles(vsys_root("<server-profile><radius/></server-profile>")) == []

    def test_full_profile_with_secret_placeholder(self):
        root = vsys_root(_profiles(f"""
        <entry name="corp-ldap">
          <server>
            <entry name="dc-1"><server>10.10.10.5</server><port>636</port></entry>
            <entry name="dc-2"><server>10.10.10.6</server></entry>
            <entry name="dc-bad"><server>10.10.10.7</server><port>not-a-port</port></entry>
          </server>
          <base>dc=example,dc=com</base>
          <bind-dn>cn=svc-ldap,dc=example,dc=com</bind-dn>
          <bind-password>{FAKE_SECRET_MARKER}</bind-password>
          <bind-timelimit>30</bind-timelimit>
          <ldap-type>active-directory</ldap-type>
          <timelimit>30</timelimit>
          <retry-interval>60</retry-interval>
          <ssl>yes</ssl>
          <verify-server-certificate>no</verify-server-certificate>
        </entry>
        """))
        out = export_ldap_server_profiles(root)
        assert out == [{
            "name": "corp-ldap",
            "server": [
                {"name": "dc-1", "address": "10.10.10.5", "port": 636},
                {"name": "dc-2", "address": "10.10.10.6", "port": 389},
                {"name": "dc-bad", "address": "10.10.10.7", "port": 389},
            ],
            "base": "dc=example,dc=com",
            "bind_dn": "cn=svc-ldap,dc=example,dc=com",
            "bind_password": PLACEHOLDER_SECRET,
            "bind_timelimit": "30",
            "ldap_type": "active-directory",
            "timelimit": 30,
            "retry_interval": 60,
            "ssl": True,
            "verify_server_certificate": False,
        }]
        assert_no_secret_leak(out)

    def test_type_fallback_and_all_type_values(self):
        for tag in ("ldap-type", "type"):
            for value in ("active-directory", "e-directory", "sun", "other"):
                root = vsys_root(_profiles(f'<entry name="p"><{tag}>{value}</{tag}></entry>'))
                assert export_ldap_server_profiles(root)[0]["ldap_type"] == value

    def test_unknown_type_omitted(self):
        root = vsys_root(_profiles('<entry name="p"><ldap-type>novell</ldap-type></entry>'))
        assert "ldap_type" not in export_ldap_server_profiles(root)[0]

    def test_invalid_numbers_skipped(self):
        root = vsys_root(_profiles("""
        <entry name="bad-numbers"><timelimit>soon</timelimit><retry-interval>later</retry-interval></entry>
        """))
        profile = export_ldap_server_profiles(root)[0]
        assert "timelimit" not in profile
        assert "retry_interval" not in profile

    def test_minimal_profile_omits_optional_keys(self):
        root = vsys_root(_profiles('<entry name="empty-ldap"/>'))
        assert export_ldap_server_profiles(root) == [{"name": "empty-ldap"}]

    def test_ssl_and_verify_yes_no(self):
        root = vsys_root(_profiles("""
        <entry name="flags"><ssl>no</ssl><verify-server-certificate>yes</verify-server-certificate></entry>
        """))
        profile = export_ldap_server_profiles(root)[0]
        assert profile["ssl"] is False
        assert profile["verify_server_certificate"] is True

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-ldap"/><entry name="a-ldap"/>'))
        assert [p["name"] for p in export_ldap_server_profiles(root)] == ["a-ldap", "Z-ldap"]
