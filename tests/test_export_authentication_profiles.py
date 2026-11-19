"""Field-asserting tests for export_authentication_profiles() — issue #92 backfill.

Covers every method mapping (local-database / ldap / radius / saml-idp /
tacplus / kerberos), the ldap/radius sub-fields, and unknown-method omission.
"""
from __future__ import annotations

from export.objects import export_authentication_profiles
from export_fixtures import vsys_root


class TestExportAuthenticationProfiles:
    def test_none_root(self):
        assert export_authentication_profiles(None) == []

    def test_missing_container(self):
        assert export_authentication_profiles(vsys_root("<server-profile/>")) == []

    def test_ldap_method_full_and_bare(self):
        root = vsys_root("""
        <authentication-profile>
          <entry name="auth-ldap">
            <description>corp LDAP</description>
            <allow-list><member>all</member></allow-list>
            <method><ldap>
              <server-profile>corp-ldap</server-profile>
              <login-attribute>sAMAccountName</login-attribute>
            </ldap></method>
          </entry>
          <entry name="auth-ldap-bare"><method><ldap/></method></entry>
        </authentication-profile>""")
        assert export_authentication_profiles(root) == [
            {"name": "auth-ldap", "description": "corp LDAP", "allow_list": ["all"],
             "method": {"ldap": {"server_profile": "corp-ldap",
                                 "login_attribute": "sAMAccountName"}}},
            {"name": "auth-ldap-bare", "method": {"ldap": {}}},
        ]

    def test_radius_method_full_and_bare(self):
        root = vsys_root("""
        <authentication-profile>
          <entry name="auth-radius"><method><radius><server-profile>corp-radius</server-profile></radius></method></entry>
          <entry name="auth-radius-bare"><method><radius/></method></entry>
        </authentication-profile>""")
        assert export_authentication_profiles(root) == [
            {"name": "auth-radius", "method": {"radius": {"server_profile": "corp-radius"}}},
            {"name": "auth-radius-bare", "method": {"radius": {}}},
        ]

    def test_simple_method_mappings(self):
        for panos_tag, scm_key in (
            ("local-database", "local_database"),
            ("saml-idp", "saml_idp"),
            ("tacplus", "tacplus"),
            ("kerberos", "kerberos"),
        ):
            root = vsys_root(f'<authentication-profile><entry name="p"><method><{panos_tag}/></method></entry></authentication-profile>')
            assert export_authentication_profiles(root) == [
                {"name": "p", "method": {scm_key: {}}},
            ], panos_tag

    def test_unknown_or_absent_method_omitted(self):
        root = vsys_root("""
        <authentication-profile>
          <entry name="no-method"/>
          <entry name="unknown-method"><method><smart-card/></method></entry>
          <entry name="empty-method"><method/></entry>
        </authentication-profile>""")
        assert export_authentication_profiles(root) == [
            {"name": "empty-method"},
            {"name": "no-method"},
            {"name": "unknown-method"},
        ]

    def test_sorted_case_insensitive(self):
        root = vsys_root('<authentication-profile><entry name="Z-auth"/><entry name="a-auth"/></authentication-profile>')
        assert [p["name"] for p in export_authentication_profiles(root)] == ["a-auth", "Z-auth"]
