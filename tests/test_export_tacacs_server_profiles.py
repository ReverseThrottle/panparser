"""Field-asserting tests for export_tacacs_server_profiles() — issue #92 backfill.

SECURITY NOTE: TACACS+ shared secrets are encrypted in PAN-OS XML. The
exporter must replace them with MIGRATION-PLACEHOLDER-SECRET. Fixtures plant
an obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) as <secret>; assertions
check the placeholder constant and the absence of the fake blob anywhere in
the exported dicts (same pattern as the RADIUS/IKE-PSK/certificate tests).
"""
from __future__ import annotations

from export.objects import export_tacacs_server_profiles
from export_fixtures import (
    FAKE_SECRET_MARKER,
    PLACEHOLDER_SECRET,
    assert_no_secret_leak,
    vsys_root,
)


def _profiles(inner: str) -> str:
    return f"<server-profile><tacacs-plus>{inner}</tacacs-plus></server-profile>"


class TestExportTacacsServerProfiles:
    def test_none_root(self):
        assert export_tacacs_server_profiles(None) == []

    def test_missing_container(self):
        assert export_tacacs_server_profiles(vsys_root("<server-profile><radius/></server-profile>")) == []

    def test_full_profile_with_secret_placeholder(self):
        root = vsys_root(_profiles(f"""
        <entry name="corp-tacacs">
          <server>
            <entry name="tac-1">
              <server>10.10.10.5</server>
              <port>4949</port>
              <secret>{FAKE_SECRET_MARKER}</secret>
            </entry>
            <entry name="tac-2"><server>10.10.10.6</server></entry>
            <entry name="tac-bad"><server>10.10.10.7</server><port>not-a-port</port></entry>
          </server>
          <protocol>chap</protocol>
          <timeout>5</timeout>
          <use-single-connection>yes</use-single-connection>
        </entry>
        """))
        out = export_tacacs_server_profiles(root)
        assert out == [{
            "name": "corp-tacacs",
            "server": [
                {"name": "tac-1", "address": "10.10.10.5", "port": 4949,
                 "secret": PLACEHOLDER_SECRET},
                {"name": "tac-2", "address": "10.10.10.6", "port": 49,
                 "secret": PLACEHOLDER_SECRET},
                {"name": "tac-bad", "address": "10.10.10.7", "port": 49,
                 "secret": PLACEHOLDER_SECRET},
            ],
            "protocol": "CHAP",  # lower-case PAN-OS value upper-cased
            "timeout": 5,
            "use_single_connection": True,
        }]
        assert_no_secret_leak(out)

    def test_protocol_pap_and_invalid_omitted(self):
        root = vsys_root(_profiles("""
        <entry name="pap"><protocol>PAP</protocol></entry>
        <entry name="bad-proto"><protocol>mschap</protocol></entry>
        """))
        out = export_tacacs_server_profiles(root)
        assert out[0] == {"name": "bad-proto"}
        assert out[1] == {"name": "pap", "protocol": "PAP"}

    def test_invalid_timeout_skipped_and_single_connection_no(self):
        root = vsys_root(_profiles("""
        <entry name="bad-timeout"><timeout>soon</timeout><use-single-connection>no</use-single-connection></entry>
        """))
        profile = export_tacacs_server_profiles(root)[0]
        assert "timeout" not in profile
        assert profile["use_single_connection"] is False

    def test_profile_without_servers(self):
        root = vsys_root(_profiles('<entry name="empty-tacacs"/>'))
        assert export_tacacs_server_profiles(root) == [{"name": "empty-tacacs"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-tacacs"/><entry name="a-tacacs"/>'))
        assert [p["name"] for p in export_tacacs_server_profiles(root)] == ["a-tacacs", "Z-tacacs"]
