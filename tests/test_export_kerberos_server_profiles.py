"""Field-asserting tests for export_kerberos_server_profiles() — issue #92 backfill.

SECURITY NOTE: the Kerberos exporter only surfaces host/port — it must never
carry secret material. The fixture plants the obviously-fake blob
(FAKE-TEST-SECRET-DO-NOT-USE) in a password element and assertions prove it
never reaches the exported dicts (same hygiene pattern as the RADIUS /
IKE-PSK / certificate tests).
"""
from __future__ import annotations

from export.objects import export_kerberos_server_profiles
from export_fixtures import FAKE_SECRET_MARKER, assert_no_secret_leak, vsys_root


def _profiles(inner: str) -> str:
    return f"<server-profile><kerberos>{inner}</kerberos></server-profile>"


class TestExportKerberosServerProfiles:
    def test_none_root(self):
        assert export_kerberos_server_profiles(None) == []

    def test_missing_container(self):
        assert export_kerberos_server_profiles(vsys_root("<server-profile><ldap/></server-profile>")) == []

    def test_full_servers_host_and_server_fallback(self):
        root = vsys_root(_profiles(f"""
        <entry name="corp-kdc">
          <server>
            <entry name="kdc-1"><host>kdc1.example.com</host><port>888</port></entry>
            <entry name="kdc-2"><server>kdc2.example.com</server></entry>
            <entry name="kdc-3"><port>not-a-port</port></entry>
          </server>
          <password>{FAKE_SECRET_MARKER}</password>
        </entry>
        """))
        out = export_kerberos_server_profiles(root)
        assert out == [{
            "name": "corp-kdc",
            "server": [
                {"name": "kdc-1", "host": "kdc1.example.com", "port": 888},
                {"name": "kdc-2", "host": "kdc2.example.com", "port": 88},
                {"name": "kdc-3", "host": "", "port": 88},
            ],
        }]
        assert_no_secret_leak(out)

    def test_profile_without_servers(self):
        root = vsys_root(_profiles('<entry name="empty-kdc"/>'))
        assert export_kerberos_server_profiles(root) == [{"name": "empty-kdc"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-kdc"/><entry name="a-kdc"/>'))
        assert [p["name"] for p in export_kerberos_server_profiles(root)] == ["a-kdc", "Z-kdc"]
