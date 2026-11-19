"""Field-asserting tests for export_syslog_server_profiles() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_syslog_server_profiles
from export_fixtures import vsys_root


def _profiles(inner: str) -> str:
    return f"<log-settings><syslog>{inner}</syslog></log-settings>"


class TestExportSyslogServerProfiles:
    def test_none_root(self):
        assert export_syslog_server_profiles(None) == []

    def test_missing_container(self):
        assert export_syslog_server_profiles(vsys_root("<log-settings><http/></log-settings>")) == []

    def test_full_servers(self):
        root = vsys_root(_profiles("""
        <entry name="siem">
          <server>
            <entry name="siem-1">
              <server>10.20.30.40</server>
              <transport>TCP</transport>
              <port>1514</port>
              <format>IETF</format>
              <facility>LOG_LOCAL0</facility>
            </entry>
          </server>
        </entry>
        """))
        assert export_syslog_server_profiles(root) == [{
            "name": "siem",
            "server": [{
                "name": "siem-1", "server": "10.20.30.40", "transport": "TCP",
                "port": 1514, "format": "IETF", "facility": "LOG_LOCAL0",
            }],
        }]

    def test_defaults_and_invalid_port(self):
        root = vsys_root(_profiles("""
        <entry name="defaults">
          <server>
            <entry name="minimal"/>
            <entry name="bad-port"><port>not-a-port</port></entry>
          </server>
        </entry>
        """))
        servers = export_syslog_server_profiles(root)[0]["server"]
        assert servers[0] == {
            "name": "minimal", "server": "", "transport": "UDP",
            "port": 514, "format": "BSD", "facility": "LOG_USER",
        }
        assert servers[1]["port"] == 514  # invalid → default

    def test_profile_without_servers(self):
        root = vsys_root(_profiles('<entry name="empty"/>'))
        assert export_syslog_server_profiles(root) == [{"name": "empty"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-syslog"/><entry name="a-syslog"/>'))
        assert [p["name"] for p in export_syslog_server_profiles(root)] == ["a-syslog", "Z-syslog"]
