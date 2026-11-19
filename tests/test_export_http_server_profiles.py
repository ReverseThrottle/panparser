"""Field-asserting tests for export_http_server_profiles() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_http_server_profiles
from export_fixtures import vsys_root


def _profiles(inner: str) -> str:
    return f"<log-settings><http>{inner}</http></log-settings>"


class TestExportHttpServerProfiles:
    def test_none_root(self):
        assert export_http_server_profiles(None) == []

    def test_missing_container(self):
        assert export_http_server_profiles(vsys_root("<log-settings><syslog/></log-settings>")) == []

    def test_full_servers(self):
        root = vsys_root(_profiles("""
        <entry name="log-collector">
          <server>
            <entry name="collector-1">
              <address>logs.example.com</address>
              <protocol>HTTP</protocol>
              <port>8080</port>
              <http-method>GET</http-method>
            </entry>
          </server>
        </entry>
        """))
        assert export_http_server_profiles(root) == [{
            "name": "log-collector",
            "server": [{
                "name": "collector-1", "address": "logs.example.com",
                "protocol": "HTTP", "port": 8080, "http_method": "GET",
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
        servers = export_http_server_profiles(root)[0]["server"]
        assert servers[0] == {
            "name": "minimal", "address": "", "protocol": "HTTPS",
            "port": 443, "http_method": "POST",
        }
        assert servers[1]["port"] == 443  # invalid → default

    def test_profile_without_servers(self):
        root = vsys_root(_profiles('<entry name="empty"/>'))
        assert export_http_server_profiles(root) == [{"name": "empty"}]

    def test_sorted_case_insensitive(self):
        root = vsys_root(_profiles('<entry name="Z-http"/><entry name="a-http"/>'))
        assert [p["name"] for p in export_http_server_profiles(root)] == ["a-http", "Z-http"]
