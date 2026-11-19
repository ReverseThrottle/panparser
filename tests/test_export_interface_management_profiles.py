"""Field-asserting tests for export_interface_management_profiles() — #92 backfill."""
from __future__ import annotations

from export.objects import export_interface_management_profiles
from export_fixtures import network_root


def _profiles(inner: str) -> str:
    return f"<profiles><interface-management-profile>{inner}</interface-management-profile></profiles>"


class TestExportInterfaceManagementProfiles:
    def test_none_root(self):
        assert export_interface_management_profiles(None) == []

    def test_missing_container(self):
        assert export_interface_management_profiles(network_root("<profiles><monitor-profile/></profiles>")) == []

    def test_empty_container(self):
        assert export_interface_management_profiles(network_root(_profiles(""))) == []

    def test_all_service_flags_and_permitted_ip(self):
        root = network_root(_profiles("""
        <entry name="mgmt-full">
          <http/><https/><telnet/><ssh/><ping/><snmp/>
          <http-ocsp/><response-pages/><userid-service/>
          <userid-syslog-listener-ssl/><userid-syslog-listener-udp/>
          <permitted-ip>
            <entry name="10.0.0.0/8"/>
            <entry name="192.168.1.0/24"/>
            <entry/>
          </permitted-ip>
        </entry>
        """))
        assert export_interface_management_profiles(root) == [{
            "name": "mgmt-full",
            "http": True, "https": True, "telnet": True, "ssh": True,
            "ping": True, "snmp": True,
            "http_ocsp": True, "response_pages": True, "userid_service": True,
            "userid_syslog_listener_ssl": True, "userid_syslog_listener_udp": True,
            "permitted_ip": ["10.0.0.0/8", "192.168.1.0/24"],  # unnamed entry dropped
        }]

    def test_minimal_profile_and_empty_permitted_ip(self):
        root = network_root(_profiles("""
        <entry name="ping-only"><ping/></entry>
        <entry name="no-flags"><permitted-ip/></entry>
        """))
        assert export_interface_management_profiles(root) == [
            {"name": "ping-only", "ping": True},
            {"name": "no-flags"},
        ]

    def test_document_order_preserved(self):
        root = network_root(_profiles('<entry name="z-mgmt"/><entry name="a-mgmt"/>'))
        assert [p["name"] for p in export_interface_management_profiles(root)] == ["z-mgmt", "a-mgmt"]
