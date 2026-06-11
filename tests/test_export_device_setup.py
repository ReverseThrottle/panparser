"""Unit tests for export_management_interface(), export_service_settings(),
and export_service_routes()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import (
    export_management_interface,
    export_service_settings,
    export_service_routes,
)


def _root(system_xml: str) -> ET.Element:
    """Wrap system XML fragment in the full config tree structure."""
    return ET.fromstring(
        f"<config>"
        f"  <devices>"
        f"    <entry name='localhost.localdomain'>"
        f"      <deviceconfig>"
        f"        <system>{system_xml}</system>"
        f"      </deviceconfig>"
        f"    </entry>"
        f"  </devices>"
        f"</config>"
    )


def _root_no_system() -> ET.Element:
    """Config root with no deviceconfig/system element."""
    return ET.fromstring("<config><devices><entry name='x'/></devices></config>")


def _empty_root() -> ET.Element:
    return ET.fromstring("<config/>")


# ── export_management_interface ────────────────────────────────────────────────

class TestExportManagementInterface:
    def test_returns_empty_dict_when_root_has_no_system(self):
        assert export_management_interface(_empty_root()) == {}

    def test_returns_empty_dict_when_no_devices_entry(self):
        assert export_management_interface(_root_no_system()) == {}

    def test_returns_empty_dict_when_system_has_no_relevant_fields(self):
        result = export_management_interface(_root("<hostname>fw01</hostname>"))
        assert result == {}

    def test_permitted_ip_entries(self):
        xml = """
        <permitted-ip>
          <entry name="10.250.98.0/24"/>
          <entry name="10.250.100.0/24"/>
        </permitted-ip>
        """
        result = export_management_interface(_root(xml))
        assert result["permitted_ip"] == ["10.250.98.0/24", "10.250.100.0/24"]

    def test_empty_permitted_ip_element_excluded(self):
        result = export_management_interface(_root("<permitted-ip/>"))
        assert "permitted_ip" not in result

    def test_protocol_flags_yes_maps_to_true(self):
        xml = "<ssh>yes</ssh><https>yes</https><ping>yes</ping><snmp>yes</snmp>"
        result = export_management_interface(_root(xml))
        assert result["ssh"] is True
        assert result["https"] is True
        assert result["ping"] is True
        assert result["snmp"] is True

    def test_protocol_flag_no_maps_to_false(self):
        result = export_management_interface(_root("<telnet>no</telnet>"))
        assert result["telnet"] is False

    def test_absent_protocol_flag_not_included(self):
        result = export_management_interface(_root("<ssh>yes</ssh>"))
        assert "telnet" not in result
        assert "https" not in result

    def test_ssh_port_override(self):
        result = export_management_interface(_root("<ssh-port>2222</ssh-port>"))
        assert result["ssh_port"] == 2222

    def test_https_port_override(self):
        result = export_management_interface(_root("<https-port>8443</https-port>"))
        assert result["https_port"] == 8443

    def test_invalid_port_value_excluded(self):
        result = export_management_interface(_root("<ssh-port>bogus</ssh-port>"))
        assert "ssh_port" not in result

    def test_full_management_interface(self):
        xml = """
        <permitted-ip>
          <entry name="10.250.98.0/24"/>
          <entry name="10.250.100.0/24"/>
        </permitted-ip>
        <ssh>yes</ssh>
        <https>yes</https>
        <ping>yes</ping>
        <snmp>yes</snmp>
        <telnet>no</telnet>
        """
        result = export_management_interface(_root(xml))
        assert result["permitted_ip"] == ["10.250.98.0/24", "10.250.100.0/24"]
        assert result["ssh"] is True
        assert result["https"] is True
        assert result["ping"] is True
        assert result["snmp"] is True
        assert result["telnet"] is False


# ── export_service_settings ────────────────────────────────────────────────────

class TestExportServiceSettings:
    def test_returns_empty_dict_when_no_system(self):
        assert export_service_settings(_empty_root()) == {}

    def test_returns_empty_dict_when_system_has_no_relevant_fields(self):
        result = export_service_settings(_root("<hostname>fw01</hostname>"))
        assert result == {}

    def test_ntp_primary(self):
        xml = """
        <ntp-servers>
          <primary-ntp-server>
            <ntp-server-address>pool.ntp.org</ntp-server-address>
          </primary-ntp-server>
        </ntp-servers>
        """
        result = export_service_settings(_root(xml))
        assert result["ntp_primary"] == "pool.ntp.org"

    def test_ntp_secondary(self):
        xml = """
        <ntp-servers>
          <secondary-ntp-server>
            <ntp-server-address>time.cloudflare.com</ntp-server-address>
          </secondary-ntp-server>
        </ntp-servers>
        """
        result = export_service_settings(_root(xml))
        assert result["ntp_secondary"] == "time.cloudflare.com"

    def test_dns_primary_and_secondary(self):
        xml = """
        <dns-setting>
          <servers>
            <primary>10.250.250.250</primary>
            <secondary>10.250.250.251</secondary>
          </servers>
        </dns-setting>
        """
        result = export_service_settings(_root(xml))
        assert result["dns_primary"] == "10.250.250.250"
        assert result["dns_secondary"] == "10.250.250.251"

    def test_login_banner(self):
        xml = "<login-banner>Authorized access only</login-banner>"
        result = export_service_settings(_root(xml))
        assert result["login_banner"] == "Authorized access only"

    def test_update_server(self):
        xml = "<update-server>updates.paloaltonetworks.com</update-server>"
        result = export_service_settings(_root(xml))
        assert result["update_server"] == "updates.paloaltonetworks.com"

    def test_absent_fields_not_included(self):
        xml = "<update-server>updates.paloaltonetworks.com</update-server>"
        result = export_service_settings(_root(xml))
        assert "ntp_primary" not in result
        assert "ntp_secondary" not in result
        assert "dns_primary" not in result
        assert "login_banner" not in result

    def test_full_service_settings(self):
        xml = """
        <ntp-servers>
          <primary-ntp-server>
            <ntp-server-address>pool.ntp.org</ntp-server-address>
          </primary-ntp-server>
          <secondary-ntp-server>
            <ntp-server-address>time.cloudflare.com</ntp-server-address>
          </secondary-ntp-server>
        </ntp-servers>
        <dns-setting>
          <servers>
            <primary>10.250.250.250</primary>
            <secondary>10.250.250.251</secondary>
          </servers>
        </dns-setting>
        <login-banner>Authorized access only</login-banner>
        <update-server>updates.paloaltonetworks.com</update-server>
        """
        result = export_service_settings(_root(xml))
        assert result["ntp_primary"] == "pool.ntp.org"
        assert result["ntp_secondary"] == "time.cloudflare.com"
        assert result["dns_primary"] == "10.250.250.250"
        assert result["dns_secondary"] == "10.250.250.251"
        assert result["login_banner"] == "Authorized access only"
        assert result["update_server"] == "updates.paloaltonetworks.com"

    def test_real_440_config_fields(self):
        """Matches the structure seen in 440-config.xml."""
        xml = """
        <ntp-servers>
          <primary-ntp-server>
            <ntp-server-address>pool.ntp.org</ntp-server-address>
          </primary-ntp-server>
          <secondary-ntp-server>
            <ntp-server-address>0.north-america.pool.ntp.org</ntp-server-address>
          </secondary-ntp-server>
        </ntp-servers>
        <dns-setting>
          <servers>
            <primary>10.250.250.250</primary>
            <secondary>10.250.250.251</secondary>
          </servers>
        </dns-setting>
        <login-banner>insanity is doing the same thing over and over and expecting different results</login-banner>
        <update-server>updates.paloaltonetworks.com</update-server>
        """
        result = export_service_settings(_root(xml))
        assert result["ntp_primary"] == "pool.ntp.org"
        assert result["ntp_secondary"] == "0.north-america.pool.ntp.org"
        assert result["dns_primary"] == "10.250.250.250"
        assert result["dns_secondary"] == "10.250.250.251"
        assert "insanity" in result["login_banner"]


# ── export_service_routes ──────────────────────────────────────────────────────

class TestExportServiceRoutes:
    def test_returns_empty_list_when_no_system(self):
        assert export_service_routes(_empty_root()) == []

    def test_returns_empty_list_when_no_route_element(self):
        result = export_service_routes(_root("<hostname>fw01</hostname>"))
        assert result == []

    def test_returns_empty_list_when_no_service_entries(self):
        result = export_service_routes(_root("<route><service/></route>"))
        assert result == []

    def test_single_route_interface_only(self):
        xml = """
        <route>
          <service>
            <entry name="dns">
              <source-address>
                <interface>management</interface>
              </source-address>
            </entry>
          </service>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0]["service"] == "dns"
        assert result[0]["interface"] == "management"
        assert "source_ip" not in result[0]

    def test_route_with_source_ip(self):
        xml = """
        <route>
          <service>
            <entry name="ntp">
              <source-address>
                <interface>management</interface>
                <ip-address>10.250.100.5</ip-address>
              </source-address>
            </entry>
          </service>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert result[0]["source_ip"] == "10.250.100.5"

    def test_multiple_service_routes(self):
        xml = """
        <route>
          <service>
            <entry name="dns">
              <source-address><interface>management</interface></source-address>
            </entry>
            <entry name="ntp">
              <source-address><interface>management</interface></source-address>
            </entry>
            <entry name="syslog">
              <source-address><interface>ethernet1/1</interface></source-address>
            </entry>
          </service>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 3
        names = [r["service"] for r in result]
        assert "dns" in names
        assert "ntp" in names
        assert "syslog" in names

    def test_entry_with_no_interface_excluded_gracefully(self):
        xml = """
        <route>
          <service>
            <entry name="dns"/>
          </service>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0] == {"service": "dns"}
