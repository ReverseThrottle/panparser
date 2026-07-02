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

    def test_ip_addressing_captured(self):
        xml = """
        <ip-address>192.168.10.213</ip-address>
        <netmask>255.255.255.0</netmask>
        <default-gateway>192.168.10.1</default-gateway>
        """
        result = export_management_interface(_root(xml))
        assert result["ip_address"] == "192.168.10.213"
        assert result["netmask"] == "255.255.255.0"
        assert result["default_gateway"] == "192.168.10.1"

    def test_type_static(self):
        result = export_management_interface(_root("<type><static/></type>"))
        assert result["type"] == "static"

    def test_type_dhcp_client(self):
        result = export_management_interface(_root("<type><dhcp-client/></type>"))
        assert result["type"] == "dhcp-client"

    def test_type_absent_when_no_type_element(self):
        result = export_management_interface(_root("<hostname>fw01</hostname>"))
        assert "type" not in result

    def test_permitted_ip_entries(self):
        xml = """
        <permitted-ip>
          <entry name="10.250.98.0/24"/>
          <entry name="10.250.100.0/24"/>
        </permitted-ip>
        """
        result = export_management_interface(_root(xml))
        assert result["permitted_ip"] == ["10.250.98.0/24", "10.250.100.0/24"]
        assert "permitted_ip_descriptions" not in result

    def test_empty_permitted_ip_element_excluded(self):
        result = export_management_interface(_root("<permitted-ip/>"))
        assert "permitted_ip" not in result

    def test_permitted_ip_descriptions_captured_separately(self):
        xml = """
        <permitted-ip>
          <entry name="137.229.21.128/26">
            <description>RCS Elvey Office LAN</description>
          </entry>
          <entry name="137.229.0.0/24"/>
        </permitted-ip>
        """
        result = export_management_interface(_root(xml))
        assert result["permitted_ip"] == ["137.229.21.128/26", "137.229.0.0/24"]
        assert result["permitted_ip_descriptions"] == {
            "137.229.21.128/26": "RCS Elvey Office LAN"
        }

    def test_protocol_flags_disable_yes_maps_to_false(self):
        xml = """
        <service>
          <disable-ssh>yes</disable-ssh>
          <disable-https>yes</disable-https>
          <disable-telnet>yes</disable-telnet>
          <disable-http>yes</disable-http>
        </service>
        """
        result = export_management_interface(_root(xml))
        assert result["ssh"] is False
        assert result["https"] is False
        assert result["telnet"] is False
        assert result["http"] is False

    def test_protocol_flag_disable_no_maps_to_true(self):
        xml = "<service><disable-telnet>no</disable-telnet></service>"
        result = export_management_interface(_root(xml))
        assert result["telnet"] is True

    def test_absent_protocol_flag_not_included(self):
        xml = "<service><disable-ssh>yes</disable-ssh></service>"
        result = export_management_interface(_root(xml))
        assert "ssh" in result
        assert "telnet" not in result
        assert "https" not in result
        assert "http" not in result

    def test_top_level_protocol_tags_no_longer_read(self):
        """Old (buggy) shape: ssh/https/telnet as direct children of <system>.

        Real PAN-OS configs nest these under service/disable-*, so the
        direct-child tags must no longer be interpreted as flags.
        """
        xml = "<ssh>yes</ssh><https>yes</https><telnet>no</telnet>"
        result = export_management_interface(_root(xml))
        assert "ssh" not in result
        assert "https" not in result
        assert "telnet" not in result

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
        <ip-address>192.168.10.213</ip-address>
        <netmask>255.255.255.0</netmask>
        <default-gateway>192.168.10.1</default-gateway>
        <type><static/></type>
        <service>
          <disable-telnet>yes</disable-telnet>
          <disable-http>yes</disable-http>
        </service>
        <permitted-ip>
          <entry name="10.250.98.0/24">
            <description>RCS Elvey Office LAN</description>
          </entry>
          <entry name="10.250.100.0/24"/>
        </permitted-ip>
        """
        result = export_management_interface(_root(xml))
        assert result["ip_address"] == "192.168.10.213"
        assert result["netmask"] == "255.255.255.0"
        assert result["default_gateway"] == "192.168.10.1"
        assert result["type"] == "static"
        assert result["permitted_ip"] == ["10.250.98.0/24", "10.250.100.0/24"]
        assert result["permitted_ip_descriptions"] == {
            "10.250.98.0/24": "RCS Elvey Office LAN"
        }
        assert result["telnet"] is False
        assert result["http"] is False
        assert "ssh" not in result
        assert "https" not in result


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
        # Real PAN-OS schema: route/service/entry/source/interface (not
        # source-address/interface — see issue #23).
        xml = """
        <route>
          <service>
            <entry name="dns">
              <source>
                <interface>management</interface>
              </source>
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
        # Real PAN-OS schema uses source/address, not
        # source-address/ip-address (see UA-HAARP-Cofnig_20260605.xml).
        xml = """
        <route>
          <service>
            <entry name="ntp">
              <source>
                <interface>management</interface>
                <address>10.250.100.5</address>
              </source>
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
              <source><interface>management</interface></source>
            </entry>
            <entry name="ntp">
              <source><interface>management</interface></source>
            </entry>
            <entry name="syslog">
              <source><interface>ethernet1/1</interface></source>
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

    def test_entry_with_blank_name_skipped(self):
        xml = """
        <route>
          <service>
            <entry name="">
              <source><interface>management</interface></source>
            </entry>
            <entry name="ntp">
              <source><interface>management</interface></source>
            </entry>
          </service>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0]["service"] == "ntp"

    def test_returns_empty_list_when_no_destination_entries(self):
        result = export_service_routes(_root("<route><destination/></route>"))
        assert result == []

    def test_single_destination_route(self):
        # Mirrors UA-HAARP-Cofnig_20260605.xml's route/destination/entry
        # shape, which is a completely separate construct from
        # route/service and was previously never read at all.
        xml = """
        <route>
          <destination>
            <entry name="10.36.0.25">
              <source>
                <interface>ethernet1/7.360</interface>
                <address>10.36.0.1/24</address>
              </source>
            </entry>
          </destination>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0]["destination"] == "10.36.0.25"
        assert result[0]["interface"] == "ethernet1/7.360"
        assert result[0]["source_ip"] == "10.36.0.1/24"

    def test_destination_entry_with_no_interface_excluded_gracefully(self):
        xml = """
        <route>
          <destination>
            <entry name="10.36.0.25"/>
          </destination>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0] == {"destination": "10.36.0.25"}

    def test_destination_entry_with_blank_name_skipped(self):
        xml = """
        <route>
          <destination>
            <entry name="">
              <source><interface>ethernet1/1</interface></source>
            </entry>
            <entry name="10.36.0.25">
              <source><interface>ethernet1/7.360</interface></source>
            </entry>
          </destination>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 1
        assert result[0]["destination"] == "10.36.0.25"

    def test_service_and_destination_routes_both_present(self):
        # Full repro from issue #23: one route/service entry ("ntp") and
        # one route/destination entry ("10.36.0.25"), both with
        # source/interface and source/address populated.
        xml = """
        <route>
          <service>
            <entry name="ntp">
              <source>
                <address>137.229.36.1/24</address>
                <interface>ethernet1/7.36</interface>
              </source>
            </entry>
          </service>
          <destination>
            <entry name="10.36.0.25">
              <source>
                <interface>ethernet1/7.360</interface>
                <address>10.36.0.1/24</address>
              </source>
            </entry>
          </destination>
        </route>
        """
        result = export_service_routes(_root(xml))
        assert len(result) == 2

        service_route = next(r for r in result if "service" in r)
        assert service_route["service"] == "ntp"
        assert service_route["interface"] == "ethernet1/7.36"
        assert service_route["source_ip"] == "137.229.36.1/24"

        destination_route = next(r for r in result if "destination" in r)
        assert destination_route["destination"] == "10.36.0.25"
        assert destination_route["interface"] == "ethernet1/7.360"
        assert destination_route["source_ip"] == "10.36.0.1/24"

    def test_login_banner_is_stripped(self):
        xml = "<login-banner>  Authorized access only  </login-banner>"
        result = export_service_settings(_root(xml))
        assert result["login_banner"] == "Authorized access only"
