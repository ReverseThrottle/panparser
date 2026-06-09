"""Unit tests for export_lldp_profiles()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_lldp_profiles


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportLLDPProfiles:
    def test_returns_empty_when_network_root_none(self):
        assert export_lldp_profiles(None) == []

    def test_returns_empty_when_no_profiles_element(self):
        assert export_lldp_profiles(_net("<profiles/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_lldp_profiles(_net("<profiles><lldp-profile/></profiles>")) == []

    def test_minimal_profile_name_only(self):
        xml = '<profiles><lldp-profile><entry name="Basic"/></lldp-profile></profiles>'
        result = export_lldp_profiles(_net(xml))
        assert result == [{"name": "Basic"}]

    def test_full_option_tlvs(self):
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="LLDP-Profile-Default">
              <mode>tx-rx</mode>
              <snmp-syslog-notification>no</snmp-syslog-notification>
              <option-tlvs>
                <port-description>yes</port-description>
                <system-name>yes</system-name>
                <system-description>yes</system-description>
                <system-capabilities>yes</system-capabilities>
                <management-address>
                  <enabled>no</enabled>
                </management-address>
              </option-tlvs>
            </entry>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        assert len(result) == 1
        p = result[0]
        assert p["name"] == "LLDP-Profile-Default"
        assert p["mode"] == "tx-rx"
        assert p["snmp_syslog_notification"] is False
        tlvs = p["option_tlvs"]
        assert tlvs["port_description"] is True
        assert tlvs["system_name"] is True
        assert tlvs["system_description"] is True
        assert tlvs["system_capabilities"] is True
        assert tlvs["management_address"]["enabled"] is False

    def test_option_tlvs_partial(self):
        """Only port_description present; absent keys are not included."""
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="Partial">
              <option-tlvs>
                <port-description>yes</port-description>
              </option-tlvs>
            </entry>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        assert result[0]["option_tlvs"] == {"port_description": True}

    def test_management_address_with_iplist(self):
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="WithIPList">
              <option-tlvs>
                <management-address>
                  <enabled>yes</enabled>
                  <iplist>
                    <entry>
                      <name>mgmt-ip</name>
                      <interface>mgmt</interface>
                      <ipv4>10.0.0.1</ipv4>
                      <ipv6></ipv6>
                    </entry>
                  </iplist>
                </management-address>
              </option-tlvs>
            </entry>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        mgmt = result[0]["option_tlvs"]["management_address"]
        assert mgmt["enabled"] is True
        assert mgmt["iplist"] == [
            {"name": "mgmt-ip", "interface": "mgmt", "ipv4": "10.0.0.1", "ipv6": ""}
        ]

    def test_sorted_by_name(self):
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="Zebra"/>
            <entry name="Alpha"/>
            <entry name="Middle"/>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        assert [p["name"] for p in result] == ["Alpha", "Middle", "Zebra"]

    def test_multiple_profiles(self):
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="Prof-A"><mode>tx-only</mode></entry>
            <entry name="Prof-B"><mode>rx-only</mode></entry>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        assert len(result) == 2
        assert result[0]["mode"] == "tx-only"
        assert result[1]["mode"] == "rx-only"

    def test_snmp_yes_maps_to_true(self):
        xml = """
        <profiles>
          <lldp-profile>
            <entry name="SnmpOn">
              <snmp-syslog-notification>yes</snmp-syslog-notification>
            </entry>
          </lldp-profile>
        </profiles>
        """
        result = export_lldp_profiles(_net(xml))
        assert result[0]["snmp_syslog_notification"] is True

    def test_no_option_tlvs_when_all_absent(self):
        """If option-tlvs element is missing entirely, option_tlvs key is absent."""
        xml = '<profiles><lldp-profile><entry name="NoTlvs"><mode>disable</mode></entry></lldp-profile></profiles>'
        result = export_lldp_profiles(_net(xml))
        assert "option_tlvs" not in result[0]
        assert result[0]["mode"] == "disable"
