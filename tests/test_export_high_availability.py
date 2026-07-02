"""Unit tests for export_high_availability()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_high_availability


def _root(ha_xml: str) -> ET.Element:
    """Wrap high-availability XML fragment in the full config tree structure."""
    return ET.fromstring(
        f"<config>"
        f"  <devices>"
        f"    <entry name='localhost.localdomain'>"
        f"      <deviceconfig>"
        f"        <high-availability>{ha_xml}</high-availability>"
        f"      </deviceconfig>"
        f"    </entry>"
        f"  </devices>"
        f"</config>"
    )


def _root_no_ha() -> ET.Element:
    """Config root with no deviceconfig/high-availability element."""
    return ET.fromstring("<config><devices><entry name='x'/></devices></config>")


def _empty_root() -> ET.Element:
    return ET.fromstring("<config/>")


class TestExportHighAvailability:
    def test_returns_empty_dict_when_root_has_no_ha_element(self):
        assert export_high_availability(_empty_root()) == {}

    def test_returns_empty_dict_when_no_devices_entry(self):
        assert export_high_availability(_root_no_ha()) == {}

    def test_returns_empty_dict_when_enabled_is_no(self):
        result = export_high_availability(_root("<enabled>no</enabled>"))
        assert result == {}

    def test_returns_empty_dict_when_enabled_missing(self):
        xml = """
        <group>
          <group-id>1</group-id>
        </group>
        """
        result = export_high_availability(_root(xml))
        assert result == {}

    def test_enabled_yes_sets_enabled_true(self):
        result = export_high_availability(_root("<enabled>yes</enabled>"))
        assert result["enabled"] is True

    def test_group_id_parsed_as_int(self):
        xml = "<group><group-id>1</group-id></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert result["group_id"] == 1

    def test_group_id_non_numeric_kept_as_string(self):
        xml = "<group><group-id>bogus</group-id></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert result["group_id"] == "bogus"

    def test_description(self):
        xml = "<group><description>HAARP-HA-Config</description></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert result["description"] == "HAARP-HA-Config"

    def test_peer_ip(self):
        xml = "<group><peer-ip>192.168.10.223</peer-ip></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert result["peer_ip"] == "192.168.10.223"

    def test_mode_active_passive(self):
        xml = """
        <group>
          <mode><active-passive><passive-link-state>auto</passive-link-state></active-passive></mode>
        </group>
        <enabled>yes</enabled>
        """
        result = export_high_availability(_root(xml))
        assert result["mode"] == "active-passive"

    def test_mode_active_active(self):
        xml = "<group><mode><active-active/></mode></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert result["mode"] == "active-active"

    def test_mode_absent_when_empty(self):
        xml = "<group><mode/></group><enabled>yes</enabled>"
        result = export_high_availability(_root(xml))
        assert "mode" not in result

    def test_election_priority(self):
        xml = """
        <group>
          <election-option>
            <device-priority>95</device-priority>
          </election-option>
        </group>
        <enabled>yes</enabled>
        """
        result = export_high_availability(_root(xml))
        assert result["election_priority"] == 95

    def test_interface_ha2_bindings(self):
        xml = """
        <interface>
          <ha2>
            <port>ethernet1/3</port>
            <ip-address>10.10.36.1</ip-address>
            <netmask>255.255.255.0</netmask>
          </ha2>
        </interface>
        <enabled>yes</enabled>
        """
        result = export_high_availability(_root(xml))
        assert result["interfaces"]["ha2"] == {
            "port": "ethernet1/3",
            "ip_address": "10.10.36.1",
            "netmask": "255.255.255.0",
        }

    def test_empty_interface_children_excluded(self):
        xml = """
        <interface>
          <ha1 />
          <ha1-backup />
          <ha2>
            <port>ethernet1/3</port>
          </ha2>
          <ha2-backup />
          <ha3 />
        </interface>
        <enabled>yes</enabled>
        """
        result = export_high_availability(_root(xml))
        assert list(result["interfaces"].keys()) == ["ha2"]
        assert result["interfaces"]["ha2"] == {"port": "ethernet1/3"}

    def test_no_interfaces_key_when_no_bindings(self):
        result = export_high_availability(_root("<enabled>yes</enabled>"))
        assert "interfaces" not in result

    def test_full_haarp_config(self):
        """Matches the structure seen in UA-HAARP-Cofnig_20260605.xml."""
        xml = """
        <interface>
          <ha1 />
          <ha1-backup />
          <ha2>
            <port>ethernet1/3</port>
            <ip-address>10.10.36.1</ip-address>
            <netmask>255.255.255.0</netmask>
          </ha2>
          <ha2-backup />
          <ha3 />
        </interface>
        <group>
          <group-id>1</group-id>
          <description>HAARP-HA-Config</description>
          <peer-ip>192.168.10.223</peer-ip>
          <state-synchronization>
            <ha2-keep-alive><enabled>yes</enabled></ha2-keep-alive>
            <transport>ip</transport>
          </state-synchronization>
          <mode>
            <active-passive><passive-link-state>auto</passive-link-state></active-passive>
          </mode>
          <election-option>
            <device-priority>95</device-priority>
            <timers><recommended /></timers>
          </election-option>
          <monitoring>
            <link-monitoring>
              <link-group>
                <entry name="Link1.3">
                  <interface><member>ethernet1/3</member></interface>
                </entry>
              </link-group>
            </link-monitoring>
          </monitoring>
        </group>
        <enabled>yes</enabled>
        """
        result = export_high_availability(_root(xml))
        assert result["enabled"] is True
        assert result["group_id"] == 1
        assert result["description"] == "HAARP-HA-Config"
        assert result["peer_ip"] == "192.168.10.223"
        assert result["mode"] == "active-passive"
        assert result["election_priority"] == 95
        assert result["interfaces"]["ha2"] == {
            "port": "ethernet1/3",
            "ip_address": "10.10.36.1",
            "netmask": "255.255.255.0",
        }
        assert "ha1" not in result["interfaces"]
        assert "ha3" not in result["interfaces"]
