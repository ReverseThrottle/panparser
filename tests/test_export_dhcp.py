"""Unit tests for export_dhcp_servers()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_dhcp_servers


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportDHCPServers:
    def test_returns_empty_when_network_root_none(self):
        assert export_dhcp_servers(None) == []

    def test_returns_empty_when_no_dhcp_element(self):
        assert export_dhcp_servers(_net("<interface/>")) == []

    def test_returns_empty_when_no_interface_element_under_dhcp(self):
        assert export_dhcp_servers(_net("<dhcp/>")) == []

    def test_returns_empty_when_no_entries(self):
        xml = "<dhcp><interface/></dhcp>"
        assert export_dhcp_servers(_net(xml)) == []

    def test_entry_with_blank_name_skipped(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="">
              <server><mode>auto</mode></server>
            </entry>
          </interface>
        </dhcp>
        """
        assert export_dhcp_servers(_net(xml)) == []

    def test_entry_with_no_server_element_skipped(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="ethernet1/7.192"/>
          </interface>
        </dhcp>
        """
        assert export_dhcp_servers(_net(xml)) == []

    def test_minimal_entry_name_only(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="ethernet1/7.192">
              <server/>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert result == [{"interface": "ethernet1/7.192"}]

    def test_full_dhcp_server_config(self):
        """Matches the ethernet1/7.192 fragment from UA-HAARP-Cofnig_20260605.xml (issue #21)."""
        xml = """
        <dhcp>
          <interface>
            <entry name="ethernet1/7.192">
              <server>
                <option>
                  <dns>
                    <primary>137.229.36.30</primary>
                    <secondary>137.229.30.66</secondary>
                  </dns>
                  <lease><timeout>10080</timeout></lease>
                  <gateway>192.168.1.1</gateway>
                  <subnet-mask>255.255.255.0</subnet-mask>
                </option>
                <ip-pool>
                  <member>192.168.1.2-192.168.1.249</member>
                </ip-pool>
                <reserved>
                  <entry name="192.168.1.16"><mac>00:20:6b:5e:e4:f7</mac></entry>
                  <entry name="192.168.1.193"><mac>5c:62:8b:a6:e8:4c</mac></entry>
                  <entry name="192.168.1.195"><mac>f8:ca:b8:0a:41:58</mac></entry>
                </reserved>
                <mode>auto</mode>
                <probe-ip>yes</probe-ip>
              </server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert len(result) == 1
        d = result[0]
        assert d["interface"] == "ethernet1/7.192"
        assert d["mode"] == "auto"
        assert d["probe_ip"] is True
        assert d["dns_primary"] == "137.229.36.30"
        assert d["dns_secondary"] == "137.229.30.66"
        assert d["lease_timeout"] == 10080
        assert d["gateway"] == "192.168.1.1"
        assert d["subnet_mask"] == "255.255.255.0"
        assert d["ip_pool"] == ["192.168.1.2-192.168.1.249"]
        assert d["reserved"] == [
            {"ip": "192.168.1.16", "mac": "00:20:6b:5e:e4:f7"},
            {"ip": "192.168.1.193", "mac": "5c:62:8b:a6:e8:4c"},
            {"ip": "192.168.1.195", "mac": "f8:ca:b8:0a:41:58"},
        ]

    def test_probe_ip_no_maps_to_false(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server><probe-ip>no</probe-ip></server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert result[0]["probe_ip"] is False

    def test_invalid_lease_timeout_excluded(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server><option><lease><timeout>bogus</timeout></lease></option></server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert "lease_timeout" not in result[0]

    def test_multiple_ip_pool_members(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server>
                <ip-pool>
                  <member>10.0.0.2-10.0.0.100</member>
                  <member>10.0.0.150-10.0.0.200</member>
                </ip-pool>
              </server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert result[0]["ip_pool"] == [
            "10.0.0.2-10.0.0.100", "10.0.0.150-10.0.0.200",
        ]

    def test_reserved_entry_with_blank_name_skipped(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server>
                <reserved>
                  <entry name=""><mac>00:11:22:33:44:55</mac></entry>
                  <entry name="10.0.0.5"><mac>aa:bb:cc:dd:ee:ff</mac></entry>
                </reserved>
              </server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert result[0]["reserved"] == [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff"}]

    def test_no_reserved_key_when_empty(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server><reserved/></server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert "reserved" not in result[0]

    def test_sorted_by_interface_name(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="ethernet1/9.100"><server><mode>auto</mode></server></entry>
            <entry name="ethernet1/2.10"><server><mode>auto</mode></server></entry>
            <entry name="ethernet1/7.192"><server><mode>auto</mode></server></entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert [d["interface"] for d in result] == [
            "ethernet1/2.10", "ethernet1/7.192", "ethernet1/9.100",
        ]

    def test_multiple_dhcp_server_entries(self):
        xml = """
        <dhcp>
          <interface>
            <entry name="eth1/1.10">
              <server><mode>auto</mode></server>
            </entry>
            <entry name="eth1/2.20">
              <server><mode>relay</mode></server>
            </entry>
          </interface>
        </dhcp>
        """
        result = export_dhcp_servers(_net(xml))
        assert len(result) == 2
        assert result[0]["mode"] == "auto"
        assert result[1]["mode"] == "relay"
