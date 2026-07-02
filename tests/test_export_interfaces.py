"""Unit tests for export_ethernet_interfaces() and export_aggregate_interfaces()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_ethernet_interfaces, export_aggregate_interfaces


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


# ── export_ethernet_interfaces ─────────────────────────────────────────────────

class TestExportEthernetInterfaces:
    def test_returns_empty_when_network_root_none(self):
        assert export_ethernet_interfaces(None) == ([], [])

    def test_returns_empty_when_no_ethernet_container(self):
        assert export_ethernet_interfaces(_net("<interface/>")) == ([], [])

    def test_static_ip_interface_has_no_dhcp_client(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip><entry name="10.250.98.1/24"/></ip>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        assert len(parents) == 1
        assert parents[0]["layer3"]["ip"] == [{"name": "10.250.98.1/24"}]
        assert "dhcp_client" not in parents[0]["layer3"]

    def test_dhcp_client_interface_populates_dhcp_client(self):
        """Regression test for issue #18: a <dhcp-client>-addressed interface
        with no <ip> entries must not export as an empty layer3 dict."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/8">
              <layer3>
                <ipv6>
                  <neighbor-discovery>
                    <router-advertisement>
                      <enable>no</enable>
                    </router-advertisement>
                  </neighbor-discovery>
                </ipv6>
                <ndp-proxy>
                  <enabled>no</enabled>
                </ndp-proxy>
                <dhcp-client>
                  <create-default-route>no</create-default-route>
                </dhcp-client>
                <lldp>
                  <enable>no</enable>
                </lldp>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        assert len(parents) == 1
        layer3 = parents[0]["layer3"]
        assert layer3 != {}
        assert "ip" not in layer3
        assert layer3["dhcp_client"] == {"create_default_route": False}

    def test_dhcp_client_create_default_route_yes(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/2">
              <layer3>
                <dhcp-client>
                  <create-default-route>yes</create-default-route>
                </dhcp-client>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        assert parents[0]["layer3"]["dhcp_client"] == {"create_default_route": True}

    def test_dhcp_client_with_default_route_metric(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/3">
              <layer3>
                <dhcp-client>
                  <create-default-route>yes</create-default-route>
                  <default-route-metric>25</default-route-metric>
                </dhcp-client>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        dhcp = parents[0]["layer3"]["dhcp_client"]
        assert dhcp["create_default_route"] is True
        assert dhcp["default_route_metric"] == 25

    def test_dhcp_client_with_no_sub_elements(self):
        """An empty <dhcp-client/> still marks the interface as DHCP-addressed."""
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/4">
              <layer3>
                <dhcp-client/>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        assert parents[0]["layer3"]["dhcp_client"] == {}

    def test_layer2_interface_unaffected(self):
        xml = """
        <interface>
          <ethernet>
            <entry name="ethernet1/5">
              <layer2/>
            </entry>
          </ethernet>
        </interface>
        """
        parents, subs = export_ethernet_interfaces(_net(xml))
        assert parents[0]["layer2"] == {}
        assert "layer3" not in parents[0]


# ── export_aggregate_interfaces ────────────────────────────────────────────────

class TestExportAggregateInterfaces:
    def test_returns_empty_when_network_root_none(self):
        assert export_aggregate_interfaces(None) == ([], [])

    def test_returns_empty_when_no_aggregate_container(self):
        assert export_aggregate_interfaces(_net("<interface/>")) == ([], [])

    def test_dhcp_client_interface_populates_dhcp_client(self):
        """Aggregate interfaces mirror the same dhcp-client fix as ethernet."""
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae1">
              <layer3>
                <dhcp-client>
                  <create-default-route>no</create-default-route>
                </dhcp-client>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs = export_aggregate_interfaces(_net(xml))
        assert len(parents) == 1
        layer3 = parents[0]["layer3"]
        assert layer3 != {}
        assert layer3["dhcp_client"] == {"create_default_route": False}

    def test_static_ip_interface_has_no_dhcp_client(self):
        xml = """
        <interface>
          <aggregate-ethernet>
            <entry name="ae2">
              <layer3>
                <ip><entry name="10.250.110.1/24"/></ip>
              </layer3>
            </entry>
          </aggregate-ethernet>
        </interface>
        """
        parents, subs = export_aggregate_interfaces(_net(xml))
        assert parents[0]["layer3"]["ip"] == [{"name": "10.250.110.1/24"}]
        assert "dhcp_client" not in parents[0]["layer3"]
