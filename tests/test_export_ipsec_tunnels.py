"""Unit tests for export_ipsec_tunnels() — issue #79 coverage backfill.

Covers tunnel-interface binding, auto-key IKE gateway references, IPsec
crypto profile, and proxy-id local/remote/protocol handling.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_ipsec_tunnels


def _net(xml_str: str):
    return ET.fromstring(f"<network>{xml_str}</network>")


def _tunnels(inner: str) -> str:
    return f"<tunnel><ipsec>{inner}</ipsec></tunnel>"


class TestExportIpsecTunnels:
    def test_returns_empty_when_network_root_none(self):
        assert export_ipsec_tunnels(None) == []

    def test_returns_empty_when_no_ipsec_container(self):
        assert export_ipsec_tunnels(_net("<tunnel><ssl/></tunnel>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_ipsec_tunnels(_net(_tunnels(""))) == []

    def test_full_tunnel_with_proxy_ids(self):
        xml = _tunnels("""
        <entry name="tun-partner">
          <tunnel-interface>tunnel.10</tunnel-interface>
          <auto-key>
            <ike-gateway>
              <entry name="gw-partner"/>
              <entry name="gw-backup"/>
            </ike-gateway>
            <ipsec-crypto-profile>strong-ipsec</ipsec-crypto-profile>
            <proxy-id>
              <entry name="net-a">
                <local>10.1.0.0/16</local>
                <remote>10.2.0.0/16</remote>
                <protocol><tcp/></protocol>
              </entry>
              <entry name="net-b">
                <local>10.3.0.0/16</local>
                <remote>10.4.0.0/16</remote>
                <protocol><udp/></protocol>
              </entry>
              <entry name="net-any">
                <local>10.5.0.0/16</local>
                <remote>10.6.0.0/16</remote>
                <protocol><any/></protocol>
              </entry>
            </proxy-id>
          </auto-key>
        </entry>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert out == [{
            "name": "tun-partner",
            "tunnel_interface": "tunnel.10",
            "auto_key": {
                "ike_gateway": [{"name": "gw-partner"}, {"name": "gw-backup"}],
                "ipsec_crypto_profile": "strong-ipsec",
                "proxy_id": [
                    {"name": "net-a", "local": "10.1.0.0/16", "remote": "10.2.0.0/16",
                     "protocol": {"tcp": {}}},
                    {"name": "net-b", "local": "10.3.0.0/16", "remote": "10.4.0.0/16",
                     "protocol": {"udp": {}}},
                    # <any/> → protocol omitted (SCM default = any)
                    {"name": "net-any", "local": "10.5.0.0/16", "remote": "10.6.0.0/16"},
                ],
            },
        }]

    def test_minimal_tunnel_name_only(self):
        xml = _tunnels('<entry name="tun-bare"/>')
        assert export_ipsec_tunnels(_net(xml)) == [{"name": "tun-bare"}]

    def test_empty_auto_key_yields_empty_dict(self):
        xml = _tunnels('<entry name="tun-ak"><auto-key/></entry>')
        out = export_ipsec_tunnels(_net(xml))
        assert out == [{"name": "tun-ak", "auto_key": {}}]

    def test_unnamed_ike_gateway_entries_filtered(self):
        xml = _tunnels("""
        <entry name="tun-gw-filter">
          <auto-key>
            <ike-gateway>
              <entry name="gw-named"/>
              <entry/>
            </ike-gateway>
          </auto-key>
        </entry>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert out[0]["auto_key"]["ike_gateway"] == [{"name": "gw-named"}]

    def test_proxy_id_name_only(self):
        xml = _tunnels("""
        <entry name="tun-px-min">
          <auto-key>
            <proxy-id><entry name="px-bare"/></proxy-id>
          </auto-key>
        </entry>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert out[0]["auto_key"]["proxy_id"] == [{"name": "px-bare"}]

    def test_proxy_id_without_protocol_element(self):
        xml = _tunnels("""
        <entry name="tun-px-noproto">
          <auto-key>
            <proxy-id>
              <entry name="px-1"><local>10.0.0.0/8</local></entry>
            </proxy-id>
          </auto-key>
        </entry>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert out[0]["auto_key"]["proxy_id"] == [{"name": "px-1", "local": "10.0.0.0/8"}]

    def test_tunnel_interface_omitted_when_absent(self):
        xml = _tunnels("""
        <entry name="tun-noiface">
          <auto-key><ipsec-crypto-profile>default</ipsec-crypto-profile></auto-key>
        </entry>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert "tunnel_interface" not in out[0]
        assert out[0]["auto_key"] == {"ipsec_crypto_profile": "default"}

    def test_multiple_tunnels_preserve_order(self):
        xml = _tunnels("""
        <entry name="tun-z"/>
        <entry name="tun-a"/>
        """)
        out = export_ipsec_tunnels(_net(xml))
        assert [t["name"] for t in out] == ["tun-z", "tun-a"]
