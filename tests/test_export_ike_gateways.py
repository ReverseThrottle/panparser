"""Unit tests for export_ike_gateways() — issue #79 coverage backfill.

SECURITY NOTE: PAN-OS stores IKE pre-shared keys encrypted in the XML. The
exporter must never carry that material into the export — every gateway is
emitted with the MIGRATION-PLACEHOLDER-PSK placeholder and the admin updates
the real key (or certificate) after migration. Fixtures use an obviously-fake
blob (FAKE-TEST-PSK-DO-NOT-USE) as the encrypted <key> text; assertions check
the placeholder constant and the *absence* of the fake blob anywhere in the
exported dicts. The fake value itself is never asserted on or printed.

Certificate-authenticated gateways: the exporter intentionally normalizes
every gateway to the placeholder-PSK shape (see its docstring — "Admin must
update each IKE gateway's PSK (or certificate) after migration"); no
certificate/local-id material is exported. These tests pin that behavior.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from export.objects import export_ike_gateways

PLACEHOLDER_PSK = "MIGRATION-PLACEHOLDER-PSK"
FAKE_KEY_MARKER = "FAKE-TEST-PSK-DO-NOT-USE"


def _net(xml_str: str):
    return ET.fromstring(f"<network>{xml_str}</network>")


def _gateways(inner: str) -> str:
    return f"<ike><gateway>{inner}</gateway></ike>"


def _assert_no_key_material(out: list[dict]) -> None:
    """No exported value may contain the fake encrypted-key blob."""
    assert FAKE_KEY_MARKER not in json.dumps(out)


class TestExportIkeGateways:
    def test_returns_empty_when_network_root_none(self):
        assert export_ike_gateways(None) == []

    def test_returns_empty_when_no_gateway_container(self):
        assert export_ike_gateways(_net("<ike><crypto-profiles/></ike>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_ike_gateways(_net(_gateways(""))) == []

    def test_psk_gateway_full_ikev2(self):
        xml = _gateways(f"""
        <entry name="gw-partner">
          <peer-address><ip>203.0.113.10</ip></peer-address>
          <local-address>
            <interface>ethernet1/1</interface>
            <ip>192.0.2.1/24</ip>
          </local-address>
          <authentication>
            <pre-shared-key><key>{FAKE_KEY_MARKER}</key></pre-shared-key>
          </authentication>
          <protocol>
            <version>ikev2</version>
            <ikev2>
              <ike-crypto-profile>strong-crypto</ike-crypto-profile>
              <dpd><enable>yes</enable></dpd>
            </ikev2>
          </protocol>
          <protocol-common>
            <nat-traversal><enable>yes</enable></nat-traversal>
            <fragmentation><enable>no</enable></fragmentation>
          </protocol-common>
        </entry>
        """)
        out = export_ike_gateways(_net(xml))
        assert len(out) == 1
        gw = out[0]
        assert gw["name"] == "gw-partner"
        assert gw["authentication"] == {"pre_shared_key": {"key": PLACEHOLDER_PSK}}
        assert gw["peer_address"] == {"ip": "203.0.113.10"}
        assert gw["protocol"] == {
            "version": "ikev2",
            "ikev2": {"ike_crypto_profile": "strong-crypto", "dpd": {"enable": True}},
        }
        assert gw["protocol_common"] == {
            "nat_traversal": {"enable": True},
            "fragmentation": {"enable": False},
        }
        assert gw["_local_ip"] == "192.0.2.1/24"
        assert gw["_local_iface"] == "ethernet1/1"
        _assert_no_key_material(out)

    def test_encrypted_psk_never_exported(self):
        """The encrypted key blob must be replaced, not copied."""
        xml = _gateways(f"""
        <entry name="gw-psk">
          <peer-address><ip>203.0.113.11</ip></peer-address>
          <authentication>
            <pre-shared-key><key>{FAKE_KEY_MARKER}</key></pre-shared-key>
          </authentication>
        </entry>
        """)
        out = export_ike_gateways(_net(xml))
        assert out[0]["authentication"]["pre_shared_key"]["key"] == PLACEHOLDER_PSK
        _assert_no_key_material(out)

    def test_certificate_auth_gateway_gets_placeholder_no_cert_material(self):
        """Cert-auth gateways are normalized to placeholder PSK; certificate
        and local-id/peer-id material is never exported (admin reconfigures
        authentication post-migration)."""
        xml = _gateways("""
        <entry name="gw-cert">
          <peer-address><ip>203.0.113.12</ip></peer-address>
          <local-address><interface>ethernet1/2</interface></local-address>
          <authentication>
            <certificate>
              <local-cert>gw-local-cert</local-cert>
            </certificate>
          </authentication>
          <local-id><type>ipaddr</type><id>192.0.2.2</id></local-id>
          <peer-id><type>ipaddr</type><id>203.0.113.12</id></peer-id>
        </entry>
        """)
        out = export_ike_gateways(_net(xml))
        gw = out[0]
        assert gw["authentication"] == {"pre_shared_key": {"key": PLACEHOLDER_PSK}}
        assert "certificate" not in json.dumps(gw)
        assert "local_id" not in gw and "peer_id" not in gw
        assert gw["_local_iface"] == "ethernet1/2"
        assert gw["_local_ip"] == ""

    def test_peer_fqdn(self):
        xml = _gateways("""
        <entry name="gw-fqdn">
          <peer-address><fqdn>vpn.partner.example.com</fqdn></peer-address>
        </entry>
        """)
        gw = export_ike_gateways(_net(xml))[0]
        assert gw["peer_address"] == {"fqdn": "vpn.partner.example.com"}

    def test_peer_dynamic_when_no_peer_address(self):
        xml = _gateways('<entry name="gw-dialin"/>')
        gw = export_ike_gateways(_net(xml))[0]
        assert gw["peer_address"] == {"dynamic": {}}
        assert gw["authentication"] == {"pre_shared_key": {"key": PLACEHOLDER_PSK}}
        assert "protocol" not in gw
        assert "protocol_common" not in gw
        assert "_local_ip" not in gw and "_local_iface" not in gw

    def test_ikev1_with_dpd_disabled(self):
        xml = _gateways("""
        <entry name="gw-v1">
          <peer-address><ip>203.0.113.13</ip></peer-address>
          <protocol>
            <version>ikev1</version>
            <ikev1>
              <ike-crypto-profile>legacy-crypto</ike-crypto-profile>
              <dpd><enable>no</enable></dpd>
            </ikev1>
          </protocol>
        </entry>
        """)
        gw = export_ike_gateways(_net(xml))[0]
        assert gw["protocol"] == {
            "version": "ikev1",
            "ikev1": {"ike_crypto_profile": "legacy-crypto", "dpd": {"enable": False}},
        }

    def test_version_block_without_settings_omitted(self):
        xml = _gateways("""
        <entry name="gw-empty-ver">
          <protocol><version>ikev2</version><ikev2/></protocol>
        </entry>
        """)
        gw = export_ike_gateways(_net(xml))[0]
        assert gw["protocol"] == {"version": "ikev2"}

    def test_protocol_common_empty_container_omitted(self):
        xml = _gateways("""
        <entry name="gw-empty-pc"><protocol-common/></entry>
        """)
        gw = export_ike_gateways(_net(xml))[0]
        assert "protocol_common" not in gw

    def test_local_address_ip_only(self):
        xml = _gateways("""
        <entry name="gw-ip-only">
          <local-address><ip>192.0.2.9</ip></local-address>
        </entry>
        """)
        gw = export_ike_gateways(_net(xml))[0]
        assert gw["_local_ip"] == "192.0.2.9"
        assert gw["_local_iface"] == ""

    def test_multiple_gateways_preserve_order(self):
        xml = _gateways("""
        <entry name="gw-b"><peer-address><ip>203.0.113.2</ip></peer-address></entry>
        <entry name="gw-a"><peer-address><ip>203.0.113.1</ip></peer-address></entry>
        """)
        out = export_ike_gateways(_net(xml))
        assert [g["name"] for g in out] == ["gw-b", "gw-a"]
        assert all(
            g["authentication"]["pre_shared_key"]["key"] == PLACEHOLDER_PSK for g in out
        )
