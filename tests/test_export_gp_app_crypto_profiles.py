"""Unit tests for export_gp_app_crypto_profiles()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_gp_app_crypto_profiles


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportGPAppCryptoProfiles:
    def test_returns_empty_when_network_root_none(self):
        assert export_gp_app_crypto_profiles(None) == []

    def test_returns_empty_when_no_crypto_profiles_element(self):
        assert export_gp_app_crypto_profiles(_net("<ike/>")) == []

    def test_returns_empty_when_no_container(self):
        xml = "<ike><crypto-profiles><ike-crypto-profiles/></crypto-profiles></ike>"
        assert export_gp_app_crypto_profiles(_net(xml)) == []

    def test_returns_empty_when_no_entries(self):
        xml = """
        <ike>
          <crypto-profiles>
            <global-protect-app-crypto-profiles/>
          </crypto-profiles>
        </ike>
        """
        assert export_gp_app_crypto_profiles(_net(xml)) == []

    def test_single_entry(self):
        xml = """
        <ike>
          <crypto-profiles>
            <global-protect-app-crypto-profiles>
              <entry name="default">
                <encryption>
                  <member>aes-128-cbc</member>
                </encryption>
                <authentication>
                  <member>sha1</member>
                </authentication>
              </entry>
            </global-protect-app-crypto-profiles>
          </crypto-profiles>
        </ike>
        """
        result = export_gp_app_crypto_profiles(_net(xml))
        assert result == [
            {
                "name": "default",
                "encryption": ["aes-128-cbc"],
                "authentication": ["sha1"],
            }
        ]

    def test_multiple_members(self):
        xml = """
        <ike>
          <crypto-profiles>
            <global-protect-app-crypto-profiles>
              <entry name="strong">
                <encryption>
                  <member>aes-256-cbc</member>
                  <member>aes-128-cbc</member>
                </encryption>
                <authentication>
                  <member>sha256</member>
                  <member>sha1</member>
                </authentication>
              </entry>
            </global-protect-app-crypto-profiles>
          </crypto-profiles>
        </ike>
        """
        result = export_gp_app_crypto_profiles(_net(xml))
        assert result[0]["encryption"] == ["aes-256-cbc", "aes-128-cbc"]
        assert result[0]["authentication"] == ["sha256", "sha1"]

    def test_multiple_entries(self):
        xml = """
        <ike>
          <crypto-profiles>
            <global-protect-app-crypto-profiles>
              <entry name="default">
                <encryption><member>aes-128-cbc</member></encryption>
                <authentication><member>sha1</member></authentication>
              </entry>
              <entry name="custom">
                <encryption><member>aes-256-cbc</member></encryption>
                <authentication><member>sha256</member></authentication>
              </entry>
            </global-protect-app-crypto-profiles>
          </crypto-profiles>
        </ike>
        """
        result = export_gp_app_crypto_profiles(_net(xml))
        assert len(result) == 2
        names = [p["name"] for p in result]
        assert names == ["default", "custom"]

    def test_does_not_pick_up_sibling_ike_crypto_profiles(self):
        """Regression: ensure the two sibling containers aren't conflated."""
        xml = """
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="phase1-default">
                <hash><member>sha256</member></hash>
                <encryption><member>aes-256-cbc</member></encryption>
                <dh-group><member>group14</member></dh-group>
              </entry>
            </ike-crypto-profiles>
            <global-protect-app-crypto-profiles>
              <entry name="default">
                <encryption><member>aes-128-cbc</member></encryption>
                <authentication><member>sha1</member></authentication>
              </entry>
            </global-protect-app-crypto-profiles>
          </crypto-profiles>
        </ike>
        """
        result = export_gp_app_crypto_profiles(_net(xml))
        assert len(result) == 1
        assert result[0]["name"] == "default"
