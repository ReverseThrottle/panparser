"""Unit tests for export_gp_portals()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_gp_portals


def _vsys(xml_str: str):
    """Wrap fragment in a <vsys> root and return the Element."""
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


class TestExportGPPortals:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_gp_portals(None) == []

    def test_returns_empty_when_no_global_protect_element(self):
        assert export_gp_portals(_vsys("<other/>")) == []

    def test_returns_empty_when_no_portal_container(self):
        xml = "<global-protect/>"
        assert export_gp_portals(_vsys(xml)) == []

    def test_returns_empty_when_no_entries(self):
        xml = "<global-protect><global-protect-portal/></global-protect>"
        assert export_gp_portals(_vsys(xml)) == []

    def test_minimal_portal_name_only(self):
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="Minimal"/>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert result == [{"name": "Minimal", "client_auth": [], "client_auth_count": 0}]

    def test_440_config_shape(self):
        """Real structure from 440-config.xml: empty <ip/> (no ipv4 child)."""
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="Homelab-Portal">
              <portal-config>
                <local-address>
                  <interface>ethernet1/1</interface>
                  <ip />
                </local-address>
                <log-setting>SLS</log-setting>
                <custom-login-page>Disable</custom-login-page>
                <custom-home-page>factory-default</custom-home-page>
                <ssl-tls-service-profile>Homelab PortalGW</ssl-tls-service-profile>
                <client-auth>
                  <entry name="default">
                    <user-credential-or-client-cert-required>yes</user-credential-or-client-cert-required>
                    <os>Any</os>
                    <authentication-profile>Local DB</authentication-profile>
                    <authentication-message>Enter login credentials</authentication-message>
                    <auto-retrieve-passcode>no</auto-retrieve-passcode>
                    <use-default-browser>no</use-default-browser>
                    <username-label>Username</username-label>
                    <password-label>Password</password-label>
                  </entry>
                </client-auth>
              </portal-config>
              <client-config>
                <configs>
                  <entry name="Homelab">
                    <gateways><external><cutoff-time>5</cutoff-time></external></gateways>
                  </entry>
                </configs>
              </client-config>
              <satellite-config>
                <client-certificate>
                  <local />
                </client-certificate>
              </satellite-config>
            </entry>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert len(result) == 1
        p = result[0]
        assert p["name"] == "Homelab-Portal"
        # No ipv4 child under <ip/> -> local_address key omitted entirely.
        assert "local_address" not in p
        assert p["ssl_tls_service_profile"] == "Homelab PortalGW"
        assert p["client_auth_count"] == 1
        ca = p["client_auth"][0]
        assert ca["name"] == "default"
        assert ca["user_credential_or_client_cert_required"] is True
        assert ca["os"] == "Any"
        assert ca["authentication_profile"] == "Local DB"
        assert ca["authentication_message"] == "Enter login credentials"
        assert ca["auto_retrieve_passcode"] is False
        assert ca["use_default_browser"] is False
        assert ca["username_label"] == "Username"
        assert ca["password_label"] == "Password"
        # client-config / satellite-config are out of scope and must not leak through.
        assert "client_config" not in p
        assert "satellite_config" not in p

    def test_uas_config_shape(self):
        """Real structure from uas-config.xml: local-address has an actual ipv4,
        and client-auth entry omits the optional use-default-browser field."""
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="UAS-Global-Protect-Portal">
              <portal-config>
                <local-address>
                  <ip>
                    <ipv4>137.229.253.106/32</ipv4>
                  </ip>
                  <interface>loopback</interface>
                </local-address>
                <client-auth>
                  <entry name="GP-Client-Authentication">
                    <user-credential-or-client-cert-required>no</user-credential-or-client-cert-required>
                    <os>Any</os>
                    <authentication-profile>SAML-idp-Auth-Profile</authentication-profile>
                    <authentication-message>Enter login credentials</authentication-message>
                    <auto-retrieve-passcode>no</auto-retrieve-passcode>
                    <username-label>Username</username-label>
                    <password-label>Password</password-label>
                  </entry>
                </client-auth>
                <custom-login-page>factory-default</custom-login-page>
                <custom-home-page>factory-default</custom-home-page>
                <ssl-tls-service-profile>Global-Protect-SSL-TLS-Profile</ssl-tls-service-profile>
                <log-success>no</log-success>
              </portal-config>
              <client-config>
                <configs>
                  <entry name="Global-Protect-Client-Config"/>
                </configs>
              </client-config>
              <satellite-config>
                <client-certificate>
                  <local />
                </client-certificate>
              </satellite-config>
            </entry>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert len(result) == 1
        p = result[0]
        assert p["name"] == "UAS-Global-Protect-Portal"
        assert p["local_address"] == "137.229.253.106/32"
        assert p["ssl_tls_service_profile"] == "Global-Protect-SSL-TLS-Profile"
        assert p["client_auth_count"] == 1
        ca = p["client_auth"][0]
        assert ca["name"] == "GP-Client-Authentication"
        assert ca["user_credential_or_client_cert_required"] is False
        assert ca["authentication_profile"] == "SAML-idp-Auth-Profile"
        # Optional field absent in source XML must not appear in the result.
        assert "use_default_browser" not in ca

    def test_no_client_auth_container(self):
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="NoAuth">
              <portal-config>
                <ssl-tls-service-profile>Some-Profile</ssl-tls-service-profile>
              </portal-config>
            </entry>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert result[0]["client_auth"] == []
        assert result[0]["client_auth_count"] == 0

    def test_multiple_client_auth_entries(self):
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="MultiAuth">
              <portal-config>
                <client-auth>
                  <entry name="first">
                    <os>Any</os>
                  </entry>
                  <entry name="second">
                    <os>Windows</os>
                  </entry>
                </client-auth>
              </portal-config>
            </entry>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert result[0]["client_auth_count"] == 2
        assert [ca["name"] for ca in result[0]["client_auth"]] == ["first", "second"]

    def test_sorted_by_name(self):
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="Zebra"/>
            <entry name="Alpha"/>
            <entry name="Middle"/>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert [p["name"] for p in result] == ["Alpha", "Middle", "Zebra"]

    def test_multiple_portals(self):
        xml = """
        <global-protect>
          <global-protect-portal>
            <entry name="Portal-A">
              <portal-config>
                <ssl-tls-service-profile>Profile-A</ssl-tls-service-profile>
              </portal-config>
            </entry>
            <entry name="Portal-B">
              <portal-config>
                <ssl-tls-service-profile>Profile-B</ssl-tls-service-profile>
              </portal-config>
            </entry>
          </global-protect-portal>
        </global-protect>
        """
        result = export_gp_portals(_vsys(xml))
        assert len(result) == 2
        assert result[0]["ssl_tls_service_profile"] == "Profile-A"
        assert result[1]["ssl_tls_service_profile"] == "Profile-B"
