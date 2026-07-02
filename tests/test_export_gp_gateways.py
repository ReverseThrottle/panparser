"""Unit tests for export_gp_gateways()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_gp_gateways


def _vsys(xml_str: str):
    """Wrap fragment in a <vsys> root and return the Element."""
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


class TestExportGPGateways:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_gp_gateways(None) == []

    def test_returns_empty_when_no_global_protect_element(self):
        assert export_gp_gateways(_vsys("<other/>")) == []

    def test_returns_empty_when_no_gateway_container(self):
        assert export_gp_gateways(_vsys("<global-protect/>")) == []

    def test_returns_empty_when_no_entries(self):
        xml = "<global-protect><global-protect-gateway/></global-protect>"
        assert export_gp_gateways(_vsys(xml)) == []

    def test_minimal_name_only(self):
        xml = (
            "<global-protect><global-protect-gateway>"
            '<entry name="Minimal"/>'
            "</global-protect-gateway></global-protect>"
        )
        result = export_gp_gateways(_vsys(xml))
        assert result == [
            {"name": "Minimal", "tunnel_mode": False, "client_auth_count": 0}
        ]

    def test_full_gateway_shape_from_440_config(self):
        """Field shape mirrors 440-config.xml's 'Homelab-GW' entry."""
        xml = """
        <global-protect>
          <global-protect-gateway>
            <entry name="Homelab-GW">
              <roles>
                <entry name="default">
                  <login-lifetime><days>1</days></login-lifetime>
                  <inactivity-logout>180</inactivity-logout>
                </entry>
              </roles>
              <client-auth>
                <entry name="default">
                  <os>Any</os>
                  <authentication-profile>Local DB</authentication-profile>
                  <authentication-message>Enter login credentials</authentication-message>
                  <user-credential-or-client-cert-required>yes</user-credential-or-client-cert-required>
                  <auto-retrieve-passcode>no</auto-retrieve-passcode>
                  <username-label>Username</username-label>
                  <password-label>Password</password-label>
                </entry>
              </client-auth>
              <remote-user-tunnel-configs>
                <entry name="Homelab">
                  <source-user><member>any</member></source-user>
                  <ip-pool><member>172.31.0.0/30</member></ip-pool>
                </entry>
              </remote-user-tunnel-configs>
              <ssl-tls-service-profile>Homelab PortalGW</ssl-tls-service-profile>
              <log-setting>SLS</log-setting>
              <tunnel-mode>yes</tunnel-mode>
              <remote-user-tunnel>tunnel.1</remote-user-tunnel>
              <gp-gw-dhcp>
                <enable-dhcp>no</enable-dhcp>
              </gp-gw-dhcp>
            </entry>
          </global-protect-gateway>
        </global-protect>
        """
        result = export_gp_gateways(_vsys(xml))
        assert len(result) == 1
        gw = result[0]
        assert gw["name"] == "Homelab-GW"
        assert gw["ssl_tls_service_profile"] == "Homelab PortalGW"
        assert gw["tunnel_mode"] is True
        assert gw["remote_user_tunnel"] == "tunnel.1"
        assert gw["client_auth_count"] == 1
        assert gw["client_auth"] == [
            {
                "name": "default",
                "os": "Any",
                "authentication_profile": "Local DB",
                "authentication_message": "Enter login credentials",
                "user_credential_or_client_cert_required": True,
                "auto_retrieve_passcode": False,
                "username_label": "Username",
                "password_label": "Password",
            }
        ]
        # Explicitly out of scope for v1 — not surfaced in the export.
        assert "roles" not in gw
        assert "remote_user_tunnel_configs" not in gw
        assert "gp_gw_dhcp" not in gw
        assert "log_setting" not in gw

    def test_full_gateway_shape_from_uas_config(self):
        """Field shape mirrors uas-config.xml's 'UAS-GP-GW' entry (log-success variant)."""
        xml = """
        <global-protect>
          <global-protect-gateway>
            <entry name="UAS-GP-GW">
              <roles>
                <entry name="default">
                  <login-lifetime><days>30</days></login-lifetime>
                  <inactivity-logout>180</inactivity-logout>
                </entry>
              </roles>
              <client-auth>
                <entry name="GP-GW-Client-Auth">
                  <os>Any</os>
                  <authentication-profile>Global-Protect_ISE-AuthProfile</authentication-profile>
                  <authentication-message>Enter login credentials</authentication-message>
                  <user-credential-or-client-cert-required>no</user-credential-or-client-cert-required>
                  <auto-retrieve-passcode>no</auto-retrieve-passcode>
                  <username-label>Username</username-label>
                  <password-label>Password</password-label>
                </entry>
              </client-auth>
              <remote-user-tunnel-configs>
                <entry name="GP-GW-Client-Config">
                  <source-user><member>any</member></source-user>
                  <ip-pool><member>10.194.230.0/24</member></ip-pool>
                </entry>
              </remote-user-tunnel-configs>
              <ssl-tls-service-profile>Global-Protect-SSL-TLS-Profile</ssl-tls-service-profile>
              <tunnel-mode>yes</tunnel-mode>
              <remote-user-tunnel>tunnel.9999</remote-user-tunnel>
              <log-success>no</log-success>
            </entry>
          </global-protect-gateway>
        </global-protect>
        """
        result = export_gp_gateways(_vsys(xml))
        assert len(result) == 1
        gw = result[0]
        assert gw["name"] == "UAS-GP-GW"
        assert gw["ssl_tls_service_profile"] == "Global-Protect-SSL-TLS-Profile"
        assert gw["tunnel_mode"] is True
        assert gw["remote_user_tunnel"] == "tunnel.9999"
        assert gw["client_auth_count"] == 1
        assert gw["client_auth"][0]["name"] == "GP-GW-Client-Auth"
        assert gw["client_auth"][0]["authentication_profile"] == "Global-Protect_ISE-AuthProfile"
        assert gw["client_auth"][0]["user_credential_or_client_cert_required"] is False

    def test_tunnel_mode_false_when_absent(self):
        xml = (
            "<global-protect><global-protect-gateway>"
            '<entry name="NoTunnel"><ssl-tls-service-profile>Prof</ssl-tls-service-profile></entry>'
            "</global-protect-gateway></global-protect>"
        )
        result = export_gp_gateways(_vsys(xml))
        assert result[0]["tunnel_mode"] is False
        assert "remote_user_tunnel" not in result[0]

    def test_client_auth_absent_when_no_entries(self):
        xml = (
            "<global-protect><global-protect-gateway>"
            '<entry name="NoClientAuth"><client-auth/></entry>'
            "</global-protect-gateway></global-protect>"
        )
        result = export_gp_gateways(_vsys(xml))
        assert "client_auth" not in result[0]
        assert result[0]["client_auth_count"] == 0

    def test_multiple_client_auth_entries_counted(self):
        xml = """
        <global-protect>
          <global-protect-gateway>
            <entry name="MultiAuth">
              <client-auth>
                <entry name="win"><os>Windows</os></entry>
                <entry name="mac"><os>Mac</os></entry>
              </client-auth>
            </entry>
          </global-protect-gateway>
        </global-protect>
        """
        result = export_gp_gateways(_vsys(xml))
        assert result[0]["client_auth_count"] == 2
        assert [c["name"] for c in result[0]["client_auth"]] == ["win", "mac"]

    def test_sorted_by_name(self):
        xml = """
        <global-protect>
          <global-protect-gateway>
            <entry name="Zebra"/>
            <entry name="Alpha"/>
            <entry name="Middle"/>
          </global-protect-gateway>
        </global-protect>
        """
        result = export_gp_gateways(_vsys(xml))
        assert [gw["name"] for gw in result] == ["Alpha", "Middle", "Zebra"]

    def test_multiple_gateways(self):
        xml = """
        <global-protect>
          <global-protect-gateway>
            <entry name="GW-A"><tunnel-mode>yes</tunnel-mode></entry>
            <entry name="GW-B"><tunnel-mode>no</tunnel-mode></entry>
          </global-protect-gateway>
        </global-protect>
        """
        result = export_gp_gateways(_vsys(xml))
        assert len(result) == 2
        assert result[0]["tunnel_mode"] is True
        assert result[1]["tunnel_mode"] is False
