"""Unit tests for export_snmp_trap_server_profiles() and
the _snmp_refs capture in export_log_forwarding_profiles()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_snmp_trap_server_profiles, export_log_forwarding_profiles


def _vsys(xml_str: str):
    """Wrap fragment in a <vsys> root and return the Element."""
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


class TestExportSnmpTrapServerProfiles:
    def test_returns_empty_when_vsys_root_none(self):
        v2c, v3 = export_snmp_trap_server_profiles(None)
        assert v2c == []
        assert v3 == []

    def test_returns_empty_when_no_snmptrap_container(self):
        v2c, v3 = export_snmp_trap_server_profiles(_vsys("<log-settings/>"))
        assert v2c == []
        assert v3 == []

    def test_returns_empty_when_snmptrap_has_no_entries(self):
        v2c, v3 = export_snmp_trap_server_profiles(_vsys("<log-settings><snmptrap/></log-settings>"))
        assert v2c == []
        assert v3 == []

    def test_v2c_profile_community_replaced_with_placeholder(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="snmp-v2c-profile">
              <version>
                <v2c>
                  <server>
                    <entry name="snmp-server-1">
                      <manager>10.250.150.10</manager>
                      <community>public</community>
                    </entry>
                  </server>
                </v2c>
              </version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, v3 = export_snmp_trap_server_profiles(_vsys(xml))
        assert v3 == []
        assert len(v2c) == 1
        profile = v2c[0]
        assert profile["name"] == "snmp-v2c-profile"
        assert len(profile["server"]) == 1
        srv = profile["server"][0]
        assert srv["name"] == "snmp-server-1"
        assert srv["manager"] == "10.250.150.10"
        assert srv["community"] == "MIGRATION-PLACEHOLDER-COMMUNITY"

    def test_v3_profile_authpwd_privpwd_replaced_with_placeholders(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="snmp-v3-profile">
              <version>
                <v3>
                  <server>
                    <entry name="snmp-server-v3">
                      <manager>10.250.150.10</manager>
                      <user>snmpuser</user>
                      <engineid>0x80000000</engineid>
                      <authpwd>secret-auth</authpwd>
                      <privpwd>secret-priv</privpwd>
                    </entry>
                  </server>
                </v3>
              </version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, v3 = export_snmp_trap_server_profiles(_vsys(xml))
        assert v2c == []
        assert len(v3) == 1
        profile = v3[0]
        assert profile["name"] == "snmp-v3-profile"
        assert len(profile["server"]) == 1
        srv = profile["server"][0]
        assert srv["name"] == "snmp-server-v3"
        assert srv["manager"] == "10.250.150.10"
        assert srv["user"] == "snmpuser"
        assert srv["engineid"] == "0x80000000"
        assert srv["authpwd"] == "MIGRATION-PLACEHOLDER-AUTHPWD"
        assert srv["privpwd"] == "MIGRATION-PLACEHOLDER-PRIVPWD"

    def test_mixed_v2c_and_v3_profiles(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="v2c-profile">
              <version><v2c><server>
                <entry name="srv1"><manager>10.0.0.1</manager><community>pub</community></entry>
              </server></v2c></version>
            </entry>
            <entry name="v3-profile">
              <version><v3><server>
                <entry name="srv2">
                  <manager>10.0.0.2</manager>
                  <user>u1</user>
                  <engineid>0x01</engineid>
                  <authpwd>a</authpwd>
                  <privpwd>p</privpwd>
                </entry>
              </server></v3></version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, v3 = export_snmp_trap_server_profiles(_vsys(xml))
        assert len(v2c) == 1
        assert len(v3) == 1
        assert v2c[0]["name"] == "v2c-profile"
        assert v3[0]["name"] == "v3-profile"

    def test_profile_without_version_child_is_skipped(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="no-version"/>
          </snmptrap>
        </log-settings>
        """
        v2c, v3 = export_snmp_trap_server_profiles(_vsys(xml))
        assert v2c == []
        assert v3 == []

    def test_v2c_profile_with_no_servers(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="empty-v2c">
              <version><v2c><server/></v2c></version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, v3 = export_snmp_trap_server_profiles(_vsys(xml))
        assert len(v2c) == 1
        assert "server" not in v2c[0]

    def test_v2c_multiple_servers_in_one_profile(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="multi-srv">
              <version><v2c><server>
                <entry name="s1"><manager>1.1.1.1</manager><community>c1</community></entry>
                <entry name="s2"><manager>2.2.2.2</manager><community>c2</community></entry>
              </server></v2c></version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, _ = export_snmp_trap_server_profiles(_vsys(xml))
        assert len(v2c[0]["server"]) == 2

    def test_sorted_by_name(self):
        xml = """
        <log-settings>
          <snmptrap>
            <entry name="zebra">
              <version><v2c><server>
                <entry name="s"><manager>1.1.1.1</manager><community>c</community></entry>
              </server></v2c></version>
            </entry>
            <entry name="alpha">
              <version><v2c><server>
                <entry name="s"><manager>2.2.2.2</manager><community>c</community></entry>
              </server></v2c></version>
            </entry>
          </snmptrap>
        </log-settings>
        """
        v2c, _ = export_snmp_trap_server_profiles(_vsys(xml))
        assert [p["name"] for p in v2c] == ["alpha", "zebra"]


class TestLogForwardingSnmpRefs:
    """Verify _snmp_refs are captured from send-snmptrap in match-list entries."""

    def test_snmp_refs_captured(self):
        xml = """
        <log-settings>
          <profiles>
            <entry name="lfp1">
              <match-list>
                <entry name="ml1">
                  <log-type>traffic</log-type>
                  <filter>All Logs</filter>
                  <send-snmptrap>
                    <using-snmptrap-setting>
                      <member>snmp-v2c-profile</member>
                      <member>snmp-v3-profile</member>
                    </using-snmptrap-setting>
                  </send-snmptrap>
                </entry>
              </match-list>
            </entry>
          </profiles>
        </log-settings>
        """
        result = export_log_forwarding_profiles(_vsys(xml))
        assert len(result) == 1
        ml = result[0]["match_list"][0]
        assert ml["_snmp_refs"] == ["snmp-v2c-profile", "snmp-v3-profile"]

    def test_snmp_refs_absent_when_not_configured(self):
        xml = """
        <log-settings>
          <profiles>
            <entry name="lfp1">
              <match-list>
                <entry name="ml1">
                  <filter>All Logs</filter>
                </entry>
              </match-list>
            </entry>
          </profiles>
        </log-settings>
        """
        result = export_log_forwarding_profiles(_vsys(xml))
        ml = result[0]["match_list"][0]
        assert "_snmp_refs" not in ml

    def test_snmp_refs_alongside_syslog_and_http_refs(self):
        xml = """
        <log-settings>
          <profiles>
            <entry name="lfp1">
              <match-list>
                <entry name="ml1">
                  <filter>All Logs</filter>
                  <send-syslog>
                    <using-syslog-setting><member>syslog-srv</member></using-syslog-setting>
                  </send-syslog>
                  <send-http>
                    <using-http-setting><member>http-srv</member></using-http-setting>
                  </send-http>
                  <send-snmptrap>
                    <using-snmptrap-setting><member>snmp-srv</member></using-snmptrap-setting>
                  </send-snmptrap>
                </entry>
              </match-list>
            </entry>
          </profiles>
        </log-settings>
        """
        result = export_log_forwarding_profiles(_vsys(xml))
        ml = result[0]["match_list"][0]
        assert ml["_syslog_refs"] == ["syslog-srv"]
        assert ml["_http_refs"] == ["http-srv"]
        assert ml["_snmp_refs"] == ["snmp-srv"]
