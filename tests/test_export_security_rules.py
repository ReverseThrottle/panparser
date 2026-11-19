"""Unit tests for export_security_rules() — issue #79 coverage backfill.

Covers source/destination zones+addresses, application/service, action,
disabled/negate flags, security profile settings (group and per-profile),
log forwarding, tags/description, and the any/application-default defaults.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_security_rules


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


class TestExportSecurityRules:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_security_rules(None) == []

    def test_returns_empty_when_no_rules_container(self):
        assert export_security_rules(_vsys("<rulebase><nat/></rulebase>")) == []

    def test_returns_empty_when_container_has_no_entries(self):
        assert export_security_rules(_vsys("<rulebase><security><rules/></security></rulebase>")) == []

    def test_full_rule_field_mapping(self):
        xml = """
        <rulebase>
          <security>
            <rules>
              <entry name="allow-web">
                <from><member>trust</member></from>
                <to><member>untrust</member></to>
                <source><member>internal-net</member></source>
                <destination><member>web-server</member></destination>
                <application><member>ssl</member><member>web-browsing</member></application>
                <service><member>service-https</member></service>
                <action>allow</action>
                <description>Outbound web access</description>
                <log-setting>forward-to-panorama</log-setting>
                <tag><member>prod</member></tag>
                <category><member>any</member></category>
                <source-user><member>corp\\users</member></source-user>
                <profile-setting>
                  <profiles>
                    <virus><member>default</member></virus>
                    <spyware><member>strict</member></spyware>
                    <vulnerability><member>strict</member></vulnerability>
                    <url-filtering><member>default</member></url-filtering>
                    <file-blocking><member>basic-file-blocking</member></file-blocking>
                    <wildfire-analysis><member>default</member></wildfire-analysis>
                    <data-filtering><member>sensitive-data</member></data-filtering>
                  </profiles>
                </profile-setting>
              </entry>
            </rules>
          </security>
        </rulebase>
        """
        out = export_security_rules(_vsys(xml))
        assert out == [{
            "name": "allow-web",
            "action": "allow",
            "source_zone": ["trust"],
            "destination_zone": ["untrust"],
            "source": ["internal-net"],
            "destination": ["web-server"],
            "application": ["ssl", "web-browsing"],
            "service": ["service-https"],
            "category": ["any"],
            "source_user": ["corp\\users"],
            "tag": ["prod"],
            "description": "Outbound web access",
            "log_setting": "forward-to-panorama",
            "profile_setting": {
                "virus": ["default"],
                "spyware": ["strict"],
                "vulnerability": ["strict"],
                "url_filtering": ["default"],
                "file_blocking": ["basic-file-blocking"],
                "wildfire_analysis": ["default"],
                "data_filtering": ["sensitive-data"],
            },
        }]

    def test_minimal_rule_gets_any_defaults(self):
        xml = """
        <rulebase><security><rules>
          <entry name="bare-rule"/>
        </rules></security></rulebase>
        """
        out = export_security_rules(_vsys(xml))
        assert out == [{
            "name": "bare-rule",
            "action": "allow",
            "source_zone": ["any"],
            "destination_zone": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "application": ["any"],
            "service": ["application-default"],
            "category": ["any"],
            "source_user": ["any"],
        }]

    def test_deny_action_and_disabled_and_negations(self):
        xml = """
        <rulebase><security><rules>
          <entry name="block-quic">
            <action>deny</action>
            <disabled>yes</disabled>
            <negate-source>yes</negate-source>
            <negate-destination>yes</negate-destination>
          </entry>
        </rules></security></rulebase>
        """
        rule = export_security_rules(_vsys(xml))[0]
        assert rule["action"] == "deny"
        assert rule["disabled"] is True
        assert rule["negate_source"] is True
        assert rule["negate_destination"] is True

    def test_disabled_no_and_negate_no_omit_keys(self):
        xml = """
        <rulebase><security><rules>
          <entry name="active">
            <disabled>no</disabled>
            <negate-source>no</negate-source>
            <negate-destination>no</negate-destination>
          </entry>
        </rules></security></rulebase>
        """
        rule = export_security_rules(_vsys(xml))[0]
        assert "disabled" not in rule
        assert "negate_source" not in rule
        assert "negate_destination" not in rule

    def test_profile_setting_group_wins_over_profiles(self):
        xml = """
        <rulebase><security><rules>
          <entry name="grouped">
            <profile-setting>
              <group><member>standard-profile-group</member></group>
              <profiles><virus><member>default</member></virus></profiles>
            </profile-setting>
          </entry>
        </rules></security></rulebase>
        """
        rule = export_security_rules(_vsys(xml))[0]
        assert rule["profile_setting"] == {"group": ["standard-profile-group"]}

    def test_empty_profiles_container_omits_profile_setting(self):
        xml = """
        <rulebase><security><rules>
          <entry name="no-profiles"><profile-setting><profiles/></profile-setting></entry>
        </rules></security></rulebase>
        """
        rule = export_security_rules(_vsys(xml))[0]
        assert "profile_setting" not in rule

    def test_fallback_container_without_rulebase(self):
        """Some configs place security/rules directly under the vsys root."""
        xml = """
        <security><rules>
          <entry name="legacy"><action>drop</action></entry>
        </rules></security>
        """
        out = export_security_rules(_vsys(xml))
        assert len(out) == 1
        assert out[0]["name"] == "legacy"
        assert out[0]["action"] == "drop"

    def test_rules_preserve_document_order(self):
        xml = """
        <rulebase><security><rules>
          <entry name="z-first"><action>allow</action></entry>
          <entry name="a-second"><action>deny</action></entry>
        </rules></security></rulebase>
        """
        out = export_security_rules(_vsys(xml))
        assert [r["name"] for r in out] == ["z-first", "a-second"]
