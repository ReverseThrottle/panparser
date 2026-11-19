"""Unit tests for export_decryption_rules() — issue #79 coverage backfill.

Covers action defaults, zone/address/user/category/service members, the
PAN-OS <type> mapping (child-element and text forms plus unknown-type
fallback), profile, disabled/tags/description, and the Panorama log-setting
suppression rule.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_decryption_rules


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _rules(inner: str) -> str:
    return f"<rulebase><decryption><rules>{inner}</rules></decryption></rulebase>"


class TestExportDecryptionRules:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_decryption_rules(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_decryption_rules(_vsys("<rulebase><security/></rulebase>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_decryption_rules(_vsys(_rules(""))) == []

    def test_minimal_rule_defaults(self):
        out = export_decryption_rules(_vsys(_rules('<entry name="dec-bare"/>')))
        assert out == [{
            "name": "dec-bare",
            "action": "no-decrypt",
            "from": ["any"],
            "to": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "source_user": ["any"],
            "category": ["any"],
            "service": ["any"],
        }]

    def test_full_rule_with_child_element_type(self):
        xml = _rules("""
        <entry name="decrypt-outbound">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>internal-net</member></source>
          <destination><member>any</member></destination>
          <source-user><member>corp\\users</member></source-user>
          <category><member>financial-services</member></category>
          <service><member>service-https</member></service>
          <action>decrypt</action>
          <type><ssl-forward-proxy/></type>
          <profile>decryption-profile-1</profile>
          <description>Inspect outbound TLS</description>
          <log-setting>forward-to-panorama</log-setting>
          <tag><member>prod</member></tag>
        </entry>
        """)
        out = export_decryption_rules(_vsys(xml))
        assert out == [{
            "name": "decrypt-outbound",
            "action": "decrypt",
            "from": ["trust"],
            "to": ["untrust"],
            "source": ["internal-net"],
            "destination": ["any"],
            "source_user": ["corp\\users"],
            "category": ["financial-services"],
            "service": ["service-https"],
            "type": {"ssl_forward_proxy": {}},
            "profile": "decryption-profile-1",
            "tag": ["prod"],
            "description": "Inspect outbound TLS",
            "log_setting": "forward-to-panorama",
        }]

    def test_type_as_text_value(self):
        xml = _rules("""
        <entry name="inbound">
          <type>ssl-inbound-inspection</type>
          <action>decrypt</action>
        </entry>
        """)
        rule = export_decryption_rules(_vsys(xml))[0]
        assert rule["type"] == {"ssl_inbound_inspection": {}}

    def test_all_known_type_mappings(self):
        for panos_type, scm_key in (
            ("ssl-forward-proxy", "ssl_forward_proxy"),
            ("ssl-inbound-inspection", "ssl_inbound_inspection"),
            ("ssl-no-proxy", "ssl_no_proxy"),
            ("ssh-proxy", "ssh_proxy"),
        ):
            xml = _rules(f'<entry name="t"><type><{panos_type}/></type></entry>')
            rule = export_decryption_rules(_vsys(xml))[0]
            assert rule["type"] == {scm_key: {}}, panos_type

    def test_unknown_type_falls_back_to_snake_case(self):
        xml = _rules('<entry name="future"><type>some-new-type</type></entry>')
        rule = export_decryption_rules(_vsys(xml))[0]
        assert rule["type"] == {"some_new_type": {}}

    def test_no_type_element_omits_type(self):
        xml = _rules('<entry name="notype"><action>no-decrypt</action></entry>')
        rule = export_decryption_rules(_vsys(xml))[0]
        assert "type" not in rule

    def test_disabled_rule(self):
        xml = _rules('<entry name="off"><disabled>yes</disabled></entry>')
        rule = export_decryption_rules(_vsys(xml))[0]
        assert rule["disabled"] is True

    def test_panorama_log_setting_suppressed(self):
        """log-setting 'Panorama' is the PAN-OS default forwarding shorthand
        and is intentionally not exported as a named log-setting object."""
        xml = _rules('<entry name="pan-log"><log-setting>Panorama</log-setting></entry>')
        rule = export_decryption_rules(_vsys(xml))[0]
        assert "log_setting" not in rule

    def test_rules_preserve_document_order(self):
        xml = _rules("""
        <entry name="z-rule"/>
        <entry name="a-rule"/>
        """)
        out = export_decryption_rules(_vsys(xml))
        assert [r["name"] for r in out] == ["z-rule", "a-rule"]
