"""Unit tests for export_dos_protection_rules() — issue #79 coverage backfill.

Covers zone/source/destination/service members, action one-of mapping,
aggregate vs classified protection (profiles + rate thresholds), disabled
flag, log-setting/schedule/tags, and the non-rulebase fallback container.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_dos_protection_rules


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _rules(inner: str) -> str:
    return f"<rulebase><dos><rules>{inner}</rules></dos></rulebase>"


class TestExportDosProtectionRules:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_dos_protection_rules(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_dos_protection_rules(_vsys("<rulebase><security/></rulebase>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_dos_protection_rules(_vsys(_rules(""))) == []

    def test_minimal_rule_defaults(self):
        out = export_dos_protection_rules(_vsys(_rules('<entry name="dos-bare"/>')))
        assert out == [{
            "name": "dos-bare",
            "disabled": False,
            "from": ["any"],
            "to": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "source_user": ["any"],
            "service": ["any"],
            "action": {"deny": {}},
        }]

    def test_full_aggregate_rule(self):
        xml = _rules("""
        <entry name="dos-aggregate">
          <disabled>yes</disabled>
          <from><zone><member>untrust</member></zone></from>
          <to><zone><member>trust</member></zone></to>
          <source><member>any</member></source>
          <destination><member>web-server</member></destination>
          <source-user><member>any</member></source-user>
          <service><member>service-http</member></service>
          <action><protect/></action>
          <protection>
            <aggregate><profile>agg-profile</profile></aggregate>
          </protection>
          <log-setting>forward-to-panorama</log-setting>
          <schedule>business-hours</schedule>
          <tag><member>prod</member></tag>
        </entry>
        """)
        out = export_dos_protection_rules(_vsys(xml))
        assert out == [{
            "name": "dos-aggregate",
            "disabled": True,
            "from": ["untrust"],
            "to": ["trust"],
            "source": ["any"],
            "destination": ["web-server"],
            "source_user": ["any"],
            "service": ["service-http"],
            "action": {"protect": {}},
            "protection": {"aggregate": {"profile": "agg-profile"}},
            "log_setting": "forward-to-panorama",
            "schedule": "business-hours",
            "tag": ["prod"],
        }]

    def test_classified_protection_with_rates(self):
        xml = _rules("""
        <entry name="dos-classified">
          <action><allow/></action>
          <protection>
            <classified>
              <profile>cls-profile</profile>
              <alarm-rate>1000</alarm-rate>
              <activate-rate>2000</activate-rate>
              <maximal-rate>5000</maximal-rate>
            </classified>
          </protection>
        </entry>
        """)
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert rule["action"] == {"allow": {}}
        assert rule["protection"] == {"classified": {
            "profile": "cls-profile",
            "alarm-rate": 1000,
            "activate-rate": 2000,
            "maximal-rate": 5000,
        }}

    def test_classified_invalid_rate_skipped(self):
        xml = _rules("""
        <entry name="dos-bad-rate">
          <protection>
            <classified><alarm-rate>not-a-number</alarm-rate></classified>
          </protection>
        </entry>
        """)
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert rule["protection"] == {"classified": {}}

    def test_aggregate_without_profile(self):
        xml = _rules("""
        <entry name="dos-agg-noprof">
          <protection><aggregate/></protection>
        </entry>
        """)
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert rule["protection"] == {"aggregate": {}}

    def test_empty_protection_container_omitted(self):
        xml = _rules('<entry name="dos-noprot"><protection/></entry>')
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert "protection" not in rule

    def test_empty_action_container_omits_action(self):
        xml = _rules('<entry name="dos-noact"><action/></entry>')
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert "action" not in rule

    def test_deny_action_explicit(self):
        xml = _rules('<entry name="dos-deny"><action><deny/></action></entry>')
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert rule["action"] == {"deny": {}}

    def test_disabled_no_is_false(self):
        xml = _rules('<entry name="dos-active"><disabled>no</disabled></entry>')
        rule = export_dos_protection_rules(_vsys(xml))[0]
        assert rule["disabled"] is False

    def test_fallback_container_without_rulebase(self):
        xml = """
        <dos><rules>
          <entry name="legacy-dos"><action><protect/></action></entry>
        </rules></dos>
        """
        out = export_dos_protection_rules(_vsys(xml))
        assert [r["name"] for r in out] == ["legacy-dos"]

    def test_rules_preserve_document_order(self):
        xml = _rules('<entry name="z-dos"/><entry name="a-dos"/>')
        out = export_dos_protection_rules(_vsys(xml))
        assert [r["name"] for r in out] == ["z-dos", "a-dos"]
