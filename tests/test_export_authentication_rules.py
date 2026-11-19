"""Field-asserting tests for export_authentication_rules() — issue #92 backfill."""
from __future__ import annotations

from export.objects import export_authentication_rules
from export_fixtures import vsys_root


def _rules(inner: str) -> str:
    return f"<rulebase><authentication><rules>{inner}</rules></authentication></rulebase>"


class TestExportAuthenticationRules:
    def test_none_root(self):
        assert export_authentication_rules(None) == []

    def test_missing_container(self):
        assert export_authentication_rules(vsys_root("<rulebase><security/></rulebase>")) == []

    def test_full_rule(self):
        root = vsys_root(_rules("""
        <entry name="auth-captive">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>10.0.0.0/8</member></source>
          <destination><member>any</member></destination>
          <source-user><member>corp\\users</member></source-user>
          <category><member>financial-services</member></category>
          <service><member>service-http</member></service>
          <authentication-enforcement>web-form</authentication-enforcement>
          <description>captive portal rule</description>
          <log-setting>custom-log</log-setting>
          <disabled>yes</disabled>
          <tag><member>prod</member></tag>
          <timeout>60</timeout>
        </entry>
        """))
        assert export_authentication_rules(root) == [{
            "name": "auth-captive",
            "from": ["trust"],
            "to": ["untrust"],
            "source": ["10.0.0.0/8"],
            "destination": ["any"],
            "source_user": ["corp\\users"],
            "category": ["financial-services"],
            "service": ["service-http"],
            "authentication_enforcement": "web-form",
            "disabled": True,
            "tag": ["prod"],
            "description": "captive portal rule",
            "log_setting": "custom-log",
            "timeout": 60,
        }]

    def test_minimal_rule_defaults_to_any(self):
        root = vsys_root(_rules('<entry name="bare"/>'))
        assert export_authentication_rules(root) == [{
            "name": "bare",
            "from": ["any"], "to": ["any"],
            "source": ["any"], "destination": ["any"],
            "source_user": ["any"], "category": ["any"], "service": ["any"],
        }]

    def test_panorama_log_setting_omitted(self):
        root = vsys_root(_rules('<entry name="pan-log"><log-setting>Panorama</log-setting></entry>'))
        assert "log_setting" not in export_authentication_rules(root)[0]

    def test_invalid_timeout_skipped_and_disabled_no(self):
        root = vsys_root(_rules("""
        <entry name="bad-timeout"><timeout>soon</timeout><disabled>no</disabled></entry>
        """))
        rule = export_authentication_rules(root)[0]
        assert "timeout" not in rule
        assert "disabled" not in rule

    def test_document_order_preserved(self):
        root = vsys_root(_rules('<entry name="z-rule"/><entry name="a-rule"/>'))
        assert [r["name"] for r in export_authentication_rules(root)] == ["z-rule", "a-rule"]
