"""Field-asserting tests for export_qos_rules() — issue #92 backfill.

SCM's QoS rule model only supports name/description/action — the exact-dict
assertions prove unsupported match criteria are dropped, not translated.
"""
from __future__ import annotations

from export.objects import export_qos_rules
from export_fixtures import vsys_root


def _rules(inner: str) -> str:
    return f"<rulebase><qos><rules>{inner}</rules></qos></rulebase>"


class TestExportQosRules:
    def test_none_root(self):
        assert export_qos_rules(None) == []

    def test_missing_container(self):
        assert export_qos_rules(vsys_root("<rulebase><security/></rulebase>")) == []

    def test_class_action_and_description(self):
        root = vsys_root(_rules("""
        <entry name="qos-voice">
          <action><class>4</class></action>
          <description>voice priority</description>
        </entry>
        """))
        assert export_qos_rules(root) == [
            {"name": "qos-voice", "action": {"class": "4"}, "description": "voice priority"},
        ]

    def test_match_criteria_dropped(self):
        root = vsys_root(_rules("""
        <entry name="qos-match">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>10.0.0.0/8</member></source>
          <destination><member>any</member></destination>
          <application><member>any</member></application>
          <service><member>any</member></service>
          <action><class>1</class></action>
        </entry>
        """))
        assert export_qos_rules(root) == [{"name": "qos-match", "action": {"class": "1"}}]

    def test_no_class_no_description(self):
        root = vsys_root(_rules("""
        <entry name="no-action"/>
        <entry name="desc-only"><description>reserved</description></entry>
        """))
        assert export_qos_rules(root) == [
            {"name": "no-action"},
            {"name": "desc-only", "description": "reserved"},
        ]

    def test_document_order_preserved(self):
        root = vsys_root(_rules('<entry name="z-qos"/><entry name="a-qos"/>'))
        assert [r["name"] for r in export_qos_rules(root)] == ["z-qos", "a-qos"]
