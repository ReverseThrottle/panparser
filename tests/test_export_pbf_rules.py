"""Field-asserting tests for export_pbf_rules() — issue #92 backfill.

Covers all three PBF actions (forward / discard / no-pbf) and the forward
sub-fields (egress interface, next-hop IP).
"""
from __future__ import annotations

from export.objects import export_pbf_rules
from export_fixtures import vsys_root


def _rules(inner: str) -> str:
    return f"<rulebase><pbf><rules>{inner}</rules></pbf></rulebase>"


class TestExportPbfRules:
    def test_none_root(self):
        assert export_pbf_rules(None) == []

    def test_missing_container(self):
        assert export_pbf_rules(vsys_root("<rulebase><security/></rulebase>")) == []

    def test_full_forward_rule(self):
        root = vsys_root(_rules("""
        <entry name="pbf-isp2">
          <from><member>trust</member><member>dmz</member></from>
          <source><member>10.10.0.0/16</member></source>
          <destination><member>any</member></destination>
          <application><member>web-browsing</member></application>
          <service><member>service-https</member></service>
          <action><forward>
            <egress-interface>ethernet1/2</egress-interface>
            <nexthop><ip-address>192.0.2.1</ip-address></nexthop>
          </forward></action>
          <description>send web traffic via ISP2</description>
          <disabled>yes</disabled>
          <tag><member>prod</member></tag>
        </entry>
        """))
        assert export_pbf_rules(root) == [{
            "name": "pbf-isp2",
            "from_": {"zone": ["trust", "dmz"]},
            "source": ["10.10.0.0/16"],
            "destination": ["any"],
            "application": ["web-browsing"],
            "service": ["service-https"],
            "action": {"forward": {
                "egress_interface": "ethernet1/2",
                "nexthop": {"ip_address": "192.0.2.1"},
            }},
            "disabled": True,
            "tag": ["prod"],
            "description": "send web traffic via ISP2",
        }]

    def test_forward_partial_and_empty(self):
        root = vsys_root(_rules("""
        <entry name="iface-only"><action><forward><egress-interface>ethernet1/3</egress-interface></forward></action></entry>
        <entry name="nexthop-only"><action><forward><nexthop><ip-address>192.0.2.9</ip-address></nexthop></forward></action></entry>
        <entry name="forward-empty"><action><forward/></action></entry>
        """))
        out = export_pbf_rules(root)
        assert out[0]["action"] == {"forward": {"egress_interface": "ethernet1/3"}}
        assert out[1]["action"] == {"forward": {"nexthop": {"ip_address": "192.0.2.9"}}}
        assert out[2]["action"] == {"forward": {}}

    def test_discard_and_no_pbf_actions(self):
        root = vsys_root(_rules("""
        <entry name="drop"><action><discard/></action></entry>
        <entry name="bypass"><action><no-pbf/></action></entry>
        """))
        out = export_pbf_rules(root)
        assert out[0]["action"] == {"discard": {}}
        assert out[1]["action"] == {"no_pbf": {}}

    def test_minimal_rule_defaults_and_no_action(self):
        root = vsys_root(_rules('<entry name="bare"/>'))
        assert export_pbf_rules(root) == [{
            "name": "bare",
            "from_": {"zone": ["any"]},
            "source": ["any"], "destination": ["any"],
            "application": ["any"], "service": ["any"],
        }]

    def test_document_order_preserved(self):
        root = vsys_root(_rules('<entry name="z-pbf"/><entry name="a-pbf"/>'))
        assert [r["name"] for r in export_pbf_rules(root)] == ["z-pbf", "a-pbf"]
