"""Unit tests for export_nat_rules() — issue #79 coverage backfill.

Covers source translation (dynamic-ip-and-port via interface-address or
translated-address pool, dynamic-ip, static-ip with/without bi-directional)
and destination translation (address and/or port), plus rule defaults.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_nat_rules


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _rule(inner: str, name: str = "nat-rule") -> str:
    return f"""
    <rulebase><nat><rules>
      <entry name="{name}">{inner}</entry>
    </rules></nat></rulebase>
    """


class TestExportNatRules:
    def test_returns_empty_when_vsys_root_none(self):
        assert export_nat_rules(None) == []

    def test_returns_empty_when_no_rules_container(self):
        assert export_nat_rules(_vsys("<rulebase><security/></rulebase>")) == []

    def test_returns_empty_when_container_has_no_entries(self):
        assert export_nat_rules(_vsys("<rulebase><nat><rules/></nat></rulebase>")) == []

    def test_minimal_rule_defaults(self):
        out = export_nat_rules(_vsys(_rule("")))
        assert out == [{
            "name": "nat-rule",
            "nat_type": "ipv4",
            "source_zone": ["any"],
            "destination_zone": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "service": "any",
        }]

    def test_full_rule_metadata(self):
        inner = """
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>internal-net</member></source>
        <destination><member>any</member></destination>
        <service>service-http</service>
        <nat-type>ipv4</nat-type>
        <disabled>yes</disabled>
        <description>Outbound source NAT</description>
        <tag><member>prod</member></tag>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_zone"] == ["trust"]
        assert rule["destination_zone"] == ["untrust"]
        assert rule["source"] == ["internal-net"]
        assert rule["service"] == "service-http"
        assert rule["nat_type"] == "ipv4"
        assert rule["disabled"] is True
        assert rule["description"] == "Outbound source NAT"
        assert rule["tag"] == ["prod"]

    def test_nat_type_nat64_preserved(self):
        rule = export_nat_rules(_vsys(_rule("<nat-type>nat64</nat-type>")))[0]
        assert rule["nat_type"] == "nat64"

    def test_source_translation_dynamic_ip_and_port_interface_address(self):
        inner = """
        <source-translation>
          <dynamic-ip-and-port>
            <interface-address>
              <interface>ethernet1/1</interface>
              <ip>192.0.2.10/24</ip>
            </interface-address>
          </dynamic-ip-and-port>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "dynamic_ip_and_port": {
                "interface_address": {"interface": "ethernet1/1", "ip": "192.0.2.10/24"},
            },
        }

    def test_source_translation_interface_address_without_ip(self):
        inner = """
        <source-translation>
          <dynamic-ip-and-port>
            <interface-address><interface>ethernet1/2</interface></interface-address>
          </dynamic-ip-and-port>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "dynamic_ip_and_port": {"interface_address": {"interface": "ethernet1/2"}},
        }

    def test_source_translation_dynamic_ip_and_port_translated_address_pool(self):
        inner = """
        <source-translation>
          <dynamic-ip-and-port>
            <translated-address>
              <member>pool-addr-1</member>
              <member>pool-addr-2</member>
            </translated-address>
          </dynamic-ip-and-port>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "dynamic_ip_and_port": {"translated_address": ["pool-addr-1", "pool-addr-2"]},
        }

    def test_source_translation_dynamic_ip(self):
        inner = """
        <source-translation>
          <dynamic-ip>
            <translated-address><member>pool-addr</member></translated-address>
          </dynamic-ip>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "dynamic_ip": {"translated_address": ["pool-addr"]},
        }

    def test_source_translation_static_ip_bi_directional(self):
        inner = """
        <source-translation>
          <static-ip>
            <translated-address>192.0.2.50</translated-address>
            <bi-directional>yes</bi-directional>
          </static-ip>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "static_ip": {"translated_address": "192.0.2.50", "bi_directional": "yes"},
        }

    def test_source_translation_static_ip_without_bi_directional(self):
        inner = """
        <source-translation>
          <static-ip><translated-address>192.0.2.51</translated-address></static-ip>
        </source-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "static_ip": {"translated_address": "192.0.2.51"},
        }

    def test_empty_source_translation_container_omitted(self):
        rule = export_nat_rules(_vsys(_rule("<source-translation/>")))[0]
        assert "source_translation" not in rule

    def test_destination_translation_address_and_port(self):
        inner = """
        <destination-translation>
          <translated-address>10.1.2.3</translated-address>
          <translated-port>8080</translated-port>
        </destination-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["destination_translation"] == {
            "translated_address": "10.1.2.3",
            "translated_port": 8080,
        }
        assert isinstance(rule["destination_translation"]["translated_port"], int)

    def test_destination_translation_address_only(self):
        inner = """
        <destination-translation><translated-address>10.1.2.4</translated-address></destination-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["destination_translation"] == {"translated_address": "10.1.2.4"}

    def test_destination_translation_port_only(self):
        inner = """
        <destination-translation><translated-port>443</translated-port></destination-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["destination_translation"] == {"translated_port": 443}

    def test_empty_destination_translation_omitted(self):
        rule = export_nat_rules(_vsys(_rule("<destination-translation/>")))[0]
        assert "destination_translation" not in rule

    def test_combined_source_and_destination_translation(self):
        inner = """
        <source-translation>
          <dynamic-ip-and-port>
            <translated-address><member>egress-pool</member></translated-address>
          </dynamic-ip-and-port>
        </source-translation>
        <destination-translation>
          <translated-address>10.1.2.3</translated-address>
          <translated-port>80</translated-port>
        </destination-translation>
        """
        rule = export_nat_rules(_vsys(_rule(inner)))[0]
        assert rule["source_translation"] == {
            "dynamic_ip_and_port": {"translated_address": ["egress-pool"]},
        }
        assert rule["destination_translation"] == {
            "translated_address": "10.1.2.3", "translated_port": 80,
        }

    def test_fallback_container_without_rulebase(self):
        xml = """
        <nat><rules>
          <entry name="legacy-nat"><nat-type>ipv4</nat-type></entry>
        </rules></nat>
        """
        out = export_nat_rules(_vsys(xml))
        assert [r["name"] for r in out] == ["legacy-nat"]
