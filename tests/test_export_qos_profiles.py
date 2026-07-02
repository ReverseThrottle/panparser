"""Unit tests for export_qos_interface_profiles().

network/qos/profile is the interface-level QoS bandwidth/priority-class
profile object — a distinct PAN-OS construct from parsers/qos_rules.py /
export_qos_rules(), which handles vsys **policy** QoS rules (rulebase match
criteria -> DSCP/class marking). These tests only cover the interface
profile export path.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_qos_interface_profiles


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportQosInterfaceProfiles:
    def test_returns_empty_when_network_root_none(self):
        assert export_qos_interface_profiles(None) == []

    def test_returns_empty_when_no_qos_element(self):
        assert export_qos_interface_profiles(_net("<other/>")) == []

    def test_returns_empty_when_no_profile_element(self):
        assert export_qos_interface_profiles(_net("<qos/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_qos_interface_profiles(_net("<qos><profile/></qos>")) == []

    def test_minimal_profile_name_only(self):
        xml = '<qos><profile><entry name="Basic"/></profile></qos>'
        result = export_qos_interface_profiles(_net(xml))
        assert result == [{"name": "Basic"}]

    def test_real_haarp_default_profile(self):
        """Matches network/qos/profile/entry[@name='default'] as seen in
        UA-HAARP-Cofnig_20260605.xml — 8 mbps classes, each with an explicit
        priority and no bandwidth values set."""
        xml = """
        <qos>
          <profile>
            <entry name="default">
              <class-bandwidth-type>
                <mbps>
                  <class>
                    <entry name="class1"><priority>real-time</priority></entry>
                    <entry name="class2"><priority>high</priority></entry>
                    <entry name="class3"><priority>high</priority></entry>
                    <entry name="class4"><priority>medium</priority></entry>
                    <entry name="class5"><priority>medium</priority></entry>
                    <entry name="class6"><priority>low</priority></entry>
                    <entry name="class7"><priority>low</priority></entry>
                    <entry name="class8"><priority>low</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert len(result) == 1
        p = result[0]
        assert p["name"] == "default"
        assert p["bandwidth_type"] == "mbps"
        assert len(p["classes"]) == 8
        priorities = {c["name"]: c["priority"] for c in p["classes"]}
        assert priorities == {
            "class1": "real-time",
            "class2": "high",
            "class3": "high",
            "class4": "medium",
            "class5": "medium",
            "class6": "low",
            "class7": "low",
            "class8": "low",
        }
        # No bandwidth values were set in the source config
        for c in p["classes"]:
            assert "egress_guaranteed" not in c
            assert "egress_max" not in c
        assert "egress_guaranteed" not in p
        assert "egress_max" not in p

    def test_percentage_bandwidth_type(self):
        xml = """
        <qos>
          <profile>
            <entry name="PctProfile">
              <class-bandwidth-type>
                <percentage>
                  <class>
                    <entry name="class1"><priority>real-time</priority></entry>
                  </class>
                </percentage>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert result[0]["bandwidth_type"] == "percentage"
        assert result[0]["classes"] == [{"name": "class1", "priority": "real-time"}]

    def test_aggregate_egress_bandwidth(self):
        xml = """
        <qos>
          <profile>
            <entry name="Aggregate">
              <class-bandwidth-type>
                <mbps>
                  <egress-guaranteed>100</egress-guaranteed>
                  <egress-max>1000</egress-max>
                  <class>
                    <entry name="class1"><priority>real-time</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        p = result[0]
        assert p["egress_guaranteed"] == 100
        assert p["egress_max"] == 1000

    def test_per_class_bandwidth_nested_wrapper(self):
        xml = """
        <qos>
          <profile>
            <entry name="PerClassBw">
              <class-bandwidth-type>
                <mbps>
                  <class>
                    <entry name="class1">
                      <priority>real-time</priority>
                      <bandwidth>
                        <egress-guaranteed>10</egress-guaranteed>
                        <egress-max>20</egress-max>
                      </bandwidth>
                    </entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        cls = result[0]["classes"][0]
        assert cls["priority"] == "real-time"
        assert cls["egress_guaranteed"] == 10
        assert cls["egress_max"] == 20

    def test_classes_sorted_by_name(self):
        xml = """
        <qos>
          <profile>
            <entry name="Unsorted">
              <class-bandwidth-type>
                <mbps>
                  <class>
                    <entry name="class8"><priority>low</priority></entry>
                    <entry name="class1"><priority>real-time</priority></entry>
                    <entry name="class4"><priority>medium</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert [c["name"] for c in result[0]["classes"]] == ["class1", "class4", "class8"]

    def test_profiles_sorted_by_name(self):
        xml = """
        <qos>
          <profile>
            <entry name="Zebra"/>
            <entry name="Alpha"/>
            <entry name="Middle"/>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert [p["name"] for p in result] == ["Alpha", "Middle", "Zebra"]

    def test_multiple_profiles(self):
        xml = """
        <qos>
          <profile>
            <entry name="Prof-A">
              <class-bandwidth-type>
                <mbps>
                  <class>
                    <entry name="class1"><priority>high</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
            <entry name="Prof-B">
              <class-bandwidth-type>
                <mbps>
                  <class>
                    <entry name="class1"><priority>low</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert len(result) == 2
        assert result[0]["classes"][0]["priority"] == "high"
        assert result[1]["classes"][0]["priority"] == "low"

    def test_no_classes_key_when_class_container_absent(self):
        xml = """
        <qos>
          <profile>
            <entry name="NoClasses">
              <class-bandwidth-type>
                <mbps/>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert "classes" not in result[0]
        assert result[0]["bandwidth_type"] == "mbps"

    def test_invalid_bandwidth_value_excluded(self):
        xml = """
        <qos>
          <profile>
            <entry name="BadBw">
              <class-bandwidth-type>
                <mbps>
                  <egress-guaranteed>bogus</egress-guaranteed>
                  <class>
                    <entry name="class1"><priority>high</priority></entry>
                  </class>
                </mbps>
              </class-bandwidth-type>
            </entry>
          </profile>
        </qos>
        """
        result = export_qos_interface_profiles(_net(xml))
        assert "egress_guaranteed" not in result[0]
