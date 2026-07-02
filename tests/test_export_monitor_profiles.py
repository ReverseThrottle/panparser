"""Unit tests for export_monitor_profiles()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_monitor_profiles


def _net(xml_str: str):
    """Wrap fragment in a <network> root and return the Element."""
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportMonitorProfiles:
    def test_returns_empty_when_network_root_none(self):
        assert export_monitor_profiles(None) == []

    def test_returns_empty_when_no_profiles_element(self):
        assert export_monitor_profiles(_net("<profiles/>")) == []

    def test_returns_empty_when_no_entries(self):
        assert export_monitor_profiles(_net("<profiles><monitor-profile/></profiles>")) == []

    def test_minimal_profile_name_only(self):
        xml = '<profiles><monitor-profile><entry name="Basic"/></monitor-profile></profiles>'
        result = export_monitor_profiles(_net(xml))
        assert result == [{"name": "Basic"}]

    def test_full_monitor_profile(self):
        xml = """
        <profiles>
          <monitor-profile>
            <entry name="default">
              <interval>3</interval>
              <threshold>5</threshold>
              <action>wait-recover</action>
            </entry>
          </monitor-profile>
        </profiles>
        """
        result = export_monitor_profiles(_net(xml))
        assert result == [{
            "name": "default",
            "interval": 3,
            "threshold": 5,
            "action": "wait-recover",
        }]

    def test_action_fail_over(self):
        xml = """
        <profiles>
          <monitor-profile>
            <entry name="failover-profile">
              <interval>2</interval>
              <threshold>3</threshold>
              <action>fail-over</action>
            </entry>
          </monitor-profile>
        </profiles>
        """
        result = export_monitor_profiles(_net(xml))
        assert result[0]["action"] == "fail-over"

    def test_multiple_profiles(self):
        xml = """
        <profiles>
          <monitor-profile>
            <entry name="Prof-A">
              <interval>3</interval>
              <threshold>5</threshold>
              <action>wait-recover</action>
            </entry>
            <entry name="Prof-B">
              <interval>10</interval>
              <threshold>2</threshold>
              <action>fail-over</action>
            </entry>
          </monitor-profile>
        </profiles>
        """
        result = export_monitor_profiles(_net(xml))
        assert len(result) == 2
        assert result[0]["name"] == "Prof-A"
        assert result[1]["name"] == "Prof-B"

    def test_interval_and_threshold_are_ints(self):
        xml = """
        <profiles>
          <monitor-profile>
            <entry name="typed">
              <interval>7</interval>
              <threshold>9</threshold>
            </entry>
          </monitor-profile>
        </profiles>
        """
        result = export_monitor_profiles(_net(xml))
        assert result[0]["interval"] == 7
        assert isinstance(result[0]["interval"], int)
        assert result[0]["threshold"] == 9
        assert isinstance(result[0]["threshold"], int)

    def test_absent_fields_not_included(self):
        xml = '<profiles><monitor-profile><entry name="NoFields"/></monitor-profile></profiles>'
        result = export_monitor_profiles(_net(xml))
        assert "interval" not in result[0]
        assert "threshold" not in result[0]
        assert "action" not in result[0]

    def test_preserves_xml_order_not_sorted(self):
        """Unlike lldp profiles, monitor profiles preserve document order."""
        xml = """
        <profiles>
          <monitor-profile>
            <entry name="Zebra"/>
            <entry name="Alpha"/>
          </monitor-profile>
        </profiles>
        """
        result = export_monitor_profiles(_net(xml))
        assert [p["name"] for p in result] == ["Zebra", "Alpha"]
