"""Unit tests for export_botnet_report()."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_botnet_report


def _shared(xml_str: str):
    """Wrap fragment in a <shared> root and return the Element."""
    return ET.fromstring(f"<shared>{xml_str}</shared>")


class TestExportBotnetReport:
    def test_returns_empty_when_shared_root_none(self):
        assert export_botnet_report(None) == {}

    def test_returns_empty_when_no_botnet_element(self):
        assert export_botnet_report(_shared("<application/>")) == {}

    def test_returns_empty_when_botnet_element_empty(self):
        assert export_botnet_report(_shared("<botnet/>")) == {}

    def test_http_threshold_entries(self):
        xml = """
        <botnet>
          <configuration>
            <http>
              <dynamic-dns><enabled>yes</enabled><threshold>5</threshold></dynamic-dns>
              <malware-sites><enabled>yes</enabled><threshold>5</threshold></malware-sites>
              <recent-domains><enabled>yes</enabled><threshold>5</threshold></recent-domains>
              <ip-domains><enabled>yes</enabled><threshold>10</threshold></ip-domains>
              <executables-from-unknown-sites><enabled>yes</enabled><threshold>5</threshold></executables-from-unknown-sites>
            </http>
          </configuration>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        http = result["configuration"]["http"]
        assert http["dynamic_dns"] == {"enabled": True, "threshold": 5}
        assert http["malware_sites"] == {"enabled": True, "threshold": 5}
        assert http["recent_domains"] == {"enabled": True, "threshold": 5}
        assert http["ip_domains"] == {"enabled": True, "threshold": 10}
        assert http["executables_from_unknown_sites"] == {"enabled": True, "threshold": 5}

    def test_http_entry_disabled(self):
        xml = """
        <botnet>
          <configuration>
            <http>
              <dynamic-dns><enabled>no</enabled><threshold>5</threshold></dynamic-dns>
            </http>
          </configuration>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        assert result["configuration"]["http"]["dynamic_dns"]["enabled"] is False

    def test_other_applications_irc_flag(self):
        xml = """
        <botnet>
          <configuration>
            <other-applications><irc>yes</irc></other-applications>
          </configuration>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        assert result["configuration"]["other_applications"] == {"irc": True}

    def test_unknown_applications_tcp_and_udp(self):
        xml = """
        <botnet>
          <configuration>
            <unknown-applications>
              <unknown-tcp>
                <destinations-per-hour>10</destinations-per-hour>
                <sessions-per-hour>10</sessions-per-hour>
                <session-length>
                  <maximum-bytes>100</maximum-bytes>
                  <minimum-bytes>50</minimum-bytes>
                </session-length>
              </unknown-tcp>
              <unknown-udp>
                <destinations-per-hour>20</destinations-per-hour>
                <sessions-per-hour>20</sessions-per-hour>
                <session-length>
                  <maximum-bytes>200</maximum-bytes>
                  <minimum-bytes>75</minimum-bytes>
                </session-length>
              </unknown-udp>
            </unknown-applications>
          </configuration>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        unknown = result["configuration"]["unknown_applications"]
        assert unknown["unknown_tcp"] == {
            "destinations_per_hour": 10,
            "sessions_per_hour": 10,
            "session_length": {"maximum_bytes": 100, "minimum_bytes": 50},
        }
        assert unknown["unknown_udp"] == {
            "destinations_per_hour": 20,
            "sessions_per_hour": 20,
            "session_length": {"maximum_bytes": 200, "minimum_bytes": 75},
        }

    def test_report_topn_and_scheduled(self):
        xml = """
        <botnet>
          <report>
            <topn>100</topn>
            <scheduled>yes</scheduled>
          </report>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        assert result["report"] == {"topn": 100, "scheduled": True}

    def test_report_scheduled_no(self):
        xml = "<botnet><report><topn>50</topn><scheduled>no</scheduled></report></botnet>"
        result = export_botnet_report(_shared(xml))
        assert result["report"] == {"topn": 50, "scheduled": False}

    def test_invalid_threshold_value_excluded(self):
        xml = """
        <botnet>
          <configuration>
            <http>
              <dynamic-dns><enabled>yes</enabled><threshold>bogus</threshold></dynamic-dns>
            </http>
          </configuration>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        assert result["configuration"]["http"]["dynamic_dns"] == {"enabled": True}

    def test_invalid_topn_value_excluded(self):
        xml = "<botnet><report><topn>bogus</topn><scheduled>yes</scheduled></report></botnet>"
        result = export_botnet_report(_shared(xml))
        assert "topn" not in result["report"]
        assert result["report"]["scheduled"] is True

    def test_full_real_haarp_config(self):
        """Matches the structure seen in UA-HAARP-Cofnig_20260605.xml."""
        xml = """
        <botnet>
          <configuration>
            <http>
              <dynamic-dns><enabled>yes</enabled><threshold>5</threshold></dynamic-dns>
              <malware-sites><enabled>yes</enabled><threshold>5</threshold></malware-sites>
              <recent-domains><enabled>yes</enabled><threshold>5</threshold></recent-domains>
              <ip-domains><enabled>yes</enabled><threshold>10</threshold></ip-domains>
              <executables-from-unknown-sites><enabled>yes</enabled><threshold>5</threshold></executables-from-unknown-sites>
            </http>
            <other-applications><irc>yes</irc></other-applications>
            <unknown-applications>
              <unknown-tcp>
                <destinations-per-hour>10</destinations-per-hour>
                <sessions-per-hour>10</sessions-per-hour>
                <session-length>
                  <maximum-bytes>100</maximum-bytes>
                  <minimum-bytes>50</minimum-bytes>
                </session-length>
              </unknown-tcp>
              <unknown-udp>
                <destinations-per-hour>10</destinations-per-hour>
                <sessions-per-hour>10</sessions-per-hour>
                <session-length>
                  <maximum-bytes>100</maximum-bytes>
                  <minimum-bytes>50</minimum-bytes>
                </session-length>
              </unknown-udp>
            </unknown-applications>
          </configuration>
          <report>
            <topn>100</topn>
            <scheduled>yes</scheduled>
          </report>
        </botnet>
        """
        result = export_botnet_report(_shared(xml))
        assert result["configuration"]["http"]["ip_domains"] == {"enabled": True, "threshold": 10}
        assert result["configuration"]["other_applications"] == {"irc": True}
        assert result["configuration"]["unknown_applications"]["unknown_tcp"]["sessions_per_hour"] == 10
        assert result["report"] == {"topn": 100, "scheduled": True}
