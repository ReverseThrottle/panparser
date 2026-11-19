"""Regression tests for issue #67 — full content export for anti-spyware,
URL filtering, DNS security, zone protection and decryption profiles.

Before the fix these exporters emitted name/description only (via
_export_named_profiles), so scm-mcp's PAN-OS -> SCM migration reported the
profiles as NOT MIGRATED. The exported shapes now mirror the pan-scm-sdk
CreateModels; contract tests validate against the real SDK when installed.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import (
    export_anti_spyware_profiles,
    export_url_access_profiles,
    export_dns_security_profiles,
    export_zone_protection_profiles,
    export_decryption_profiles,
)


def _vsys(xml_str: str):
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


def _net(xml_str: str):
    return ET.fromstring(f"<network>{xml_str}</network>")


class TestExportAntiSpywareProfiles:
    def test_returns_empty_when_root_none(self):
        assert export_anti_spyware_profiles(None) == []

    def test_returns_empty_when_no_container(self):
        assert export_anti_spyware_profiles(_vsys("<profiles/>")) == []

    def test_full_profile_content(self):
        xml = """
        <profiles><spyware>
          <entry name="Strict">
            <description>block everything</description>
            <rules>
              <entry name="critical-block">
                <severity><member>critical</member><member>high</member></severity>
                <category>any</category>
                <threat-name>any</threat-name>
                <packet-capture>single-packet</packet-capture>
                <action><reset-both/></action>
              </entry>
              <entry name="temp-block">
                <severity><member>medium</member></severity>
                <category>spyware</category>
                <action>
                  <block-ip><track-by>source</track-by><duration>300</duration></block-ip>
                </action>
              </entry>
            </rules>
            <threat-exception>
              <entry name="10001">
                <action><allow/></action>
                <exempt-ip><entry name="10.0.0.1"/></exempt-ip>
                <notes>vendor exception</notes>
              </entry>
            </threat-exception>
            <mica-engine-spyware-enabled>
              <entry name="inline"><inline-policy-action>drop</inline-policy-action></entry>
            </mica-engine-spyware-enabled>
            <cloud-inline-analysis>yes</cloud-inline-analysis>
            <inline-exception-edl-url><member>https://example.com/edl</member></inline-exception-edl-url>
            <inline-exception-ip-address><member>192.0.2.1</member></inline-exception-ip-address>
          </entry>
        </spyware></profiles>
        """
        p = export_anti_spyware_profiles(_vsys(xml))[0]
        assert p["name"] == "Strict"
        assert p["description"] == "block everything"
        assert p["rules"][0] == {
            "name": "critical-block",
            "severity": ["critical", "high"],
            "category": "any",
            "threat_name": "any",
            "packet_capture": "single-packet",
            "action": {"reset_both": {}},
        }
        assert p["rules"][1]["action"] == {
            "block_ip": {"track_by": "source", "duration": 300}
        }
        # packet_capture absent in XML -> PAN-OS default 'disable' (SCM requires it)
        assert p["threat_exception"] == [{
            "name": "10001",
            "packet_capture": "disable",
            "action": {"allow": {}},
            "exempt_ip": [{"name": "10.0.0.1"}],
            "notes": "vendor exception",
        }]
        assert p["mica_engine_spyware_enabled"] == [
            {"name": "inline", "inline_policy_action": "drop"}
        ]
        assert p["cloud_inline_analysis"] is True
        assert p["inline_exception_edl_url"] == ["https://example.com/edl"]
        assert p["inline_exception_ip_address"] == ["192.0.2.1"]
        assert "_migration_notes" not in p

    def test_rule_defaults_fill_scm_required_fields(self):
        xml = """
        <profiles><spyware><entry name="Minimal">
          <rules><entry name="r1"/></rules>
          <mica-engine-spyware-enabled><entry name="m1"/></mica-engine-spyware-enabled>
        </entry></spyware></profiles>
        """
        p = export_anti_spyware_profiles(_vsys(xml))[0]
        assert p["rules"][0]["severity"] == ["any"]
        assert p["rules"][0]["category"] == "any"
        assert p["rules"][0]["threat_name"] == "any"
        # PAN-OS default inline-policy-action per codegen spec
        assert p["mica_engine_spyware_enabled"][0]["inline_policy_action"] == "alert"

    def test_legacy_botnet_domains_noted_not_dropped(self):
        xml = """
        <profiles><spyware><entry name="Legacy">
          <botnet-domains><lists><entry name="x"><action><block/></action></entry></lists></botnet-domains>
          <disable-override>yes</disable-override>
        </entry></spyware></profiles>
        """
        p = export_anti_spyware_profiles(_vsys(xml))[0]
        assert "botnet-domains" in p["_migration_notes"][0]
        assert "disable-override" in p["_migration_notes"][0]

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.security.anti_spyware_profiles import AntiSpywareProfileCreateModel

        xml = """
        <profiles><spyware><entry name="SDK">
          <rules><entry name="r">
            <severity><member>any</member></severity>
            <category>any</category>
            <action><block-ip><track-by>source-and-destination</track-by><duration>600</duration></block-ip></action>
          </entry></rules>
          <threat-exception><entry name="1"><action><alert/></action></entry></threat-exception>
        </entry></spyware></profiles>
        """
        for p in export_anti_spyware_profiles(_vsys(xml)):
            payload = {k: v for k, v in p.items() if k != "_migration_notes"}
            AntiSpywareProfileCreateModel(folder="All", **payload)


class TestExportUrlAccessProfiles:
    def test_returns_empty_when_root_none(self):
        assert export_url_access_profiles(None) == []

    def test_full_profile_content(self):
        xml = """
        <profiles><url-filtering>
          <entry name="Corp">
            <alert><member>grayware</member></alert>
            <allow><member>business-and-economy</member></allow>
            <block><member>malware</member><member>phishing</member></block>
            <continue><member>unknown</member></continue>
            <redirect><member>newly-registered-domain</member></redirect>
            <credential-enforcement>
              <mode><ip-user><agent-name>Agent1</agent-name><user-agent>UA</user-agent></ip-user></mode>
              <block><member>malware</member></block>
              <log-severity>high</log-severity>
            </credential-enforcement>
            <safe-search-enforcement>yes</safe-search-enforcement>
            <log-http-hdr-xff>yes</log-http-hdr-xff>
            <log-http-hdr-user-agent>no</log-http-hdr-user-agent>
            <mlav-category-exception><member>benign</member></mlav-category-exception>
          </entry>
        </url-filtering></profiles>
        """
        p = export_url_access_profiles(_vsys(xml))[0]
        assert p["block"] == ["malware", "phishing"]
        assert p["continue"] == ["unknown"]
        assert p["redirect"] == ["newly-registered-domain"]
        assert p["credential_enforcement"] == {
            "mode": {"ip_user": {"agent_name": "Agent1", "user_agent": "UA"}},
            "block": ["malware"],
            "log_severity": "high",
        }
        assert p["safe_search_enforcement"] is True
        assert p["log_http_hdr_xff"] is True
        # 'no' flags are SDK defaults and carry no migratable content
        assert "log_http_hdr_user_agent" not in p
        assert p["mlav_category_exception"] == ["benign"]
        # Category lists / credential-enforcement are exported content, not
        # unsupported — they must not appear in migration notes.
        assert "_migration_notes" not in p

    def test_disable_override_noted(self):
        xml = """
        <profiles><url-filtering><entry name="Locked">
          <disable-override>yes</disable-override>
        </entry></url-filtering></profiles>
        """
        p = export_url_access_profiles(_vsys(xml))[0]
        assert "disable-override" in p["_migration_notes"][0]

    def test_credential_enforcement_group_mapping_and_disabled_modes(self):
        xml = """
        <profiles><url-filtering>
          <entry name="GM">
            <credential-enforcement><mode><group-mapping>corp-groups</group-mapping></mode></credential-enforcement>
          </entry>
          <entry name="Off">
            <credential-enforcement><mode><disabled/></mode></credential-enforcement>
          </entry>
        </url-filtering></profiles>
        """
        gm, off = export_url_access_profiles(_vsys(xml))
        assert gm["credential_enforcement"]["mode"] == {"group_mapping": "corp-groups"}
        assert off["credential_enforcement"]["mode"] == {"disabled": {}}

    def test_unrepresentable_content_noted(self):
        xml = """
        <profiles><url-filtering><entry name="Extra">
          <enable-container-page>yes</enable-container-page>
          <http-header-insertion><entry name="H"><header>X-Test</header></entry></http-header-insertion>
          <override><member>someone</member></override>
          <credential-enforcement><redirect><member>cat</member></redirect></credential-enforcement>
        </entry></url-filtering></profiles>
        """
        p = export_url_access_profiles(_vsys(xml))[0]
        notes = p["_migration_notes"][0]
        for tag in ("enable-container-page", "http-header-insertion", "override",
                    "credential-enforcement/redirect"):
            assert tag in notes

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.security.url_access_profiles import URLAccessProfileCreateModel

        xml = """
        <profiles><url-filtering><entry name="SDK">
          <block><member>malware</member></block>
          <continue><member>unknown</member></continue>
          <credential-enforcement>
            <mode><domain-credentials/></mode>
            <alert><member>grayware</member></alert>
          </credential-enforcement>
          <safe-search-enforcement>yes</safe-search-enforcement>
        </entry></url-filtering></profiles>
        """
        for p in export_url_access_profiles(_vsys(xml)):
            payload = {k: v for k, v in p.items() if k != "_migration_notes"}
            URLAccessProfileCreateModel(folder="All", **payload)


class TestExportDnsSecurityProfiles:
    def test_returns_empty_when_root_none(self):
        assert export_dns_security_profiles(None) == []

    def test_full_botnet_domains_content(self):
        xml = """
        <profiles><dns-security>
          <entry name="DNS">
            <botnet-domains>
              <dns-security-categories>
                <entry name="pan-dns-sec-malware">
                  <action>sinkhole</action><log-level>high</log-level>
                  <packet-capture>single-packet</packet-capture>
                </entry>
                <entry name="pan-dns-sec-benign"/>
              </dns-security-categories>
              <lists>
                <entry name="bad-domains">
                  <action><block/></action><packet-capture>extended-capture</packet-capture>
                </entry>
              </lists>
              <sinkhole/>
              <whitelist><entry name="good.example"><description>internal</description></entry></whitelist>
            </botnet-domains>
          </entry>
        </dns-security></profiles>
        """
        p = export_dns_security_profiles(_vsys(xml))[0]
        bd = p["botnet_domains"]
        assert bd["dns_security_categories"][0] == {
            "name": "pan-dns-sec-malware",
            "action": "sinkhole",
            "log_level": "high",
            "packet_capture": "single-packet",
        }
        # SCM requires action; PAN-OS default is 'default'
        assert bd["dns_security_categories"][1] == {
            "name": "pan-dns-sec-benign", "action": "default"
        }
        assert bd["lists"] == [{
            "name": "bad-domains",
            "action": {"block": {}},
            "packet_capture": "extended-capture",
        }]
        # SCM requires both sinkhole addresses; PAN-OS defaults filled in
        assert bd["sinkhole"] == {
            "ipv4_address": "pan-sinkhole-default-ip", "ipv6_address": "::1"
        }
        assert bd["whitelist"] == [{"name": "good.example", "description": "internal"}]
        assert "_migration_notes" not in p

    def test_custom_sinkhole_ip_noted(self):
        xml = """
        <profiles><dns-security><entry name="Custom">
          <botnet-domains><sinkhole>
            <ipv4-address>10.1.2.3</ipv4-address><ipv6-address>2001:db8::1</ipv6-address>
          </sinkhole></botnet-domains>
        </entry></dns-security></profiles>
        """
        p = export_dns_security_profiles(_vsys(xml))[0]
        notes = p["_migration_notes"][0]
        assert "10.1.2.3" in notes and "2001:db8::1" in notes
        # value is still exported — never dropped silently
        assert p["botnet_domains"]["sinkhole"]["ipv4_address"] == "10.1.2.3"

    def test_legacy_botnet_content_noted(self):
        xml = """
        <profiles><dns-security><entry name="Legacy">
          <botnet-domains>
            <threat-exception><entry name="1"/></threat-exception>
            <rtype-action><action><block/></action></rtype-action>
          </botnet-domains>
        </entry></dns-security></profiles>
        """
        p = export_dns_security_profiles(_vsys(xml))[0]
        notes = p["_migration_notes"][0]
        assert "botnet-domains/threat-exception" in notes
        assert "botnet-domains/rtype-action" in notes

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.security.dns_security_profiles import DNSSecurityProfileCreateModel

        xml = """
        <profiles><dns-security><entry name="SDK">
          <botnet-domains>
            <dns-security-categories><entry name="pan-dns-sec-c2">
              <action>block</action><log-level>default</log-level>
            </entry></dns-security-categories>
            <lists><entry name="l"><action><sinkhole/></action></entry></lists>
            <sinkhole><ipv4-address>127.0.0.1</ipv4-address></sinkhole>
            <whitelist><entry name="w"/></whitelist>
          </botnet-domains>
        </entry></dns-security></profiles>
        """
        for p in export_dns_security_profiles(_vsys(xml)):
            payload = {k: v for k, v in p.items() if k != "_migration_notes"}
            DNSSecurityProfileCreateModel(folder="All", **payload)


class TestExportZoneProtectionProfiles:
    def test_returns_empty_when_root_none(self):
        assert export_zone_protection_profiles(None) == []

    def test_reads_zone_protection_profile_tag(self):
        """The PAN-OS tag is zone-protection-profile (codegen panos_xpath);
        the old 'zone-protection' path matched nothing and always returned []."""
        xml = '<profiles><zone-protection-profile><entry name="ZP"/></zone-protection-profile></profiles>'
        assert export_zone_protection_profiles(_net(xml)) == [{"name": "ZP"}]
        old_path = '<profiles><zone-protection><entry name="ZP"/></zone-protection></profiles>'
        assert export_zone_protection_profiles(_net(old_path)) == []

    def test_flood_scan_and_whitelist(self):
        xml = """
        <profiles><zone-protection-profile><entry name="ZP">
          <flood>
            <tcp-syn>
              <enable>yes</enable>
              <syn-cookies><alarm-rate>5000</alarm-rate><activate-rate>10000</activate-rate><maximal-rate>20000</maximal-rate></syn-cookies>
            </tcp-syn>
            <udp><enable>no</enable></udp>
            <sctp-init><enable>yes</enable><red><activate-rate>500</activate-rate></red></sctp-init>
          </flood>
          <scan>
            <entry name="8001">
              <action><block-ip><track-by>source</track-by><duration>60</duration></block-ip></action>
              <interval>10</interval><threshold>100</threshold>
            </entry>
            <entry name="8003"><action><alert/></action></entry>
          </scan>
          <scan-white-list>
            <entry name="scanner"><ipv4>10.0.0.0/24</ipv4></entry>
            <entry name="v6scanner"><ipv6>2001:db8::/32</ipv6></entry>
          </scan-white-list>
        </entry></zone-protection-profile></profiles>
        """
        p = export_zone_protection_profiles(_net(xml))[0]
        assert p["flood"]["tcp_syn"] == {
            "enable": True,
            "syn_cookies": {"alarm_rate": 5000, "activate_rate": 10000, "maximal_rate": 20000},
        }
        assert p["flood"]["udp"] == {"enable": False}
        assert p["flood"]["sctp_init"] == {"enable": True, "red": {"activate_rate": 500}}
        assert p["scan"][0] == {
            "name": "8001",
            "action": {"block_ip": {"track_by": "source", "duration": 60}},
            "interval": 10,
            "threshold": 100,
        }
        assert p["scan"][1]["action"] == {"alert": {}}
        assert p["scan_white_list"] == [
            {"name": "scanner", "ipv4": "10.0.0.0/24"},
            {"name": "v6scanner", "ipv6": "2001:db8::/32"},
        ]

    def test_red_and_syn_cookies_both_present_keeps_one_with_note(self):
        """PAN-OS models red/syn-cookies as mutually exclusive variants and
        the SDK forbids both; a config carrying both must not drop silently."""
        xml = """
        <profiles><zone-protection-profile><entry name="ZP">
          <flood><tcp-syn><enable>yes</enable>
            <red><alarm-rate>100</alarm-rate><activate-rate>200</activate-rate><maximal-rate>300</maximal-rate></red>
            <syn-cookies><alarm-rate>100</alarm-rate><activate-rate>200</activate-rate><maximal-rate>300</maximal-rate></syn-cookies>
          </tcp-syn></flood>
        </entry></zone-protection-profile></profiles>
        """
        p = export_zone_protection_profiles(_net(xml))[0]
        assert "red" not in p["flood"]["tcp_syn"]
        assert "syn_cookies" in p["flood"]["tcp_syn"]
        assert "flood/tcp-syn/red" in p["_migration_notes"][0]

    def test_discard_flags_use_sdk_field_names(self):
        xml = """
        <profiles><zone-protection-profile><entry name="ZP">
          <discard-ip-spoof>yes</discard-ip-spoof>
          <discard-ip-frag>yes</discard-ip-frag>
          <discard-icmp-error>yes</discard-icmp-error>
          <discard-tcp-split-handshake>yes</discard-tcp-split-handshake>
          <discard-overlapping-tcp-segment-mismatch>yes</discard-overlapping-tcp-segment-mismatch>
          <remove-tcp-timestamp>yes</remove-tcp-timestamp>
          <strip-tcp-fast-open-and-data>yes</strip-tcp-fast-open-and-data>
          <suppress-icmp-needfrag>yes</suppress-icmp-needfrag>
          <strict-ip-check>yes</strict-ip-check>
          <discard-timestamp>no</discard-timestamp>
          <tcp-reject-non-syn>global</tcp-reject-non-syn>
          <asymmetric-path>drop</asymmetric-path>
          <strip-mptcp-option>yes</strip-mptcp-option>
        </entry></zone-protection-profile></profiles>
        """
        p = export_zone_protection_profiles(_net(xml))[0]
        assert p["spoofed_ip_discard"] is True
        assert p["fragmented_traffic_discard"] is True
        assert p["discard_icmp_embedded_error"] is True
        assert p["tcp_handshake_discard"] is True
        assert p["mismatched_overlapping_tcp_segment_discard"] is True
        assert p["tcp_timestamp_strip"] is True
        assert p["tcp_fast_open_and_data_strip"] is True
        assert p["suppress_icmp_needfrag"] is True
        assert p["strict_ip_check"] is True
        assert "timestamp_discard" not in p  # 'no' carries no migratable content
        assert p["reject_non_syn_tcp"] == "global"
        assert p["asymmetric_path"] == "drop"
        assert p["mptcp_option_strip"] == "yes"

    def test_ipv6_non_ip_protocol_and_l2_sgt(self):
        xml = """
        <profiles><zone-protection-profile><entry name="ZP">
          <ipv6>
            <discard-ip-spoof>yes</discard-ip-spoof>
            <extension-hdr><discard-routing-hdr>yes</discard-routing-hdr></extension-hdr>
          </ipv6>
          <non-ip-protocol>
            <list-type>exclude</list-type>
            <protocol><entry name="0x88CC"><ether-type>0x88CC</ether-type><enable>yes</enable></entry></protocol>
          </non-ip-protocol>
          <l2-sec-group-tag-protection>
            <tags><entry name="sgt-100"><tag>100</tag><enable>yes</enable></entry></tags>
          </l2-sec-group-tag-protection>
          <net-inspection><signatures><entry name="sig1"/></signatures></net-inspection>
        </entry></zone-protection-profile></profiles>
        """
        p = export_zone_protection_profiles(_net(xml))[0]
        # SDK models ipv6 as a free-form dict — the whole block is preserved
        assert p["ipv6"] == {
            "discard_ip_spoof": True,
            "extension_hdr": {"discard_routing_hdr": True},
        }
        assert p["non_ip_protocol"] == {
            "list_type": "exclude",
            "protocol": [{"name": "0x88CC", "ether_type": "0x88CC", "enable": True}],
        }
        assert p["l2_sec_group_tag_protection"] == {
            "tags": [{"name": "sgt-100", "tag": "100", "enable": True}]
        }
        assert "net-inspection" in p["_migration_notes"][0]

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.network.zone_protection_profile import ZoneProtectionProfileCreateModel

        xml = """
        <profiles><zone-protection-profile><entry name="SDK">
          <flood><tcp-syn><enable>yes</enable>
            <red><alarm-rate>100</alarm-rate><activate-rate>200</activate-rate><maximal-rate>300</maximal-rate></red>
            <syn-cookies><alarm-rate>100</alarm-rate><activate-rate>200</activate-rate><maximal-rate>300</maximal-rate></syn-cookies>
          </tcp-syn></flood>
          <scan><entry name="8001"><action><block-ip><track-by>source</track-by><duration>60</duration></block-ip></action>
            <interval>2</interval><threshold>10</threshold></entry></scan>
          <scan-white-list><entry name="w"><ipv4>10.0.0.1</ipv4></entry></scan-white-list>
          <discard-ip-spoof>yes</discard-ip-spoof>
          <discard-overlapping-tcp-segment-mismatch>yes</discard-overlapping-tcp-segment-mismatch>
          <tcp-reject-non-syn>yes</tcp-reject-non-syn>
          <ipv6><discard-ip-spoof>yes</discard-ip-spoof></ipv6>
          <non-ip-protocol><list-type>include</list-type>
            <protocol><entry name="0x88CC"><ether-type>0x88CC</ether-type></entry></protocol>
          </non-ip-protocol>
          <l2-sec-group-tag-protection><tags><entry name="t"><tag>5</tag></entry></tags></l2-sec-group-tag-protection>
        </entry></zone-protection-profile></profiles>
        """
        for p in export_zone_protection_profiles(_net(xml)):
            payload = {k: v for k, v in p.items() if k != "_migration_notes"}
            ZoneProtectionProfileCreateModel(folder="All", **payload)


class TestExportDecryptionProfiles:
    def test_returns_empty_when_root_none(self):
        assert export_decryption_profiles(None) == []

    def test_full_ssl_content(self):
        xml = """
        <profiles><decryption>
          <entry name="Decrypt">
            <description>corporate decryption</description>
            <ssl-forward-proxy>
              <block-expired-certificate>yes</block-expired-certificate>
              <block-untrusted-issuer>yes</block-untrusted-issuer>
              <block-unsupported-version>no</block-unsupported-version>
              <strip-alpn>yes</strip-alpn>
            </ssl-forward-proxy>
            <ssl-inbound-proxy>
              <block-if-hsm-unavailable>yes</block-if-hsm-unavailable>
            </ssl-inbound-proxy>
            <ssl-no-proxy>
              <block-expired-certificate>yes</block-expired-certificate>
            </ssl-no-proxy>
            <ssl-protocol-settings>
              <min-version>tls1-2</min-version>
              <max-version>max</max-version>
              <enc-algo-3des>no</enc-algo-3des>
              <enc-algo-rc4>no</enc-algo-rc4>
              <auth-algo-sha1>no</auth-algo-sha1>
              <enc-algo-aes-256-gcm>yes</enc-algo-aes-256-gcm>
            </ssl-protocol-settings>
          </entry>
        </decryption></profiles>
        """
        p = export_decryption_profiles(_vsys(xml))[0]
        assert p["description"] == "corporate decryption"
        assert p["ssl_forward_proxy"] == {
            "block_expired_certificate": True,
            "block_untrusted_issuer": True,
            "strip_alpn": True,
        }
        assert p["ssl_inbound_proxy"] == {"block_if_hsm_unavailable": True}
        assert p["ssl_no_proxy"] == {"block_expired_certificate": True}
        # SDK defaults protocol toggles to True — explicit 'no' must survive
        assert p["ssl_protocol_settings"] == {
            "min_version": "tls1-2",
            "max_version": "max",
            "enc_algo_3des": False,
            "enc_algo_rc4": False,
            "auth_algo_sha1": False,
            "enc_algo_aes_256_gcm": True,
        }
        assert "_migration_notes" not in p

    def test_unsupported_ssl_flags_noted(self):
        xml = """
        <profiles><decryption><entry name="Extra">
          <ssl-forward-proxy><block-if-sni-mismatch>yes</block-if-sni-mismatch></ssl-forward-proxy>
          <ssl-inbound-proxy><block-tls13-downgrade-no-resource>yes</block-tls13-downgrade-no-resource></ssl-inbound-proxy>
          <ssh-proxy><block-unsupported-alg>yes</block-unsupported-alg><block-ssh-errors>no</block-ssh-errors></ssh-proxy>
          <forwarded-only>yes</forwarded-only>
        </entry></decryption></profiles>
        """
        p = export_decryption_profiles(_vsys(xml))[0]
        notes = p["_migration_notes"][0]
        assert "ssl-forward-proxy/block-if-sni-mismatch" in notes
        assert "ssl-inbound-proxy/block-tls13-downgrade-no-resource" in notes
        assert "ssh-proxy" in notes
        assert "forwarded-only" in notes
        # ssh-proxy settings are still exported informationally
        assert p["ssh_proxy"] == {"block_unsupported_alg": True, "block_ssh_errors": False}

    def test_contract_with_scm_sdk(self):
        import pytest

        pytest.importorskip("scm")
        from scm.models.security.decryption_profiles import DecryptionProfileCreateModel

        xml = """
        <profiles><decryption><entry name="SDK">
          <ssl-forward-proxy><block-untrusted-issuer>yes</block-untrusted-issuer>
            <block-tls13-downgrade-no-resource>yes</block-tls13-downgrade-no-resource></ssl-forward-proxy>
          <ssl-protocol-settings><min-version>tls1-2</min-version><max-version>tls1-3</max-version>
            <keyxchg-algo-rsa>no</keyxchg-algo-rsa></ssl-protocol-settings>
        </entry></decryption></profiles>
        """
        for p in export_decryption_profiles(_vsys(xml)):
            # SCM cannot store description/ssh-proxy — informational only
            payload = {k: v for k, v in p.items()
                       if k not in ("_migration_notes", "description", "ssh_proxy")}
            DecryptionProfileCreateModel(folder="All", **payload)


class TestBuildExportSurfacesProfileWarnings:
    XML_VSYS = """
    <vsys>
      <profiles>
        <spyware><entry name="Legacy">
          <botnet-domains><lists><entry name="x"><action><block/></action></entry></lists></botnet-domains>
        </entry></spyware>
        <decryption><entry name="SSHOnly">
          <ssh-proxy><block-ssh-errors>yes</block-ssh-errors></ssh-proxy>
        </entry></decryption>
      </profiles>
    </vsys>
    """
    XML_NET = """
    <network>
      <profiles><zone-protection-profile><entry name="ZP">
        <flood><tcp-syn><enable>yes</enable>
          <red><alarm-rate>100</alarm-rate><activate-rate>200</activate-rate><maximal-rate>300</maximal-rate></red>
        </tcp-syn></flood>
        <net-inspection><signatures><entry name="s"/></signatures></net-inspection>
      </entry></zone-protection-profile></profiles>
    </network>
    """

    def test_warnings_and_full_content_in_build_export(self):
        from export.writer import build_export

        data = build_export(
            ET.fromstring("<config version='11.1.0'/>"),
            ET.fromstring(self.XML_VSYS),
            None,
            ET.fromstring(self.XML_NET),
            "test.xml",
            "vsys1",
        )
        sp = data["security_profiles"]
        assert sp["anti_spyware"][0]["name"] == "Legacy"
        assert sp["zone_protection"][0]["flood"]["tcp_syn"]["red"]["activate_rate"] == 200
        assert sp["decryption"][0]["ssh_proxy"] == {"block_ssh_errors": True}

        by_path = {w["object_path"]: w for w in data["migration_warnings"]}
        assert "security_profiles/anti_spyware/Legacy" in by_path
        assert "botnet-domains" in by_path["security_profiles/anti_spyware/Legacy"]["message"]
        assert "security_profiles/zone_protection/ZP" in by_path
        assert "net-inspection" in by_path["security_profiles/zone_protection/ZP"]["message"]
        assert "security_profiles/decryption/SSHOnly" in by_path
        assert "ssh-proxy" in by_path["security_profiles/decryption/SSHOnly"]["message"]
        for w in data["migration_warnings"]:
            assert w["severity"] == "warn"
