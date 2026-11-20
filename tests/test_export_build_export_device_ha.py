"""build_export() integration tests for the device-scoped conditional keys
and their migration warnings — issue #105.

The getters (export_device_setup / export_high_availability /
export_botnet_report / export_ike_gateways) are unit-tested in isolation;
these tests guard the *integration layer* in export/writer.py:

* conditional top-level keys — data["device_setup"], data["high_availability"],
  data["shared"]["botnet_report"] — appear only when the source config
  actually carries the corresponding content;
* the five migration warnings emitted alongside them (device_setup,
  high_availability, network/ike_gateways, network/ike_gateways/<name>,
  shared/botnet_report);
* the IKE local-address metadata keys (_local_ip / _local_iface) are popped
  by the writer before the gateway list is serialized — they must never
  reach the export JSON.

Tests only: no exporter behavior is changed here. Inline XML fragments
follow the suite convention (the repo gitignores *.xml); the IKE gateway
shape mirrors tests/sample_config.py's ike-gw-1 (local-address ip+interface)
and ike-gw-cert (ip only), which no build_export() test consumed before.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from export.writer import build_export, write_export
from export_fixtures import network_root, shared_root

# ── fixture fragments ─────────────────────────────────────────────────────────

SYSTEM_XML = """
<system>
  <hostname>fw-ha-01</hostname>
  <ip-address>192.168.10.213</ip-address>
  <netmask>255.255.255.0</netmask>
  <default-gateway>192.168.10.1</default-gateway>
  <type><static/></type>
  <service><disable-telnet>yes</disable-telnet></service>
  <ntp-servers>
    <primary-ntp-server><ntp-server-address>pool.ntp.org</ntp-server-address></primary-ntp-server>
  </ntp-servers>
  <dns-setting><servers><primary>10.250.250.250</primary></servers></dns-setting>
  <route>
    <service>
      <entry name="dns"><source><interface>management</interface></source></entry>
    </service>
  </route>
</system>
"""

HA_ENABLED_XML = """
<high-availability>
  <enabled>yes</enabled>
  <group>
    <group-id>7</group-id>
    <peer-ip>10.0.0.2</peer-ip>
  </group>
</high-availability>
"""

BOTNET_XML = """
<botnet>
  <configuration>
    <http>
      <dynamic-dns><enabled>yes</enabled><threshold>5</threshold></dynamic-dns>
    </http>
  </configuration>
</botnet>
"""

# Two binding shapes: ip+interface (binding reported as the interface) and
# ip-only (binding reported as the ip) — same shapes as sample_config.py.
IKE_XML = """
<ike>
  <gateway>
    <entry name="ike-gw-1">
      <peer-address><ip>203.0.113.1</ip></peer-address>
      <local-address><ip>10.1.1.1</ip><interface>ethernet1/1</interface></local-address>
      <protocol><version>ikev2</version></protocol>
    </entry>
    <entry name="ike-gw-2">
      <peer-address><ip>203.0.113.2</ip></peer-address>
      <local-address><ip>10.1.1.2</ip></local-address>
      <protocol><version>ikev1</version></protocol>
    </entry>
  </gateway>
</ike>
"""

# The five warning object_paths this issue guards. The per-gateway IKE
# warning is matched by prefix (network/ike_gateways/<name>).
CONDITIONAL_PATHS = (
    "device_setup",
    "high_availability",
    "network/ike_gateways",
    "shared/botnet_report",
)


def _config_root(deviceconfig_xml: str = "") -> ET.Element:
    """Device-scoped content lives at devices/entry/deviceconfig — the same
    tree shape the getter unit tests use, here driven through build_export."""
    return ET.fromstring(
        f"<config version='11.1.0'>"
        f"<devices><entry name='localhost.localdomain'>"
        f"<deviceconfig>{deviceconfig_xml}</deviceconfig>"
        f"</entry></devices></config>"
    )


def _export(deviceconfig_xml: str = "", shared_xml: str | None = "",
            network_xml: str | None = "") -> dict:
    return build_export(
        _config_root(deviceconfig_xml),
        ET.fromstring("<vsys/>"),
        None if shared_xml is None else shared_root(shared_xml),
        None if network_xml is None else network_root(network_xml),
        "device-ha.xml",
        "vsys1",
    )


def _positive_export() -> dict:
    return _export(SYSTEM_XML + HA_ENABLED_XML, BOTNET_XML, IKE_XML)


def _warnings_at(data: dict, path: str) -> list[dict]:
    return [w for w in data["migration_warnings"] if w["object_path"] == path]


def _ike_gateway_warnings(data: dict) -> list[dict]:
    return [w for w in data["migration_warnings"]
            if w["object_path"].startswith("network/ike_gateways/")]


def _conditional_warnings(data: dict) -> list[dict]:
    return [w for w in data["migration_warnings"]
            if w["object_path"] in CONDITIONAL_PATHS
            or w["object_path"].startswith("network/ike_gateways/")]


# ── positive integration: content present → keys + warnings + stripping ──────

class TestBuildExportDeviceHaPositive:
    def test_device_setup_sections_populated(self):
        data = _positive_export()
        assert data["device_setup"] == {
            "management_interface": {
                "ip_address": "192.168.10.213",
                "netmask": "255.255.255.0",
                "default_gateway": "192.168.10.1",
                "type": "static",
                "telnet": False,
            },
            "service_settings": {
                "ntp_primary": "pool.ntp.org",
                "dns_primary": "10.250.250.250",
            },
            "service_routes": [{"service": "dns", "interface": "management"}],
        }

    def test_high_availability_enabled_with_group_and_peer(self):
        data = _positive_export()
        assert data["high_availability"]["enabled"] is True
        assert data["high_availability"]["group_id"] == 7
        assert data["high_availability"]["peer_ip"] == "10.0.0.2"

    def test_shared_botnet_report_present(self):
        data = _positive_export()
        assert data["shared"]["botnet_report"] == {
            "configuration": {"http": {"dynamic_dns": {"enabled": True, "threshold": 5}}},
        }

    def test_meta_reads_hostname_and_version_from_device_root(self):
        data = _positive_export()
        assert data["meta"]["hostname"] == "fw-ha-01"
        assert data["meta"]["sw_version"] == "11.1.0"
        assert data["meta"]["source_file"] == "device-ha.xml"
        assert data["meta"]["vsys"] == "vsys1"

    def test_exactly_the_five_migration_warnings_emitted(self):
        data = _positive_export()
        assert len(_warnings_at(data, "device_setup")) == 1
        assert len(_warnings_at(data, "high_availability")) == 1
        assert len(_warnings_at(data, "network/ike_gateways")) == 1
        assert len(_warnings_at(data, "shared/botnet_report")) == 1
        assert len(_ike_gateway_warnings(data)) == 2  # one per bound gateway
        # No unrelated warning fires for this config — the five blocks above
        # are the complete warning surface of the fixture.
        assert len(data["migration_warnings"]) == 6
        assert all(w["severity"] == "warn" for w in _conditional_warnings(data))

    def test_device_setup_warning_lists_sections_and_serial_notice(self):
        data = _positive_export()
        message = _warnings_at(data, "device_setup")[0]["message"]
        assert "management_interface" in message
        assert "service_settings" in message
        assert "service_routes (1 entries)" in message
        assert "device_serial" in message

    def test_ha_warning_names_group_and_peer(self):
        data = _positive_export()
        message = _warnings_at(data, "high_availability")[0]["message"]
        assert "group 7" in message
        assert "peer 10.0.0.2" in message

    def test_botnet_warning_is_reference_only_notice(self):
        data = _positive_export()
        message = _warnings_at(data, "shared/botnet_report")[0]["message"]
        assert "reference only" in message

    def test_ike_warnings_cover_placeholder_psk_and_each_binding(self):
        data = _positive_export()
        aggregate = _warnings_at(data, "network/ike_gateways")[0]["message"]
        assert "2 IKE gateway(s)" in aggregate
        assert "MIGRATION-PLACEHOLDER-PSK" in aggregate
        per_gw = {w["object_path"]: w["message"] for w in _ike_gateway_warnings(data)}
        assert set(per_gw) == {
            "network/ike_gateways/ike-gw-1",
            "network/ike_gateways/ike-gw-2",
        }
        # ip+interface binding is reported as the interface; ip-only as the ip.
        assert "(ethernet1/1)" in per_gw["network/ike_gateways/ike-gw-1"]
        assert "(10.1.1.2)" in per_gw["network/ike_gateways/ike-gw-2"]
        assert all("local-address binding" in m for m in per_gw.values())

    def test_ike_local_address_metadata_stripped_from_serialized_export(self):
        data = _positive_export()
        gateways = data["network"]["ike_gateways"]
        assert [gw["name"] for gw in gateways] == ["ike-gw-1", "ike-gw-2"]
        for gw in gateways:
            assert "_local_ip" not in gw
            assert "_local_iface" not in gw
            # The pushable gateway content survives the stripping.
            assert gw["authentication"]["pre_shared_key"]["key"] == "MIGRATION-PLACEHOLDER-PSK"
        serialized = json.dumps(data)
        assert "_local_ip" not in serialized
        assert "_local_iface" not in serialized


# ── negative paths: content absent → keys omitted, warnings silent ────────────

class TestBuildExportDeviceHaNegative:
    def test_empty_config_omits_conditional_keys_and_warnings(self):
        data = _export()
        assert "device_setup" not in data
        assert "high_availability" not in data
        assert "shared" not in data
        assert _conditional_warnings(data) == []

    def test_none_shared_and_network_roots_omit_conditional_keys(self):
        data = _export(shared_xml=None, network_xml=None)
        assert "device_setup" not in data
        assert "high_availability" not in data
        assert "shared" not in data
        assert _conditional_warnings(data) == []

    def test_disabled_ha_omits_key_and_warning(self):
        ha_disabled = HA_ENABLED_XML.replace("<enabled>yes</enabled>", "<enabled>no</enabled>")
        data = _export(SYSTEM_XML + ha_disabled, BOTNET_XML, IKE_XML)
        assert "high_availability" not in data
        assert _warnings_at(data, "high_availability") == []
        # The other conditional surfaces are unaffected.
        assert "device_setup" in data
        assert "shared" in data

    def test_hostname_only_system_omits_device_setup(self):
        data = _export("<system><hostname>fw01</hostname></system>")
        assert "device_setup" not in data
        assert _warnings_at(data, "device_setup") == []

    def test_empty_botnet_element_omits_shared_key_and_warning(self):
        data = _export(shared_xml="<botnet/>")
        assert "shared" not in data
        assert _warnings_at(data, "shared/botnet_report") == []

    def test_ike_gateway_without_local_address_has_no_per_gateway_warning(self):
        network_xml = IKE_XML.replace(
            "<local-address><ip>10.1.1.1</ip><interface>ethernet1/1</interface></local-address>",
            "",
        ).replace("<local-address><ip>10.1.1.2</ip></local-address>", "")
        data = _export(network_xml=network_xml)
        assert len(data["network"]["ike_gateways"]) == 2
        # Aggregate placeholder-PSK warning still fires; no binding warnings.
        assert len(_warnings_at(data, "network/ike_gateways")) == 1
        assert _ike_gateway_warnings(data) == []
        assert "_local_ip" not in json.dumps(data)
        assert "_local_iface" not in json.dumps(data)


# ── opportunistic: write_export() console summary for the new keys ────────────

class TestWriteExportDeviceHaSummary:
    def test_console_summary_and_json_roundtrip(self, tmp_path, capsys):
        data = _positive_export()
        out = tmp_path / "export.json"
        write_export(data, str(out))
        assert json.loads(out.read_text(encoding="utf-8")) == data
        err = capsys.readouterr().err
        assert "device  : mgmt_iface | svc_settings | 1 svc_routes" in err
        assert "ha      : group 7" in err
        assert "peer 10.0.0.2" in err
        assert "shared  : botnet_report present" in err
        assert "migration warning(s)" in err
