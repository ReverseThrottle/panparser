"""Field-asserting tests for export_loopback_interfaces() — issue #92 backfill.

Covers numbered units plus the bare-parent normalization to 'loopback.1'
(with its migration note) and the skip when loopback.1 already exists.
"""
from __future__ import annotations

from export.objects import export_loopback_interfaces
from export_fixtures import network_root


def _loopback(inner: str) -> str:
    return f"<interface><loopback>{inner}</loopback></interface>"


class TestExportLoopbackInterfaces:
    def test_none_root(self):
        assert export_loopback_interfaces(None) == ([], [])

    def test_missing_container(self):
        assert export_loopback_interfaces(network_root("<interface><ethernet/></interface>")) == ([], [])

    def test_numbered_units_full_and_minimal(self):
        root = network_root(_loopback("""
        <units>
          <entry name="loopback.10">
            <comment>management loopback</comment>
            <mtu>1500</mtu>
            <interface-management-profile>mgmt-full</interface-management-profile>
            <ip><entry name="10.255.255.1/32"/><entry name="10.255.255.2/32"/><entry/></ip>
          </entry>
          <entry name="loopback.20"/>
        </units>
        """))
        out, notes = export_loopback_interfaces(root)
        assert out == [
            {
                "name": "loopback.10",
                "comment": "management loopback",
                "mtu": 1500,
                "interface_management_profile": "mgmt-full",
                "ip": [{"name": "10.255.255.1/32"}, {"name": "10.255.255.2/32"}],
            },
            {"name": "loopback.20"},
        ]
        assert notes == []

    def test_bare_parent_with_ips_and_mgmt_normalized(self):
        root = network_root(_loopback("""
        <ip><entry name="10.255.255.9/32"/></ip>
        <interface-management-profile>ping-only</interface-management-profile>
        """))
        out, notes = export_loopback_interfaces(root)
        assert out == [{
            "name": "loopback.1",
            "interface_management_profile": "ping-only",
            "ip": [{"name": "10.255.255.9/32"}],
        }]
        assert len(notes) == 1
        assert "normalized to 'loopback.1'" in notes[0]

    def test_bare_parent_mgmt_only(self):
        root = network_root(_loopback("<interface-management-profile>ping-only</interface-management-profile>"))
        out, notes = export_loopback_interfaces(root)
        assert out == [{"name": "loopback.1", "interface_management_profile": "ping-only"}]
        assert len(notes) == 1

    def test_bare_parent_ips_only(self):
        root = network_root(_loopback('<ip><entry name="10.0.0.1/32"/></ip>'))
        out, notes = export_loopback_interfaces(root)
        assert out == [{"name": "loopback.1", "ip": [{"name": "10.0.0.1/32"}]}]
        assert len(notes) == 1

    def test_bare_parent_skipped_when_unit_loopback_1_exists(self):
        root = network_root(_loopback("""
        <ip><entry name="10.0.0.1/32"/></ip>
        <units><entry name="loopback.1"><ip><entry name="10.0.0.2/32"/></ip></entry></units>
        """))
        out, notes = export_loopback_interfaces(root)
        assert out == [{"name": "loopback.1", "ip": [{"name": "10.0.0.2/32"}]}]
        assert notes == []

    def test_bare_parent_without_ips_or_mgmt_ignored(self):
        root = network_root(_loopback("<comment>nothing to carry over</comment>"))
        assert export_loopback_interfaces(root) == ([], [])
