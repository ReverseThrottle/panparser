"""Integration regression for issue #122: export ⊇ viewer parity for the
auth-profile and server-profile families on the canonical sample config.

Before #122 the exporters read vsys-only paths while the viewers read
shared-only paths — exact inverses — so build_export carried ZERO auth and
ZERO server profiles while the CLI/TUI showed 2 auth + 7 server profiles.
These tests assert the merged export carries EVERY row the viewers show
(one-directional parity: kerberos/saml/tacacs are exporter-only families
with no viewer surface, which is fine), with the secret-placeholder contract
preserved (no FAKE-TEST-* blob may leak into the artifact).
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from export.objects import export_authentication_profiles
from export.writer import build_export
from parsers._data import get_auth_profiles, get_server_profiles
from sample_config import SAMPLE_CONFIG_XML
from viewer_harness import sample_roots

# Export output key per viewer server-profile type. snmptrap splits into
# v2c/v3 export lists (the exporter returns a tuple); both count.
_SERVER_EXPORT_KEYS = {
    "ldap": ("ldap_server_profiles",),
    "radius": ("radius_server_profiles",),
    "syslog": ("syslog_server_profiles",),
    "snmptrap": ("snmp_v2c_server_profiles", "snmp_v3_server_profiles"),
    "email": ("email_server_profiles",),
    "http": ("http_server_profiles",),
}


@pytest.fixture(scope="module")
def roots():
    return sample_roots()


@pytest.fixture(scope="module")
def export_data(roots):
    vsys, shared, network = roots
    return build_export(
        ET.fromstring(SAMPLE_CONFIG_XML), vsys, shared, network,
        "sample.xml", "vsys1",
    )


def _export_names(export_data: dict, keys: tuple) -> set[str]:
    names = set()
    for key in keys:
        names.update(p["name"] for p in export_data["objects"][key])
    return names


class TestAuthProfileParity:
    def test_export_carries_every_viewer_auth_profile(self, roots, export_data):
        vsys, shared, _ = roots
        viewer_names = {r[0] for r in get_auth_profiles(vsys, shared)}
        export_names = {p["name"] for p in export_data["objects"]["authentication_profiles"]}
        assert viewer_names <= export_names
        # The exact sample families the issue named, plus the vsys entry.
        assert {"auth-local", "auth-nomethod", "auth-vsys"} <= export_names

    def test_same_name_entries_kept_per_scope(self):
        # #107 convention: same-name entries in both scopes are both kept.
        vsys = ET.fromstring(
            "<vsys><authentication-profile><entry name='dup'/></authentication-profile></vsys>")
        shared = ET.fromstring(
            "<shared><authentication-profile><entry name='dup'/></authentication-profile></shared>")
        out = export_authentication_profiles(vsys, shared)
        assert [p["name"] for p in out] == ["dup", "dup"]


class TestServerProfileParity:
    def test_export_carries_every_viewer_server_profile(self, roots, export_data):
        vsys, shared, _ = roots
        for ptype, name, _count, _details in get_server_profiles(vsys, shared):
            assert name in _export_names(export_data, _SERVER_EXPORT_KEYS[ptype]), (
                f"viewer shows {ptype}/{name} but the export does not carry it (#122)"
            )

    def test_all_sample_server_profiles_present(self, export_data):
        # AC2: all 7 shared server profiles + the vsys radius entry.
        expected = {
            "ldap": {"ldap-main", "ldap-nobase"},
            "radius": {"radius-main", "radius-vsys"},
            "syslog": {"syslog-main"},
            "snmptrap": {"snmp-main"},
            "email": {"email-main"},
            "http": {"http-main"},
        }
        for ptype, names in expected.items():
            assert names <= _export_names(export_data, _SERVER_EXPORT_KEYS[ptype])

    def test_snmp_main_exported_as_v2c(self, export_data):
        v2c = {p["name"] for p in export_data["objects"]["snmp_v2c_server_profiles"]}
        assert "snmp-main" in v2c
        assert export_data["objects"]["snmp_v3_server_profiles"] == []


class TestSecretPlaceholderContract:
    def test_no_fake_secret_leaks_into_artifact(self, export_data):
        blob = json.dumps(export_data)
        assert "FAKE-TEST-SECRET-DO-NOT-USE" not in blob
        assert "FAKE-TEST-COMMUNITY-DO-NOT-USE" not in blob

    def test_radius_secret_placeholder(self, export_data):
        profiles = {p["name"]: p for p in export_data["objects"]["radius_server_profiles"]}
        assert profiles["radius-main"]["server"][0]["secret"] == "MIGRATION-PLACEHOLDER-SECRET"
        assert profiles["radius-vsys"]["server"][0]["secret"] == "MIGRATION-PLACEHOLDER-SECRET"

    def test_ldap_bind_password_placeholder(self, export_data):
        profiles = {p["name"]: p for p in export_data["objects"]["ldap_server_profiles"]}
        assert profiles["ldap-main"]["bind_password"] == "MIGRATION-PLACEHOLDER-SECRET"

    def test_snmp_community_placeholder(self, export_data):
        profiles = {p["name"]: p for p in export_data["objects"]["snmp_v2c_server_profiles"]}
        assert profiles["snmp-main"]["server"][0]["community"] == "MIGRATION-PLACEHOLDER-COMMUNITY"

    def test_email_password_placeholder(self, export_data):
        profiles = {p["name"]: p for p in export_data["objects"]["email_server_profiles"]}
        assert profiles["email-main"]["server"][0]["password"] == "MIGRATION-PLACEHOLDER-SECRET"

    def test_email_no_scm_model_warning(self, export_data):
        # pan-scm-sdk has no EmailServerProfile model — the writer must warn
        # (ssl/snmp no-model precedent), not silently drop the family.
        warns = [w for w in export_data["migration_warnings"]
                 if w["object_path"] == "objects/email_server_profiles"]
        assert len(warns) == 1
        assert "no Email Server Profile model" in warns[0]["message"]
