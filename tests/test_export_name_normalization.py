"""Regression tests for issue #93: trailing-underscore name normalization.

The normalization contract, decided once and pinned here:

* Scope — EVERY named collection item in the export is normalized (not just
  addresses/address-groups/service-groups/tags). Nested sub-entities that
  also carry 'name' keys (e.g. syslog servers inside a profile) are not
  standalone SCM objects and keep their spelling.
* Collisions — a rename whose target already exists, is claimed by another
  candidate, or would be empty is skipped: the name keeps its original
  spelling and a 'warn' migration warning reports it. Never silent
  duplicate SCM names.
* Rewrite semantics — any string VALUE exactly equal to a renamed name is
  rewritten export-wide (including free-text fields such as descriptions);
  dict keys, non-string values, and partial matches are never touched.
* Warnings — the info/warn name warnings must be present in the RETURNED
  export (regression: they used to be appended after _apply_renames rebuilt
  every list, orphaning them from the result).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.writer import (
    _apply_renames,
    _build_rename_map,
    _iter_named_objects,
    _normalize_name,
    build_export,
)


def _export(vsys_xml: str = "", network_xml: str = "") -> dict:
    return build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        ET.fromstring(f"<vsys>{vsys_xml}</vsys>"),
        None,
        ET.fromstring(f"<network>{network_xml}</network>"),
        "fixture.xml",
        "vsys1",
    )


def _name_warnings(data: dict) -> list[dict]:
    return [w for w in data["migration_warnings"] if w["object_path"] == "names"]


def _string_values(node):
    """Yield every string value in the export, excluding warning messages
    (which legitimately quote the original names)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "migration_warnings":
                continue
            yield from _string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _string_values(item)
    elif isinstance(node, str):
        yield node


# --------------------------------------------------------------------------
# Unit: _normalize_name
# --------------------------------------------------------------------------

def test_normalize_name_strips_all_trailing_underscores():
    assert _normalize_name("host-web_") == "host-web"
    assert _normalize_name("foo__") == "foo"
    assert _normalize_name("foo_bar_") == "foo_bar"  # internal '_' preserved
    assert _normalize_name("clean") == "clean"
    assert _normalize_name("___") == ""


# --------------------------------------------------------------------------
# Unit: _build_rename_map (collision contract)
# --------------------------------------------------------------------------

def test_build_rename_map_clean_names_is_empty():
    assert _build_rename_map([{"name": "foo"}, {"name": "bar"}]) == ({}, [])


def test_build_rename_map_basic():
    rename_map, skipped = _build_rename_map([{"name": "foo_"}, {"name": "bar"}])
    assert rename_map == {"foo_": "foo"}
    assert skipped == []


def test_build_rename_map_skips_collision_with_existing_name():
    rename_map, skipped = _build_rename_map([{"name": "foo_"}, {"name": "foo"}])
    assert rename_map == {}
    assert skipped == ["foo_"]


def test_build_rename_map_skips_ambiguous_shared_target():
    # Both normalize to 'foo' — neither may silently win.
    rename_map, skipped = _build_rename_map([{"name": "foo_"}, {"name": "foo__"}])
    assert rename_map == {}
    assert sorted(skipped) == ["foo_", "foo__"]


def test_build_rename_map_skips_empty_target():
    rename_map, skipped = _build_rename_map([{"name": "___"}])
    assert rename_map == {}
    assert skipped == ["___"]


def test_build_rename_map_mixed_safe_and_unsafe():
    items = [{"name": "ok_"}, {"name": "foo_"}, {"name": "foo"}]
    rename_map, skipped = _build_rename_map(items)
    assert rename_map == {"ok_": "ok"}
    assert skipped == ["foo_"]


# --------------------------------------------------------------------------
# Unit: _apply_renames / fix (traversal + rewrite boundary)
# --------------------------------------------------------------------------

def test_apply_renames_empty_map_returns_same_object():
    data = {"objects": {"addresses": [{"name": "foo_"}]}}
    assert _apply_renames(data, {}) is data


def test_apply_renames_nested_traversal_and_rewrite_boundary():
    data = {
        "objects": {
            "addresses": [
                {"name": "foo_", "tag": ["t_"], "description": "foo_"},
            ],
        },
        "policy": {
            "security_rules": [
                {
                    "name": "r",
                    "source": ["foo_", "foo_ backup"],  # exact vs partial
                    "disabled": True,
                    "priority": 1,
                    "weight": None,
                },
            ],
        },
        "foo_": "dict keys are never rewritten",
    }
    result = _apply_renames(data, {"foo_": "foo", "t_": "t"})
    addr = result["objects"]["addresses"][0]
    assert addr["name"] == "foo"
    assert addr["tag"] == ["t"]
    # Documented collateral boundary (#93): a free-text value exactly equal
    # to a renamed name IS rewritten — exact matches are treated as references.
    assert addr["description"] == "foo"
    rule = result["policy"]["security_rules"][0]
    assert rule["source"] == ["foo", "foo_ backup"]  # partial match untouched
    assert rule["disabled"] is True
    assert rule["priority"] == 1
    assert rule["weight"] is None
    assert result["foo_"] == "dict keys are never rewritten"


def test_apply_renames_non_string_scalars_untouched():
    data = {"n": 3, "f": 1.5, "b": False, "none": None, "s": "foo_"}
    result = _apply_renames(data, {"foo_": "foo"})
    assert result == {"n": 3, "f": 1.5, "b": False, "none": None, "s": "foo"}


# --------------------------------------------------------------------------
# Unit: _iter_named_objects (structural scope)
# --------------------------------------------------------------------------

def test_iter_named_objects_yields_collection_items_only():
    data = {
        "objects": {
            "addresses": [{"name": "a_", "ip": [{"name": "10.0.0.1/24"}]}],
            "syslog_server_profiles": [
                {"name": "p_", "server": [{"name": "srv_"}]},
            ],
        },
        "network": {"interfaces": {"loopback": [{"name": "loopback.1"}]}},
        "migration_warnings": [{"severity": "info", "message": "m"}],
        "meta": {"hostname": "h"},
        "misc": ["plain string", 3, None, {"no_name": 1}],
    }
    assert [o["name"] for o in _iter_named_objects(data)] == [
        "a_", "p_", "loopback.1",
    ]


# --------------------------------------------------------------------------
# End-to-end: AC1 — populated fixture, names + ALL references + info warning
# --------------------------------------------------------------------------

AC1_VSYS = """
<tag><entry name="tag_"><comments>marker</comments></entry></tag>
<address>
  <entry name="host-web_">
    <ip-netmask>10.1.1.1/32</ip-netmask>
    <tag><member>tag_</member></tag>
  </entry>
</address>
<address-group>
  <entry name="grp_"><static><member>host-web_</member></static></entry>
</address-group>
<rulebase><security><rules>
  <entry name="allow-web">
    <from><member>trust</member></from>
    <to><member>untrust</member></to>
    <source><member>grp_</member></source>
    <destination><member>host-web_</member></destination>
    <application><member>any</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
  </entry>
</rules></security></rulebase>
"""


def test_e2e_names_and_all_references_normalized_with_info_warning():
    data = _export(AC1_VSYS)

    assert data["objects"]["tags"][0]["name"] == "tag"
    addr = data["objects"]["addresses"][0]
    assert addr["name"] == "host-web"
    assert addr["tag"] == ["tag"]
    grp = data["objects"]["address_groups"][0]
    assert grp["name"] == "grp"
    assert grp["static"] == ["host-web"]
    rule = data["policy"]["security_rules"][0]
    assert rule["source"] == ["grp"]
    assert rule["destination"] == ["host-web"]

    # Regression: the info warning must survive into the RETURNED export.
    infos = [w for w in _name_warnings(data) if w["severity"] == "info"]
    assert len(infos) == 1
    for old in ("host-web_", "grp_", "tag_"):
        assert old in infos[0]["message"]

    # No stale reference anywhere outside the warning messages.
    assert not any(
        s in ("host-web_", "grp_", "tag_") for s in _string_values(data)
    )


# --------------------------------------------------------------------------
# End-to-end: AC2 — scope extends beyond the original four collections
# --------------------------------------------------------------------------

AC2_VSYS = """
<service>
  <entry name="svc_"><protocol><tcp><port>8443</port></tcp></protocol></entry>
</service>
<service-group>
  <entry name="sg_"><members><member>svc_</member></members></entry>
</service-group>
<log-settings><syslog>
  <entry name="prof_">
    <server><entry name="srv_"><server>10.0.0.9</server></entry></server>
  </entry>
</syslog></log-settings>
<rulebase><security><rules>
  <entry name="rule_">
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application><member>any</member></application>
    <service><member>svc_</member></service>
    <action>allow</action>
  </entry>
</rules></security></rulebase>
"""


def test_e2e_service_rule_and_profile_names_normalized():
    data = _export(AC2_VSYS)

    svc = data["objects"]["services"][0]
    assert svc["name"] == "svc"
    assert svc["destination_port"] == "8443"
    sg = data["objects"]["service_groups"][0]
    assert sg["name"] == "sg"
    assert sg["members"] == ["svc"]
    rule = data["policy"]["security_rules"][0]
    assert rule["name"] == "rule"
    assert rule["service"] == ["svc"]
    profile = data["objects"]["syslog_server_profiles"][0]
    assert profile["name"] == "prof"
    # Scope boundary: a nested server is a sub-entity, not a standalone SCM
    # object — its name is NOT normalized (and no top-level 'srv_' exists,
    # so the export-wide rewrite leaves it alone too).
    assert profile["server"][0]["name"] == "srv_"

    infos = [w for w in _name_warnings(data) if w["severity"] == "info"]
    assert len(infos) == 1
    for old in ("svc_", "sg_", "rule_", "prof_"):
        assert old in infos[0]["message"]


# --------------------------------------------------------------------------
# End-to-end: AC3 — no trailing underscores → unchanged, no warning
# --------------------------------------------------------------------------

def test_e2e_clean_names_unchanged_and_no_warning():
    vsys = AC1_VSYS.replace("host-web_", "host-web").replace("grp_", "grp").replace("tag_", "tag")
    data = _export(vsys)
    assert data["objects"]["addresses"][0]["name"] == "host-web"
    assert data["objects"]["address_groups"][0]["static"] == ["host-web"]
    assert data["policy"]["security_rules"][0]["source"] == ["grp"]
    assert _name_warnings(data) == []


# --------------------------------------------------------------------------
# End-to-end: AC3 — collision guard, never silent duplicate SCM names
# --------------------------------------------------------------------------

COLLISION_VSYS = """
<address>
  <entry name="foo_"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
  <entry name="foo"><ip-netmask>10.0.0.2/32</ip-netmask></entry>
  <entry name="ok_"><ip-netmask>10.0.0.3/32</ip-netmask></entry>
</address>
<address-group>
  <entry name="cols_"><static><member>foo_</member></static></entry>
</address-group>
"""


def test_e2e_collision_keeps_original_name_and_warns():
    data = _export(COLLISION_VSYS)

    names = [a["name"] for a in data["objects"]["addresses"]]
    assert sorted(names) == ["foo", "foo_", "ok"]  # no duplicate 'foo'
    # References to the skipped name stay consistent with its kept spelling.
    assert data["objects"]["address_groups"][0]["static"] == ["foo_"]

    warns = [w for w in _name_warnings(data) if w["severity"] == "warn"]
    assert len(warns) == 1
    assert "foo_" in warns[0]["message"]
    # The safe rename still happens and is reported.
    infos = [w for w in _name_warnings(data) if w["severity"] == "info"]
    assert len(infos) == 1
    assert "ok_" in infos[0]["message"]
    assert "cols_" in infos[0]["message"]


def test_e2e_ambiguous_double_underscore_collision_warns():
    vsys = """
    <address>
      <entry name="foo_"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
      <entry name="foo__"><ip-netmask>10.0.0.2/32</ip-netmask></entry>
    </address>
    """
    data = _export(vsys)
    names = sorted(a["name"] for a in data["objects"]["addresses"])
    assert names == ["foo_", "foo__"]  # neither silently wins
    warns = [w for w in _name_warnings(data) if w["severity"] == "warn"]
    assert len(warns) == 1
    assert "foo_" in warns[0]["message"] and "foo__" in warns[0]["message"]
    assert [w for w in _name_warnings(data) if w["severity"] == "info"] == []


# --------------------------------------------------------------------------
# End-to-end: info warning truncates the name list after 10 entries
# --------------------------------------------------------------------------

def test_e2e_info_warning_truncates_long_rename_list():
    entries = "".join(
        f'<entry name="a{i:02d}_"><ip-netmask>10.0.1.{i}/32</ip-netmask></entry>'
        for i in range(12)
    )
    data = _export(f"<address>{entries}</address>")
    assert all(
        a["name"] == f"a{i:02d}" for i, a in enumerate(data["objects"]["addresses"])
    )
    infos = [w for w in _name_warnings(data) if w["severity"] == "info"]
    assert len(infos) == 1
    assert "Normalized 12 object name(s)" in infos[0]["message"]
    assert infos[0]["message"].endswith("...")
