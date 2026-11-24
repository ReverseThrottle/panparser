"""Panorama device-group export (--device-group).

Uses a small inline synthetic Panorama config (never a real one). Covers the
device-group object root, <shared> merge and precedence, parent-dg hierarchy
(inline and <readonly> forms), unknown-group / flag-conflict errors, the
objects-only output shape, and that vsys behaviour is unchanged.
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET

import pytest

import panparser
from parsers._devicegroup import DeviceGroupNotFoundError, resolve_device_group

PANORAMA = """
<config version="11.0.0">
  <shared>
    <address>
      <entry name="shared-addr"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
      <entry name="clash"><ip-netmask>10.9.9.9/32</ip-netmask></entry>
    </address>
    <tag><entry name="shared-tag"/></tag>
    <pre-rulebase><security><rules>
      <entry name="shared-rule"><action>allow</action></entry>
    </rules></security></pre-rulebase>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <device-group>
        <entry name="Campus">
          <address>
            <entry name="campus-addr"><ip-netmask>10.1.0.1/32</ip-netmask></entry>
            <entry name="clash"><ip-netmask>10.1.1.1/32</ip-netmask></entry>
          </address>
          <service>
            <entry name="campus-svc"><protocol><tcp><port>8080</port></tcp></protocol></entry>
          </service>
        </entry>
        <entry name="Fairbanks">
          <address>
            <entry name="fbx-addr"><ip-netmask>10.2.0.1/32</ip-netmask></entry>
          </address>
          <address-group>
            <entry name="fbx-grp"><static><member>fbx-addr</member></static></entry>
          </address-group>
          <tag><entry name="fbx-tag"/></tag>
          <service>
            <entry name="fbx-svc"><protocol><tcp><port>443</port></tcp></protocol></entry>
          </service>
          <service-group>
            <entry name="fbx-svcgrp"><members><member>fbx-svc</member></members></entry>
          </service-group>
          <application-group>
            <entry name="fbx-appgrp"><members><member>ssl</member></members></entry>
          </application-group>
          <pre-rulebase><security><rules>
            <entry name="fbx-rule"><action>allow</action></entry>
          </rules></security></pre-rulebase>
          <devices/>
        </entry>
        <entry name="Solo">
          <address>
            <entry name="solo-addr"><ip-netmask>10.3.0.1/32</ip-netmask></entry>
          </address>
        </entry>
        <entry name="Orphan">
          <parent-dg>Missing</parent-dg>
          <address>
            <entry name="orphan-addr"><ip-netmask>10.4.0.1/32</ip-netmask></entry>
          </address>
        </entry>
      </device-group>
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="vsys-addr"><ip-netmask>10.5.0.1/32</ip-netmask></entry>
          </address>
        </entry>
      </vsys>
    </entry>
  </devices>
  <readonly>
    <devices>
      <entry name="localhost.localdomain">
        <device-group>
          <entry name="Fairbanks"><parent-dg>Campus</parent-dg></entry>
          <entry name="Campus"/>
          <entry name="Solo"/>
        </device-group>
      </entry>
    </devices>
  </readonly>
</config>
"""

POLICY_KEYS = ("security_rules", "nat_rules", "decryption_rules",
               "authentication_rules", "pbf_rules", "qos_rules",
               "dos_protection_rules")


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "panorama.xml"
    path.write_text(PANORAMA, encoding="utf-8")
    return path


def _export(monkeypatch, tmp_path, config_path, *extra):
    out = tmp_path / "out.json"
    monkeypatch.setattr(
        sys, "argv",
        ["panparser", str(config_path), "--output", str(out), *extra],
    )
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 0
    return json.loads(out.read_text(encoding="utf-8"))


def _names(items):
    return [i["name"] for i in items]


def test_device_group_objects_merge_parent_and_shared(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Fairbanks")
    objs = data["objects"]
    assert _names(objs["addresses"]) == ["campus-addr", "clash", "fbx-addr", "shared-addr"]
    assert _names(objs["address_groups"]) == ["fbx-grp"]
    assert _names(objs["tags"]) == ["fbx-tag", "shared-tag"]
    assert _names(objs["services"]) == ["campus-svc", "fbx-svc"]
    assert _names(objs["service_groups"]) == ["fbx-svcgrp"]
    assert _names(objs["application_groups"]) == ["fbx-appgrp"]
    # vsys objects are not part of a device group
    assert "vsys-addr" not in _names(objs["addresses"])


def test_child_overrides_parent_overrides_shared(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Fairbanks")
    clash = [a for a in data["objects"]["addresses"] if a["name"] == "clash"]
    assert len(clash) == 1
    assert clash[0]["ip_netmask"] == "10.1.1.1/32"  # Campus beats shared


def test_no_shared_skips_shared(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path,
                   "--device-group", "Fairbanks", "--no-shared")
    names = _names(data["objects"]["addresses"])
    assert "shared-addr" not in names
    assert "campus-addr" in names and "fbx-addr" in names
    assert _names(data["objects"]["tags"]) == ["fbx-tag"]


def test_group_without_parent_only_shared_and_self(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Solo")
    assert _names(data["objects"]["addresses"]) == ["clash", "shared-addr", "solo-addr"]
    assert data["meta"]["device_group_chain"] == ["Solo"]


def test_objects_only_shape_and_meta(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Fairbanks")
    assert data["meta"]["device_group"] == "Fairbanks"
    assert data["meta"]["device_group_chain"] == ["Fairbanks", "Campus"]
    assert data["meta"]["vsys"] is None
    assert data["meta"]["schema_version"] == "1.2"
    for key in POLICY_KEYS:
        assert data["policy"][key] == []
    assert data["zones"] == []
    assert data["network"]["virtual_routers"] == []
    assert data["network"]["interfaces"]["ethernet"] == []
    assert "device_setup" not in data and "high_availability" not in data
    assert data["objects"]["certificates"] == []
    assert data["objects"]["gp_portals"] == []
    infos = [w for w in data["migration_warnings"] if w["severity"] == "info"
             and "objects-only" in w["message"]]
    assert len(infos) == 1


def test_unknown_parent_is_warned_not_fatal(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Orphan")
    assert "orphan-addr" in _names(data["objects"]["addresses"])
    assert any("'Missing'" in w["message"] and w["severity"] == "warn"
               for w in data["migration_warnings"])


def test_unknown_device_group_errors_with_available(monkeypatch, tmp_path, config_path, capsys):
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["panparser", str(config_path),
                                      "--output", str(out), "--device-group", "Nope"])
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "device group 'Nope' not found" in err
    assert "available: Campus, Fairbanks, Solo, Orphan" in err
    assert not out.exists()


def test_resolve_unknown_device_group_raises():
    root = ET.fromstring(PANORAMA)
    with pytest.raises(DeviceGroupNotFoundError) as excinfo:
        resolve_device_group(root, "Nope", root.find("shared"))
    assert excinfo.value.available == ["Campus", "Fairbanks", "Solo", "Orphan"]


def test_device_group_on_firewall_config_errors(monkeypatch, tmp_path, capsys):
    path = tmp_path / "fw.xml"
    path.write_text("<config><devices><entry name='d'><vsys><entry name='vsys1'/>"
                    "</vsys></entry></devices></config>", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["panparser", str(path), "--output",
                                      str(tmp_path / "o.json"), "--device-group", "X"])
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 1
    assert "no device groups" in capsys.readouterr().err


def test_vsys_and_device_group_conflict(monkeypatch, tmp_path, config_path, capsys):
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["panparser", str(config_path), "--output", str(out),
                                      "--vsys", "vsys2", "--device-group", "Fairbanks"])
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err
    assert not out.exists()


def test_explicit_vsys1_with_device_group_conflicts(monkeypatch, tmp_path, config_path, capsys):
    monkeypatch.setattr(sys, "argv", ["panparser", str(config_path), "--output",
                                      str(tmp_path / "o.json"), "--vsys", "vsys1",
                                      "--device-group", "Fairbanks"])
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err


def test_no_ancestors_requires_device_group(monkeypatch, tmp_path, config_path, capsys):
    monkeypatch.setattr(sys, "argv", ["panparser", str(config_path), "--output",
                                      str(tmp_path / "o.json"), "--no-ancestors"])
    with pytest.raises(SystemExit) as excinfo:
        panparser.main()
    assert excinfo.value.code == 2
    assert "--no-ancestors requires --device-group" in capsys.readouterr().err


def test_vsys_export_unchanged(monkeypatch, tmp_path, config_path):
    data = _export(monkeypatch, tmp_path, config_path)
    assert data["meta"]["vsys"] == "vsys1"
    assert "device_group" not in data["meta"]
    assert _names(data["objects"]["addresses"]) == ["clash", "shared-addr", "vsys-addr"]


def test_viewer_cli_device_group(monkeypatch, config_path, capsys):
    monkeypatch.setattr(sys, "argv", ["panparser", str(config_path), "--no-color",
                                      "--device-group", "Fairbanks", "-s", "addresses"])
    try:
        panparser.main()
    except SystemExit as e:
        assert e.code in (0, None)
    out = capsys.readouterr().out
    assert "fbx-addr" in out and "campus-addr" in out
    assert "vsys-addr" not in out


# ── hierarchy, nested containers, wrapper, no-ancestors ───────────────────────

_VP_RULE = (
    "<rules><entry name='r'><severity><member>any</member></severity>"
    "<threat-name>any</threat-name><category>any</category><host>any</host>"
    "<action><alert/></action><packet-capture>disable</packet-capture>"
    "</entry></rules>"
)

HIER = f"""
<config version="11.0.0">
  <shared>
    <profile-group>
      <entry name="pg"><spyware><member>shared-spy</member></spyware></entry>
    </profile-group>
    <external-list>
      <entry name="edl"><type><ip><url>http://shared.example/l</url></ip></type></entry>
    </external-list>
  </shared>
  <devices><entry name="localhost.localdomain"><device-group>
    <entry name="Root">
      <profiles><vulnerability>
        <entry name="vp">{_VP_RULE}<description>root</description></entry>
      </vulnerability></profiles>
      <log-settings><profiles><entry name="lfp-root"/></profiles></log-settings>
      <external-list>
        <entry name="edl"><type><ip><url>http://root.example/l</url></ip></type></entry>
      </external-list>
      <profile-group>
        <entry name="pg"><spyware><member>root-spy</member></spyware></entry>
      </profile-group>
      <address><entry name="root-a"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
    </entry>
    <entry name="Mid">
      <profiles><vulnerability>
        <entry name="vp">{_VP_RULE}<description>mid</description></entry>
        <entry name="vp-mid">{_VP_RULE}</entry>
      </vulnerability></profiles>
      <address><entry name="mid-a"><ip-netmask>10.0.1.1/32</ip-netmask></entry></address>
    </entry>
    <entry name="Leaf">
      <profiles><vulnerability>
        <entry name="vp">{_VP_RULE}<description>leaf</description></entry>
      </vulnerability></profiles>
      <log-settings><profiles><entry name="lfp-leaf"/></profiles></log-settings>
      <external-list>
        <entry name="edl"><type><ip><url>http://leaf.example/l</url></ip></type></entry>
      </external-list>
      <profile-group>
        <entry name="pg"><spyware><member>leaf-spy</member></spyware></entry>
      </profile-group>
      <address-group>
        <entry name="ag"><static><member>mid-a</member><member>leaf-a</member></static></entry>
      </address-group>
      <address><entry name="leaf-a"><ip-netmask>10.0.2.1/32</ip-netmask></entry></address>
      <dynamic-user-group><entry name="dug"><filter>x</filter></entry></dynamic-user-group>
      <region><entry name="reg"/></region>
      <pre-rulebase/>
    </entry>
    <entry name="A"><parent-dg>B</parent-dg>
      <address><entry name="a-a"><ip-netmask>10.7.0.1/32</ip-netmask></entry></address></entry>
    <entry name="B"><parent-dg>A</parent-dg>
      <address><entry name="b-a"><ip-netmask>10.7.1.1/32</ip-netmask></entry></address></entry>
    <entry name="Conf"><parent-dg>Root</parent-dg></entry>
    <entry name="Blank"><parent-dg>   </parent-dg></entry>
  </device-group></entry></devices>
  <readonly><devices><entry name="localhost.localdomain"><device-group>
    <entry name="Leaf"><parent-dg>Mid</parent-dg></entry>
    <entry name="Mid"><parent-dg>Root</parent-dg></entry>
    <entry name="Conf"><parent-dg>Mid</parent-dg></entry>
  </device-group></entry></devices></readonly>
</config>
"""


def _hier_export(monkeypatch, tmp_path, *extra, wrap=False):
    xml = HIER if not wrap else f"<response><result>{HIER}</result></response>"
    path = tmp_path / "h.xml"
    path.write_text(xml, encoding="utf-8")
    return _export(monkeypatch, tmp_path, path, *extra)


def test_grandparent_chain_and_nested_profiles(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf")
    assert data["meta"]["device_group_chain"] == ["Leaf", "Mid", "Root"]
    assert _names(data["objects"]["addresses"]) == ["leaf-a", "mid-a", "root-a"]
    vps = data["security_profiles"]["vulnerability_protection"]
    vp = [p for p in vps if p["name"] == "vp"]
    assert len(vp) == 1 and vp[0].get("description") == "leaf"
    assert "vp-mid" in _names(vps)
    assert _names(data["objects"]["log_forwarding_profiles"]) == ["lfp-leaf", "lfp-root"]


def test_external_list_and_profile_group_precedence(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf")
    edls = [e for e in data["objects"]["edls"] if e["name"] == "edl"]
    assert len(edls) == 1 and "leaf.example" in json.dumps(edls[0])
    pgs = [g for g in data["objects"]["profile_groups"] if g["name"] == "pg"]
    assert len(pgs) == 1 and pgs[0]["spyware"] == ["leaf-spy"]
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Mid", "--force")
    pgs = [g for g in data["objects"]["profile_groups"] if g["name"] == "pg"]
    assert len(pgs) == 1 and pgs[0]["spyware"] == ["root-spy"]  # Root beats shared


def test_cycle_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "A")
    assert data["meta"]["device_group_chain"] == ["A", "B"]
    assert _names(data["objects"]["addresses"]) == ["a-a", "b-a"]
    assert any("cycle" in w["message"] for w in data["migration_warnings"])


def test_response_wrapped_config(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf", wrap=True)
    assert data["meta"]["device_group_chain"] == ["Leaf", "Mid", "Root"]


def test_blank_parent_dg_no_bogus_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Blank")
    assert data["meta"]["device_group_chain"] == ["Blank"]
    assert not any("Parent device group" in w["message"]
                   for w in data["migration_warnings"])


def test_readonly_parent_wins_over_inline_with_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Conf")
    assert data["meta"]["device_group_chain"] == ["Conf", "Mid", "Root"]
    assert any("conflicting parents" in w["message"] and "readonly" in w["message"]
               for w in data["migration_warnings"])


def test_unexported_containers_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf")
    msgs = [w["message"] for w in data["migration_warnings"]
            if "but not exported" in w["message"] and w["severity"] == "info"]
    assert len(msgs) == 1
    assert "Leaf/dynamic-user-group" in msgs[0] and "Leaf/region" in msgs[0]
    assert "Leaf/pre-rulebase" in msgs[0]


def test_no_ancestors_own_objects_and_unresolved_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf", "--no-ancestors")
    assert data["meta"]["device_group_chain"] == ["Leaf"]
    assert _names(data["objects"]["addresses"]) == ["leaf-a"]
    warn = [w for w in data["migration_warnings"]
            if w["severity"] == "warn" and "--no-ancestors" in w["message"]]
    assert len(warn) == 1
    # ag -> mid-a unresolved (1); pg spyware 'leaf-spy' has no spyware profile (1)
    assert warn[0]["message"].startswith("--no-ancestors: 2 reference(s)")
    assert "unless --no-shared is also given" in warn[0]["message"]


def test_default_includes_ancestors_no_unresolved_warning(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf")
    assert not any("--no-ancestors" in w["message"] for w in data["migration_warnings"])


def test_no_ancestors_zero_unresolved_no_warning(monkeypatch, tmp_path, config_path):
    # Solo has no address-group/service-group/profile-group of its own, so
    # --no-ancestors has nothing to flag as unresolved (issue #134).
    data = _export(monkeypatch, tmp_path, config_path, "--device-group", "Solo", "--no-ancestors")
    assert not any("--no-ancestors" in w["message"] for w in data["migration_warnings"])


def test_no_ancestors_no_shared_message_scopes_shared_correctly(monkeypatch, tmp_path):
    data = _hier_export(monkeypatch, tmp_path, "--device-group", "Leaf",
                        "--no-ancestors", "--no-shared")
    warn = [w for w in data["migration_warnings"]
            if w["severity"] == "warn" and "--no-ancestors" in w["message"]]
    assert len(warn) == 1
    # Message must not unconditionally claim shared is in scope.
    assert "(group itself + shared);" not in warn[0]["message"]
    assert "unless --no-shared is also given" in warn[0]["message"]


def test_resolving_twice_leaves_source_tree_unchanged():
    root = ET.fromstring(HIER)
    before = ET.tostring(root)
    shared = root.find("shared")
    first = resolve_device_group(root, "Leaf", shared)
    snap = ET.tostring(first.root)
    second = resolve_device_group(root, "Leaf", shared)
    assert ET.tostring(root) == before
    assert ET.tostring(second.root) == snap
    src = {id(e) for e in root.iter()}
    assert not any(id(e) in src for e in first.root.iter())
