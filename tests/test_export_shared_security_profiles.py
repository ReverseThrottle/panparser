"""Shared-scope security profile export (issue #107).

All 8 security-profile content exporters must merge vsys + shared scopes via
the established iter_entries pattern (vsys entries first, then shared), the
same way export_profile_groups and the viewer already do. Same-name entries
in both scopes are BOTH kept (no dedupe) — pinned here to match the other
shared-merged exporters (tags/addresses/profile-groups/...). The one
exception is the ratified #65 WildFire-wins collision policy, which now
applies across scopes: a virus entry whose name matches any wildfire-analysis
entry (vsys or shared) is skipped in favor of the WildFire definition.

Out of scope (per issue #107): zone-protection profiles (network root),
data-filtering (viewer-only, no exporter), DoS rules (vsys rulebase).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from export.objects import (
    export_anti_spyware_profiles,
    export_decryption_profiles,
    export_dns_security_profiles,
    export_dos_protection_profiles,
    export_file_blocking_profiles,
    export_url_access_profiles,
    export_vulnerability_protection_profiles,
    export_wildfire_antivirus_profiles,
    list_antivirus_profile_names,
)
from export.writer import build_export
from export_fixtures import (
    FAKE_SECRET_MARKER,
    assert_no_secret_leak,
    shared_root,
    vsys_root,
)

DEFAULT_RULE = {
    "name": "default", "direction": "both",
    "application": ["any"], "file_type": ["any"], "analysis": "public-cloud",
}

# The 7 exporters whose merge is a straight iter_entries append (no collision
# policy): (exporter, XML path key). virus/wildfire-analysis is covered
# separately because of the WildFire-wins policy.
SIMPLE_EXPORTERS = [
    (export_anti_spyware_profiles, "spyware"),
    (export_vulnerability_protection_profiles, "vulnerability"),
    (export_url_access_profiles, "url-filtering"),
    (export_decryption_profiles, "decryption"),
    (export_dns_security_profiles, "dns-security"),
    (export_file_blocking_profiles, "file-blocking"),
    (export_dos_protection_profiles, "dos-protection"),
]

# (XML path key, security_profiles export key) for all 8 exporter types.
EXPORT_KEYS = [
    ("spyware", "anti_spyware"),
    ("virus", "wildfire_antivirus"),
    ("wildfire-analysis", "wildfire_antivirus"),
    ("vulnerability", "vulnerability_protection"),
    ("url-filtering", "url_access"),
    ("decryption", "decryption"),
    ("dns-security", "dns_security"),
    ("file-blocking", "file_blocking"),
    ("dos-protection", "dos_protection"),
]


def _build(vsys_xml: str = "", shared_xml: str = "") -> dict:
    return build_export(
        ET.fromstring("<config version='11.1.0'/>"),
        vsys_root(vsys_xml),
        shared_root(shared_xml),
        None,
        "fixture.xml",
        "vsys1",
    )


class TestSharedOnlyProfilesInBuildExport:
    """AC3: a shared-only profile of each of the 8 types reaches build_export."""

    @pytest.mark.parametrize("xml_key,export_key", EXPORT_KEYS)
    def test_shared_only_profile_is_exported(self, xml_key, export_key):
        name = f"SH-{xml_key}"
        data = _build(shared_xml=f"""
        <profiles><{xml_key}><entry name="{name}">
          <description>shared only</description>
        </entry></{xml_key}></profiles>""")
        profiles = data["security_profiles"][export_key]
        assert name in [p["name"] for p in profiles]
        assert_no_secret_leak(data)

    @pytest.mark.parametrize("exporter,xml_key", SIMPLE_EXPORTERS)
    def test_shared_only_with_no_vsys_root(self, exporter, xml_key):
        shared = shared_root(
            f'<profiles><{xml_key}><entry name="S"/></{xml_key}></profiles>')
        assert [p["name"] for p in exporter(None, shared)] == ["S"]

    def test_wildfire_shared_only_with_no_vsys_root(self):
        shared = shared_root(
            '<profiles><wildfire-analysis><entry name="S"/></wildfire-analysis></profiles>')
        assert [p["name"] for p in export_wildfire_antivirus_profiles(None, shared)] == ["S"]

    def test_virus_shared_only_with_no_vsys_root(self):
        shared = shared_root(
            '<profiles><virus><entry name="S"/></virus></profiles>')
        out = export_wildfire_antivirus_profiles(None, shared)
        assert out == [{"name": "S", "rules": [DEFAULT_RULE]}]


class TestSameNameBothScopes:
    """AC1: same-name behavior pinned to the other shared-merged exporters —
    iter_entries yields both scopes' entries and both are appended, sorted."""

    @pytest.mark.parametrize("exporter,xml_key", SIMPLE_EXPORTERS)
    def test_same_name_in_both_scopes_keeps_both(self, exporter, xml_key):
        vsys = vsys_root(f"""
        <profiles><{xml_key}><entry name="Dup">
          <description>vsys-side</description>
        </entry></{xml_key}></profiles>""")
        shared = shared_root(f"""
        <profiles><{xml_key}><entry name="Dup">
          <description>shared-side</description>
        </entry></{xml_key}></profiles>""")
        out = exporter(vsys, shared)
        assert [p["name"] for p in out] == ["Dup", "Dup"]
        assert sorted(p["description"] for p in out) == ["shared-side", "vsys-side"]

    def test_virus_same_name_in_both_scopes_keeps_both(self):
        vsys = vsys_root('<profiles><virus><entry name="Dup"/></virus></profiles>')
        shared = shared_root('<profiles><virus><entry name="Dup"/></virus></profiles>')
        out = export_wildfire_antivirus_profiles(vsys, shared)
        assert out == [
            {"name": "Dup", "rules": [DEFAULT_RULE]},
            {"name": "Dup", "rules": [DEFAULT_RULE]},
        ]

    def test_wildfire_same_name_in_both_scopes_keeps_both(self):
        xml = '<profiles><wildfire-analysis><entry name="Dup"/></wildfire-analysis></profiles>'
        out = export_wildfire_antivirus_profiles(vsys_root(xml), shared_root(xml))
        assert [p["name"] for p in out] == ["Dup", "Dup"]

    def test_list_antivirus_names_same_name_in_both_scopes_no_dedupe(self):
        vsys = vsys_root('<profiles><virus><entry name="Dup"/></virus></profiles>')
        shared = shared_root('<profiles><virus><entry name="Dup"/></virus></profiles>')
        assert list_antivirus_profile_names(vsys, shared) == ["Dup", "Dup"]


class TestWildFireCollisionAcrossScopes:
    """The ratified #65 WildFire-wins policy applies to the merged name set."""

    WF_CUSTOM = """
    <wildfire-analysis><entry name="X"><rules>
      <entry name="r1"><direction>upload</direction><analysis>private-cloud</analysis></entry>
    </rules></entry></wildfire-analysis>"""

    def test_vsys_virus_collides_with_shared_wildfire(self):
        vsys = vsys_root('<profiles><virus><entry name="X"/></virus></profiles>')
        shared = shared_root(f"<profiles>{self.WF_CUSTOM}</profiles>")
        out = export_wildfire_antivirus_profiles(vsys, shared)
        assert [p["name"] for p in out] == ["X"]
        assert out[0]["rules"][0]["direction"] == "upload"
        assert out[0]["rules"][0]["analysis"] == "private-cloud"

    def test_shared_virus_collides_with_vsys_wildfire(self):
        vsys = vsys_root(f"<profiles>{self.WF_CUSTOM}</profiles>")
        shared = shared_root('<profiles><virus><entry name="X"/></virus></profiles>')
        out = export_wildfire_antivirus_profiles(vsys, shared)
        assert [p["name"] for p in out] == ["X"]
        assert out[0]["rules"][0]["direction"] == "upload"

    def test_non_colliding_names_from_both_scopes_all_exported(self):
        vsys = vsys_root('<profiles><virus><entry name="V-virus"/></virus></profiles>')
        shared = shared_root("""
        <profiles>
          <virus><entry name="S-virus"/></virus>
          <wildfire-analysis><entry name="S-wf"/></wildfire-analysis>
        </profiles>""")
        out = export_wildfire_antivirus_profiles(vsys, shared)
        assert [p["name"] for p in out] == ["S-virus", "S-wf", "V-virus"]


class TestListAntivirusProfileNamesShared:
    def test_merges_and_sorts_both_scopes(self):
        vsys = vsys_root('<profiles><virus><entry name="Z-av"/></virus></profiles>')
        shared = shared_root('<profiles><virus><entry name="a-av"/></virus></profiles>')
        assert list_antivirus_profile_names(vsys, shared) == ["a-av", "Z-av"]

    def test_shared_only_and_none_roots(self):
        shared = shared_root('<profiles><virus><entry name="S"/></virus></profiles>')
        assert list_antivirus_profile_names(None, shared) == ["S"]
        assert list_antivirus_profile_names(None, None) == []


# The issue's probe config: shared group referencing shared profiles, vsys
# empty. A fake secret blob is planted in a decoder action (never exported —
# Antivirus profiles migrate by name/description only) to prove no leak.
PROBE_SHARED = f"""
<profiles>
  <virus><entry name="AV-shared">
    <decoder>
      <entry name="http"><action>reset-both</action></entry>
      <entry name="smtp"><action>{FAKE_SECRET_MARKER}</action></entry>
    </decoder>
  </entry></virus>
  <spyware><entry name="AS-shared"/></spyware>
  <wildfire-analysis><entry name="WF-shared"><rules>
    <entry name="r1"><direction>upload</direction><analysis>private-cloud</analysis></entry>
  </rules></entry></wildfire-analysis>
</profiles>
<profile-group><entry name="G-shared">
  <virus><member>AV-shared</member></virus>
  <spyware><member>AS-shared</member></spyware>
  <wildfire-analysis><member>WF-shared</member></wildfire-analysis>
</entry></profile-group>
"""


class TestProbeConfigEndToEnd:
    """AC3: G-shared/AV-shared/AS-shared/WF-shared covered end-to-end."""

    def test_group_and_referenced_profiles_both_exported(self):
        data = _build(shared_xml=PROBE_SHARED)
        assert data["objects"]["profile_groups"] == [{
            "name": "G-shared",
            "virus_and_wildfire_analysis": ["AV-shared"],
            "spyware": ["AS-shared"],
        }]
        sp = data["security_profiles"]
        assert [p["name"] for p in sp["anti_spyware"]] == ["AS-shared"]
        av = {p["name"]: p for p in sp["wildfire_antivirus"]}
        assert sorted(av) == ["AV-shared", "WF-shared"]
        assert av["AV-shared"]["rules"] == [DEFAULT_RULE]
        assert av["WF-shared"]["rules"][0]["direction"] == "upload"
        assert av["WF-shared"]["rules"][0]["analysis"] == "private-cloud"
        assert_no_secret_leak(data)

    def test_antivirus_warning_covers_shared_names(self):
        data = _build(shared_xml=PROBE_SHARED)
        av_warnings = [
            w for w in data["migration_warnings"]
            if w["object_path"] == "security_profiles/wildfire_antivirus"
        ]
        assert len(av_warnings) == 1
        assert "1 Antivirus profile(s)" in av_warnings[0]["message"]
        assert "AV-shared" in av_warnings[0]["message"]

    def test_group_warning_accurate_after_shared_export(self):
        data = _build(shared_xml=PROBE_SHARED)
        group_warnings = [
            w for w in data["migration_warnings"]
            if w["object_path"] == "objects/profile_groups/G-shared"
        ]
        assert len(group_warnings) == 1
        msg = group_warnings[0]["message"]
        # The group keeps only the Antivirus reference in SCM's combined slot.
        assert "keeps only the 'AV-shared' reference" in msg
        assert "'WF-shared' reference is dropped from the group" in msg
        # The old #66 claim ("only 'AV-shared' is exported") was false for
        # shared scope — both profiles are exported now, and the warning must
        # not imply the WildFire profile itself is dropped.
        assert "only 'AV-shared' is exported" not in msg
        assert "WF-shared" in [
            p["name"] for p in data["security_profiles"]["wildfire_antivirus"]
        ]

    def test_vsys_and_shared_profiles_merge_sorted_in_build_export(self):
        data = _build(
            vsys_xml='<profiles><spyware><entry name="Z-as"/></spyware></profiles>',
            shared_xml='<profiles><spyware><entry name="a-as"/></spyware></profiles>',
        )
        assert [p["name"] for p in data["security_profiles"]["anti_spyware"]] == [
            "a-as", "Z-as",
        ]
