"""Antivirus (profiles/virus) export and profile-group reference reconciliation (#65)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import (
    export_profile_groups,
    export_wildfire_antivirus_profiles,
    find_profile_groups_dropping_wildfire,
    list_antivirus_profile_names,
)

DEFAULT_RULE = {
    "name": "default", "direction": "both",
    "application": ["any"], "file_type": ["any"], "analysis": "public-cloud",
}


def _vsys(profiles_xml: str = "", groups_xml: str = ""):
    return ET.fromstring(
        f"<entry name='vsys1'><profiles>{profiles_xml}</profiles>"
        f"<profile-group>{groups_xml}</profile-group></entry>"
    )


AV = """
<virus>
  <entry name="strict-UA-ANC">
    <description>block everything</description>
    <decoder>
      <entry name="http"><action>reset-both</action></entry>
    </decoder>
  </entry>
</virus>
"""

WF = """
<wildfire-analysis>
  <entry name="wf-custom">
    <rules>
      <entry name="r1"><application><member>any</member></application>
      <file-type><member>pe</member></file-type>
      <direction>upload</direction><analysis>private-cloud</analysis></entry>
    </rules>
  </entry>
</wildfire-analysis>
"""


class TestAntivirusProfilesExported:
    def test_virus_profile_is_exported_with_default_rule(self):
        out = export_wildfire_antivirus_profiles(_vsys(AV))
        assert out == [{
            "name": "strict-UA-ANC",
            "description": "block everything",
            "rules": [DEFAULT_RULE],
        }]

    def test_virus_and_wildfire_profiles_are_both_exported_sorted(self):
        out = export_wildfire_antivirus_profiles(_vsys(AV + WF))
        assert [p["name"] for p in out] == ["strict-UA-ANC", "wf-custom"]
        wf = next(p for p in out if p["name"] == "wf-custom")
        assert wf["rules"][0]["direction"] == "upload"

    def test_same_name_in_both_keeps_wildfire_rules_once(self):
        wf_same = WF.replace("wf-custom", "strict-UA-ANC")
        out = export_wildfire_antivirus_profiles(_vsys(AV + wf_same))
        assert [p["name"] for p in out] == ["strict-UA-ANC"]
        assert out[0]["rules"][0]["direction"] == "upload"

    def test_no_virus_profiles_changes_nothing(self):
        assert export_wildfire_antivirus_profiles(_vsys(WF))[0]["name"] == "wf-custom"
        assert export_wildfire_antivirus_profiles(_vsys("")) == []

    def test_none_vsys_root(self):
        assert export_wildfire_antivirus_profiles(None) == []


class TestListAntivirusProfileNames:
    def test_lists_virus_names_only(self):
        assert list_antivirus_profile_names(_vsys(AV + WF)) == ["strict-UA-ANC"]

    def test_empty_and_none(self):
        assert list_antivirus_profile_names(_vsys("")) == []
        assert list_antivirus_profile_names(None) == []


GROUP_BOTH = """
<entry name="g1">
  <virus><member>strict-UA-ANC</member></virus>
  <wildfire-analysis><member>default</member></wildfire-analysis>
</entry>
"""
GROUP_VIRUS_ONLY = """
<entry name="g2"><virus><member>strict-UA-ANC</member></virus></entry>
"""
GROUP_SAME = """
<entry name="g3">
  <virus><member>x</member></virus>
  <wildfire-analysis><member>x</member></wildfire-analysis>
</entry>
"""


class TestProfileGroupWildfireReconciliation:
    def test_group_exports_virus_reference_as_before(self):
        out = export_profile_groups(_vsys(groups_xml=GROUP_BOTH), None)
        assert out == [{"name": "g1", "virus_and_wildfire_analysis": ["strict-UA-ANC"]}]

    def test_group_with_both_differing_is_reported(self):
        found = find_profile_groups_dropping_wildfire(_vsys(groups_xml=GROUP_BOTH), None)
        assert found == [{"name": "g1", "virus": "strict-UA-ANC", "wildfire": "default"}]

    def test_virus_only_and_identical_references_are_not_reported(self):
        xml = _vsys(groups_xml=GROUP_VIRUS_ONLY + GROUP_SAME)
        assert find_profile_groups_dropping_wildfire(xml, None) == []
