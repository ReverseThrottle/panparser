"""Antivirus migration-warning accuracy under the #65 collision policy — #108.

build_export()-level: the warning must describe what was actually exported.
A virus entry whose name also exists under profiles/wildfire-analysis is
skipped by export_wildfire_antivirus_profiles (the WildFire definition wins,
ratified #65 owner decision), so the warning may not claim a default-rule
export for that name — but the per-decoder antivirus action loss must still
be flagged for collision names (AC2). Inline XML fragments follow the suite
convention (the repo gitignores *.xml); the collision config is the issue's
probe: AV1 virus reset-both + AV1 wildfire-analysis custom-rule
upload/web-browsing/pdf/private-cloud.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.writer import build_export
from export_fixtures import vsys_root

WARN_PATH = "security_profiles/wildfire_antivirus"

# One container per profile type, as in a real PAN-OS config (ElementTree
# find() returns the first match, so sibling duplicate containers would hide
# entries). The collision config is the issue's probe: AV1 in both types.
def _virus_xml(*names: str) -> str:
    entries = "".join(
        f'<entry name="{n}">'
        '<decoder><entry name="http"><action>reset-both</action></entry></decoder>'
        "</entry>"
        for n in names
    )
    return f"<virus>{entries}</virus>"


def _wildfire_xml(*names: str) -> str:
    entries = "".join(
        f'<entry name="{n}"><rules><entry name="custom-rule">'
        "<direction>upload</direction>"
        "<application><member>web-browsing</member></application>"
        "<file-type><member>pdf</member></file-type>"
        "<analysis>private-cloud</analysis>"
        "</entry></rules></entry>"
        for n in names
    )
    return f"<wildfire-analysis>{entries}</wildfire-analysis>"

DEFAULT_RULE = {
    "name": "default", "direction": "both",
    "application": ["any"], "file_type": ["any"], "analysis": "public-cloud",
}
CUSTOM_RULE = {
    "name": "custom-rule", "direction": "upload",
    "application": ["web-browsing"], "file_type": ["pdf"], "analysis": "private-cloud",
}

# The decoder-action-loss tail shared by every antivirus warning variant.
TAIL = (
    "SCM has no equivalent of the PAN-OS per-decoder antivirus actions "
    "(e.g. reset-both), so those settings are not migrated. "
    "Review each profile in SCM."
)


def _export(profiles_xml: str) -> dict:
    root = ET.fromstring(
        "<config version='11.1.0'><devices><entry name='localhost.localdomain'>"
        "<deviceconfig/></entry></devices></config>"
    )
    return build_export(
        root,
        vsys_root(f"<profiles>{profiles_xml}</profiles>"),
        None,
        None,
        "av-warning.xml",
        "vsys1",
    )


def _warning(data: dict) -> dict | None:
    found = [w for w in data["migration_warnings"] if w["object_path"] == WARN_PATH]
    assert len(found) <= 1
    return found[0] if found else None


def _warning_message(data: dict) -> str:
    w = _warning(data)
    assert w is not None
    return w["message"]


class TestCollisionConfig:
    def test_export_keeps_wildfire_custom_rule(self):
        data = _export(_virus_xml("AV1") + _wildfire_xml("AV1"))
        assert data["security_profiles"]["wildfire_antivirus"] == [
            {"name": "AV1", "rules": [CUSTOM_RULE]},
        ]

    def test_warning_does_not_claim_default_rule_export(self):
        w = _warning(_export(_virus_xml("AV1") + _wildfire_xml("AV1")))
        assert w is not None and w["severity"] == "warn"
        msg = w["message"]
        # No false default-rule claim for the collision name (AC1/AC3).
        assert "with a default WildFire rule" not in msg
        assert "Antivirus profile(s) exported" not in msg
        # Accurate collision note naming AV1 (AC1).
        assert "1 Antivirus profile(s) share a name with a WildFire Analysis profile" in msg
        assert "the WildFire definition was exported instead" in msg
        assert "AV1" in msg
        # Decoder-action loss is still flagged (AC2).
        assert TAIL in msg


class TestAllCollidingConfig:
    def test_no_false_default_rule_count(self):
        data = _export(_virus_xml("AV1", "AV2") + _wildfire_xml("AV1", "AV2"))
        msg = _warning_message(data)
        assert "with a default WildFire rule" not in msg
        assert "Antivirus profile(s) exported" not in msg
        assert msg.startswith(
            "2 Antivirus profile(s) share a name with a WildFire Analysis profile"
        )
        assert "AV1, AV2" in msg
        assert TAIL in msg
        # Zero antivirus-derived exports: every profile carries the WildFire rule.
        assert data["security_profiles"]["wildfire_antivirus"] == [
            {"name": "AV1", "rules": [CUSTOM_RULE]},
            {"name": "AV2", "rules": [CUSTOM_RULE]},
        ]


class TestNonCollisionBehaviorUnchanged:
    def test_virus_only_warning_text_is_identical(self):
        data = _export(_virus_xml("AV1"))
        assert data["security_profiles"]["wildfire_antivirus"] == [
            {"name": "AV1", "rules": [DEFAULT_RULE]},
        ]
        assert _warning_message(data) == (
            "1 Antivirus profile(s) exported as SCM WildFire and Antivirus "
            "profile(s) with a default WildFire rule: AV1. " + TAIL
        )

    def test_wildfire_only_produces_no_antivirus_warning(self):
        assert _warning(_export(_wildfire_xml("AV1"))) is None

    def test_no_profiles_produces_no_antivirus_warning(self):
        assert _warning(_export("")) is None


class TestMixedConfig:
    def test_counts_and_names_are_partitioned(self):
        data = _export(_virus_xml("AV1", "AV2") + _wildfire_xml("AV1"))
        assert _warning_message(data) == (
            "1 Antivirus profile(s) exported as SCM WildFire and Antivirus "
            "profile(s) with a default WildFire rule: AV2. "
            "1 Antivirus profile(s) share a name with a WildFire Analysis "
            "profile; the WildFire definition was exported instead "
            "(the Antivirus entry was skipped): AV1. " + TAIL
        )
        assert data["security_profiles"]["wildfire_antivirus"] == [
            {"name": "AV1", "rules": [CUSTOM_RULE]},
            {"name": "AV2", "rules": [DEFAULT_RULE]},
        ]
