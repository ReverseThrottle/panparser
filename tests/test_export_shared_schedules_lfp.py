"""Shared-scope merge for export_schedules / export_log_forwarding_profiles (#129).

Panorama configs keep schedules under <shared>/schedule and log forwarding
profiles under <shared>/log-settings/profiles. Both exporters merge vsys +
shared via iter_entries (vsys first, same-name entries kept once per scope,
the #107 convention), like export_edls (#127).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from export.objects import export_log_forwarding_profiles, export_schedules


def _vsys(inner: str = ""):
    return ET.fromstring(f"<vsys>{inner}</vsys>")


def _shared(inner: str = ""):
    return ET.fromstring(f"<shared>{inner}</shared>")


def _sched(name: str, day: str = "monday") -> str:
    return (
        f'<entry name="{name}"><schedule-type><recurring><weekly>'
        f"<{day}>09:00-17:00</{day}></weekly></recurring></schedule-type></entry>"
    )


def _lfp(name: str, log_type: str = "traffic") -> str:
    return (
        f'<entry name="{name}"><match-list><entry name="ml">'
        f"<log-type>{log_type}</log-type></entry></match-list></entry>"
    )


def _sch(inner: str) -> str:
    return f"<schedule>{inner}</schedule>"


def _lfps(inner: str) -> str:
    return f"<log-settings><profiles>{inner}</profiles></log-settings>"


def _names(out):
    return [e["name"] for e in out]


class TestSchedulesSharedScope:
    def test_shared_only(self):
        out = export_schedules(_vsys(), _shared(_sch(_sched("sh-sched"))))
        assert _names(out) == ["sh-sched"]
        assert out[0]["schedule_type"] == {
            "recurring": {"weekly": {"monday": ["09:00-17:00"]}}}

    def test_shared_only_with_vsys_root_none(self):
        out = export_schedules(None, _shared(_sch(_sched("sh-sched"))))
        assert _names(out) == ["sh-sched"]

    def test_vsys_only_with_shared_present(self):
        out = export_schedules(_vsys(_sch(_sched("v-sched"))), _shared())
        assert _names(out) == ["v-sched"]

    def test_vsys_only_without_shared_arg(self):
        assert _names(export_schedules(_vsys(_sch(_sched("v-sched"))))) == ["v-sched"]

    def test_none_none(self):
        assert export_schedules(None, None) == []

    def test_name_collision_kept_per_scope_vsys_first(self):
        out = export_schedules(
            _vsys(_sch(_sched("dup", "monday"))),
            _shared(_sch(_sched("dup", "friday"))),
        )
        assert _names(out) == ["dup", "dup"]
        assert list(out[0]["schedule_type"]["recurring"]["weekly"]) == ["monday"]
        assert list(out[1]["schedule_type"]["recurring"]["weekly"]) == ["friday"]

    def test_merged_sorted_case_insensitive(self):
        out = export_schedules(
            _vsys(_sch(_sched("b-v") + _sched("Z-v"))),
            _shared(_sch(_sched("a-s"))),
        )
        assert _names(out) == ["a-s", "b-v", "Z-v"]

    def test_build_export_includes_shared_schedules(self):
        from export.writer import build_export

        root = ET.fromstring("<config version='11.0.0'/>")
        data = build_export(
            root, _vsys(_sch(_sched("v-sched"))),
            _shared(_sch(_sched("sh-sched"))), None, "x.xml", "vsys1")
        assert _names(data["objects"]["schedules"]) == ["sh-sched", "v-sched"]


class TestLogForwardingProfilesSharedScope:
    def test_shared_only(self):
        out = export_log_forwarding_profiles(_vsys(), _shared(_lfps(_lfp("sh-lfp"))))
        assert _names(out) == ["sh-lfp"]
        assert out[0]["match_list"][0]["log_type"] == "traffic"

    def test_shared_only_with_vsys_root_none(self):
        out = export_log_forwarding_profiles(None, _shared(_lfps(_lfp("sh-lfp"))))
        assert _names(out) == ["sh-lfp"]

    def test_vsys_only_with_shared_present(self):
        out = export_log_forwarding_profiles(_vsys(_lfps(_lfp("v-lfp"))), _shared())
        assert _names(out) == ["v-lfp"]

    def test_vsys_only_without_shared_arg(self):
        out = export_log_forwarding_profiles(_vsys(_lfps(_lfp("v-lfp"))))
        assert _names(out) == ["v-lfp"]

    def test_none_none(self):
        assert export_log_forwarding_profiles(None, None) == []

    def test_name_collision_kept_per_scope_vsys_first(self):
        out = export_log_forwarding_profiles(
            _vsys(_lfps(_lfp("dup", "traffic"))),
            _shared(_lfps(_lfp("dup", "threat"))),
        )
        assert _names(out) == ["dup", "dup"]
        assert out[0]["match_list"][0]["log_type"] == "traffic"
        assert out[1]["match_list"][0]["log_type"] == "threat"

    def test_merged_sorted_case_insensitive(self):
        out = export_log_forwarding_profiles(
            _vsys(_lfps(_lfp("b-v") + _lfp("Z-v"))),
            _shared(_lfps(_lfp("a-s"))),
        )
        assert _names(out) == ["a-s", "b-v", "Z-v"]

    def test_shared_refs_preserved(self):
        shared = _shared(_lfps(
            '<entry name="sh-lfp"><match-list><entry name="ml">'
            "<send-syslog><using-syslog-setting><member>sys1</member>"
            "</using-syslog-setting></send-syslog></entry></match-list></entry>"))
        out = export_log_forwarding_profiles(None, shared)
        assert out[0]["match_list"][0]["_syslog_refs"] == ["sys1"]

    def test_build_export_includes_shared_lfps(self):
        from export.writer import build_export

        root = ET.fromstring("<config version='11.0.0'/>")
        data = build_export(
            root, _vsys(_lfps(_lfp("v-lfp"))),
            _shared(_lfps(_lfp("sh-lfp"))), None, "x.xml", "vsys1")
        assert _names(data["objects"]["log_forwarding_profiles"]) == ["sh-lfp", "v-lfp"]
