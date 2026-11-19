"""Field-asserting tests for export_schedules() — issue #92 backfill.

PAN-OS weekly days carry comma-separated time ranges as text content (not
member elements); daily/non-recurring use member lists. All three shapes
plus the empty-container omissions are asserted.
"""
from __future__ import annotations

from export.objects import export_schedules
from export_fixtures import vsys_root


class TestExportSchedules:
    def test_none_root(self):
        assert export_schedules(None) == []

    def test_missing_container(self):
        assert export_schedules(vsys_root("<schedule-type/>")) == []

    def test_recurring_weekly_multi_range(self):
        root = vsys_root("""
        <schedule>
          <entry name="business-hours">
            <schedule-type><recurring><weekly>
              <monday>09:00-17:00</monday>
              <tuesday>08:00-12:00, 13:00-17:00</tuesday>
              <wednesday/>
              <sunday>  </sunday>
            </weekly></recurring></schedule-type>
          </entry>
        </schedule>""")
        assert export_schedules(root) == [{
            "name": "business-hours",
            "schedule_type": {"recurring": {"weekly": {
                "monday": ["09:00-17:00"],
                "tuesday": ["08:00-12:00", "13:00-17:00"],
            }}},
        }]

    def test_recurring_daily(self):
        root = vsys_root("""
        <schedule>
          <entry name="nightly">
            <schedule-type><recurring><daily>
              <member>02:00-04:00</member><member>22:00-23:59</member>
            </daily></recurring></schedule-type>
          </entry>
        </schedule>""")
        assert export_schedules(root) == [{
            "name": "nightly",
            "schedule_type": {"recurring": {"daily": ["02:00-04:00", "22:00-23:59"]}},
        }]

    def test_non_recurring(self):
        root = vsys_root("""
        <schedule>
          <entry name="maintenance-window">
            <schedule-type><non-recurring>
              <member>2026/12/01@02:00-2026/12/01@06:00</member>
            </non-recurring></schedule-type>
          </entry>
        </schedule>""")
        assert export_schedules(root) == [{
            "name": "maintenance-window",
            "schedule_type": {"non_recurring": ["2026/12/01@02:00-2026/12/01@06:00"]},
        }]

    def test_empty_shapes_omit_schedule_type(self):
        root = vsys_root("""
        <schedule>
          <entry name="no-type"/>
          <entry name="empty-weekly"><schedule-type><recurring><weekly><monday/></weekly></recurring></schedule-type></entry>
          <entry name="empty-daily"><schedule-type><recurring><daily/></recurring></schedule-type></entry>
          <entry name="empty-non-rec"><schedule-type><non-recurring/></schedule-type></entry>
          <entry name="empty-recurring"><schedule-type><recurring/></schedule-type></entry>
        </schedule>""")
        assert export_schedules(root) == [
            {"name": "empty-daily"},
            {"name": "empty-non-rec"},
            {"name": "empty-recurring"},
            {"name": "empty-weekly"},
            {"name": "no-type"},
        ]

    def test_sorted_case_insensitive(self):
        root = vsys_root('<schedule><entry name="Z-sched"/><entry name="a-sched"/></schedule>')
        assert [s["name"] for s in export_schedules(root)] == ["a-sched", "Z-sched"]
