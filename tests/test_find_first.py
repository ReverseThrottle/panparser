"""Regression tests for issue #91 — find_first presence-based selection.

Pins the intended contract at three levels:
  1. the shared `find_first` helper itself,
  2. a rule getter (parsers._data.get_security_rules, plus the multi-line
     app-override site), and
  3. an export path (export.objects.export_security_rules).

Semantics: a present-but-empty primary container is SELECTED (not fallen
through to the legacy fallback); an absent primary falls back; both absent
→ None / empty rows. Also asserts the deprecated Element truth-value
DeprecationWarning is gone (baseline: 118 across the suite).
"""
from __future__ import annotations

import warnings
import xml.etree.ElementTree as ET

from parsers._helpers import find_first
from parsers._data import get_security_rules, get_app_override_rules
from export.objects import export_security_rules


def _vsys(xml_str: str) -> ET.Element:
    return ET.fromstring(f"<vsys>{xml_str}</vsys>")


# Both containers present: primary empty, legacy populated. Under the old
# `find(a) or find(b)` idiom the empty primary was falsy and the legacy row
# leaked through; presence-based selection must return the empty primary.
EMPTY_PRIMARY_POPULATED_LEGACY = """
<rulebase><security><rules/></security></rulebase>
<security><rules>
  <entry name="legacy"><action>drop</action></entry>
</rules></security>
"""

LEGACY_ONLY = """
<security><rules>
  <entry name="legacy"><action>drop</action></entry>
</rules></security>
"""


class TestFindFirstContract:
    def test_present_but_empty_primary_is_selected(self):
        root = _vsys(EMPTY_PRIMARY_POPULATED_LEGACY)
        selected = find_first(root, "rulebase/security/rules", "security/rules")
        assert selected is not None
        assert selected is root.find("rulebase/security/rules")
        assert len(selected) == 0

    def test_absent_primary_falls_back(self):
        root = _vsys(LEGACY_ONLY)
        selected = find_first(root, "rulebase/security/rules", "security/rules")
        assert selected is not None
        assert selected is root.find("security/rules")
        assert len(selected) == 1

    def test_both_absent_returns_none(self):
        root = _vsys("<rulebase><nat/></rulebase>")
        assert find_first(root, "rulebase/security/rules", "security/rules") is None

    def test_none_root_returns_none(self):
        assert find_first(None, "rulebase/security/rules", "security/rules") is None

    def test_populated_primary_wins_over_populated_legacy(self):
        root = _vsys("""
        <rulebase><security><rules>
          <entry name="primary"/>
        </rules></security></rulebase>
        <security><rules><entry name="legacy"/></rules></security>
        """)
        selected = find_first(root, "rulebase/security/rules", "security/rules")
        assert selected is not None
        entry = selected.find("entry")
        assert entry is not None
        assert entry.get("name") == "primary"

    def test_no_paths_returns_none(self):
        assert find_first(_vsys("")) is None


class TestRuleGetterSemantics:
    """AC2 at the TUI getter layer (parsers/_data.py)."""

    def test_empty_primary_selected_not_legacy(self):
        assert get_security_rules(_vsys(EMPTY_PRIMARY_POPULATED_LEGACY)) == []

    def test_absent_primary_falls_back_to_legacy(self):
        rows = get_security_rules(_vsys(LEGACY_ONLY))
        assert len(rows) == 1
        assert rows[0][1] == "legacy"
        assert rows[0][9] == "drop"

    def test_both_absent_returns_empty(self):
        assert get_security_rules(_vsys("<rulebase/>")) == []

    def test_app_override_multiline_site_empty_primary_selected(self):
        # app_override.py's site was a multi-line parenthesized form; pin it
        # explicitly so a future grep-based refactor cannot silently skip it.
        xml = """
        <rulebase><application-override><rules/></application-override></rulebase>
        <application-override><rules>
          <entry name="legacy-ov"><protocol>tcp</protocol><port>8080</port></entry>
        </rules></application-override>
        """
        assert get_app_override_rules(_vsys(xml)) == []

    def test_app_override_absent_primary_falls_back(self):
        xml = """
        <application-override><rules>
          <entry name="legacy-ov"><protocol>tcp</protocol><port>8080</port></entry>
        </rules></application-override>
        """
        rows = get_app_override_rules(_vsys(xml))
        assert len(rows) == 1
        assert rows[0][1] == "legacy-ov"


class TestExportPathSemantics:
    """AC2 at the export layer (export/objects.py)."""

    def test_empty_primary_selected_not_legacy(self):
        assert export_security_rules(_vsys(EMPTY_PRIMARY_POPULATED_LEGACY)) == []

    def test_absent_primary_falls_back_to_legacy(self):
        out = export_security_rules(_vsys(LEGACY_ONLY))
        assert len(out) == 1
        assert out[0]["name"] == "legacy"
        assert out[0]["action"] == "drop"

    def test_both_absent_returns_empty(self):
        assert export_security_rules(_vsys("<rulebase/>")) == []


class TestNoElementTruthValueWarning:
    """AC3: selection must not test an Element's truth value."""

    def _truth_value_warnings(self, fn, root):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            fn(root)
        return [w for w in caught
                if issubclass(w.category, DeprecationWarning)
                and "truth value" in str(w.message)]

    def test_getter_emits_no_truth_value_warning(self):
        # The empty-primary fixture forced the second find() under the old
        # idiom — exactly the path that emitted the DeprecationWarning.
        root = _vsys(EMPTY_PRIMARY_POPULATED_LEGACY)
        assert self._truth_value_warnings(get_security_rules, root) == []

    def test_export_emits_no_truth_value_warning(self):
        root = _vsys(EMPTY_PRIMARY_POPULATED_LEGACY)
        assert self._truth_value_warnings(export_security_rules, root) == []
