"""Shared fixture scaffolding for the export_* coverage backfill (#92).

One reusable scaffolding for the exporter family instead of 25 bespoke
one-off helpers (foundational-thinking). Provides:

- XML root builders matching the roots build_export() passes to each
  exporter family (vsys / shared / network). Inline XML strings, not .xml
  files: the repo gitignores *.xml so customer configs can never be
  committed by accident (same convention as the rest of the suite).
- The secret-placeholder contract constants and a leak assertion, shared
  with the existing IKE-PSK / RADIUS / certificate / SNMP test pattern:
  fixtures plant an obviously-fake blob (FAKE-TEST-SECRET-DO-NOT-USE) and
  assertions prove it never reaches the exported dicts.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

PLACEHOLDER_SECRET = "MIGRATION-PLACEHOLDER-SECRET"
FAKE_SECRET_MARKER = "FAKE-TEST-SECRET-DO-NOT-USE"


def vsys_root(inner: str) -> ET.Element:
    """Wrap inline object/rulebase XML in a <vsys> root."""
    return ET.fromstring(f"<vsys>{inner}</vsys>")


def shared_root(inner: str) -> ET.Element:
    """Wrap inline object XML in a <shared> root (Panorama shared scope)."""
    return ET.fromstring(f"<shared>{inner}</shared>")


def network_root(inner: str) -> ET.Element:
    """Wrap inline network XML in a <network> root."""
    return ET.fromstring(f"<network>{inner}</network>")


def assert_no_secret_leak(out) -> None:
    """The fake secret blob planted in fixture XML must never be exported."""
    assert FAKE_SECRET_MARKER not in json.dumps(out)
