"""Reusable viewer/TUI test harness (issue #80).

Foundational-thinking: future TUI/viewer tests should build on these helpers
rather than re-parsing configs or hand-rolling console/pilot plumbing.

- ``sample_roots()``: load the shared populated sample config and return the
  same ``(vsys_root, shared_root, network_root)`` tuple panparser.find_roots
  produces. Realistic root placement (zones under vsys, network constructs
  under devices/entry/network, shared objects under <shared>).
- ``render_text()``: call a parsers.* render function against a rich Console
  writing to an in-memory buffer and return the plain text — lets tests assert
  on rendered cells without a terminal or ANSI codes.
- ``run_app_test()``: drive a Textual app through App.run_test headlessly from
  a sync pytest test via asyncio.run (no pytest-asyncio dependency needed;
  matches CI's plain `python -m pytest` invocation).
"""

from __future__ import annotations

import asyncio
import io
import xml.etree.ElementTree as ET
from typing import Any, Callable

from rich.console import Console

from tests.sample_config import SAMPLE_CONFIG_XML


def sample_roots() -> tuple[ET.Element, ET.Element, ET.Element]:
    """Return (vsys_root, shared_root, network_root) for the sample config.

    Mirrors panparser.find_roots for a single-device, single-vsys config:
    first device entry, vsys1, and the device's network subtree.
    """
    root = ET.fromstring(SAMPLE_CONFIG_XML)
    dev = root.find("devices/entry")
    assert dev is not None, "sample config must contain a device entry"
    vsys = dev.find("vsys/entry[@name='vsys1']")
    assert vsys is not None, "sample config must contain vsys1"
    network = dev.find("network")
    assert network is not None, "sample config must contain a network subtree"
    shared = root.find("shared")
    assert shared is not None, "sample config must contain a shared subtree"
    return vsys, shared, network


def roots_for(spec: str, vsys: ET.Element, shared: ET.Element, network: ET.Element) -> tuple:
    """Resolve a tui.SECTIONS ``roots`` spec to a getter argument tuple."""
    roots_map = {
        "vsys": (vsys,),
        "network": (network,),
        "vsys_shared": (vsys, shared),
        "shared": (shared,),
    }
    return roots_map[spec]


def sample_roots_for(spec: str) -> tuple:
    """Resolve a short roots spec against the shared sample config.

    v=vsys, s=shared, n=network, vs=vsys+shared, vsn=all three (in the
    order renderers/getters expect).
    """
    vsys, shared, network = sample_roots()
    return {
        "v": (vsys,),
        "s": (shared,),
        "n": (network,),
        "vs": (vsys, shared),
        "vsn": (vsys, shared, network),
    }[spec]


def render_text(render_fn: Callable[..., None], *roots: Any, grep: str | None = None) -> str:
    """Render via a parsers.* renderer into an in-memory plain-text buffer.

    Renderer convention is ``render_x(*roots, console, grep=None)``. Wide
    console (400 cols) so long cells don't wrap mid-substring; no color and
    no terminal detection, so markup/styles never leak ANSI codes into the
    text assertions.
    """
    buf = io.StringIO()
    console = Console(file=buf, width=400, no_color=True, force_terminal=False, highlight=False)
    render_fn(*roots, console, grep)
    return buf.getvalue()


def run_app_test(app_factory: Callable[[], Any], body: Callable[[Any, Any], Any]) -> Any:
    """Run ``body(app, pilot)`` inside a headless Textual pilot session.

    Sync wrapper around App.run_test so tests stay plain pytest functions
    (CI has no pytest-asyncio). ``body`` must be an async coroutine function;
    its return value is propagated.
    """

    async def _run() -> Any:
        app = app_factory()
        async with app.run_test(headless=True, size=(200, 50)) as pilot:
            return await body(app, pilot)

    return asyncio.run(_run())
