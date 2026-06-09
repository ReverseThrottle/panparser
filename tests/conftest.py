"""pytest configuration for panparser tests.

Adds the repo root to sys.path so that export.* and parsers.* imports resolve
without installing the package.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
