"""Shared local fixtures for the Binary Static Analysis tests.

The checked-in binary samples are synthetic and inert. They contain only minimal
headers/data required to exercise parsers and are never executed.
"""
from pathlib import Path
import importlib.util
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/"fixtures"

@pytest.fixture(scope="session")
def package():
    """Load the hyphenated plugin directory under an import-safe test name."""
    name="binary_static_analysis"
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/"__init__.py",submodule_search_locations=[str(ROOT)])
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return name

@pytest.fixture
def fixtures():
    """Return the immutable fixture directory."""
    return FIXTURES
