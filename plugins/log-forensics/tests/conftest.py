"""Shared import-safe access to the hyphenated plugin and inert fixtures."""
from pathlib import Path
import importlib.util,sys,pytest
ROOT=Path(__file__).resolve().parents[1];FIXTURES=ROOT/'fixtures'
@pytest.fixture(scope='session')
def package():
    """Load plugin under a legal package name for relative imports."""
    name='log_forensics_test'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'__init__.py',submodule_search_locations=[str(ROOT)]);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return name
@pytest.fixture
def fixtures():return FIXTURES
