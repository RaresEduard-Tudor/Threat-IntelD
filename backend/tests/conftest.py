import pytest
from app.main import _cache


@pytest.fixture(autouse=True)
def clear_result_cache():
    """Clear the TTLCache before and after every test to prevent state leakage."""
    _cache.clear()
    yield
    _cache.clear()
