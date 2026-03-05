import itertools

import pytest

import app.main
from app.main import _cache, _history_store, limiter


@pytest.fixture(autouse=True)
def clear_state():
    """Clear caches and in-memory stores before and after every test."""
    _cache.clear()
    _history_store.clear()
    app.main._id_counter = itertools.count(1)
    limiter.reset()
    yield
    _cache.clear()
    _history_store.clear()
    app.main._id_counter = itertools.count(1)
    limiter.reset()
