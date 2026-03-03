import asyncio
import time
from urllib.parse import urlparse, urlunparse

import httpx

# Official public mirror — the openphish.com/feed.txt endpoint requires a paid
# subscription and blocks automated requests.  The repo below is the authoritative
# community feed maintained by the OpenPhish project itself.
_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
_FEED_TTL = 6 * 3600  # refresh every 6 hours

_feed: set[str] = set()
_last_refresh: float = 0.0
_refresh_lock = asyncio.Lock()


def _normalize(url: str) -> str:
    """Lowercase scheme+host and strip trailing slash/fragment for feed comparison."""
    try:
        p = urlparse(url)
        return urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path.rstrip("/") or "/",
            p.params,
            p.query,
            "",  # strip fragment
        ))
    except Exception:
        return url.lower().rstrip("/")


async def _refresh_if_needed() -> None:
    global _feed, _last_refresh
    if _feed and time.time() - _last_refresh < _FEED_TTL:
        return
    async with _refresh_lock:
        # Double-check after acquiring the lock
        if _feed and time.time() - _last_refresh < _FEED_TTL:
            return
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(_FEED_URL)
                resp.raise_for_status()
            _feed = {line.strip() for line in resp.text.splitlines() if line.strip()}
            _last_refresh = time.time()
        except Exception:  # noqa: BLE001
            pass  # keep stale feed; do not raise


async def check_openphish(url: str) -> dict:
    """Check the URL against the OpenPhish community phishing feed (no API key required)."""
    await _refresh_if_needed()

    if not _feed:
        return {
            "flagged": False,
            "details": "OpenPhish feed could not be loaded; check unavailable.",
        }

    norm = _normalize(url)
    flagged = norm in _feed or url in _feed

    if flagged:
        return {"flagged": True, "details": "URL found in OpenPhish phishing feed."}
    return {"flagged": False, "details": "Not found in OpenPhish feed."}
