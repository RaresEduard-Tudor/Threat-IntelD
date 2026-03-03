import httpx

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"

# URLhaus query_status values that indicate a live/confirmed malicious URL
_MALICIOUS_STATUSES = {"online", "is_malware", "phishing"}


async def check_urlhaus(url: str) -> dict:
    """Query the URLhaus API (abuse.ch) for known malware / phishing URLs.

    No API key required.

    Returns a dict with keys:
        flagged (bool)      – True if URLhaus has the URL on record as malicious
        threat_type (str)   – URLhaus threat category, or None
        query_status (str)  – raw status from APIv1 response
        details (str)       – human-readable summary
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                _URLHAUS_API,
                data={"url": url},
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        return {
            "flagged": False,
            "threat_type": None,
            "query_status": "error",
            "details": f"URLhaus API error: {exc.response.status_code}.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "flagged": False,
            "threat_type": None,
            "query_status": "error",
            "details": f"URLhaus check failed: {str(exc)[:80]}",
        }

    query_status = data.get("query_status", "no_results")

    if query_status == "no_results":
        return {
            "flagged": False,
            "threat_type": None,
            "query_status": query_status,
            "details": "Not found in URLhaus database.",
        }

    flagged = query_status in _MALICIOUS_STATUSES
    tags = data.get("tags") or []
    threat = data.get("threat") or (", ".join(tags) if tags else None)

    if flagged:
        detail = f"Flagged by URLhaus as {query_status}"
        if threat:
            detail += f" ({threat})"
        detail += "."
    else:
        # known but taken offline / already cleaned up
        detail = f"Previously reported in URLhaus (status: {query_status})."

    return {
        "flagged": flagged,
        "threat_type": threat,
        "query_status": query_status,
        "details": detail,
    }
