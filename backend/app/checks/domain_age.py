import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url


def _get_domain_age_days(domain: str) -> int | None:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - creation_date
        return delta.days
    except Exception:
        logger.warning("WHOIS lookup failed for %s", domain, exc_info=True)
        return None


async def check_domain_age(url: str) -> dict:
    """Use python-whois to determine domain registration age."""
    domain = _extract_domain(url)

    # WHOIS lookup is blocking; run in thread pool to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    days = await loop.run_in_executor(None, _get_domain_age_days, domain)

    if days is None:
        return {
            "days_registered": None,
            "risk_level": "Unknown",
            "details": "Could not retrieve domain registration data.",
        }

    if days < 30:
        risk_level = "High"
        details = f"Domain registered {days} days ago. High risk indicator."
    elif days < 180:
        risk_level = "Medium"
        details = f"Domain registered {days} days ago. Moderately new domain."
    else:
        risk_level = "Low"
        details = f"Domain registered {days} days ago. Established domain."

    return {
        "days_registered": days,
        "risk_level": risk_level,
        "details": details,
    }
