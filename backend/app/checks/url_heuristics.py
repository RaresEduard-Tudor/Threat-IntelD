"""URL heuristics check — no external API required.

Inspects the URL's structure and hostname for patterns commonly associated
with phishing, typosquatting, and drive-by-download sites:

  • IP address used as hostname (+1 flag)
  • Excessive subdomain depth — > 3 labels deep (+1 flag)
  • Suspicious TLD (.xyz, .top, .click, .loan, .work, .gq, .tk, .ml, .cf, .ga) (+1 flag)
  • Phishing keywords in the hostname (login, verify, secure, update, account,
    confirm, banking, signin, ebayisapi, paypal, amazon) (+1 per keyword, capped at 2)
  • Non-standard port (not 80/443/None) (+1 flag)
  • Excessively long hostname — > 50 chars (+1 flag)
  • Punycode / IDN domain (xn-- in any label) (+1 flag)
  • Path contains suspicious patterns (/wp-login, /admin, encoded % % chars) (+1)
  • URL total length > 200 characters (+1 flag)
"""

import ipaddress
import re
from urllib.parse import urlparse

_PHISHING_KEYWORDS = re.compile(
    r"(login|verify|secure|update|account|confirm|banking|signin|ebayisapi|paypal|amazon)",
    re.IGNORECASE,
)

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cf", ".ga",
    ".buzz", ".icu", ".pw", ".rest", ".cyou", ".cam", ".surf", ".monster",
}

_SUSPICIOUS_PATH = re.compile(r"(/wp-login|/admin|%[0-9a-fA-F]{2}[^%]*%[0-9a-fA-F]{2})", re.IGNORECASE)

_MAX_URL_LEN = 2048


async def check_url_heuristics(url: str) -> dict:
    """Heuristic scan — instant, no I/O. Async so it composes with asyncio.gather."""
    url = url[:_MAX_URL_LEN]
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    flags: list[str] = []

    # 1. IP address as hostname
    try:
        ipaddress.ip_address(hostname)
        flags.append("IP address used as hostname — legitimate sites use domain names")
    except ValueError:
        pass

    # 2. Excessive subdomain depth (> 3 labels, e.g. a.b.c.d.com)
    labels = hostname.split(".")
    if len(labels) > 4:
        flags.append(f"Excessive subdomain depth ({len(labels)} labels) — common in phishing redirects")

    # 3. Suspicious TLD
    tld = f".{labels[-1]}" if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD ({tld}) — frequently abused in malicious campaigns")

    # 4. Phishing keywords in hostname (cap at 2 flags to avoid score inflation)
    kw_matches = _PHISHING_KEYWORDS.findall(hostname)
    for kw in list(dict.fromkeys(kw for kw in kw_matches))[:2]:
        flags.append(f'Phishing keyword "{kw}" found in hostname')

    # 5. Non-standard port
    port = parsed.port
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        flags.append(f"Non-standard port ({port}) — unusual for legitimate web services")

    # 6. Long hostname
    if len(hostname) > 50:
        flags.append(f"Unusually long hostname ({len(hostname)} chars) — typical of typosquatting")

    # 7. Punycode / IDN
    if any(label.startswith("xn--") for label in labels):
        flags.append("Punycode / IDN domain detected — may visually mimic a trusted brand")

    # 8. Suspicious path patterns
    full_path = parsed.path + ("?" + parsed.query if parsed.query else "")
    if _SUSPICIOUS_PATH.search(full_path):
        flags.append("Suspicious path pattern (encoded characters or admin paths)")

    # 9. Very long URL
    if len(url) > 200:
        flags.append(f"Excessively long URL ({len(url)} chars) — often used to obscure destination")

    risk_score = min(len(flags), 5)  # cap at 5 individual flags for display
    is_suspicious = len(flags) > 0

    if len(flags) == 0:
        details = "No suspicious URL patterns detected."
    elif len(flags) == 1:
        details = flags[0]
    else:
        details = f"{len(flags)} suspicious pattern(s) detected."

    return {
        "is_suspicious": is_suspicious,
        "flag_count": len(flags),
        "flags": flags,
        "risk_score": risk_score,
        "details": details,
    }
