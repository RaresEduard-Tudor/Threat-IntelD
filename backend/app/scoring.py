# ---------------------------------------------------------------------------
# Scoring weights (tune these to adjust sensitivity)
# ---------------------------------------------------------------------------
WEIGHT_SAFE_BROWSING = 50
WEIGHT_DOMAIN_AGE_HIGH = 30
WEIGHT_DOMAIN_AGE_MEDIUM = 15
WEIGHT_SSL_INVALID = 20
WEIGHT_SSL_EXPIRING = 10
WEIGHT_VT_STRONG = 40          # ≥3 malicious engines (strong consensus)
WEIGHT_VT_LOW = 10             # 1–2 malicious engines (weak signal / likely FP)
WEIGHT_VT_SUSPICIOUS = 15      # suspicious-only, no malicious hits
WEIGHT_IP_REPUTATION = 25
WEIGHT_HEURISTICS_HIGH = 20    # ≥5 flags
WEIGHT_HEURISTICS_MEDIUM = 10  # ≥3 flags
WEIGHT_HEURISTICS_LOW = 5      # ≥1 flag
WEIGHT_OPENPHISH = 40
WEIGHT_DNSBL = 20

THRESHOLD_MALICIOUS = 70
THRESHOLD_SUSPICIOUS = 35


def compute_score(
    safe_browsing: dict,
    domain_age: dict,
    ssl: dict,
    virustotal: dict | None = None,
    ip_reputation: dict | None = None,
    url_heuristics: dict | None = None,
    openphish: dict | None = None,
    dnsbl: dict | None = None,
) -> tuple[int, str]:
    score = 0

    if safe_browsing.get("flagged"):
        score += WEIGHT_SAFE_BROWSING

    risk_level = domain_age.get("risk_level", "Low")
    if risk_level == "High":
        score += WEIGHT_DOMAIN_AGE_HIGH
    elif risk_level == "Medium":
        score += WEIGHT_DOMAIN_AGE_MEDIUM

    if not ssl.get("valid"):
        score += WEIGHT_SSL_INVALID
    else:
        expires_in_days = ssl.get("expires_in_days")
        if expires_in_days is not None and 0 <= expires_in_days < 14:
            score += WEIGHT_SSL_EXPIRING

    if virustotal is not None:
        malicious_count = virustotal.get("malicious", 0)
        if malicious_count >= 3:
            score += WEIGHT_VT_STRONG
        elif malicious_count >= 1:
            score += WEIGHT_VT_LOW
        elif virustotal.get("suspicious", 0) > 2:
            score += WEIGHT_VT_SUSPICIOUS

    if ip_reputation is not None and ip_reputation.get("is_flagged"):
        score += WEIGHT_IP_REPUTATION

    if url_heuristics is not None:
        flag_count = url_heuristics.get("flag_count", 0)
        if flag_count >= 5:
            score += WEIGHT_HEURISTICS_HIGH
        elif flag_count >= 3:
            score += WEIGHT_HEURISTICS_MEDIUM
        elif flag_count >= 1:
            score += WEIGHT_HEURISTICS_LOW

    if openphish is not None and openphish.get("flagged"):
        score += WEIGHT_OPENPHISH

    if dnsbl is not None and dnsbl.get("flagged"):
        score += WEIGHT_DNSBL

    score = min(score, 100)

    if score >= THRESHOLD_MALICIOUS:
        assessment = "Malicious"
    elif score >= THRESHOLD_SUSPICIOUS:
        assessment = "Suspicious"
    else:
        assessment = "Safe"

    return score, assessment
