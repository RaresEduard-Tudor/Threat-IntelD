# Threat Score Weights
# safe_browsing flagged        → +50 points
# domain_age High risk         → +30 points
# domain_age Medium risk       → +15 points
# ssl invalid                  → +20 points
# ssl expiring < 14 days       → +10 points (only when cert is still valid)
# virustotal detected          → +40 points
# virustotal suspicious (>2)   → +15 points (only when not detected)
# ip_reputation flagged        → +25 points
# url_heuristics flag_count≥1  → +5 pts; ≥3 → +10 pts; ≥5 → +20 pts

def compute_score(
    safe_browsing: dict,
    domain_age: dict,
    ssl: dict,
    virustotal: dict | None = None,
    ip_reputation: dict | None = None,
    url_heuristics: dict | None = None,
) -> tuple[int, str]:
    score = 0

    if safe_browsing.get("flagged"):
        score += 50

    risk_level = domain_age.get("risk_level", "Low")
    if risk_level == "High":
        score += 30
    elif risk_level == "Medium":
        score += 15

    if not ssl.get("valid"):
        score += 20
    else:
        expires_in_days = ssl.get("expires_in_days")
        if expires_in_days is not None and 0 <= expires_in_days < 14:
            score += 10

    if virustotal is not None:
        if virustotal.get("detected"):
            score += 40
        elif virustotal.get("suspicious", 0) > 2:
            score += 15

    if ip_reputation is not None and ip_reputation.get("is_flagged"):
        score += 25

    if url_heuristics is not None:
        flag_count = url_heuristics.get("flag_count", 0)
        if flag_count >= 5:
            score += 20
        elif flag_count >= 3:
            score += 10
        elif flag_count >= 1:
            score += 5

    score = min(score, 100)

    if score >= 70:
        assessment = "Malicious"
    elif score >= 35:
        assessment = "Suspicious"
    else:
        assessment = "Safe"

    return score, assessment
