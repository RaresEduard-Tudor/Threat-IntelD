# Threat Score Weights
# safe_browsing flagged  → +50 points
# domain_age High risk   → +30 points
# domain_age Medium risk → +15 points
# ssl invalid            → +20 points

def compute_score(
    safe_browsing: dict,
    domain_age: dict,
    ssl: dict,
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

    score = min(score, 100)

    if score >= 70:
        assessment = "Malicious"
    elif score >= 35:
        assessment = "Suspicious"
    else:
        assessment = "Safe"

    return score, assessment
