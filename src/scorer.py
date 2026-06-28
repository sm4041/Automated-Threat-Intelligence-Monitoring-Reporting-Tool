"""
Scoring Engine — produces a composite priority score (0.0–10.0) per advisory.

Scoring dimensions
──────────────────
1. Base CVSS          0–4.0 pts   (cvss_score / 10 * 4)
2. Severity tier      0–3.0 pts   Critical=3, High=2, Medium=1, Low=0.5
3. In CISA KEV        +2.0 pts    Confirmed active exploitation
4. Has CVE ID         +0.5 pts    Standardized identifier present
5. High-risk tags     +0–1.0 pts  Up to 0.25 per dangerous tag (max 4 tags)

Max theoretical score: 4 + 3 + 2 + 0.5 + 1 = 10.5 → capped at 10.0
"""

from typing import Union

SEVERITY_SCORES = {
    "Critical": 3.0,
    "High": 2.0,
    "Medium": 1.0,
    "Low": 0.5,
    "Unknown": 0.0,
}

# Tags that elevate priority
HIGH_RISK_TAGS = {
    "rce", "zero_day", "ransomware", "auth_bypass", "memory_corruption"
}


def score_advisory(advisory: dict) -> float:
    """
    Compute a composite priority score for a normalized advisory.
    Returns a float in [0.0, 10.0].
    """
    score = 0.0

    # 1. CVSS base score contribution (0–4.0)
    cvss = float(advisory.get("cvss_score") or 0.0)
    score += (cvss / 10.0) * 4.0

    # 2. Severity tier (0–3.0)
    severity = advisory.get("severity", "Unknown")
    score += SEVERITY_SCORES.get(severity, 0.0)

    # 3. KEV bonus (+2.0)
    if advisory.get("in_kev"):
        score += 2.0

    # 4. CVE ID present (+0.5)
    if advisory.get("cve_ids"):
        score += 0.5

    # 5. High-risk tag bonus (up to +1.0)
    tags = set(advisory.get("tags", []))
    risky_matches = tags & HIGH_RISK_TAGS
    score += min(len(risky_matches) * 0.25, 1.0)

    return round(min(score, 10.0), 2)


def score_label(score: float) -> str:
    """Human-readable priority label."""
    if score >= 8.0:
        return "CRITICAL"
    elif score >= 6.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 2.0:
        return "LOW"
    else:
        return "INFO"
