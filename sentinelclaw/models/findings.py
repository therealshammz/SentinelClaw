from sentinelclaw.config.constants import (
    SEVERITY_SCORES,
    risk_level_from_score,
)


def calculate_risk_score(findings: list[dict]) -> dict:
    score = 0

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        score += SEVERITY_SCORES.get(severity, 0)

    score = min(score, 100)

    return {
        "score": score,
        "level": risk_level_from_score(
            score
        ),
    }
