from dataclasses import asdict, dataclass
from typing import Any


SEVERITY_SCORES = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 10,
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    evidence: Any = None
    recommendation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def calculate_risk_score(findings: list[dict]) -> dict:
    score = 0

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        score += SEVERITY_SCORES.get(severity, 0)

    score = min(score, 100)

    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "informational"

    return {
        "score": score,
        "level": level,
    }
