from dataclasses import asdict, dataclass
from typing import Any

from sentinelclaw.config.constants import (
    SEVERITY_SCORES,
    risk_level_from_score,
)


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

    return {
        "score": score,
        "level": risk_level_from_score(
            score
        ),
    }
