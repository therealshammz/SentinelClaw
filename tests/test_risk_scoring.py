from sentinelclaw.models.findings import calculate_risk_score


def make_finding(severity: str) -> dict:
    return {
        "rule_id": f"TEST-{severity.upper()}",
        "title": f"{severity.title()} test finding",
        "severity": severity,
        "category": "test",
        "description": "Synthetic test finding.",
        "evidence": {},
    }


def test_empty_findings_are_informational() -> None:
    result = calculate_risk_score([])

    assert result["score"] == 0
    assert result["level"] == "informational"


def test_low_finding_adds_one_point() -> None:
    result = calculate_risk_score(
        [make_finding("low")]
    )

    assert result["score"] == 1
    assert result["level"] == "low"


def test_medium_finding_adds_three_points() -> None:
    result = calculate_risk_score(
        [make_finding("medium")]
    )

    assert result["score"] == 3
    assert result["level"] == "low"


def test_high_finding_adds_seven_points() -> None:
    result = calculate_risk_score(
        [make_finding("high")]
    )

    assert result["score"] == 7
    assert result["level"] == "low"


def test_critical_finding_adds_ten_points() -> None:
    result = calculate_risk_score(
        [make_finding("critical")]
    )

    assert result["score"] == 10
    assert result["level"] == "low"


def test_risk_score_is_capped_at_100() -> None:
    findings = [
        make_finding("critical")
        for _ in range(20)
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 100
    assert result["level"] == "critical"
