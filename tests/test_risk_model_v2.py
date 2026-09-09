"""Risk model v2 (P4-24) unit and integration tests.

The module docstring of ``sentinelclaw.models.risk`` is the normative
specification; these tests freeze its behaviour:

* severity x confidence ordering is monotonic,
* the geometric saturation curve makes N identical findings cost less
  than N times a single finding (10 criticals == 80, 20 == capped 100),
* category modifiers steer the intrinsic base score,
* incident risk aggregates member findings with the shared model
  (never a max-of-severity weight),
* every processed finding carries a documented ``risk`` breakdown.
"""

from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.main import run_scan
from sentinelclaw.models.risk import (
    calculate_incident_risk,
    calculate_overall_risk,
    calculate_risk_score,
    finding_base_score,
    finding_risk_breakdown,
)


def make_finding(
    *,
    severity: str = "medium",
    confidence: str | None = None,
    category: str = "test",
    rule_id: str = "RISK-TEST",
) -> dict:
    return {
        "rule_id": rule_id,
        "title": "Risk model test finding",
        "description": "Synthetic finding.",
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "evidence": {},
    }


def test_empty_findings_are_informational() -> None:
    result = calculate_risk_score([])

    assert result["score"] == 0
    assert result["level"] == "informational"


def test_single_finding_keeps_historical_base_scores() -> None:
    expectations = {
        "low": (1, "low"),
        "medium": (3, "low"),
        "high": (7, "low"),
        "critical": (10, "low"),
    }

    for severity, (
        score,
        level,
    ) in expectations.items():
        result = calculate_risk_score(
            [make_finding(severity=severity)]
        )

        assert result["score"] == score
        assert result["level"] == level


def test_severity_times_confidence_is_monotonic() -> None:
    high_low = calculate_risk_score(
        [make_finding(severity="high", confidence="low")]
    )

    high_medium = calculate_risk_score(
        [make_finding(severity="high", confidence="medium")]
    )

    high_high = calculate_risk_score(
        [make_finding(severity="high", confidence="high")]
    )

    assert high_low["score"] < high_medium["score"] < high_high["score"]

    assert finding_base_score(
        make_finding(severity="high", confidence="high")
    ) > finding_base_score(
        make_finding(severity="high")
    )


def test_missing_confidence_is_neutral_multiplier() -> None:
    assert finding_base_score(
        make_finding(severity="high")
    ) == 7.0

    assert finding_base_score(
        make_finding(severity="high", confidence="high")
    ) == 7.0 * 1.3


def test_category_modifiers_steer_base_score() -> None:
    persistence = calculate_risk_score(
        [make_finding(severity="critical", confidence="high", category="persistence")]
    )

    network = calculate_risk_score(
        [make_finding(severity="critical", confidence="high", category="network")]
    )

    windows = calculate_risk_score(
        [make_finding(severity="critical", confidence="high", category="windows_event")]
    )

    unknown = calculate_risk_score(
        [make_finding(severity="critical", confidence="high", category="unknown")]
    )

    assert persistence["score"] > unknown["score"]
    assert network["score"] > unknown["score"]
    assert windows["score"] < unknown["score"]
    assert unknown["score"] == 13  # 10 * 1.3 * 1.0


def test_ten_identical_critical_findings_saturate() -> None:
    findings = [
        make_finding(severity="critical")
        for _ in range(10)
    ]

    result = calculate_risk_score(findings)

    # 10 * (1 - 0.95^10) / 0.05 == 80.25, rounded to 80 -- well below
    # the linear value of 100, and never above the 100 cap.
    assert result["score"] == 80
    assert result["score"] < 10 * calculate_risk_score(
        [make_finding(severity="critical")]
    )["score"]
    assert result["level"] == "critical"


def test_twenty_critical_findings_hit_the_cap() -> None:
    findings = [
        make_finding(severity="critical")
        for _ in range(20)
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 100
    assert result["level"] == "critical"


def test_incident_risk_aggregates_members_not_max_severity() -> None:
    incident = {
        "incident_id": "INC-TEST-001",
        "severity": "medium",
        "findings": [
            make_finding(severity="medium"),
            make_finding(severity="low"),
        ],
    }

    result = calculate_incident_risk(
        [incident]
    )

    # Saturating aggregate over member bases: 3 + 0.95 * 1 == 3.95 -> 4.
    assert result["score"] == 4
    assert result["score"] > 3


def test_two_medium_incidents_are_not_flattened_to_one() -> None:
    medium = make_finding(severity="medium")

    incidents = [
        {
            "incident_id": "INC-TEST-001",
            "severity": "medium",
            "findings": [dict(medium, pid=1)],
        },
        {
            "incident_id": "INC-TEST-002",
            "severity": "medium",
            "findings": [dict(medium, pid=2)],
        },
    ]

    result = calculate_incident_risk(
        incidents
    )

    assert result["score"] == 6
    assert result["score"] > 3


def test_overall_risk_keeps_both_strata() -> None:
    findings = [
        make_finding(severity="high")
    ]

    incidents = [
        {
            "incident_id": "INC-TEST-001",
            "severity": "high",
            "findings": [
                make_finding(severity="high"),
                make_finding(severity="medium"),
            ],
        }
    ]

    result = calculate_overall_risk(
        findings,
        incidents,
    )

    assert set(result) == {
        "score",
        "level",
        "finding_risk",
        "incident_risk",
    }

    assert result["finding_risk"]["score"] == 7
    assert result["incident_risk"]["score"] == 10  # 7 + 0.95 * 3
    assert result["score"] == 10


def test_processed_finding_carries_risk_breakdown() -> None:
    processed = process_findings(
        [make_finding(severity="high", confidence="high", category="process")]
    )

    finding = processed[0]

    risk = finding["risk"]

    assert set(risk) == {
        "score",
        "level",
        "components",
    }

    assert set(risk["components"]) == {
        "severity_score",
        "confidence",
        "category_modifier",
        "saturation_applied",
    }

    assert risk["components"]["severity_score"] == 7
    assert risk["components"]["confidence"] == 1.3
    assert risk["components"]["category_modifier"] == 1.05
    assert risk["components"]["saturation_applied"] is False

    assert risk["score"] == int(
        round(
            finding_risk_breakdown(
                finding
            )["components"]["severity_score"]
            * risk["components"]["confidence"]
            * risk["components"]["category_modifier"]
        )
    )


def run_canned_scan(
    monkeypatch,
    processes,
    connections,
    windows_events,
) -> dict:
    monkeypatch.setattr(
        "sentinelclaw.main.get_processes",
        lambda: processes,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_network_connections",
        lambda: connections,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_windows_events",
        lambda **kwargs: windows_events,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_auth_events",
        lambda: [],
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_persistence_records",
        lambda: [],
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_system_info",
        lambda: {"hostname": "RISK-V2-TEST"},
    )

    return run_scan(
        show_progress=False,
    )


def test_every_report_finding_has_risk_breakdown(
    monkeypatch,
    sample_processes,
    sample_connections,
    sample_windows_events,
) -> None:
    report = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=sample_windows_events,
    )

    assert report["findings"]["all"]

    for finding in report["findings"]["all"]:
        components = finding["risk"]["components"]

        assert "severity_score" in components
        assert "confidence" in components
        assert "category_modifier" in components
        assert "saturation_applied" in components

    assert report["risk"]["level"] == "high"
