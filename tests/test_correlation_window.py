from sentinelclaw.config.settings import get_settings
from sentinelclaw.engine.correlation_engine import correlate_findings


def finding(
    rule_id: str,
    severity: str,
    pid: int,
    timestamp: str | None = None,
) -> dict:
    item = {
        "rule_id": rule_id,
        "title": f"Finding {rule_id}",
        "description": "Synthetic windowed finding.",
        "severity": severity,
        "category": "process",
        "confidence": "high",
        "pid": pid,
        "process_name": "powershell.exe",
        "evidence": {
            "pid": pid,
            "name": "powershell.exe",
        },
    }

    if timestamp is not None:
        item["timestamp"] = timestamp

    return item


def process_incidents(
    incidents: list[dict],
) -> list[dict]:
    return [
        incident
        for incident in incidents
        if str(incident.get("incident_id", "")).startswith("INC-PROC-")
    ]


def test_findings_one_hour_apart_correlate() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-08T10:00:00+00:00",
            ),
        ]
    )

    assert process_incidents(incidents)


def test_findings_forty_eight_hours_apart_do_not_correlate() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-10T09:00:00+00:00",
            ),
        ]
    )

    assert process_incidents(incidents) == []


def test_window_configurable_via_settings(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_CORRELATION_WINDOW_HOURS",
        "72",
    )

    assert get_settings().correlation_window_hours == 72

    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-10T09:00:00+00:00",
            ),
        ]
    )

    assert process_incidents(incidents)


def test_window_hours_parameter_overrides_default() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-10T09:00:00+00:00",
            ),
        ],
        window_hours=72,
    )

    assert process_incidents(incidents)


def test_untimestamped_findings_still_correlate() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
            ),
            finding(
                "T2",
                "high",
                9001,
            ),
        ]
    )

    assert process_incidents(incidents)


def test_mixed_timestamped_and_untimestamped_correlate() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-08T10:00:00+00:00",
            ),
        ]
    )

    assert process_incidents(incidents)


def test_incident_carries_time_bounds() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-08T10:00:00+00:00",
            ),
        ]
    )

    incident = process_incidents(incidents)[0]

    assert incident["first_seen"] == ("2026-09-08T09:00:00+00:00")
    assert incident["last_seen"] == ("2026-09-08T10:00:00+00:00")


def test_incident_without_timestamps_omits_bounds() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
            ),
            finding(
                "T2",
                "high",
                9001,
            ),
        ]
    )

    incident = process_incidents(incidents)[0]

    assert "first_seen" not in incident
    assert "last_seen" not in incident


def test_z_suffix_timestamps_are_parsed() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "2026-09-08T09:00:00Z",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-08T10:00:00Z",
            ),
        ]
    )

    assert process_incidents(incidents)


def test_unparseable_timestamp_is_treated_within_window() -> None:
    incidents = correlate_findings(
        [
            finding(
                "T1",
                "medium",
                9001,
                "not-a-timestamp",
            ),
            finding(
                "T2",
                "high",
                9001,
                "2026-09-08T09:00:00+00:00",
            ),
        ]
    )

    assert process_incidents(incidents)
