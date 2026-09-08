from sentinelclaw.engine.timeline_engine import build_timeline


def make_finding(
    *,
    rule_id: str,
    timestamp: str | None,
    severity: str = "medium",
) -> dict:
    finding = {
        "rule_id": rule_id,
        "title": f"Finding {rule_id}",
        "severity": severity,
        "category": "process",
        "description": "Synthetic timeline finding.",
        "pid": 1234,
        "process_name": "powershell.exe",
        "evidence": {
            "pid": 1234,
            "name": "powershell.exe",
        },
    }

    if timestamp is not None:
        finding["timestamp"] = timestamp

    return finding


def test_empty_timeline_is_empty() -> None:
    result = build_timeline(
        findings=[],
        incidents=[],
        scan_timestamp="2026-09-08T12:00:00+00:00",
    )

    assert result == []


def test_finding_becomes_timeline_event() -> None:
    result = build_timeline(
        findings=[
            make_finding(
                rule_id="TEST-001",
                timestamp="2026-09-08T10:00:00+00:00",
            )
        ],
        incidents=[],
        scan_timestamp="2026-09-08T12:00:00+00:00",
    )

    assert len(result) == 1
    assert result[0]["rule_id"] == "TEST-001"
    assert result[0]["event_type"] == "finding"


def test_timeline_orders_oldest_event_first() -> None:
    result = build_timeline(
        findings=[
            make_finding(
                rule_id="TEST-LATE",
                timestamp="2026-09-08T11:00:00+00:00",
            ),
            make_finding(
                rule_id="TEST-EARLY",
                timestamp="2026-09-08T09:00:00+00:00",
            ),
        ],
        incidents=[],
        scan_timestamp="2026-09-08T12:00:00+00:00",
    )

    assert result[0]["rule_id"] == "TEST-EARLY"
    assert result[1]["rule_id"] == "TEST-LATE"


def test_missing_timestamp_does_not_break_timeline() -> None:
    result = build_timeline(
        findings=[
            make_finding(
                rule_id="TEST-KNOWN",
                timestamp="2026-09-08T09:00:00+00:00",
            ),
            make_finding(
                rule_id="TEST-UNKNOWN",
                timestamp=None,
            ),
        ],
        incidents=[],
        scan_timestamp="2026-09-08T12:00:00+00:00",
    )

    assert len(result) == 2
    assert result[0]["rule_id"] == "TEST-KNOWN"
