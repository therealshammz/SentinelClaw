from sentinelclaw.engine.correlation_engine import correlate_findings


def process_finding(
    rule_id: str,
    title: str,
    severity: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": "process",
        "description": "Synthetic correlated process activity.",
        "confidence": "high",
        "pid": 9001,
        "process_name": "powershell.exe",
        "mitre": ["T1059.001"],
        "evidence": {
            "pid": 9001,
            "name": "powershell.exe",
        },
    }


def test_no_findings_produce_no_incidents() -> None:
    assert correlate_findings([]) == []


def test_single_process_finding_does_not_create_process_chain() -> None:
    incidents = correlate_findings(
        [
            process_finding(
                "TEST-001",
                "Single process signal",
                "medium",
            )
        ]
    )

    process_incidents = [
        incident
        for incident in incidents
        if str(
            incident.get("incident_id", "")
        ).startswith("INC-PROC-")
    ]

    assert process_incidents == []


def test_multiple_suspicious_findings_same_pid_correlate() -> None:
    incidents = correlate_findings(
        [
            process_finding(
                "TEST-001",
                "Encoded PowerShell",
                "medium",
            ),
            process_finding(
                "TEST-002",
                "Suspicious PowerShell download",
                "high",
            ),
        ]
    )

    process_incidents = [
        incident
        for incident in incidents
        if str(
            incident.get("incident_id", "")
        ).startswith("INC-PROC-")
    ]

    assert process_incidents
    assert process_incidents[0]["severity"] in {
        "medium",
        "high",
        "critical",
    }


def test_correlated_incident_keeps_related_findings() -> None:
    incidents = correlate_findings(
        [
            process_finding(
                "TEST-001",
                "Encoded PowerShell",
                "medium",
            ),
            process_finding(
                "TEST-002",
                "Suspicious PowerShell download",
                "high",
            ),
        ]
    )

    process_incident = next(
        incident
        for incident in incidents
        if str(
            incident.get("incident_id", "")
        ).startswith("INC-PROC-")
    )

    related = (
        process_incident.get("findings")
        or process_incident.get("related_findings")
        or process_incident.get("finding_ids")
        or []
    )

    assert related
