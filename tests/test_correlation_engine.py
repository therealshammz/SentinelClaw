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


def process_rule(
    rule_id: str,
    title: str,
    severity: str,
) -> dict:
    return {
        "id": rule_id,
        "title": title,
        "description": "Synthetic rule for correlation tests.",
        "category": "process",
        "severity": severity,
        "conditions": [
            {
                "field": "name",
                "operator": "equals",
                "value": "powershell.exe",
            }
        ],
    }


def network_rule(
    rule_id: str,
    title: str,
    severity: str,
) -> dict:
    return {
        "id": rule_id,
        "title": title,
        "description": "Synthetic network rule for correlation tests.",
        "category": "network",
        "severity": severity,
        "conditions": [
            {
                "field": "remote_port",
                "operator": "equals",
                "value": 4444,
            }
        ],
    }


def test_yaml_process_and_network_findings_correlate_on_pid() -> None:
    from sentinelclaw.engine.rule_engine import run_rules

    process_findings = run_rules(
        [
            process_rule(
                "PROC-TEST-001",
                "Encoded PowerShell",
                "medium",
            )
        ],
        [
            {
                "pid": 5555,
                "name": "powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand VABFAFMAVA=="
                ),
            }
        ],
        category="process",
    )

    network_findings = run_rules(
        [
            network_rule(
                "NET-TEST-001",
                "Connection to monitored port",
                "medium",
            )
        ],
        [
            {
                "pid": 5555,
                "remote_ip": "203.0.113.5",
                "remote_port": 4444,
            }
        ],
        category="network",
    )

    assert process_findings
    assert network_findings

    incidents = correlate_findings(
        process_findings + network_findings
    )

    net_incidents = [
        incident
        for incident in incidents
        if str(
            incident.get(
                "incident_id",
                "",
            )
        ).startswith("INC-NET-")
    ]

    assert net_incidents
    assert net_incidents[0]["title"] == (
        "Suspicious process with network activity"
    )
    assert net_incidents[0]["related_pids"] == [5555]
    assert "203.0.113.5" in (
        net_incidents[0]["related_ips"]
    )


def test_lone_low_severity_rule_finding_does_not_correlate() -> None:
    from sentinelclaw.engine.rule_engine import run_rules

    findings = run_rules(
        [
            process_rule(
                "PROC-TEST-LOW",
                "Low severity process signal",
                "low",
            )
        ],
        [
            {
                "pid": 3333,
                "name": "powershell.exe",
            }
        ],
        category="process",
    )

    assert findings
    assert correlate_findings(findings) == []
