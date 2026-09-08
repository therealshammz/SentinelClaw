from sentinelclaw.engine.finding_processor import process_findings


def make_finding(
    *,
    rule_id: str = "TEST-001",
    title: str = "Synthetic finding",
    severity: str = "medium",
    source: str = "builtin",
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": "process",
        "description": "Synthetic finding used by pytest.",
        "confidence": "medium",
        "source": source,
        "pid": 4242,
        "process_name": "powershell.exe",
        "evidence": {
            "pid": 4242,
            "name": "powershell.exe",
            "command_line": "powershell.exe -enc TEST",
        },
    }


def test_process_findings_returns_list() -> None:
    result = process_findings(
        [make_finding()]
    )

    assert isinstance(result, list)
    assert len(result) == 1


def test_process_findings_normalizes_severity() -> None:
    result = process_findings(
        [make_finding(severity="HIGH")]
    )

    assert result[0]["severity"] == "high"


def test_exact_duplicate_findings_are_removed() -> None:
    finding = make_finding()

    result = process_findings(
        [
            finding,
            dict(finding),
        ]
    )

    assert len(result) == 1


def test_different_findings_are_preserved() -> None:
    first = make_finding(
        rule_id="TEST-001",
        title="First finding",
    )

    second = make_finding(
        rule_id="TEST-002",
        title="Second finding",
    )

    result = process_findings(
        [
            first,
            second,
        ]
    )

    assert len(result) == 2


def test_processed_finding_preserves_core_fields() -> None:
    result = process_findings(
        [make_finding()]
    )

    finding = result[0]

    assert finding["rule_id"] == "TEST-001"
    assert finding["title"] == "Synthetic finding"
    assert finding["category"] == "process"
    assert finding["source"] == "builtin"
    assert finding["pid"] == 4242
    assert finding["process_name"] == "powershell.exe"


def test_processed_finding_preserves_evidence() -> None:
    result = process_findings(
        [make_finding()]
    )

    evidence = result[0]["evidence"]

    assert evidence["pid"] == 4242
    assert evidence["name"] == "powershell.exe"
    assert (
        evidence["command_line"]
        == "powershell.exe -enc TEST"
    )
