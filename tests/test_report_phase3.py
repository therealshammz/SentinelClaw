"""Report-generation and provenance tests (P3-18, P3-20).

Covers the stable ``schema_version`` in JSON output, the JSONL and CSV
machine-readable writers, the capped text report, the HTML incident
drill-down, rule provenance propagation, and MITRE coverage.
"""

import csv
import io
import json

import pytest

from sentinelclaw.config.constants import REPORT_SCHEMA_VERSION
from sentinelclaw.config.settings import Settings
from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.engine.rule_engine import (
    load_rule_file,
    run_rules,
)
from sentinelclaw.reporting.report_generator import (
    compute_mitre_coverage,
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_jsonl_report,
    generate_text_report,
    save_report_formats,
)
from sentinelclaw.main import build_parser, execute_command


def make_finding(
    rule_id: str,
    title: str,
    severity: str = "medium",
    category: str = "process",
    mitre: dict | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "confidence": "medium",
        "mitre": mitre,
        "evidence": {},
    }


def make_incident(
    incident_id: str,
    title: str,
    findings: list[dict],
) -> dict:
    return {
        "incident_id": incident_id,
        "title": title,
        "description": "Correlated activity.",
        "severity": "high",
        "confidence": "medium",
        "finding_count": len(findings),
        "related_rule_ids": sorted({str(finding.get("rule_id")) for finding in findings}),
        "related_pids": [],
        "related_ips": [],
        "findings": findings,
    }


def basic_report() -> dict:
    findings = [
        make_finding(
            "PROC-004",
            "Encoded PowerShell",
            severity="high",
            mitre={
                "tactic": "Execution",
                "technique": "T1059.001",
                "name": "PowerShell",
            },
        ),
        make_finding(
            "NET-001",
            "Monitored reverse-shell port",
            severity="high",
            category="network",
            mitre={
                "tactic": "Command and Control",
                "technique": "T1071.001",
                "name": "Web Protocols",
            },
        ),
    ]

    incidents = [
        make_incident(
            "INC-PROC-001",
            "Suspicious process group",
            findings,
        )
    ]

    return {
        "scan": {
            "application": "SentinelClaw",
            "timestamp": "2026-09-09T10:00:00+00:00",
        },
        "summary": {
            "rules_loaded": 20,
            "total_findings": len(findings),
            "incidents": len(incidents),
            "timeline_events": 1,
        },
        "risk": {
            "score": 40,
            "level": "high",
        },
        "findings": {
            "processes": findings,
            "all": findings,
        },
        "incidents": incidents,
        "timeline": [
            {
                "timestamp": "2026-09-09T10:00:00+00:00",
                "severity": "high",
                "event_type": "finding",
                "title": "Encoded PowerShell detected",
                "incident_id": "INC-PROC-001",
            }
        ],
        "collector_status": {
            "process_error": None,
            "network_error": None,
            "windows_event_error": None,
            "system_info_error": None,
        },
        "system": {},
    }


def test_generate_json_report_has_schema_version_and_mitre() -> None:
    parsed = json.loads(generate_json_report(basic_report()))

    assert parsed["schema_version"] == REPORT_SCHEMA_VERSION

    coverage = parsed["mitre_coverage"]

    assert coverage["Execution"]["T1059.001"] == 1
    assert coverage["Command and Control"]["T1071.001"] == 1

    assert parsed["findings"]["all"]


def test_generate_jsonl_report_parses_line_by_line() -> None:
    report = basic_report()

    lines = generate_jsonl_report(report).splitlines()

    parsed = [json.loads(line) for line in lines]

    first = parsed[0]

    assert first["type"] == "scan"
    assert first["schema_version"] == "1.0.0"
    assert first["scan"]["application"] == "SentinelClaw"
    assert first["risk"]["score"] == 40

    findings = [item for item in parsed[1:] if item["type"] == "finding"]

    incidents = [item for item in parsed[1:] if item["type"] == "incident"]

    assert len(findings) == len(report["findings"]["all"])
    assert len(incidents) == len(report["incidents"])

    finding_ids = {item["rule_id"] for item in findings}

    assert finding_ids == {
        "PROC-004",
        "NET-001",
    }

    assert incidents[0]["incident_id"] == "INC-PROC-001"


def test_generate_csv_report_has_header_and_rows() -> None:
    report = basic_report()

    csv_text = generate_csv_report(report)

    rows = list(csv.reader(io.StringIO(csv_text)))

    assert rows[0] == [
        "id",
        "severity",
        "title",
        "category",
        "source",
        "mitre",
        "timestamp",
    ]

    incident_header = [
        "incident_id",
        "severity",
        "title",
        "confidence",
        "finding_count",
        "related_rule_ids",
    ]

    header_index = rows.index(incident_header)

    finding_rows = [
        row
        for row in rows[1:header_index]
        if row
    ]

    ids = {row[0] for row in finding_rows}

    assert ids == {
        "PROC-004",
        "NET-001",
    }

    assert "Encoded PowerShell" in csv_text

    assert incident_header in rows

    assert any(
        row
        and row[0] == "INC-PROC-001"
        for row in rows
    )


def test_text_report_caps_findings_with_truncation_note(
    monkeypatch,
) -> None:
    report = basic_report()

    report["findings"]["all"] = [
        make_finding(
            f"RULE-{index:03d}",
            f"Finding {index}",
            mitre={
                "tactic": "Execution",
                "technique": "T1059.001",
            },
        )
        for index in range(55)
    ]

    monkeypatch.setattr(
        "sentinelclaw.reporting.report_generator.get_settings",
        lambda: Settings(report_max_findings=50),
    )

    text = generate_text_report(report)

    assert "... 5 more finding(s) not shown (report_max_findings cap)." in text

    assert "[1] Finding 0" in text

    assert "[51]" not in text

    assert "Finding 54" not in text


def test_text_report_shows_mitre_coverage() -> None:
    text = generate_text_report(basic_report())

    assert "MITRE ATT&CK COVERAGE" in text
    assert "Tactic: Execution" in text
    assert "T1059.001: 1 finding(s)" in text


def test_html_report_has_incident_drilldown() -> None:
    html = generate_html_report(basic_report())

    assert "Incident Drill-down" in html
    assert "<details" in html
    assert "INC-PROC-001" in html
    assert "PROC-004" in html
    assert "Encoded PowerShell detected" in html

    assert "MITRE ATT&amp;CK Coverage" in html
    assert "T1059.001" in html


def test_compute_mitre_coverage() -> None:
    findings = [
        {
            "mitre": {
                "tactic": "Execution",
                "technique": "T1059.001",
            }
        },
        {
            "mitre": {
                "tactic": "Execution",
                "technique": "T1059.001",
            }
        },
        {
            "mitre": {
                "tactic": "Persistence",
                "technique": "T1547.001",
            }
        },
        {"mitre": "T1055"},
        {"rule_id": "no-mitre"},
    ]

    coverage = compute_mitre_coverage(findings)

    assert coverage["Execution"]["T1059.001"] == 2
    assert coverage["Persistence"]["T1547.001"] == 1
    assert coverage["Unmapped"]["T1055"] == 1
    assert len(coverage["Execution"]) == 1


def test_rule_loader_stamps_source_file(
    tmp_path,
) -> None:
    rule_file = tmp_path / "provenance.yaml"

    rule_file.write_text(
        "rules:\n"
        "  - id: PROC-PROV-001\n"
        "    title: Provenance rule\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    status: experimental\n"
        "    enabled: true\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n",
        encoding="utf-8",
    )

    rules = load_rule_file(rule_file)

    assert len(rules) == 1

    assert rules[0]["source_file"] == str(rule_file)

    findings = run_rules(
        rules,
        [
            {
                "name": "powershell.exe",
                "pid": 4242,
            }
        ],
        category="process",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_source"] == str(rule_file)

    assert finding["rule_status"] == "experimental"


def test_rule_without_status_still_has_source() -> None:
    rule = {
        "id": "PROC-001",
        "title": "Plain rule",
        "category": "process",
        "severity": "high",
        "source_file": "/tmp/rules/process_rules.yaml",
        "conditions": [
            {
                "field": "name",
                "operator": "equals",
                "value": "powershell.exe",
            }
        ],
    }

    findings = run_rules(
        [rule],
        [
            {
                "name": "powershell.exe",
                "pid": 1,
            }
        ],
        category="process",
    )

    assert findings[0]["rule_source"] == ("/tmp/rules/process_rules.yaml")

    assert "rule_status" not in findings[0]


def test_merge_preserves_rule_provenance() -> None:
    base = {
        "rule_id": "PROC-004",
        "title": "Encoded PowerShell",
        "category": "process",
        "severity": "high",
        "pid": 4242,
        "process_name": "powershell.exe",
        "evidence": {
            "command_line": ["-EncodedCommand"],
        },
        "rule_source": "/rules/process_rules.yaml",
        "rule_status": "proven",
    }

    without_provenance = dict(base)

    without_provenance.pop("rule_source")

    without_provenance.pop("rule_status")

    results = process_findings(
        [
            without_provenance,
            base,
        ]
    )

    assert len(results) == 1

    assert results[0]["rule_source"] == ("/rules/process_rules.yaml")

    assert results[0]["rule_status"] == "proven"


def test_save_report_formats_writes_csv_and_jsonl(
    tmp_path,
) -> None:
    created = save_report_formats(
        basic_report(),
        output_directory=tmp_path,
        formats=(
            "csv",
            "jsonl",
        ),
    )

    assert set(created) == {
        "csv",
        "jsonl",
    }

    csv_path = created["csv"]

    assert csv_path.suffix == ".csv"
    assert csv_path.read_text(encoding="utf-8").startswith("id,severity,title")

    jsonl_path = created["jsonl"]

    assert jsonl_path.suffix == ".jsonl"

    first_line = json.loads(jsonl_path.read_text(encoding="utf-8").splitlines()[0])

    assert first_line["type"] == "scan"
    assert first_line["schema_version"] == "1.0.0"


def test_parser_accepts_scan_format_and_delta_flags() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "scan",
            "--format",
            "jsonl",
            "--last",
            "--since",
            "2026-09-09T00:00:00+00:00",
            "--json-raw",
        ]
    )

    assert args.command == "scan"
    assert args.format == "jsonl"
    assert args.last is True
    assert args.since == "2026-09-09T00:00:00+00:00"
    assert args.json_raw is True


def test_parser_accepts_report_csv_and_jsonl() -> None:
    parser = build_parser()

    for report_format in (
        "csv",
        "jsonl",
    ):
        args = parser.parse_args(
            [
                "report",
                "--format",
                report_format,
            ]
        )

        assert args.format == report_format


def test_parser_accepts_hunting_commands() -> None:
    parser = build_parser()

    assert parser.parse_args(["history"]).command == "history"

    assert (
        parser.parse_args(
            [
                "diff",
                "sc-a",
                "sc-b",
            ]
        ).command
        == "diff"
    )

    assert parser.parse_args(["diff", "--last"]).command == "diff"

    assert parser.parse_args(["search", "powershell"]).command == "search"

    assert parser.parse_args(["tree", "INC-1"]).command == "tree"

    assert parser.parse_args(["accounts"]).command == "accounts"

    assert parser.parse_args(["stats"]).command == "stats"

    assert (
        parser.parse_args(
            [
                "watch",
                "--interval",
                "5",
                "--count",
                "3",
            ]
        ).command
        == "watch"
    )


def test_scan_command_appends_state_record_and_prints_schema_version(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(tmp_path / "data"),
    )

    monkeypatch.setattr(
        "sentinelclaw.main.run_scan",
        lambda **kwargs: basic_report(),
    )

    execute_command(build_parser().parse_args(["scan"]))

    from sentinelclaw.state.store import (
        list_records,
    )

    records = list_records()

    assert len(records) == 1

    record = records[0]

    assert record["record_id"].startswith("sc-")
    assert record["schema_version"] == "1.0.0"
    assert record["hostname"]
    assert len(record["findings"]) == 2

    output = json.loads(capsys.readouterr().out)

    assert output["schema_version"] == "1.0.0"


def test_scan_jsonl_command_output(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(tmp_path / "data"),
    )

    monkeypatch.setattr(
        "sentinelclaw.main.run_scan",
        lambda **kwargs: basic_report(),
    )

    execute_command(
        build_parser().parse_args(
            [
                "scan",
                "--format",
                "jsonl",
            ]
        )
    )

    output = capsys.readouterr().out

    lines = [line for line in output.splitlines() if line.strip()]

    assert len(lines) == 4

    first = json.loads(lines[0])

    assert first["type"] == "scan"
    assert first["schema_version"] == "1.0.0"

    kinds = [json.loads(line)["type"] for line in lines[1:]]

    assert kinds.count("finding") == 2
    assert kinds.count("incident") == 1


def test_scan_last_delta_uses_previous_record(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(tmp_path / "data"),
    )

    from sentinelclaw.state.store import (
        append_scan_record,
        record_from_report,
    )

    earlier = basic_report()

    earlier["findings"]["all"] = [
        make_finding(
            "PROC-004",
            "Encoded PowerShell",
        )
    ]

    append_scan_record(record_from_report(earlier))

    monkeypatch.setattr(
        "sentinelclaw.main.run_scan",
        lambda **kwargs: basic_report(),
    )

    execute_command(build_parser().parse_args(["scan", "--last"]))

    output = capsys.readouterr().out

    assert "SCAN DELTA" in output
    assert "New findings" in output
    assert "NET-001" in output


def test_scan_invalid_since_fails_cleanly(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(tmp_path / "data"),
    )

    monkeypatch.setattr(
        "sentinelclaw.main.run_scan",
        lambda **kwargs: basic_report(),
    )

    with pytest.raises(RuntimeError):
        execute_command(
            build_parser().parse_args(
                [
                    "scan",
                    "--since",
                    "not-a-timestamp",
                ]
            )
        )
