import json
import subprocess
import sys

from sentinelclaw.detectors.log_detector import analyze_log_events
from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.models.findings import calculate_risk_score
from sentinelclaw.tools.log_analyzer import analyze_log_file

FAILED_LOGIN_LINES = [
    "2026-09-08T09:10:00+00:00 sshd[1234]: "
    "Failed login for root from 10.0.0.5 port 22 ssh2",
    "2026-09-08T09:10:05+00:00 sshd[1234]: "
    "Failed password for admin from 10.0.0.5 port 22 ssh2",
    "2026-09-08T09:10:10+00:00 sshd[1234]: "
    "Failed login for root from 10.0.0.6 port 22 ssh2",
    "2026-09-08T09:10:15+00:00 sshd[1234]: "
    "Failed password for analyst from 10.0.0.6 port 22 ssh2",
    "2026-09-08T09:10:20+00:00 sshd[1234]: "
    "Failed login for root from 10.0.0.7 port 22 ssh2",
    "2026-09-08T09:10:25+00:00 sshd[1234]: "
    "Failed password for operator from 10.0.0.7 port 22 ssh2",
]

REVERSE_SHELL_LINE = (
    "2026-09-08T09:15:00+00:00 sshd[1234]: "
    "reverse shell connection from 10.0.0.9 port 4444"
)

CLEAN_LINE = (
    "2026-09-08T09:16:00+00:00 sshd[1234]: "
    "Accepted publickey for analyst"
)


def write_canned_log(tmp_path) -> str:
    lines = FAILED_LOGIN_LINES + [REVERSE_SHELL_LINE, CLEAN_LINE]

    log_path = tmp_path / "canned.log"

    log_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return str(log_path)


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelclaw.main",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_analyze_log_file_preserves_raw_contract(tmp_path) -> None:
    log_data = analyze_log_file(
        write_canned_log(tmp_path)
    )

    assert "error" not in log_data
    assert log_data["total_lines"] == 8
    assert log_data["suspicious_matches"] == 7
    assert len(log_data["matches"]) == 7

    match = log_data["matches"][0]

    assert "line_number" in match
    assert "matched_keywords" in match
    assert "text" in match

    assert "events" in log_data
    assert len(log_data["events"]) == 7


def test_analyze_log_file_builds_structured_events(tmp_path) -> None:
    log_data = analyze_log_file(
        write_canned_log(tmp_path)
    )

    events = log_data["events"]

    auth_events = [
        event
        for event in events
        if event.get("event_class") == "authentication"
    ]

    assert len(auth_events) == 6

    failed = auth_events[0]

    assert failed["timestamp"] == "2026-09-08T09:10:00+00:00"
    assert failed["source"] == "ssh"
    assert failed["event_type"] == "failed_login"
    assert failed["event_class"] == "authentication"
    assert failed["severity_hint"] == "low"
    assert failed["username"] == "root"
    assert failed["ip"] == "10.0.0.5"
    assert "failed login" in failed["matched_keywords"]

    reverse_shell = [
        event
        for event in events
        if event.get("event_class") == "command_and_control"
    ]

    assert len(reverse_shell) == 1
    assert reverse_shell[0]["severity_hint"] == "high"
    assert reverse_shell[0]["ip"] == "10.0.0.9"

    clean_line_events = [
        event
        for event in events
        if "Accepted publickey" in event.get("message", "")
    ]

    assert clean_line_events == []


def test_log_detector_failed_logon_threshold(tmp_path) -> None:
    log_data = analyze_log_file(
        write_canned_log(tmp_path)
    )

    findings = analyze_log_events(
        log_data["events"]
    )

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "LOG-001" in rule_ids

    logon = next(
        finding
        for finding in findings
        if finding["rule_id"] == "LOG-001"
    )

    assert logon["severity"] == "medium"
    assert logon["category"] == "log"
    assert logon["evidence"]["count"] == 6
    assert "10.0.0.5" in logon["evidence"]["ips"]
    assert "root" in logon["evidence"]["usernames"]
    assert logon["mitre"]["tactic"] == "Credential Access"


def test_log_detector_below_threshold_no_logon_finding(tmp_path) -> None:
    log_path = tmp_path / "quiet.log"

    log_path.write_text(
        "\n".join(FAILED_LOGIN_LINES[:2]) + "\n",
        encoding="utf-8",
    )

    log_data = analyze_log_file(
        str(log_path)
    )

    findings = analyze_log_events(
        log_data["events"]
    )

    assert all(
        finding["rule_id"] != "LOG-001"
        for finding in findings
    )


def test_log_detector_reverse_shell_finding(tmp_path) -> None:
    log_data = analyze_log_file(
        write_canned_log(tmp_path)
    )

    findings = analyze_log_events(
        log_data["events"]
    )

    reverse_shell = [
        finding
        for finding in findings
        if finding["rule_id"] == "LOG-002"
    ]

    assert len(reverse_shell) == 1
    assert reverse_shell[0]["severity"] == "high"
    assert reverse_shell[0]["mitre"]["tactic"] == (
        "Command and Control"
    )


def test_log_pipeline_produces_findings_and_incident(tmp_path) -> None:
    log_data = analyze_log_file(
        write_canned_log(tmp_path)
    )

    raw_findings = analyze_log_events(
        log_data["events"]
    )

    findings = process_findings(
        raw_findings
    )

    incidents = correlate_findings(
        findings
    )

    risk = calculate_risk_score(
        findings
    )

    assert len(findings) >= 2

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "LOG-001" in rule_ids
    assert "LOG-002" in rule_ids

    assert len(incidents) >= 1

    assert any(
        str(incident.get("incident_id", "")).startswith(
            "INC-MITRE-"
        )
        for incident in incidents
    )

    assert risk["score"] >= 10


def test_logs_cli_prints_finding_and_incident_summary(tmp_path) -> None:
    result = run_cli(
        "logs",
        write_canned_log(tmp_path),
    )

    assert result.returncode == 0
    assert "SENTINELCLAW LOG ANALYSIS" in result.stdout
    assert "Multiple failed authentication" in result.stdout
    assert "INC-MITRE" in result.stdout


def test_logs_cli_json_flag_emits_pipeline_report(tmp_path) -> None:
    result = run_cli(
        "logs",
        "--json",
        write_canned_log(tmp_path),
    )

    assert result.returncode == 0

    report = json.loads(
        result.stdout
    )

    assert report["analysis"]["type"] == "log"
    assert len(report["findings"]) >= 2
    assert len(report["incidents"]) >= 1
    assert report["log"]["total_lines"] == 8
