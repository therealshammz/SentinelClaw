"""End-to-end ``run_scan`` pipeline tests over the canned conftest fixtures.

Every collector is monkeypatched at the ``sentinelclaw.main`` module level
so the full deterministic pipeline (collectors -> detectors -> rule engine
-> finding processor -> correlation -> timeline -> risk) runs without any
host enumeration or network activity.

These tests freeze the Phase 1 upgrade behavior end to end:

* P1-7: YAML-rule findings are correlated with builtin findings.
* P1-8: the correlation time window is honored at ``run_scan`` level and
  incidents carry first_seen/last_seen bounds.
* P1-9: a malformed rule file is isolated at load time and a full scan
  still completes with the remaining valid rules.
* P1-10: Linux collectors (auth logs, persistence) are stubbed like the
  other collectors so the canned fixtures stay deterministic on any host.
"""

import sys
from datetime import datetime, timezone

from sentinelclaw.config.settings import get_settings
from sentinelclaw.detectors.process_detector import (
    analyze_processes as real_analyze_processes,
)
from sentinelclaw.engine.timeline_engine import parse_timestamp
from sentinelclaw.main import run_scan

TOP_LEVEL_KEYS = {
    "scan",
    "summary",
    "findings",
    "incidents",
    "risk",
    "timeline",
    "collector_status",
    "system",
}

RAW_KEYS = {
    "processes",
    "network",
    "windows_events",
}

RISK_LEVELS = {
    "informational",
    "low",
    "medium",
    "high",
    "critical",
}


def run_canned_scan(
    monkeypatch,
    processes,
    connections,
    windows_events,
    include_raw: bool = False,
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
        lambda: {"hostname": "E2E-TEST-HOST"},
    )

    return run_scan(
        show_progress=False,
        include_raw=include_raw,
    )


def finding_rule_ids(findings: list[dict]) -> set[str]:
    return {str(finding.get("rule_id")) for finding in findings}


def all_rule_ids(report: dict) -> set[str]:
    return finding_rule_ids(report["findings"]["all"])


def test_scan_schema_is_stable_and_raw_data_is_gated(
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

    assert set(report) == TOP_LEVEL_KEYS

    assert not (RAW_KEYS & set(report))

    assert report["scan"]["application"] == "SentinelClaw"
    assert report["scan"]["timestamp"]

    assert report["collector_status"] == {
        "process_error": None,
        "network_error": None,
        "windows_event_error": None,
        "system_info_error": None,
    }

    summary = report["summary"]

    assert summary["processes_scanned"] == len(sample_processes)
    assert summary["network_connections_scanned"] == len(sample_connections)
    assert summary["windows_events_scanned"] == len(sample_windows_events)
    assert summary["total_findings"] == len(report["findings"]["all"])
    assert summary["incidents"] == len(report["incidents"])
    assert summary["timeline_events"] == len(report["timeline"])

    raw_report = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=sample_windows_events,
        include_raw=True,
    )

    assert set(raw_report) == TOP_LEVEL_KEYS | RAW_KEYS

    assert raw_report["processes"] == sample_processes
    assert raw_report["network"] == sample_connections
    assert raw_report["windows_events"] == sample_windows_events


def test_scan_produces_known_findings_without_duplicates_and_orders_timeline(
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

    process_ids = finding_rule_ids(report["findings"]["processes"])

    assert {"PROC-001", "PROC-002", "PROC-004", "PROC-005"} <= process_ids

    process_findings = report["findings"]["processes"]

    high_risk = [finding for finding in process_findings if finding.get("rule_id") == "PROC-001"]

    assert len(high_risk) == 1
    assert high_risk[0]["pid"] == 1337

    encoded = [finding for finding in process_findings if finding.get("rule_id") == "PROC-004"]

    assert len(encoded) == 1
    assert encoded[0]["pid"] == 4242
    assert encoded[0]["process_name"] == "powershell.exe"

    office_spawn = [finding for finding in process_findings if finding.get("rule_id") == "PROC-005"]

    assert len(office_spawn) == 1
    assert office_spawn[0]["pid"] == 9001

    network_ids = finding_rule_ids(report["findings"]["network"])

    assert network_ids == {"NET-001", "NET-002"}

    monitored = [
        finding for finding in report["findings"]["network"] if finding.get("rule_id") == "NET-001"
    ]

    assert len(monitored) == 1
    assert monitored[0]["pid"] == 4242
    assert monitored[0]["remote_ip"] == "8.8.8.8"
    assert monitored[0]["remote_port"] == 4444

    public = [
        finding for finding in report["findings"]["network"] if finding.get("rule_id") == "NET-002"
    ]

    assert len(public) == 1
    assert public[0]["remote_ip"] == "8.8.8.8"

    windows_ids = finding_rule_ids(report["findings"]["windows_events"])

    assert {"WIN-1102", "WIN-4720"} <= windows_ids

    rule_ids = all_rule_ids(report)

    assert "PROC-YAML-001" in rule_ids

    # PROC-YAML-003 (office spawn) is OS-gated to Windows (P1-10) and
    # therefore only loads and fires on Windows hosts.
    if sys.platform.startswith(
        "win"
    ):
        assert "PROC-YAML-003" in rule_ids
    else:
        assert "PROC-YAML-003" not in rule_ids

    assert "WIN-001" not in rule_ids
    assert "LOG-001" not in rule_ids

    fingerprints = [
        (
            finding.get("rule_id"),
            finding.get("pid"),
            finding.get("remote_ip"),
            finding.get("remote_port"),
        )
        for finding in report["findings"]["all"]
    ]

    assert len(fingerprints) == len(set(fingerprints))

    timeline = report["timeline"]

    assert timeline
    assert len(timeline) == report["summary"]["timeline_events"]

    previous: datetime | None = None

    for event in timeline:
        parsed = parse_timestamp(event.get("timestamp"))

        sort_value = parsed if parsed is not None else datetime.max.replace(tzinfo=timezone.utc)

        if previous is not None:
            assert previous <= sort_value

        previous = sort_value


def test_scan_correlates_yaml_findings_with_builtin_findings(
    monkeypatch,
    rules_dir_tmp,
    sample_processes,
    sample_connections,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(rules_dir_tmp),
    )

    report = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=[],
    )

    assert report["summary"]["rules_loaded"] == 2

    rule_ids = all_rule_ids(report)

    assert "PROC-004" in rule_ids
    assert "PROC-FIX-001" in rule_ids

    assert "NET-FIX-001" not in rule_ids
    joined = [
        incident
        for incident in report["incidents"]
        if str(incident.get("incident_id", "")).startswith("INC-PROC-")
        and {"PROC-004", "PROC-FIX-001"} <= set(incident.get("related_rule_ids", []))
    ]

    assert len(joined) == 1

    incident = joined[0]

    assert incident["related_pids"] == [4242]
    assert incident["severity"] == "high"

    member_sources = {
        finding.get("rule_id"): finding.get("source") for finding in incident["findings"]
    }

    assert member_sources["PROC-004"] == "builtin"
    assert member_sources["PROC-FIX-001"] == "yaml"


def test_scan_respects_correlation_window(
    monkeypatch,
) -> None:
    def spread_findings(processes):
        return [
            {
                "rule_id": "PROC-001",
                "title": "First high-risk finding",
                "description": "Synthetic windowed finding.",
                "severity": "high",
                "pid": 4242,
                "process_name": "powershell.exe",
                "timestamp": "2026-09-08T09:00:00+00:00",
            },
            {
                "rule_id": "PROC-004",
                "title": "Second high-risk finding",
                "description": "Synthetic windowed finding.",
                "severity": "high",
                "pid": 4242,
                "process_name": "powershell.exe",
                "timestamp": "2026-09-10T09:00:00+00:00",
            },
        ]

    monkeypatch.setattr(
        "sentinelclaw.main.analyze_processes",
        spread_findings,
    )

    default_window = run_canned_scan(
        monkeypatch,
        processes=[],
        connections=[],
        windows_events=[],
    )

    assert default_window["summary"]["process_findings"] == 2
    assert default_window["incidents"] == []

    assert get_settings().correlation_window_hours == 24

    monkeypatch.setenv(
        "SENTINELCLAW_CORRELATION_WINDOW_HOURS",
        "72",
    )

    assert get_settings().correlation_window_hours == 72

    wide_window = run_canned_scan(
        monkeypatch,
        processes=[],
        connections=[],
        windows_events=[],
    )

    incidents = wide_window["incidents"]

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["incident_id"].startswith("INC-PROC-")
    assert incident["related_pids"] == [4242]
    assert incident["first_seen"] == ("2026-09-08T09:00:00+00:00")
    assert incident["last_seen"] == ("2026-09-10T09:00:00+00:00")


def test_scan_survives_malformed_rule_files_and_keeps_valid_rules(
    monkeypatch,
    tmp_path,
    sample_processes,
    sample_connections,
) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "broken.yaml").write_text(
        ": not: [valid: [yaml",
        encoding="utf-8",
    )

    (rule_directory / "valid.yaml").write_text(
        "rules:\n"
        "  - id: PROC-E2E-001\n"
        "    title: End-to-end encoded PowerShell rule\n"
        "    description: Synthetic rule for end-to-end tests.\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    enabled: true\n"
        "    match: all\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value:\n"
        "          - powershell.exe\n"
        "          - pwsh.exe\n"
        "      - field: command_line\n"
        "        operator: contains\n"
        "        value:\n"
        '          - "-encodedcommand"\n'
        '          - "-enc"\n',
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(rule_directory),
    )

    report = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=[],
    )

    assert report["summary"]["rules_loaded"] == 1

    rule_ids = all_rule_ids(report)

    assert "PROC-004" in rule_ids
    assert "PROC-E2E-001" in rule_ids

    encoded = [
        finding
        for finding in report["findings"]["processes"]
        if finding.get("rule_id") == "PROC-E2E-001"
    ]

    assert len(encoded) == 1
    assert encoded[0]["pid"] == 4242
    assert encoded[0]["severity"] == "high"


def test_scan_deduplicates_detections_and_is_deterministic(
    monkeypatch,
    sample_processes,
    sample_connections,
    sample_windows_events,
) -> None:
    def duplicated_processes(processes):
        return real_analyze_processes(processes) + real_analyze_processes(processes)

    monkeypatch.setattr(
        "sentinelclaw.main.analyze_processes",
        duplicated_processes,
    )

    first = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=sample_windows_events,
    )

    second = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=sample_windows_events,
    )

    rule_ids = all_rule_ids(first)

    assert rule_ids == all_rule_ids(second)
    assert first["findings"] == second["findings"]
    assert first["incidents"] == second["incidents"]
    assert first["summary"] == second["summary"]
    assert first["risk"] == second["risk"]

    assert (
        len(
            [
                finding
                for finding in first["findings"]["processes"]
                if finding.get("rule_id") == "PROC-001"
            ]
        )
        == 1
    )

    assert (
        len(
            [
                finding
                for finding in first["findings"]["processes"]
                if finding.get("rule_id") == "PROC-004"
            ]
        )
        == 1
    )


def test_scan_risk_ranks_malicious_fixtures_above_benign(
    monkeypatch,
    sample_processes,
    sample_connections,
    sample_windows_events,
) -> None:
    benign_processes = [
        {
            "pid": 500,
            "ppid": 4,
            "name": "svchost.exe",
            "parent_name": "services.exe",
            "username": "NT AUTHORITY\\SYSTEM",
            "executable": (r"C:\Windows\System32\svchost.exe"),
            "status": "running",
            "memory_percent": 0.4,
            "command_line": [
                "C:\\Windows\\System32\\svchost.exe",
                "-k",
                "netsvcs",
            ],
            "create_time": "2026-09-08T09:00:00+00:00",
        }
    ]

    benign_connections = [
        {
            "local_address": {
                "ip": "192.168.1.10",
                "port": 49153,
            },
            "remote_address": {
                "ip": "10.0.0.5",
                "port": 443,
            },
            "status": "ESTABLISHED",
            "pid": 500,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_STREAM",
        }
    ]

    benign = run_canned_scan(
        monkeypatch,
        processes=benign_processes,
        connections=benign_connections,
        windows_events=[],
    )

    assert benign["summary"]["total_findings"] == 0
    assert benign["incidents"] == []
    assert benign["risk"] == {
        "score": 0,
        "level": "informational",
        "finding_risk": {
            "score": 0,
            "level": "informational",
        },
        "incident_risk": {
            "score": 0,
            "level": "informational",
        },
    }

    malicious = run_canned_scan(
        monkeypatch,
        processes=sample_processes,
        connections=sample_connections,
        windows_events=sample_windows_events,
    )

    risk = malicious["risk"]

    assert set(risk) == {
        "score",
        "level",
        "finding_risk",
        "incident_risk",
    }

    assert 0 <= risk["score"] <= 100
    assert risk["level"] in RISK_LEVELS
    assert risk["finding_risk"]["level"] in RISK_LEVELS
    assert risk["incident_risk"]["level"] in RISK_LEVELS

    assert risk["score"] > benign["risk"]["score"]
    # Windows aggregates a few extra findings (user-writable path
    # heuristics), pushing the level to critical; both are elevated.
    assert risk["level"] in ("high", "critical")
