"""P1-10 Linux parity acceptance tests.

These tests exercise the full ``run_scan`` pipeline with every collector
monkeypatched to canned Linux fixtures, plus focused detector/collector
unit tests. All fixtures are deterministic and no host enumeration or
network activity occurs.
"""

import sys

import pytest

from sentinelclaw.config.settings import get_settings
from sentinelclaw.detectors.auth_detector import analyze_auth_events
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.persistence_detector import (
    analyze_persistence_records,
)
from sentinelclaw.detectors.process_detector import analyze_processes
from sentinelclaw.engine.rule_engine import (
    load_rule_file,
    rule_matches_current_os,
    validate_rule,
)
from sentinelclaw.main import run_scan
from sentinelclaw.tools.auth_log_analyzer import parse_auth_text
from sentinelclaw.tools.process_analyzer import probe_deleted_executable

AUTH_LOG_TEXT = """\
Sep  8 09:10:00 host sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
Sep  8 09:10:01 host sshd[1235]: Failed password for admin from 10.0.0.5 port 22 ssh2
Sep  8 09:10:02 host sshd[1236]: Failed password for analyst from 10.0.0.6 port 22 ssh2
Sep  8 09:10:03 host sshd[1237]: Failed password for root from 10.0.0.6 port 22 ssh2
Sep  8 09:10:04 host sshd[1238]: Failed password for operator from 10.0.0.7 port 22 ssh2
Sep  8 09:10:05 host sshd[1239]: Failed password for root from 10.0.0.7 port 22 ssh2
Sep  8 09:11:00 host sudo[1240]: pam_unix(sudo:auth): authentication failure; logname=analyst uid=1000 euid=0 tty=pts/0 ruser=analyst rhost=localhost user=root
Sep  8 09:11:05 host sshd[1241]: Accepted publickey for root from 10.0.0.8 port 22 ssh2
Sep  8 09:12:00 host useradd[1242]: new user: name=backup_usr, UID=1001
"""


def run_scan_with(
    monkeypatch,
    processes,
    connections,
    windows_events,
    auth_events,
    persistence_records,
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
        lambda: auth_events,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_persistence_records",
        lambda: persistence_records,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_system_info",
        lambda: {"hostname": "LINUX-PARITY-TEST"},
    )

    return run_scan(
        show_progress=False,
        include_raw=False,
    )


def rule_ids(findings: list[dict]) -> set[str]:
    return {str(finding.get("rule_id")) for finding in findings}


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Linux parity fixtures require POSIX-style process records",
)
def test_linux_process_fixture_yields_medium_plus_findings(
    monkeypatch,
    sample_linux_processes,
) -> None:
    report = run_scan_with(
        monkeypatch,
        processes=sample_linux_processes,
        connections=[],
        windows_events=[],
        auth_events=[],
        persistence_records=[],
    )

    process_ids = rule_ids(report["findings"]["processes"])

    assert "LIN-PROC-001" in process_ids
    assert "LIN-PROC-002" in process_ids
    assert "LIN-PROC-003" in process_ids
    assert "LIN-PROC-004" in process_ids
    assert "LIN-PROC-005" in process_ids
    assert "DEL-001" in process_ids

    process_findings = report["findings"]["processes"]

    for finding in process_findings:
        assert finding.get("severity") in {
            "medium",
            "high",
            "critical",
        }

    download_exec = [
        finding for finding in process_findings if finding.get("rule_id") == "LIN-PROC-001"
    ]

    assert len(download_exec) == 1
    assert download_exec[0]["pid"] == 31337

    deleted = [finding for finding in process_findings if finding.get("rule_id") == "DEL-001"]

    assert len(deleted) == 1
    assert deleted[0]["pid"] == 31340

    all_ids = rule_ids(report["findings"]["all"])

    # Linux YAML rules fire alongside the builtin detectors.
    assert "LINPROC-YAML-001" in all_ids
    assert "LINPROC-YAML-002" in all_ids


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Linux parity fixtures require POSIX-style process records",
)
def test_windows_only_rules_do_not_fire_on_linux_fixtures(
    monkeypatch,
    sample_linux_processes,
) -> None:
    report = run_scan_with(
        monkeypatch,
        processes=sample_linux_processes,
        connections=[],
        windows_events=[],
        auth_events=[],
        persistence_records=[],
    )

    process_ids = rule_ids(report["findings"]["processes"])

    assert "PROC-001" not in process_ids
    assert "PROC-004" not in process_ids
    assert "PROC-010" not in process_ids

    all_ids = rule_ids(report["findings"]["all"])

    # Windows-only rules are not loaded on Linux (P1-10 OS gating).
    assert "PROC-YAML-003" not in all_ids
    assert "PROC-YAML-004" not in all_ids
    assert "WIN-YAML-001" not in all_ids


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Linux auth fixtures require POSIX-style event parsing",
)
def test_auth_log_fixture_yields_auth_findings(
    monkeypatch,
) -> None:
    auth_events = parse_auth_text(
        AUTH_LOG_TEXT,
        source="auth.log",
    )

    report = run_scan_with(
        monkeypatch,
        processes=[],
        connections=[],
        windows_events=[],
        auth_events=auth_events,
        persistence_records=[],
    )

    auth_ids = rule_ids(report["findings"]["auth"])

    assert "AUTH-001" in auth_ids
    assert "AUTH-002" in auth_ids
    assert "AUTH-003" in auth_ids
    assert "AUTH-004" in auth_ids

    all_ids = rule_ids(report["findings"]["all"])

    assert "AUTH-YAML-001" in all_ids
    assert "AUTH-YAML-002" in all_ids
    assert "AUTH-YAML-003" in all_ids

    auth_findings = report["findings"]["auth"]

    aggregate = [finding for finding in auth_findings if finding.get("rule_id") == "AUTH-001"]

    assert len(aggregate) == 1
    assert aggregate[0]["evidence"]["count"] == 6


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Linux persistence fixtures require POSIX-style records",
)
def test_persistence_fixture_yields_pers_findings(
    monkeypatch,
    sample_persistence_records,
) -> None:
    report = run_scan_with(
        monkeypatch,
        processes=[],
        connections=[],
        windows_events=[],
        auth_events=[],
        persistence_records=sample_persistence_records,
    )

    pers_ids = rule_ids(report["findings"]["persistence"])

    assert "PERS-001" in pers_ids
    assert "PERS-002" in pers_ids
    assert "PERS-003" in pers_ids
    assert "PERS-004" in pers_ids
    assert "PERS-005" in pers_ids

    all_ids = rule_ids(report["findings"]["all"])

    assert "LINPERS-YAML-001" in all_ids
    assert "LINPERS-YAML-002" in all_ids
    assert "LINPERS-YAML-003" in all_ids
    assert "LINPERS-YAML-004" in all_ids
    assert "LINPERS-YAML-005" in all_ids


def test_deleted_binary_fixture_yields_del_001() -> None:
    deleted_process = {
        "pid": 424242,
        "ppid": 1,
        "name": "bash",
        "parent_name": "init",
        "username": "analyst",
        "executable": "/tmp/evil.sh",
        "exe_deleted": True,
        "status": "running",
        "memory_percent": 0.1,
        "command_line": ["/tmp/evil.sh"],
        "create_time": "2026-09-08T10:00:00+00:00",
    }

    findings = analyze_processes([deleted_process])

    deleted = [finding for finding in findings if finding.get("rule_id") == "DEL-001"]

    assert len(deleted) == 1
    assert deleted[0]["pid"] == 424242
    assert deleted[0]["mitre"]["technique"] == ("T1070.004")


def test_probe_deleted_executable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "sentinelclaw.tools.process_analyzer.os.readlink",
        lambda _path: "/usr/bin/foo (deleted)",
    )

    assert probe_deleted_executable(
        9999,
        "/usr/bin/foo",
    )

    monkeypatch.setattr(
        "sentinelclaw.tools.process_analyzer.os.readlink",
        lambda _path: "/usr/bin/foo",
    )

    assert not probe_deleted_executable(
        9999,
        "/usr/bin/foo",
    )

    monkeypatch.setattr(
        "sentinelclaw.tools.process_analyzer.os.readlink",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError),
    )

    assert probe_deleted_executable(
        9999,
        "/usr/bin/foo",
    )


def test_auth_parser_extracts_structured_events() -> None:
    events = parse_auth_text(
        AUTH_LOG_TEXT,
        source="auth.log",
    )

    event_types = {event.get("event_type") for event in events}

    assert event_types == {
        "failed_password",
        "sudo_failure",
        "accepted_publickey",
        "new_user",
    }

    failed = [event for event in events if event.get("event_type") == "failed_password"]

    assert len(failed) == 6
    assert all(event.get("username") for event in failed)
    assert all(event.get("ip") for event in failed)

    sudo_failures = [event for event in events if event.get("event_type") == "sudo_failure"]

    assert len(sudo_failures) == 1


def test_auth_detector_respects_logon_failure_threshold(
    monkeypatch,
) -> None:
    events = parse_auth_text(
        AUTH_LOG_TEXT,
        source="auth.log",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_LOGON_FAILURE_THRESHOLD",
        "100",
    )

    assert get_settings().logon_failure_threshold == 100

    findings = analyze_auth_events(events)

    rule_ids = {finding.get("rule_id") for finding in findings}

    assert "AUTH-001" not in rule_ids
    assert "AUTH-003" in rule_ids


def test_persistence_detector_over_canned_records(
    sample_persistence_records,
) -> None:
    findings = analyze_persistence_records(sample_persistence_records)

    ids = rule_ids(findings)

    assert "PERS-001" in ids
    assert "PERS-002" in ids
    assert "PERS-003" in ids
    assert "PERS-004" in ids
    assert "PERS-005" in ids

    download_exec = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PERS-001" and finding.get("severity") == "high"
    ]

    assert len(download_exec) == 1


def test_network_detector_flags_listening_non_standard_port() -> None:
    connections = [
        {
            "local_address": {
                "ip": "0.0.0.0",
                "port": 31337,
            },
            "remote_address": None,
            "status": "LISTEN",
            "pid": 1234,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_STREAM",
        },
        {
            "local_address": {
                "ip": "127.0.0.1",
                "port": 5353,
            },
            "remote_address": None,
            "status": "LISTEN",
            "pid": 5678,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_DGRAM",
        },
    ]

    findings = analyze_network(connections)

    listen = [finding for finding in findings if finding.get("rule_id") == "NET-LISTEN-001"]

    assert len(listen) == 1
    assert listen[0]["local_port"] == 31337
    assert listen[0]["pid"] == 1234


def test_rule_os_gating_load_and_validation(
    tmp_path,
) -> None:
    rule_file = tmp_path / "os_gated.yaml"

    rule_file.write_text(
        "rules:\n"
        "  - id: OS-WIN-001\n"
        "    title: Windows only\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    os:\n"
        "      - windows\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: cmd.exe\n"
        "  - id: OS-LIN-001\n"
        "    title: Linux only\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    os:\n"
        "      - linux\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: bash\n",
        encoding="utf-8",
    )

    rules = load_rule_file(rule_file)

    loaded_ids = {rule.get("id") for rule in rules}

    on_linux = sys.platform.startswith("linux")

    assert "OS-LIN-001" in loaded_ids

    if on_linux:
        assert "OS-WIN-001" not in loaded_ids
    else:
        assert "OS-WIN-001" in loaded_ids

    ok, reason = validate_rule(
        {
            "id": "OS-BAD-001",
            "title": "Bad os",
            "description": "x",
            "category": "process",
            "severity": "high",
            "confidence": "high",
            "os": ["solaris"],
            "conditions": [
                {
                    "field": "name",
                    "operator": "equals",
                    "value": "bash",
                }
            ],
        }
    )

    assert not ok
    assert "invalid os" in reason


def test_rule_matches_current_os_defaults_to_all() -> None:
    assert rule_matches_current_os({})

    assert rule_matches_current_os({"os": ["all"]})

    assert not rule_matches_current_os({"os": ["windows"]})
