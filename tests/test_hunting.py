"""Stateful hunting command tests (P3-17, P3-19).

Every command reads from the scan-state store, so these tests build a
canned store with ``append_scan_record`` and drive the ``cmd_*``
functions with capsys. No live collection happens; ``watch`` uses an
injected fake scan callable.
"""

from argparse import Namespace
from pathlib import Path

import pytest

from sentinelclaw.state.analytics import (
    compare_records,
    incident_process_tree_lines,
    search_records,
    summarize_account_events,
)
from sentinelclaw.state.hunting import (
    cmd_accounts,
    cmd_diff,
    cmd_history,
    cmd_search,
    cmd_stats,
    cmd_tree,
    cmd_watch,
)
from sentinelclaw.state.store import (
    append_scan_record,
    list_records,
)


@pytest.fixture
def data_dir(
    monkeypatch,
    tmp_path,
) -> Path:
    directory = tmp_path / "data"
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(directory),
    )
    return directory


def make_finding(
    rule_id: str,
    title: str,
    severity: str = "medium",
    category: str = "process",
    pid: int | None = None,
    evidence: dict | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "pid": pid,
        "evidence": evidence or {},
    }


def make_record(
    record_id: str,
    timestamp: str,
    findings: list[dict] | None = None,
    incidents: list[dict] | None = None,
    windows_events: list[dict] | None = None,
    hostname: str = "canned-host",
) -> dict:
    findings = findings or []
    record = {
        "record_id": record_id,
        "schema_version": "1.0.0",
        "hostname": hostname,
        "timestamp": timestamp,
        "scan": {
            "application": "SentinelClaw",
            "timestamp": timestamp,
        },
        "summary": {
            "total_findings": len(findings),
        },
        "risk": {
            "score": 40,
            "level": "high",
        },
        "findings": findings,
        "incidents": incidents or [],
    }

    if windows_events:
        record["windows_events"] = windows_events

    return record


def populate_canned_store() -> None:
    append_scan_record(
        make_record(
            "sc-old",
            "2026-09-08T10:00:00+00:00",
            findings=[
                make_finding(
                    "PROC-004",
                    "Encoded PowerShell",
                ),
                make_finding(
                    "PROC-001",
                    "Suspicious credential tool",
                ),
            ],
            incidents=[
                {
                    "incident_id": "INC-PROC-001",
                    "title": "Suspicious process group",
                    "severity": "high",
                    "findings": [],
                }
            ],
            windows_events=[
                {
                    "event_id": 4625,
                    "event_name": "Failed logon",
                    "message_data": ("LogonType 3 | S-1-5-18 | WORKSTATION\\analyst"),
                },
                {
                    "event_id": 4720,
                    "event_name": "User account created",
                    "message_data": "backup_usr | WORKSTATION",
                },
            ],
        )
    )

    append_scan_record(
        make_record(
            "sc-new",
            "2026-09-09T10:00:00+00:00",
            findings=[
                make_finding(
                    "PROC-004",
                    "Encoded PowerShell",
                ),
                make_finding(
                    "NET-001",
                    "Monitored reverse-shell port",
                    severity="high",
                    category="network",
                    pid=4242,
                    evidence={
                        "remote_ip": "8.8.8.8",
                        "remote_port": 4444,
                    },
                ),
            ],
            incidents=[
                {
                    "incident_id": "INC-NET-002",
                    "title": "Network beaconing",
                    "severity": "high",
                    "findings": [],
                }
            ],
            windows_events=[
                {
                    "event_id": 4624,
                    "event_name": "Successful logon",
                    "message_data": ("Account Name: ANALYST\\svc_delta"),
                }
            ],
        )
    )


def test_history_lists_records(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_history()

    output = capsys.readouterr().out

    assert "SCAN HISTORY" in output
    assert "RECORD ID" in output
    assert "sc-old" in output
    assert "sc-new" in output
    assert "canned-host" in output
    assert "Records: 2" in output


def test_history_empty_store_prints_hint(
    data_dir,
    capsys,
) -> None:
    cmd_history()

    output = capsys.readouterr().out

    assert "SCAN HISTORY" in output
    assert "no scan records yet" in output


def test_compare_records_reports_new_and_closed() -> None:
    baseline = make_record(
        "sc-old",
        "2026-09-08T10:00:00+00:00",
        findings=[
            make_finding("A", "Alpha"),
            make_finding("B", "Bravo"),
        ],
    )

    target = make_record(
        "sc-new",
        "2026-09-09T10:00:00+00:00",
        findings=[
            make_finding("A", "Alpha"),
            make_finding("C", "Charlie"),
        ],
    )

    comparison = compare_records(
        baseline,
        target,
    )

    new_ids = {finding["rule_id"] for finding in comparison["new"]}

    closed_ids = {finding["rule_id"] for finding in comparison["closed"]}

    assert new_ids == {"C"}
    assert closed_ids == {"B"}

    assert comparison["new_count"] == 1
    assert comparison["closed_count"] == 1
    assert comparison["baseline_findings"] == 2
    assert comparison["target_findings"] == 2


def test_cmd_diff_last_prints_delta(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_diff(
        Namespace(
            id1=None,
            id2=None,
            last=True,
        )
    )

    output = capsys.readouterr().out

    assert "SCAN DELTA" in output
    assert "New findings" in output
    assert "Closed findings" in output

    new_section = output.split("Closed findings")[0]

    assert "Monitored reverse-shell port" in new_section
    assert "Suspicious credential tool" not in new_section


def test_cmd_diff_by_ids(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_diff(
        Namespace(
            id1="sc-old",
            id2="sc-new",
            last=False,
        )
    )

    output = capsys.readouterr().out

    assert "SCAN DELTA" in output
    assert "sc-old -> sc-new" in output
    assert "Monitored reverse-shell port" in output
    assert "Suspicious credential tool" in output


def test_search_records_case_insensitive() -> None:
    records = [
        make_record(
            "sc-old",
            "2026-09-08T10:00:00+00:00",
            findings=[
                make_finding(
                    "PROC-004",
                    "Encoded PowerShell",
                )
            ],
        )
    ]

    matches = search_records(
        records,
        "powershell",
    )

    assert len(matches) == 1
    assert matches[0]["kind"] == "finding"
    assert matches[0]["finding_id"].startswith("F-")
    assert matches[0]["record_id"] == "sc-old"


def test_cmd_search_matches_incidents(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_search(
        Namespace(
            keyword="beaconing",
            state=None,
        )
    )

    output = capsys.readouterr().out

    assert "SEARCH" in output
    assert "incident" in output
    assert "INC-NET-002" in output


def test_cmd_search_restricted_to_state(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_search(
        Namespace(
            keyword="reverse-shell",
            state="sc-new",
        )
    )

    output = capsys.readouterr().out

    assert "Record : sc-new" in output
    assert "sc-old" not in output


def test_cmd_search_no_matches(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_search(
        Namespace(
            keyword="nonexistent-term",
            state=None,
        )
    )

    output = capsys.readouterr().out

    assert "(no matches)" in output


def test_accounts_summary() -> None:
    events = [
        {
            "event_id": 4625,
            "message_data": "LogonType 3 | S-1-5-18 | WORKSTATION\\analyst",
        },
        {
            "event_id": 4625,
            "message_data": "Account Name: DOMAIN\\svc_backup",
        },
        {
            "event_id": 4624,
            "message_data": "Account Name: DOMAIN\\analyst",
        },
        {
            "event_id": 4720,
            "message_data": "new_user | WORKSTATION",
        },
    ]

    summary = summarize_account_events(events)

    assert summary["failed_logons"]["analyst"] == 1
    assert summary["failed_logons"]["svc_backup"] == 1
    assert summary["successful_logons"]["analyst"] == 1
    assert summary["account_creations"]["new_user"] == 1


def test_cmd_accounts(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_accounts()

    output = capsys.readouterr().out

    assert "ACCOUNTS" in output
    assert "Failed logons by account" in output
    assert "analyst" in output
    assert "svc_delta" in output
    assert "backup_usr" in output


def test_incident_process_tree_lines() -> None:
    member_a = make_finding(
        "A",
        "Child finding",
        pid=4242,
        evidence={
            "ppid": 500,
            "parent_name": "services.exe",
        },
    )

    member_a["process_name"] = "powershell.exe"

    member_b = make_finding(
        "B",
        "Parent finding",
        pid=500,
        evidence={
            "ppid": 4,
        },
    )

    member_b["process_name"] = "services.exe"

    incident = {
        "incident_id": "INC-PROC-001",
        "title": "Suspicious process tree",
        "severity": "high",
        "findings": [
            member_a,
            member_b,
        ],
    }

    lines = incident_process_tree_lines(incident)

    joined = "\n".join(lines)

    assert "[Incident INC-PROC-001]" in joined
    assert "services.exe (pid=500)" in joined
    assert "powershell.exe (pid=4242)" in joined


def test_tree_renders_member_processes(
    data_dir,
    capsys,
) -> None:
    member = make_finding(
        "NET-001",
        "Monitored reverse-shell port",
        pid=4242,
        evidence={
            "ppid": 500,
            "parent_name": "services.exe",
        },
    )

    append_scan_record(
        make_record(
            "sc-tree",
            "2026-09-09T10:00:00+00:00",
            findings=[member],
            incidents=[
                {
                    "incident_id": "INC-PROC-001",
                    "title": "Suspicious process tree",
                    "severity": "high",
                    "findings": [member],
                }
            ],
        )
    )

    cmd_tree(Namespace(incident_id="INC-PROC-001"))

    output = capsys.readouterr().out

    assert "[Incident INC-PROC-001]" in output
    assert "pid=4242" in output


def test_tree_unknown_incident_fails_cleanly(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    with pytest.raises(SystemExit):
        cmd_tree(Namespace(incident_id="INC-MISSING"))

    assert "Incident not found" in capsys.readouterr().err


def test_cmd_stats(
    data_dir,
    capsys,
) -> None:
    populate_canned_store()

    cmd_stats()

    output = capsys.readouterr().out

    assert "STATS" in output
    assert "EVENT ID FREQUENCY" in output
    assert "4625" in output
    assert "Failed logon" in output
    assert "FINDING COUNTS" in output
    assert "FINDING COUNTS BY CATEGORY" in output


def test_watch_runs_bounded_cycles_with_fake_scan(
    data_dir,
    capsys,
) -> None:
    def fake_scan() -> dict:
        return {
            "scan": {
                "application": "SentinelClaw",
                "timestamp": "2026-09-09T12:00:00+00:00",
            },
            "summary": {},
            "risk": {},
            "findings": [],
            "incidents": [],
        }

    cmd_watch(
        Namespace(
            interval=0,
            count=2,
        ),
        scan_fn=fake_scan,
    )

    output = capsys.readouterr().out

    assert "[watch] cycle 1" in output
    assert "[watch] cycle 2" in output
    assert "first scan recorded" in output
    assert "findings unchanged" in output

    records = list_records()

    assert len(records) == 2

    for record in records:
        assert record["record_id"].startswith("sc-")


def test_watch_scan_failure_exits_cleanly(
    data_dir,
    capsys,
) -> None:
    def broken_scan() -> dict:
        raise RuntimeError("boom")

    with pytest.raises(SystemExit):
        cmd_watch(
            Namespace(
                interval=0,
                count=1,
            ),
            scan_fn=broken_scan,
        )

    assert "scan failed: boom" in capsys.readouterr().err


def test_watch_keyboard_interrupt_prints_message(
    data_dir,
    capsys,
    monkeypatch,
) -> None:
    calls = {"n": 0}

    def fake_scan() -> dict:
        calls["n"] += 1

        if calls["n"] >= 2:
            raise KeyboardInterrupt

        return {
            "scan": {
                "timestamp": "2026-09-09T12:00:00+00:00",
            },
            "summary": {},
            "risk": {},
            "findings": [],
            "incidents": [],
        }

    cmd_watch(
        Namespace(
            interval=0,
            count=0,
        ),
        scan_fn=fake_scan,
    )

    output = capsys.readouterr().out

    assert "[watch] stopped by user" in output
