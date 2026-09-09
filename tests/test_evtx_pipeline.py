"""P4-22 tests: offline .evtx analysis and parsed-field extraction.

python-evtx is an optional extra. The pure XML field parser is
exercised on canned strings unconditionally; anything that must open a
real .evtx file is skip-guarded so CI (which installs only the base,
dev, and pcap extras) stays green.

The committed fixture ``tests/fixtures/security_4625_failed_logons.evtx``
is a real Windows Security log sample (69,632 bytes) sourced from the
EVTX-to-MITRE-Attack corpus (Yamato-Security/hayabusa-sample-evtx,
"ID4625-failed login with denied access due to account restriction").
It holds two 4625 events from 10.23.23.9; the target account is the
anonymous SID (S-1-0-0), so TargetUserName is "-" -- a documented
property of the fixture, not a parsing gap.
"""

from pathlib import Path

import pytest

from sentinelclaw.detectors.log_detector import (
    HIGH_RISK_EVENT_IDS,
    analyze_windows_events,
)
from sentinelclaw.tools.evtx_analyzer import (
    EVTX_NOT_INSTALLED_NOTE,
    analyze_evtx,
    parse_windows_event_xml,
)

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "security_4625_failed_logons.evtx"
)


def test_evtx_module_imports_without_python_evtx() -> None:
    import sentinelclaw.tools.evtx_analyzer as module

    assert callable(
        module.analyze_evtx
    )
    assert callable(
        module.parse_windows_event_xml
    )


def test_missing_python_evtx_returns_operational_note(
    monkeypatch,
) -> None:
    import sys

    monkeypatch.setitem(
        sys.modules,
        "Evtx",
        None,
    )

    monkeypatch.setitem(
        sys.modules,
        "Evtx.Evtx",
        None,
    )

    result = analyze_evtx(
        str(FIXTURE)
    )

    assert "error" in result
    assert EVTX_NOT_INSTALLED_NOTE in result["error"]


def test_missing_file_and_wrong_suffix_report_cleanly() -> None:
    missing = analyze_evtx(
        "/nonexistent/log.evtx"
    )

    assert "not found" in missing["error"]

    wrong_suffix = analyze_evtx(
        str(
            Path(__file__)
        )
    )

    assert "Unsupported file type" in (
        wrong_suffix["error"]
    )


CANNED_4625_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"
Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"></Provider>
<EventID Qualifiers="">4625</EventID>
<Version>0</Version>
<Level>0</Level>
<Task>12544</Task>
<Opcode>0</Opcode>
<Keywords>0x8010000000000000</Keywords>
<TimeCreated SystemTime="2026-09-08 09:10:05.123456"></TimeCreated>
<EventRecordID>1101</EventRecordID>
<Correlation ActivityID="" RelatedActivityID=""></Correlation>
<Execution ProcessID="640" ThreadID="684"></Execution>
<Channel>Security</Channel>
<Computer>HOST-01</Computer>
<Security UserID=""></Security>
</System>
<EventData><Data Name="SubjectUserName">svc</Data>
<Data Name="TargetUserSid">S-1-5-21-1001</Data>
<Data Name="TargetUserName">Administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="IpAddress">10.20.30.40</Data>
<Data Name="IpPort">55123</Data>
</EventData>
</Event>
"""


def test_parse_4625_xml_extracts_parsed_fields() -> None:
    event = parse_windows_event_xml(
        CANNED_4625_XML
    )

    assert event["event_id"] == 4625
    assert event["event_name"] == "Failed logon"
    assert event["source"] == (
        "Microsoft-Windows-Security-Auditing"
    )
    assert event["computer"] == "HOST-01"
    assert event["timestamp"] == (
        "2026-09-08T09:10:05.123456+00:00"
    )
    assert event["record_number"] == 1101
    assert event["target_user"] == "Administrator"
    assert event["ip_address"] == "10.20.30.40"
    assert event["logon_type"] == "3"
    assert "Administrator" in event["message_data"]


def test_parse_4104_script_block_and_cap() -> None:
    script = "Write-Host 'x'\n" * 2000

    xml = f"""
<Event><System><Provider Name="Microsoft-Windows-PowerShell"/>
<EventID>4104</EventID>
<TimeCreated SystemTime="2026-09-08 09:11:00.000000"></TimeCreated>
<Computer>HOST-01</Computer>
</System>
<EventData><Data Name="ScriptBlockText">{script}</Data>
</EventData>
</Event>
"""

    event = parse_windows_event_xml(
        xml
    )

    assert event["event_id"] == 4104
    assert event["script_block"].endswith("...")
    assert len(
        event["script_block"]
    ) <= 2003


def test_parse_4688_process_creation_fields() -> None:
    xml = """
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4688</EventID>
<TimeCreated SystemTime="2026-09-08 09:12:00.000000"></TimeCreated>
<Computer>HOST-01</Computer>
</System>
<EventData><Data Name="NewProcessId">0x1a2b</Data>
<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
</EventData>
</Event>
"""

    event = parse_windows_event_xml(
        xml
    )

    assert event["event_id"] == 4688
    assert event["new_process_id"] == "0x1a2b"
    assert event["new_process_name"].endswith(
        "cmd.exe"
    )


def test_parse_malformed_xml_falls_back_to_regex() -> None:
    malformed = (
        '<Event><System><EventID Qualifiers="">1102</EventID>'
        '<TimeCreated SystemTime="2026-09-08 09:13:00.000000"/>'
        "<Computer>HOST-01</Computer>"
        "</System></Event>"
    )

    event = parse_windows_event_xml(
        malformed,
        default_name="Audit log cleared",
    )

    assert event["event_id"] == 1102
    assert event["timestamp"].startswith(
        "2026-09-08T09:13:00"
    )
    assert event["computer"] == "HOST-01"


def test_dash_values_are_treated_as_absent() -> None:
    event = parse_windows_event_xml(
        CANNED_4625_XML.replace(
            "Administrator",
            "-",
        )
    )

    assert event.get(
        "target_user"
    ) is None


def test_event_id_expansion_adds_4104_and_4688() -> None:
    assert 4104 in HIGH_RISK_EVENT_IDS
    assert 4688 in HIGH_RISK_EVENT_IDS
    assert HIGH_RISK_EVENT_IDS[4104][0] == "medium"
    assert HIGH_RISK_EVENT_IDS[4688][0] == "info"


def test_windows_detector_carries_parsed_fields(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_LOGON_FAILURE_THRESHOLD",
        "1",
    )

    event = parse_windows_event_xml(
        CANNED_4625_XML
    )

    findings = analyze_windows_events(
        [event]
    )

    rule_ids = {
        finding.get("rule_id")
        for finding in findings
    }

    assert "WIN-001" in rule_ids

    aggregate = [
        finding
        for finding in findings
        if finding.get("rule_id") == "WIN-001"
    ][0]

    assert aggregate["evidence"]["ips"] == [
        "10.20.30.40"
    ]
    assert "Administrator" in (
        aggregate["evidence"]["usernames"]
    )


@pytest.mark.skipif(
    not FIXTURE.is_file(),
    reason="committed evtx fixture missing",
)
def test_analyze_evtx_requires_fixture() -> None:
    assert FIXTURE.stat().st_size < 200 * 1024


try:
    import Evtx.Evtx  # noqa: F401

    EVTX_INSTALLED = True
except ImportError:
    EVTX_INSTALLED = False

needs_evtx = pytest.mark.skipif(
    not EVTX_INSTALLED,
    reason="python-evtx not installed ([evtx] extra)",
)


@needs_evtx
def test_analyze_fixture_parses_real_records() -> None:
    result = analyze_evtx(
        str(FIXTURE)
    )

    assert "error" not in result
    assert result["events_returned"] == 2
    assert result["records_total"] == 2
    assert result["skipped_records"] == 0
    assert result["truncated"] is False

    events = result["events"]

    assert all(
        event["event_id"] == 4625
        for event in events
    )

    first = events[0]

    assert first["event_name"] == "Failed logon"
    assert first["source"] == (
        "Microsoft-Windows-Security-Auditing"
    )
    assert first["computer"] == "FS03.offsec.lan"
    assert first["timestamp"].startswith(
        "2021-10-23T21:50:11"
    )
    assert first["record_number"] == 90907
    assert first["ip_address"] == "10.23.23.9"


@needs_evtx
def test_fixture_4625_detector_finding_carries_fields(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_LOGON_FAILURE_THRESHOLD",
        "1",
    )

    result = analyze_evtx(
        str(FIXTURE)
    )

    findings = analyze_windows_events(
        result["events"]
    )

    aggregate = [
        finding
        for finding in findings
        if finding.get("rule_id") == "WIN-001"
    ]

    assert len(aggregate) == 1
    assert aggregate[0]["severity"] == "medium"
    assert aggregate[0]["evidence"]["count"] == 2
    assert "10.23.23.9" in (
        aggregate[0]["evidence"]["ips"]
    )

    # Anonymous logon: TargetUserName is "-" and is intentionally not
    # surfaced as a parsed target user (see fixture README).
    assert aggregate[0]["evidence"]["usernames"] == []
