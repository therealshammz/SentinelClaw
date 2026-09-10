from sentinelclaw.detectors.log_detector import analyze_windows_events
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.pcap_detector import analyze_pcap_findings
from sentinelclaw.detectors.process_detector import analyze_processes
from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.rule_engine import (
    load_rules_from_directory,
    run_rules,
)
from sentinelclaw.config.settings import get_settings


def test_process_detector_over_sample_processes(
    sample_processes,
) -> None:
    findings = analyze_processes(sample_processes)

    rule_ids = {finding.get("rule_id") for finding in findings}

    assert "PROC-001" in rule_ids
    assert "PROC-004" in rule_ids
    assert "PROC-005" in rule_ids

    encoded = [finding for finding in findings if finding.get("rule_id") == "PROC-004"]

    assert encoded[0]["pid"] == 4242
    assert encoded[0]["process_name"] == ("powershell.exe")


def test_network_detector_over_sample_connections(
    sample_connections,
) -> None:
    findings = analyze_network(sample_connections)

    monitored = [finding for finding in findings if finding.get("rule_id") == "NET-001"]

    assert len(monitored) == 1
    assert monitored[0]["pid"] == 4242
    assert monitored[0]["remote_ip"] == "8.8.8.8"
    assert monitored[0]["remote_port"] == 4444

    public = [finding for finding in findings if finding.get("rule_id") == "NET-002"]

    assert len(public) == 1
    assert public[0]["status"] == "ESTABLISHED"


def test_correlation_builds_incident_from_canned_detections(
    sample_processes,
    sample_connections,
) -> None:
    raw_findings = analyze_processes(sample_processes) + analyze_network(sample_connections)

    incidents = correlate_findings(raw_findings)

    network_incidents = [
        incident
        for incident in incidents
        if str(incident.get("incident_id", "")).startswith("INC-NET-")
    ]

    assert network_incidents
    assert network_incidents[0]["related_pids"] == [4242]
    assert "8.8.8.8" in network_incidents[0]["related_ips"]
    assert network_incidents[0]["severity"] in {
        "medium",
        "high",
        "critical",
    }


def test_settings_env_override_drives_windows_event_detector(
    env_isolation,
    monkeypatch,
    sample_windows_events,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_LOGON_FAILURE_THRESHOLD",
        "2",
    )

    assert get_settings().logon_failure_threshold == 2

    findings = analyze_windows_events(sample_windows_events)

    rule_ids = {finding.get("rule_id") for finding in findings}

    assert "WIN-001" in rule_ids
    assert "WIN-1102" in rule_ids
    assert "WIN-4720" in rule_ids


def test_pcap_detector_over_sample_pcap_data(
    sample_pcap_data,
) -> None:
    findings = analyze_pcap_findings(sample_pcap_data)

    rule_ids = {finding.get("rule_id") for finding in findings}

    assert "PCAP-001" in rule_ids
    assert "PCAP-003" in rule_ids
    assert "PCAP-004" in rule_ids

    monitored = [finding for finding in findings if finding.get("rule_id") == "PCAP-003"]

    assert len(monitored) == 1
    assert monitored[0]["remote_port"] == 4444


def test_rules_dir_tmp_drives_rule_engine_end_to_end(
    rules_dir_tmp,
    sample_processes,
    sample_connections,
) -> None:
    rules = load_rules_from_directory(rules_dir_tmp)

    assert {rule.get("id") for rule in rules} == {
        "PROC-FIX-001",
        "NET-FIX-001",
    }

    process_findings = run_rules(
        rules,
        sample_processes,
        category="process",
    )

    assert any(finding.get("rule_id") == "PROC-FIX-001" for finding in process_findings)

    network_findings = run_rules(
        rules,
        sample_connections,
        category="network",
    )

    assert any(finding.get("rule_id") == "NET-FIX-001" for finding in network_findings)
