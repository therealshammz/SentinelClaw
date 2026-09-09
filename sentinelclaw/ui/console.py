from __future__ import annotations

import json
import os
import sys
from typing import Any

from sentinelclaw.config.constants import (
    SEVERITY_RANK,
    SEVERITY_ORDER as _SEVERITY_ORDER,
)


WIDTH = 72

SEVERITY_ORDER = tuple(
    reversed(_SEVERITY_ORDER)
)


def supports_color() -> bool:
    if not sys.stdout.isatty():
        return False

    if os.environ.get("NO_COLOR"):
        return False

    return True


COLOR_ENABLED = supports_color()


COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "white": "\033[97m",
}


def colorize(
    text: str,
    color: str,
) -> str:
    if not COLOR_ENABLED:
        return text

    return (
        COLORS.get(color, "")
        + text
        + COLORS["reset"]
    )


def severity_color(
    severity: str,
) -> str:
    severity = str(
        severity
    ).lower()

    if severity == "critical":
        return "magenta"

    if severity == "high":
        return "red"

    if severity == "medium":
        return "yellow"

    if severity == "low":
        return "cyan"

    return "white"


def banner(
    title: str,
) -> None:
    print()
    print("=" * WIDTH)

    print(
        colorize(
            title.center(WIDTH),
            "bold",
        )
    )

    print("=" * WIDTH)


def section(
    title: str,
) -> None:
    print()

    print(
        colorize(
            title.upper(),
            "bold",
        )
    )

    print("-" * WIDTH)


def status(
    label: str,
    value: Any,
    width: int = 22,
) -> None:
    print(
        f"{label:<{width}}"
        f"{value}"
    )


def severity_counts(
    findings: list[dict],
) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "info",
            )
        ).lower()

        if severity not in counts:
            severity = "info"

        counts[
            severity
        ] += 1

    return counts


def risk_label(
    score: int,
    level: str,
) -> str:
    level = str(
        level
    ).lower()

    text = (
        f"{score}/100 "
        f"({level.upper()})"
    )

    return colorize(
        text,
        severity_color(
            level
        ),
    )


def compact_finding(
    finding: dict,
    verbose: bool = False,
) -> None:
    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).lower()

    rule_id = finding.get(
        "rule_id",
        "UNKNOWN",
    )

    title = finding.get(
        "title",
        "Unknown finding",
    )

    severity_text = colorize(
        f"{severity.upper():8}",
        severity_color(
            severity
        ),
    )

    print(
        f"{severity_text} "
        f"{rule_id:<16} "
        f"{title}"
    )

    if not verbose:
        return

    description = finding.get(
        "description"
    )

    if description:
        print(
            f"    Reason      : "
            f"{description}"
        )

    confidence = finding.get(
        "confidence"
    )

    if confidence:
        print(
            f"    Confidence  : "
            f"{confidence}"
        )

    pid = finding.get(
        "pid"
    )

    if pid is not None:
        print(
            f"    PID         : "
            f"{pid}"
        )

    process_name = finding.get(
        "process_name"
    )

    if process_name:
        print(
            f"    Process     : "
            f"{process_name}"
        )

    source_ip = finding.get(
        "source_ip"
    )

    if source_ip:
        print(
            f"    Source IP   : "
            f"{source_ip}"
        )

    destination_ip = finding.get(
        "destination_ip"
    )

    if destination_ip:
        print(
            f"    Destination : "
            f"{destination_ip}"
        )

    remote_ip = finding.get(
        "remote_ip"
    )

    remote_port = finding.get(
        "remote_port"
    )

    if remote_ip:
        remote = remote_ip

        if remote_port is not None:
            remote = (
                f"{remote_ip}:"
                f"{remote_port}"
            )

        print(
            f"    Remote      : "
            f"{remote}"
        )

    mitre = finding.get(
        "mitre"
    )

    if isinstance(
        mitre,
        dict,
    ):
        technique = mitre.get(
            "technique"
        )

        name = mitre.get(
            "name"
        )

        tactic = mitre.get(
            "tactic"
        )

        if technique or name:
            print(
                f"    MITRE       : "
                f"{technique or 'Unknown'}"
                f" - "
                f"{name or 'Unknown'}"
            )

        if tactic:
            print(
                f"    Tactic      : "
                f"{tactic}"
            )

    evidence = finding.get(
        "evidence"
    )

    if evidence:
        print(
            "    Evidence    : "
            + json.dumps(
                evidence,
                ensure_ascii=False,
                default=str,
            )
        )


def compact_incident(
    incident: dict,
    verbose: bool = False,
) -> None:
    severity = str(
        incident.get(
            "severity",
            "info",
        )
    ).lower()

    incident_id = incident.get(
        "incident_id",
        "UNKNOWN",
    )

    title = incident.get(
        "title",
        "Unknown incident",
    )

    severity_text = colorize(
        f"{severity.upper():8}",
        severity_color(
            severity
        ),
    )

    print(
        f"{severity_text} "
        f"{incident_id:<18} "
        f"{title}"
    )

    if not verbose:
        return

    description = incident.get(
        "description"
    )

    if description:
        print(
            f"    Reason      : "
            f"{description}"
        )

    confidence = incident.get(
        "confidence"
    )

    if confidence:
        print(
            f"    Confidence  : "
            f"{confidence}"
        )

    finding_count = incident.get(
        "finding_count",
        0,
    )

    print(
        f"    Findings    : "
        f"{finding_count}"
    )

    related_rule_ids = incident.get(
        "related_rule_ids",
        [],
    )

    if related_rule_ids:
        print(
            "    Rules       : "
            + ", ".join(
                related_rule_ids
            )
        )


def print_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    findings = (
        report
        .get(
            "findings",
            {},
        )
        .get(
            "all",
            [],
        )
    )

    incidents = report.get(
        "incidents",
        [],
    )

    risk = report.get(
        "risk",
        {},
    )

    summary = report.get(
        "summary",
        {},
    )

    counts = severity_counts(
        findings
    )

    banner(
        "SENTINELCLAW SECURITY CONSOLE"
    )

    section(
        "System scan"
    )

    status(
        "Processes",
        summary.get(
            "processes_scanned",
            0,
        ),
    )

    status(
        "Connections",
        summary.get(
            "network_connections_scanned",
            0,
        ),
    )

    status(
        "Windows Events",
        summary.get(
            "windows_events_scanned",
            0,
        ),
    )

    status(
        "Detection Rules",
        summary.get(
            "rules_loaded",
            0,
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    section(
        "Findings"
    )

    for severity in SEVERITY_ORDER:
        value = counts[
            severity
        ]

        label = (
            severity.upper()
        )

        label = colorize(
            label,
            severity_color(
                severity
            ),
        )

        status(
            label,
            value,
        )

    status(
        "TOTAL",
        len(
            findings
        ),
    )

    section(
        "Incidents"
    )

    status(
        "Correlated",
        len(
            incidents
        ),
    )

    if incidents:
        print()

        for incident in incidents[
            :10
        ]:
            compact_incident(
                incident,
                verbose=verbose,
            )

    section(
        "Top findings"
    )

    if not findings:
        print(
            "[+] No findings detected."
        )

    else:
        ranked = sorted(
            findings,
            key=lambda item: SEVERITY_RANK.get(
                str(
                    item.get(
                        "severity",
                        "info",
                    )
                ).lower(),
                0,
            ),
            reverse=True,
        )

        limit = (
            len(ranked)
            if verbose
            else 10
        )

        for finding in ranked[
            :limit
        ]:
            compact_finding(
                finding,
                verbose=verbose,
            )

    section(
        "Assessment"
    )

    if not findings:
        print(
            "[+] No security indicators "
            "were detected by the current rules."
        )

    elif (
        counts["critical"]
        or counts["high"]
    ):
        print(
            "[!] High-priority indicators "
            "require investigation."
        )

    elif counts["medium"]:
        print(
            "[!] Suspicious indicators were "
            "detected. Review the findings."
        )

    else:
        print(
            "[+] Only low or informational "
            "indicators were detected."
        )

    print()
    print("=" * WIDTH)

    print(
        "SentinelClaw findings are indicators, "
        "not proof of compromise."
    )

    print("=" * WIDTH)
    print()


def print_pcap_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    if "error" in report:
        banner(
            "SENTINELCLAW PCAP ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{report['error']}"
        )
        print()
        return

    pcap = report.get(
        "pcap",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    incidents = report.get(
        "incidents",
        [],
    )

    protocols = pcap.get(
        "protocols",
        {},
    )

    banner(
        "SENTINELCLAW PCAP ANALYSIS"
    )

    section(
        "Capture"
    )

    status(
        "File",
        pcap.get(
            "name",
            "Unknown",
        ),
    )

    status(
        "Packets",
        pcap.get(
            "packets_total",
            0,
        ),
    )

    status(
        "TCP",
        protocols.get(
            "tcp",
            0,
        ),
    )

    status(
        "UDP",
        protocols.get(
            "udp",
            0,
        ),
    )

    status(
        "Other",
        protocols.get(
            "other",
            0,
        ),
    )

    status(
        "Unique IPs",
        pcap.get(
            "unique_ips",
            0,
        ),
    )

    status(
        "Flows",
        pcap.get(
            "unique_flows",
            0,
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    status(
        "Incidents",
        len(
            incidents
        ),
    )

    section(
        "Top destination ports"
    )

    ports = pcap.get(
        "top_destination_ports",
        [],
    )

    if not ports:
        print(
            "No destination-port data."
        )

    else:
        for item in ports[
            :10
        ]:
            print(
                f"{str(item.get('port')):<10}"
                f"{item.get('packets', 0)} packets"
            )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No suspicious PCAP "
            "behavior detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)

    print(
        "PCAP findings are indicators "
        "and require investigation."
    )

    print("=" * WIDTH)
    print()


def print_file_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    if "error" in report:
        banner(
            "SENTINELCLAW FILE ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{report['error']}"
        )
        print()
        return

    file_info = report.get(
        "file",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    banner(
        "SENTINELCLAW FILE ANALYSIS"
    )

    section(
        "File"
    )

    status(
        "Name",
        file_info.get(
            "name",
            "Unknown",
        ),
    )

    status(
        "Path",
        file_info.get(
            "path",
            "Unknown",
        ),
    )

    status(
        "SHA-256",
        file_info.get(
            "sha256",
            "Unknown",
        ),
    )

    status(
        "Entropy",
        file_info.get(
            "entropy",
            "Unknown",
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No file indicators detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()


def print_incidents_dashboard(
    incidents: list[dict],
    verbose: bool = False,
) -> None:
    banner(
        "SENTINELCLAW INCIDENTS"
    )

    if not incidents:
        print()
        print(
            "[+] No correlated incidents detected."
        )

    else:
        section(
            "Correlated incidents"
        )

        for incident in incidents:
            compact_incident(
                incident,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()
