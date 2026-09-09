from __future__ import annotations

import logging

from sentinelclaw.config.constants import MONITORED_PORTS
from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)


def detect_tcp_port_scans(
    pcap_data: dict,
) -> list[dict]:
    findings = []

    candidates = pcap_data.get(
        "tcp_scan_candidates",
        [],
    )

    for candidate in candidates:
        port_count = candidate.get(
            "unique_destination_ports",
            0,
        )

        if port_count < get_settings().pcap_port_scan_threshold:
            continue

        severity = (
            "high"
            if port_count
            >= get_settings().pcap_port_scan_high_threshold
            else "medium"
        )

        findings.append(
            {
                "severity": severity,
                "rule_id": "PCAP-001",
                "title": "Possible TCP port scan",
                "description": (
                    "A source contacted many different TCP "
                    "destination ports on the same host."
                ),
                "category": "pcap",
                "confidence": "medium",
                "source_ip": candidate.get(
                    "source_ip"
                ),
                "destination_ip": candidate.get(
                    "destination_ip"
                ),
                "evidence": {
                    "source_ip": candidate.get(
                        "source_ip"
                    ),
                    "destination_ip": candidate.get(
                        "destination_ip"
                    ),
                    "unique_destination_ports": port_count,
                    "destination_ports": candidate.get(
                        "destination_ports",
                        [],
                    )[:100],
                },
                "mitre": {
                    "technique": "T1046",
                    "name": "Network Service Discovery",
                    "tactic": "Discovery",
                },
            }
        )

    return findings


def detect_udp_port_scans(
    pcap_data: dict,
) -> list[dict]:
    findings = []

    candidates = pcap_data.get(
        "udp_scan_candidates",
        [],
    )

    for candidate in candidates:
        port_count = candidate.get(
            "unique_destination_ports",
            0,
        )

        if port_count < get_settings().pcap_port_scan_threshold:
            continue

        findings.append(
            {
                "severity": "medium",
                "rule_id": "PCAP-002",
                "title": "Possible UDP port scan",
                "description": (
                    "A source contacted many different UDP "
                    "destination ports on the same host."
                ),
                "category": "pcap",
                "confidence": "medium",
                "source_ip": candidate.get(
                    "source_ip"
                ),
                "destination_ip": candidate.get(
                    "destination_ip"
                ),
                "evidence": {
                    "source_ip": candidate.get(
                        "source_ip"
                    ),
                    "destination_ip": candidate.get(
                        "destination_ip"
                    ),
                    "unique_destination_ports": port_count,
                    "destination_ports": candidate.get(
                        "destination_ports",
                        [],
                    )[:100],
                },
                "mitre": {
                    "technique": "T1046",
                    "name": "Network Service Discovery",
                    "tactic": "Discovery",
                },
            }
        )

    return findings


def detect_monitored_ports(
    pcap_data: dict,
) -> list[dict]:
    findings = []
    seen = set()

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        destination_port = flow.get(
            "destination_port"
        )

        if destination_port not in MONITORED_PORTS:
            continue

        key = (
            flow.get("source_ip"),
            flow.get("destination_ip"),
            destination_port,
            flow.get("protocol"),
        )

        if key in seen:
            continue

        seen.add(key)

        findings.append(
            {
                "severity": "medium",
                "rule_id": "PCAP-003",
                "title": "Traffic to monitored port",
                "description": (
                    "Traffic was observed to a port commonly "
                    "associated with remote administration, "
                    "debugging, IRC, or reverse-shell activity. "
                    "This is an indicator only and may be legitimate."
                ),
                "category": "pcap",
                "confidence": "low",
                "source_ip": flow.get(
                    "source_ip"
                ),
                "destination_ip": flow.get(
                    "destination_ip"
                ),
                "remote_ip": flow.get(
                    "destination_ip"
                ),
                "remote_port": destination_port,
                "evidence": {
                    "source_ip": flow.get(
                        "source_ip"
                    ),
                    "destination_ip": flow.get(
                        "destination_ip"
                    ),
                    "destination_port": destination_port,
                    "protocol": flow.get(
                        "protocol"
                    ),
                    "packet_count": flow.get(
                        "packet_count"
                    ),
                    "port_description": MONITORED_PORTS[
                        destination_port
                    ],
                },
            }
        )

    return findings


def detect_high_volume_flows(
    pcap_data: dict,
) -> list[dict]:
    findings = []

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        packet_count = flow.get(
            "packet_count",
            0,
        )

        if packet_count < get_settings().pcap_flow_high_volume:
            continue

        findings.append(
            {
                "severity": "low",
                "rule_id": "PCAP-004",
                "title": "High-volume network flow",
                "description": (
                    "A single flow contains a large number of packets. "
                    "This may be normal for streaming, downloads, "
                    "backups, or other bulk traffic."
                ),
                "category": "pcap",
                "confidence": "low",
                "source_ip": flow.get(
                    "source_ip"
                ),
                "destination_ip": flow.get(
                    "destination_ip"
                ),
                "remote_ip": flow.get(
                    "destination_ip"
                ),
                "remote_port": flow.get(
                    "destination_port"
                ),
                "evidence": {
                    "source_ip": flow.get(
                        "source_ip"
                    ),
                    "source_port": flow.get(
                        "source_port"
                    ),
                    "destination_ip": flow.get(
                        "destination_ip"
                    ),
                    "destination_port": flow.get(
                        "destination_port"
                    ),
                    "protocol": flow.get(
                        "protocol"
                    ),
                    "packet_count": packet_count,
                },
            }
        )

    return findings


def analyze_pcap_findings(
    pcap_data: dict,
) -> list[dict]:
    if "error" in pcap_data:
        return []

    findings = []

    findings.extend(
        detect_tcp_port_scans(
            pcap_data
        )
    )

    findings.extend(
        detect_udp_port_scans(
            pcap_data
        )
    )

    findings.extend(
        detect_monitored_ports(
            pcap_data
        )
    )

    findings.extend(
        detect_high_volume_flows(
            pcap_data
        )
    )

    logger.debug(
        "PCAP detector produced %d finding(s)",
        len(findings),
    )

    return findings
