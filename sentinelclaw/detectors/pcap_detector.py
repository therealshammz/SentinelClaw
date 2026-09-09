from __future__ import annotations

import ipaddress
import logging

from sentinelclaw.config.constants import (
    MONITORED_PORTS,
    SUSPICIOUS_DNS_TLDS,
)
from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)


def flow_timestamp(
    flow: dict,
) -> str | None:
    """Return the per-flow ``first_seen`` ISO timestamp, if any.

    P4-21: PCAP findings used to be untimestamped and sank to the
    bottom of the investigation timeline. Flow-based findings now
    carry the flow's first-observed time when the capture provided
    packet timestamps.
    """
    first_seen = flow.get(
        "first_seen"
    )

    if isinstance(
        first_seen,
        str,
    ) and first_seen:
        return first_seen

    return None


def suspicious_tld_of(
    hostname: str,
) -> str | None:
    """Return the final DNS label of ``hostname`` when it appears in the
    documented suspicious-TLD list (constants.SUSPICIOUS_DNS_TLDS).
    Matching is case-insensitive; a trailing dot is ignored.
    """
    hostname = (
        hostname.strip().lower().rstrip(".")
    )

    if not hostname:
        return None

    tld = hostname.rsplit(
        ".",
        1,
    )[-1]

    if tld in SUSPICIOUS_DNS_TLDS:
        return tld

    return None


def is_ip_literal(
    hostname: str,
) -> bool:
    """True when ``hostname`` is a raw IPv4/IPv6 address.

    A numeric IP address is a non-standard TLS SNI value (RFC 6066
    permits hostnames only), so its presence is worth surfacing.
    """
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False

    return True


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
                "timestamp": flow_timestamp(
                    flow
                ),
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
                    "first_seen": flow.get(
                        "first_seen"
                    ),
                    "last_seen": flow.get(
                        "last_seen"
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
                "timestamp": flow_timestamp(
                    flow
                ),
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


def detect_dns_suspicious_tlds(
    pcap_data: dict,
) -> list[dict]:
    """Flag DNS queries whose name ends in a documented risky TLD."""
    findings = []
    seen_qnames: set[str] = set()

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        queries = flow.get(
            "dns_queries",
            [],
        )

        if not queries:
            continue

        for qname in queries:
            if qname in seen_qnames:
                continue

            tld = suspicious_tld_of(
                qname
            )

            if tld is None:
                continue

            seen_qnames.add(
                qname
            )

            findings.append(
                {
                    "severity": "medium",
                    "rule_id": "PCAP-005",
                    "title": "Suspicious DNS query to risky TLD",
                    "description": (
                        "A DNS query targeted a top-level domain "
                        "that is disproportionately abused for "
                        "phishing, malware staging, or C2 rendezvous."
                    ),
                    "category": "pcap",
                    "confidence": "medium",
                    "timestamp": flow_timestamp(
                        flow
                    ),
                    "source_ip": flow.get(
                        "source_ip"
                    ),
                    "destination_ip": flow.get(
                        "destination_ip"
                    ),
                    "evidence": {
                        "qname": qname,
                        "tld": tld,
                        "source_ip": flow.get(
                            "source_ip"
                        ),
                        "destination_ip": flow.get(
                            "destination_ip"
                        ),
                        "destination_port": flow.get(
                            "destination_port"
                        ),
                        "timestamp": flow.get(
                            "first_seen"
                        ),
                    },
                    "mitre": {
                        "technique": "T1071.004",
                        "name": "Application Layer Protocol: DNS",
                        "tactic": "Command and Control",
                    },
                }
            )

    return findings


def detect_suspicious_tls_snis(
    pcap_data: dict,
) -> list[dict]:
    """Flag TLS SNI values that are risky or non-standard."""
    findings = []
    seen_snis: set[str] = set()

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        snis = flow.get(
            "tls_snis",
            [],
        )

        if not snis:
            continue

        for sni in snis:
            if sni in seen_snis:
                continue

            tld = suspicious_tld_of(
                sni
            )

            if tld is not None:
                reason = f"suspicious TLD ({tld})"
                severity = "medium"
            elif is_ip_literal(
                sni
            ):
                reason = "IP address used as SNI"
                severity = "low"
            elif "." not in sni:
                reason = "single-label server name"
                severity = "low"
            else:
                continue

            seen_snis.add(
                sni
            )

            findings.append(
                {
                    "severity": severity,
                    "rule_id": "PCAP-006",
                    "title": "Suspicious TLS server name (SNI)",
                    "description": (
                        "A TLS ClientHello advertised a server name "
                        "that is risky or non-standard. This is an "
                        "indicator only and may be legitimate."
                    ),
                    "category": "pcap",
                    "confidence": "low",
                    "timestamp": flow_timestamp(
                        flow
                    ),
                    "source_ip": flow.get(
                        "source_ip"
                    ),
                    "destination_ip": flow.get(
                        "destination_ip"
                    ),
                    "evidence": {
                        "sni": sni,
                        "reason": reason,
                        "source_ip": flow.get(
                            "source_ip"
                        ),
                        "destination_ip": flow.get(
                            "destination_ip"
                        ),
                        "destination_port": flow.get(
                            "destination_port"
                        ),
                    },
                    "mitre": {
                        "technique": "T1071.001",
                        "name": "Application Layer Protocol: Web",
                        "tactic": "Command and Control",
                    },
                }
            )

    return findings


def detect_beaconing(
    pcap_data: dict,
) -> list[dict]:
    """Flag RITA-style periodic beacons.

    A flow whose inter-arrival times are highly regular (coefficient
    of variation below ``pcap_beacon_max_cv``) across at least
    ``pcap_beacon_min_packets`` packets is a beacon candidate:
    malware that phones home on a fixed schedule produces this
    signature.
    """
    findings = []
    settings = get_settings()

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        packet_count = flow.get(
            "packet_count",
            0,
        )

        iat_cv = flow.get(
            "iat_cv"
        )

        if (
            packet_count
            < settings.pcap_beacon_min_packets
        ):
            continue

        if not isinstance(
            iat_cv,
            (int, float),
        ):
            continue

        if iat_cv >= settings.pcap_beacon_max_cv:
            continue

        findings.append(
            {
                "severity": "medium",
                "rule_id": "PCAP-007",
                "title": "Periodic beaconing pattern",
                "description": (
                    "A flow shows highly regular inter-arrival times "
                    "across many packets, consistent with scheduled "
                    "command-and-control beaconing. Legitimate "
                    "polling traffic can look identical."
                ),
                "category": "pcap",
                "confidence": "low",
                "timestamp": flow_timestamp(
                    flow
                ),
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
                    "iat_mean_seconds": flow.get(
                        "iat_mean_seconds"
                    ),
                    "iat_cv": iat_cv,
                    "first_seen": flow.get(
                        "first_seen"
                    ),
                    "last_seen": flow.get(
                        "last_seen"
                    ),
                },
                "mitre": {
                    "technique": "T1071",
                    "name": "Application Layer Protocol",
                    "tactic": "Command and Control",
                },
            }
        )

    return findings


def detect_syn_scans(
    pcap_data: dict,
) -> list[dict]:
    """Flag TCP SYN-only probes spread across many destination ports.

    Flows whose every packet was a bare SYN (no ACK/RST/FIN observed)
    are connection attempts that never completed a handshake. When one
    source aims such probes at many ports on one host, it is a SYN
    scan rather than ordinary connectivity failure.
    """
    findings = []
    settings = get_settings()

    probes: dict[
        tuple[str, str],
        dict,
    ] = {}

    flows = pcap_data.get(
        "flows",
        [],
    )

    for flow in flows:
        if flow.get(
            "protocol"
        ) != "TCP":
            continue

        packet_count = flow.get(
            "packet_count",
            0,
        )

        syn_only = flow.get(
            "syn_only_count",
            0,
        )

        if syn_only != packet_count:
            continue

        source_ip = flow.get(
            "source_ip"
        )

        destination_ip = flow.get(
            "destination_ip"
        )

        destination_port = flow.get(
            "destination_port"
        )

        if (
            not source_ip
            or not destination_ip
            or destination_port is None
        ):
            continue

        key = (
            source_ip,
            destination_ip,
        )

        probe = probes.setdefault(
            key,
            {
                "ports": set(),
                "first_seen": None,
            },
        )

        probe["ports"].add(
            int(destination_port)
        )

        first_seen = flow.get(
            "first_seen"
        )

        if (
            isinstance(
                first_seen,
                str,
            )
            and (
                probe["first_seen"] is None
                or first_seen
                < probe["first_seen"]
            )
        ):
            probe["first_seen"] = first_seen

    threshold = settings.pcap_port_scan_threshold

    high_threshold = (
        settings.pcap_port_scan_high_threshold
    )

    for (
        source_ip,
        destination_ip,
    ), probe in sorted(
        probes.items()
    ):
        ports = probe["ports"]

        port_count = len(
            ports
        )

        if port_count < threshold:
            continue

        severity = (
            "high"
            if port_count
            >= high_threshold
            else "medium"
        )

        findings.append(
            {
                "severity": severity,
                "rule_id": "PCAP-008",
                "title": "Possible SYN port scan",
                "description": (
                    "A source sent SYN-only probes to many different "
                    "TCP destination ports without completing "
                    "handshakes, which is consistent with a SYN scan."
                ),
                "category": "pcap",
                "confidence": "medium",
                "timestamp": probe.get(
                    "first_seen"
                ),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "unique_destination_ports": port_count,
                    "destination_ports": sorted(
                        ports
                    )[:100],
                    "first_seen": probe.get(
                        "first_seen"
                    ),
                },
                "mitre": {
                    "technique": "T1046",
                    "name": "Network Service Discovery",
                    "tactic": "Discovery",
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

    findings.extend(
        detect_dns_suspicious_tlds(
            pcap_data
        )
    )

    findings.extend(
        detect_suspicious_tls_snis(
            pcap_data
        )
    )

    findings.extend(
        detect_beaconing(
            pcap_data
        )
    )

    findings.extend(
        detect_syn_scans(
            pcap_data
        )
    )

    logger.debug(
        "PCAP detector produced %d finding(s)",
        len(findings),
    )

    return findings
