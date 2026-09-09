from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, PcapReader


def normalize_ip(packet) -> tuple[str | None, str | None]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)

    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)

    return None, None


def analyze_pcap(file_path: str) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        return {
            "error": f"PCAP file not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    if path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
        ".cap",
    }:
        return {
            "error": (
                "Unsupported capture type. "
                "Use .pcap, .pcapng, or .cap"
            )
        }

    protocol_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    destination_port_counts: Counter[int] = Counter()

    tcp_port_targets = defaultdict(set)
    udp_port_targets = defaultdict(set)

    flows: Counter[tuple[str, int | None, str, int | None, str]] = Counter()

    packets_total = 0
    tcp_packets = 0
    udp_packets = 0
    other_packets = 0

    packet_samples: list[dict] = []

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                packets_total += 1

                source_ip, destination_ip = normalize_ip(
                    packet
                )

                if source_ip:
                    ip_counts[source_ip] += 1
                    source_counts[source_ip] += 1

                if destination_ip:
                    ip_counts[destination_ip] += 1
                    destination_counts[
                        destination_ip
                    ] += 1

                protocol = "OTHER"
                source_port = None
                destination_port = None
                tcp_flags = None

                if TCP in packet:
                    protocol = "TCP"
                    tcp_packets += 1

                    source_port = int(
                        packet[TCP].sport
                    )

                    destination_port = int(
                        packet[TCP].dport
                    )

                    tcp_flags = str(
                        packet[TCP].flags
                    )

                    if (
                        source_ip
                        and destination_ip
                    ):
                        tcp_port_targets[
                            (
                                source_ip,
                                destination_ip,
                            )
                        ].add(
                            destination_port
                        )

                elif UDP in packet:
                    protocol = "UDP"
                    udp_packets += 1

                    source_port = int(
                        packet[UDP].sport
                    )

                    destination_port = int(
                        packet[UDP].dport
                    )

                    if (
                        source_ip
                        and destination_ip
                    ):
                        udp_port_targets[
                            (
                                source_ip,
                                destination_ip,
                            )
                        ].add(
                            destination_port
                        )

                else:
                    other_packets += 1

                protocol_counts[
                    protocol
                ] += 1

                if destination_port is not None:
                    destination_port_counts[
                        destination_port
                    ] += 1

                if (
                    source_ip
                    and destination_ip
                ):
                    flow_key = (
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        protocol,
                    )

                    flows[
                        flow_key
                    ] += 1

                if len(
                    packet_samples
                ) < 100:
                    packet_samples.append(
                        {
                            "source_ip": source_ip,
                            "source_port": source_port,
                            "destination_ip": destination_ip,
                            "destination_port": destination_port,
                            "protocol": protocol,
                            "tcp_flags": tcp_flags,
                            "length": len(packet),
                        }
                    )

    except Exception as exc:
        return {
            "error": (
                "Could not parse PCAP file: "
                f"{exc}"
            )
        }

    flow_records = []

    for (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    ), count in flows.most_common():
        flow_records.append(
            {
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
                "packet_count": count,
            }
        )

    tcp_scan_candidates = []

    for (
        source_ip,
        destination_ip,
    ), ports in tcp_port_targets.items():
        tcp_scan_candidates.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_destination_ports": len(
                    ports
                ),
                "destination_ports": sorted(
                    ports
                ),
            }
        )

    udp_scan_candidates = []

    for (
        source_ip,
        destination_ip,
    ), ports in udp_port_targets.items():
        udp_scan_candidates.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_destination_ports": len(
                    ports
                ),
                "destination_ports": sorted(
                    ports
                ),
            }
        )

    top_source_ips = [
        {
            "ip": ip,
            "packets": count,
        }
        for ip, count in source_counts.most_common(
            20
        )
    ]

    top_destination_ips = [
        {
            "ip": ip,
            "packets": count,
        }
        for ip, count in destination_counts.most_common(
            20
        )
    ]

    top_destination_ports = [
        {
            "port": port,
            "packets": count,
        }
        for port, count in destination_port_counts.most_common(
            20
        )
    ]

    return {
        "path": str(
            path.resolve()
        ),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "packets_total": packets_total,
        "protocols": {
            "tcp": tcp_packets,
            "udp": udp_packets,
            "other": other_packets,
        },
        "protocol_counts": dict(
            protocol_counts
        ),
        "unique_ips": len(
            ip_counts
        ),
        "unique_flows": len(
            flows
        ),
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_destination_ports": top_destination_ports,
        "flows": flow_records,
        "tcp_scan_candidates": tcp_scan_candidates,
        "udp_scan_candidates": udp_scan_candidates,
        "packet_samples": packet_samples,
    }
