"""P4-21 tests: timestamped PCAP findings, DNS/TLS capture, beaconing, SYN scans.

The detector and pure-parsing logic is exercised on canned normalized
data so none of these tests require scapy (the analyzer module itself
imports cleanly without scapy; real capture parsing is covered by the
CLI smoke checks and the optional real-pcap integration path).
"""

import struct

from sentinelclaw.detectors.pcap_detector import (
    analyze_pcap_findings,
    is_ip_literal,
    suspicious_tld_of,
)
from sentinelclaw.engine.timeline_engine import build_timeline
from sentinelclaw.tools.pcap_analyzer import _iat_variation
from sentinelclaw.tools.tls_parse import (
    decode_dns_qname,
    extract_sni_from_client_hello,
)


def make_flow(**overrides) -> dict:
    flow = {
        "source_ip": "192.168.1.10",
        "source_port": 49152,
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "protocol": "UDP",
        "packet_count": 1,
        "first_seen": None,
        "last_seen": None,
        "iat_mean_seconds": None,
        "iat_cv": None,
        "syn_only_count": 0,
        "tcp_flags_seen": [],
        "dns_queries": [],
        "tls_snis": [],
    }

    flow.update(overrides)

    return flow


def test_dns_suspicious_tld_fires_on_canned_data() -> None:
    data = {
        "flows": [
            make_flow(
                dns_queries=[
                    "update.example.xyz",
                ],
            ),
            make_flow(
                destination_ip="8.8.8.8",
                destination_port=53,
                dns_queries=[
                    "www.legit.com",
                    "cdn.example.net",
                ],
            ),
        ]
    }

    findings = analyze_pcap_findings(data)

    dns_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PCAP-005"
    ]

    assert len(dns_findings) == 1
    assert dns_findings[0]["evidence"]["qname"] == (
        "update.example.xyz"
    )
    assert dns_findings[0]["evidence"]["tld"] == "xyz"
    assert dns_findings[0]["severity"] == "medium"


def test_dns_same_qname_across_flows_reported_once() -> None:
    data = {
        "flows": [
            make_flow(
                dns_queries=[
                    "stage.c2.bad.tk",
                ],
            ),
            make_flow(
                source_port=49153,
                dns_queries=[
                    "stage.c2.bad.tk",
                ],
            ),
        ]
    }

    findings = analyze_pcap_findings(data)

    dns_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PCAP-005"
    ]

    assert len(dns_findings) == 1


def test_timestamped_pcap_findings_land_in_timeline_order() -> None:
    data = {
        "flows": [
            make_flow(
                source_ip="192.168.1.10",
                destination_ip="203.0.113.50",
                destination_port=53,
                packet_count=1,
                first_seen="2026-09-08T10:00:00+00:00",
                dns_queries=[
                    "later.example.xyz",
                ],
            ),
            make_flow(
                source_ip="192.168.1.10",
                destination_ip="203.0.113.60",
                destination_port=53,
                packet_count=1,
                first_seen="2026-09-08T09:00:00+00:00",
                dns_queries=[
                    "earlier.example.top",
                ],
            ),
        ]
    }

    findings = analyze_pcap_findings(data)

    timeline = build_timeline(
        findings=findings,
        incidents=[],
        scan_timestamp="2026-09-08T11:00:00+00:00",
    )

    finding_events = [
        event
        for event in timeline
        if event.get("event_type") == "finding"
    ]

    assert len(finding_events) == 2

    timestamps = [
        event.get("timestamp")
        for event in finding_events
    ]

    assert timestamps == sorted(timestamps)
    assert timestamps[0] == "2026-09-08T09:00:00+00:00"
    assert timestamps[1] == "2026-09-08T10:00:00+00:00"

    rule_sequence = [
        event.get("rule_id")
        for event in finding_events
    ]

    assert rule_sequence == ["PCAP-005", "PCAP-005"]


def test_beaconing_regular_flow_fires_irregular_does_not() -> None:
    data = {
        "flows": [
            make_flow(
                protocol="TCP",
                source_ip="10.0.0.5",
                destination_ip="203.0.113.77",
                destination_port=8443,
                packet_count=24,
                iat_mean_seconds=2.0,
                iat_cv=0.02,
                first_seen="2026-09-08T10:00:00+00:00",
                last_seen="2026-09-08T10:00:46+00:00",
            ),
            make_flow(
                protocol="TCP",
                source_ip="10.0.0.6",
                destination_ip="203.0.113.78",
                destination_port=8443,
                packet_count=24,
                iat_mean_seconds=2.0,
                iat_cv=0.93,
            ),
            make_flow(
                protocol="TCP",
                source_ip="10.0.0.7",
                destination_ip="203.0.113.79",
                destination_port=8443,
                packet_count=5,
                iat_mean_seconds=2.0,
                iat_cv=0.01,
            ),
        ]
    }

    findings = analyze_pcap_findings(data)

    beacons = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PCAP-007"
    ]

    assert len(beacons) == 1
    assert beacons[0]["source_ip"] == "10.0.0.5"
    assert beacons[0]["timestamp"] == "2026-09-08T10:00:00+00:00"
    assert beacons[0]["evidence"]["iat_cv"] == 0.02


def test_iat_variation_helper() -> None:
    mean, cv = _iat_variation(
        count=2,
        mean=10.0,
        m2=2.0,
    )

    assert mean == 10.0
    assert abs(cv - 0.1414) < 0.001

    assert _iat_variation(
        count=1,
        mean=10.0,
        m2=2.0,
    ) == (
        None,
        None,
    )

    assert _iat_variation(
        count=5,
        mean=0.0,
        m2=2.0,
    ) == (
        None,
        None,
    )

    assert _iat_variation(
        count=12,
        mean=2.0,
        m2=0.0,
    ) == (
        2.0,
        0.0,
    )


def test_syn_scan_fires_on_canned_flags_data(monkeypatch) -> None:
    from sentinelclaw.config.settings import Settings

    import sentinelclaw.detectors.pcap_detector as pcap_detector

    monkeypatch.setattr(
        pcap_detector,
        "get_settings",
        lambda: Settings(
            pcap_port_scan_threshold=5,
            pcap_port_scan_high_threshold=50,
        ),
    )

    syn_flows = [
        make_flow(
            protocol="TCP",
            source_ip="10.0.0.99",
            destination_ip="10.0.0.5",
            destination_port=port,
            packet_count=1,
            syn_only_count=1,
            tcp_flags_seen=["S"],
            first_seen=(
                "2026-09-08T08:00:00+00:00"
                if port == 1001
                else "2026-09-08T08:00:01+00:00"
            ),
        )
        for port in range(1001, 1011)
    ]

    syn_flows.append(
        make_flow(
            protocol="TCP",
            source_ip="10.0.0.99",
            destination_ip="10.0.0.5",
            destination_port=443,
            packet_count=9,
            syn_only_count=3,
            tcp_flags_seen=["S", "SA", "A"],
        )
    )

    data = {
        "flows": syn_flows,
    }

    findings = analyze_pcap_findings(data)

    syn_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PCAP-008"
    ]

    assert len(syn_findings) == 1
    assert syn_findings[0]["source_ip"] == "10.0.0.99"
    assert syn_findings[0]["destination_ip"] == "10.0.0.5"
    assert syn_findings[0]["severity"] == "medium"
    assert syn_findings[0]["evidence"][
        "unique_destination_ports"
    ] == 10
    assert syn_findings[0]["timestamp"] == (
        "2026-09-08T08:00:00+00:00"
    )


def test_suspicious_tls_sni_fires_with_reason() -> None:
    data = {
        "flows": [
            make_flow(
                protocol="TCP",
                source_ip="192.168.1.10",
                destination_ip="198.51.100.7",
                destination_port=443,
                packet_count=3,
                tls_snis=[
                    "c2-staging.example.xyz",
                ],
            ),
            make_flow(
                protocol="TCP",
                source_ip="192.168.1.11",
                destination_ip="198.51.100.8",
                destination_port=443,
                packet_count=3,
                tls_snis=[
                    "10.1.2.3",
                ],
            ),
            make_flow(
                protocol="TCP",
                source_ip="192.168.1.12",
                destination_ip="198.51.100.9",
                destination_port=443,
                packet_count=3,
                tls_snis=[
                    "internal-only",
                ],
            ),
            make_flow(
                protocol="TCP",
                source_ip="192.168.1.13",
                destination_ip="198.51.100.10",
                destination_port=443,
                packet_count=3,
                tls_snis=[
                    "www.cdn.legit.com",
                ],
            ),
        ]
    }

    findings = analyze_pcap_findings(data)

    sni_findings = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PCAP-006"
    ]

    assert len(sni_findings) == 3

    reasons = {
        finding["evidence"]["sni"]: finding["evidence"]["reason"]
        for finding in sni_findings
    }

    assert reasons["c2-staging.example.xyz"] == (
        "suspicious TLD (xyz)"
    )
    assert reasons["10.1.2.3"] == (
        "IP address used as SNI"
    )
    assert reasons["internal-only"] == (
        "single-label server name"
    )


def test_existing_pcap_findings_still_fire(
    sample_pcap_data,
) -> None:
    findings = analyze_pcap_findings(sample_pcap_data)

    rule_ids = {
        finding.get("rule_id")
        for finding in findings
    }

    assert "PCAP-001" in rule_ids
    assert "PCAP-003" in rule_ids
    assert "PCAP-004" in rule_ids


def test_tld_and_ip_literal_helpers() -> None:
    assert suspicious_tld_of(
        "update.example.xyz"
    ) == "xyz"

    assert suspicious_tld_of(
        "UPDATES.EXAMPLE.TK."
    ) == "tk"

    assert suspicious_tld_of(
        "www.legit.com"
    ) is None

    assert suspicious_tld_of(
        ""
    ) is None

    assert is_ip_literal("10.0.0.1")
    assert is_ip_literal("2001:db8::1")
    assert not is_ip_literal("server.example.com")


def build_client_hello_with_sni(hostname: bytes) -> bytes:
    server_name_block = (
        struct.pack(">B", 0)
        + struct.pack(">H", len(hostname))
        + hostname
    )

    extension_payload = (
        struct.pack(">H", len(server_name_block))
        + server_name_block
    )

    extension = (
        struct.pack(">H", 0)
        + struct.pack(">H", len(extension_payload))
        + extension_payload
    )

    hello_body = struct.pack(">H", 0x0303) + b"\x00" * 32
    hello_body += bytes([32]) + b"\x00" * 32
    hello_body += struct.pack(">H", 2) + b"\x13\x01"
    hello_body += bytes([1, 0])
    hello_body += struct.pack(">H", len(extension)) + extension

    handshake = (
        bytes([1])
        + len(hello_body).to_bytes(3, "big")
        + hello_body
    )

    return (
        bytes([0x16, 0x03, 0x01])
        + len(handshake).to_bytes(2, "big")
        + handshake
    )


def test_extract_sni_from_client_hello() -> None:
    hostname = b"c2-staging.example.xyz"

    hello = build_client_hello_with_sni(hostname)

    assert extract_sni_from_client_hello(hello) == (
        hostname.decode()
    )

    assert extract_sni_from_client_hello(
        b"\x00\x01\x02"
    ) is None

    assert extract_sni_from_client_hello(
        b"\x16\x03\x01\x00\x02\x00\x00"
    ) is None

    no_sni = build_client_hello_with_sni(
        b"server.example.com"
    )

    assert extract_sni_from_client_hello(
        no_sni
    ) == "server.example.com"


def test_decode_dns_qname_wire_and_dotted() -> None:
    assert decode_dns_qname(
        b"\x06update\x07example\x03xyz\x00"
    ) == "update.example.xyz"

    assert decode_dns_qname(
        b"update.example.xyz."
    ) == "update.example.xyz"

    assert decode_dns_qname(
        b""
    ) is None

    assert decode_dns_qname(
        b"\xc0\x0c"
    ) is None
