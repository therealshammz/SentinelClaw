import math
import random
import subprocess
import sys
import types
from collections import Counter
from collections.abc import Iterator

import pytest

from sentinelclaw.config.settings import load_settings
from sentinelclaw.main import (
    build_parser,
    run_scan,
)
from sentinelclaw.tools.file_analyzer import (
    analyze_file,
    calculate_entropy,
)


def test_chunked_entropy_matches_one_shot(tmp_path) -> None:
    data = random.Random(42).randbytes(10 * 1024 * 1024)

    path = tmp_path / "random.bin"

    path.write_bytes(data)

    chunked = calculate_entropy(path)

    byte_counts = Counter(data)
    length = len(data)

    expected = 0.0

    for count in byte_counts.values():
        probability = count / length
        expected -= probability * math.log2(probability)

    assert chunked == round(expected, 4)
    assert chunked > 7.0


def test_chunked_entropy_matches_one_shot_small_file(tmp_path) -> None:
    data = bytes(range(256)) * 4

    path = tmp_path / "small.bin"

    path.write_bytes(data)

    assert calculate_entropy(path) == 8.0


def test_max_file_analysis_size_skips_large_file(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_MAX_FILE_ANALYSIS_SIZE",
        "1024",
    )

    path = tmp_path / "large.bin"

    path.write_bytes(
        random.Random(1).randbytes(2048)
    )

    result = analyze_file(
        str(path)
    )

    assert "error" not in result
    assert result["skipped"] is True
    assert result["skipped_reason"] == "too large"
    assert result["sha256"] is None
    assert result["entropy"] is None


def test_file_within_cap_is_analyzed_normally(tmp_path) -> None:
    path = tmp_path / "small.bin"

    path.write_bytes(
        random.Random(2).randbytes(512)
    )

    result = analyze_file(
        str(path)
    )

    assert "skipped" not in result
    assert result["sha256"] is not None
    assert result["entropy"] is not None


def test_skipped_large_file_does_not_break_file_detector(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_MAX_FILE_ANALYSIS_SIZE",
        "1024",
    )

    path = tmp_path / "large.exe"

    path.write_bytes(
        random.Random(3).randbytes(2048)
    )

    result = analyze_file(
        str(path)
    )

    from sentinelclaw.detectors.file_detector import (
        analyze_file_findings,
    )

    findings = analyze_file_findings(
        result
    )

    # On Windows the temp path matches the user-writable heuristic
    # (FILE-002); on Linux it does not. Either way the detector must
    # not crash and must not emit anything beyond that heuristic.
    assert all(
        finding.get("rule_id") == "FILE-002"
        for finding in findings
    )


def test_new_streaming_settings_defaults_and_env(
    tmp_path,
    monkeypatch,
) -> None:
    settings = load_settings(
        config_file=tmp_path / "missing.toml"
    )

    assert settings.max_file_analysis_size == (
        100 * 1024 * 1024
    )
    assert settings.max_pcap_packets == 2000000
    assert settings.max_pcap_flows == 100000

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_FILE_ANALYSIS_SIZE",
        "2048",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_PCAP_PACKETS",
        "10",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_PCAP_FLOWS",
        "5",
    )

    settings = load_settings(
        config_file=tmp_path / "missing.toml"
    )

    assert settings.max_file_analysis_size == 2048
    assert settings.max_pcap_packets == 10
    assert settings.max_pcap_flows == 5


def test_new_streaming_settings_toml(
    tmp_path,
    monkeypatch,
) -> None:
    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "max_file_analysis_size = 4096\n"
        "max_pcap_packets = 99\n"
        "max_pcap_flows = 42\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.max_file_analysis_size == 4096
    assert settings.max_pcap_packets == 99
    assert settings.max_pcap_flows == 42


def test_report_json_is_bounded_by_default() -> None:
    report = run_scan(
        show_progress=False
    )

    assert "summary" in report
    assert "findings" in report
    assert "incidents" in report
    assert "risk" in report
    assert "timeline" in report

    assert "processes" not in report
    assert "network" not in report
    assert "windows_events" not in report


def test_report_json_raw_flag_embeds_collector_dumps() -> None:
    report = run_scan(
        show_progress=False,
        include_raw=True,
    )

    assert isinstance(
        report.get("processes"),
        list,
    )
    assert isinstance(
        report.get("network"),
        list,
    )
    assert isinstance(
        report.get("windows_events"),
        list,
    )


def test_scan_and_report_parsers_accept_json_raw_flag() -> None:
    parser = build_parser()

    scan_args = parser.parse_args(
        [
            "scan",
            "--json-raw",
        ]
    )

    assert scan_args.json_raw is True

    report_args = parser.parse_args(
        [
            "report",
            "--json-raw",
        ]
    )

    assert report_args.json_raw is True

    default_args = parser.parse_args(
        ["scan"]
    )

    assert default_args.json_raw is False


def install_fake_scapy() -> None:
    scapy = types.ModuleType("scapy")
    scapy_all = types.ModuleType("scapy.all")

    class IP:
        pass

    class IPv6:
        pass

    class TCP:
        pass

    class UDP:
        pass

    class PcapReader:
        pass

    scapy_all.IP = IP
    scapy_all.IPv6 = IPv6
    scapy_all.TCP = TCP
    scapy_all.UDP = UDP
    scapy_all.PcapReader = PcapReader

    sys.modules["scapy"] = scapy
    sys.modules["scapy.all"] = scapy_all


class FakeTransport:
    def __init__(
        self,
        sport: int,
        dport: int,
        flags: str = "S",
    ) -> None:
        self.sport = sport
        self.dport = dport
        self.flags = flags


class FakeAddress:
    def __init__(
        self,
        address: str,
    ) -> None:
        self.address = address

    def __str__(self) -> str:
        return self.address


class FakePacket:
    def __init__(
        self,
        source: str,
        destination: str,
        source_port: int | None = None,
        destination_port: int | None = None,
    ) -> None:
        self.source = source
        self.destination = destination
        self.source_port = source_port
        self.destination_port = destination_port

    def __contains__(self, key: object) -> bool:
        if key.__name__ == "TCP":
            return (
                self.source_port is not None
                and self.destination_port is not None
            )

        return True

    def __getitem__(self, key: object) -> object:
        if key.__name__ == "TCP":
            return FakeTransport(
                self.source_port or 0,
                self.destination_port or 0,
            )

        return self

    @property
    def src(self) -> FakeAddress:
        return FakeAddress(
            self.source
        )

    @property
    def dst(self) -> FakeAddress:
        return FakeAddress(
            self.destination
        )

    def __len__(self) -> int:
        return 64


class FakeReader:
    def __init__(
        self,
        packets: list[FakePacket],
    ) -> None:
        self._packets = iter(packets)

    def __enter__(self) -> "FakeReader":
        return self

    def __exit__(
        self,
        *args: object,
    ) -> bool:
        return False

    def __iter__(self) -> Iterator[FakePacket]:
        return self._packets


@pytest.fixture
def fake_pcap_analyzer() -> Iterator[object]:
    install_fake_scapy()

    from sentinelclaw.tools import pcap_analyzer

    yield pcap_analyzer


def test_pcap_packet_cap_truncates(
    fake_pcap_analyzer,
    monkeypatch,
    tmp_path,
) -> None:
    from sentinelclaw.config.settings import Settings

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "get_settings",
        lambda: Settings(
            max_pcap_packets=3,
            max_pcap_flows=100000,
        ),
    )

    capture = tmp_path / "capture.pcap"

    capture.write_bytes(
        b"\x00" * 100
    )

    packets = [
        FakePacket(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
        )
        for _ in range(5)
    ]

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "PcapReader",
        lambda path: FakeReader(packets),
    )

    result = fake_pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert "error" not in result
    assert result["truncated"] is True
    assert result["packets_total"] == 3
    assert "packet limit reached" in (
        result["truncation_reason"]
    )


def test_pcap_flow_cap_truncates(
    fake_pcap_analyzer,
    monkeypatch,
    tmp_path,
) -> None:
    from sentinelclaw.config.settings import Settings

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "get_settings",
        lambda: Settings(
            max_pcap_packets=1000000,
            max_pcap_flows=1,
        ),
    )

    capture = tmp_path / "capture.pcap"

    capture.write_bytes(
        b"\x00" * 100
    )

    packets = [
        FakePacket(
            "10.0.0.1",
            "10.0.0.2",
            1000 + index,
            80,
        )
        for index in range(3)
    ]

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "PcapReader",
        lambda path: FakeReader(packets),
    )

    result = fake_pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert "error" not in result
    assert result["truncated"] is True
    assert result["unique_flows"] == 1
    assert "flow limit reached" in (
        result["truncation_reason"]
    )


def test_pcap_within_caps_not_truncated(
    fake_pcap_analyzer,
    monkeypatch,
    tmp_path,
) -> None:
    from sentinelclaw.config.settings import Settings

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "get_settings",
        lambda: Settings(
            max_pcap_packets=1000000,
            max_pcap_flows=100000,
        ),
    )

    capture = tmp_path / "capture.pcap"

    capture.write_bytes(
        b"\x00" * 100
    )

    packets = [
        FakePacket(
            "10.0.0.1",
            "10.0.0.2",
            1000 + index,
            80,
        )
        for index in range(3)
    ]

    monkeypatch.setattr(
        fake_pcap_analyzer,
        "PcapReader",
        lambda path: FakeReader(packets),
    )

    result = fake_pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert "error" not in result
    assert result["truncated"] is False
    assert result["truncation_reason"] is None
    assert result["packets_total"] == 3


def test_cli_scan_accepts_json_raw_flag() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelclaw.main",
            "scan",
            "--json-raw",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0

    import json

    report = json.loads(
        result.stdout
    )

    assert "processes" in report
