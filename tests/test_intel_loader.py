"""Offline threat-intel bundle loader and checker tests (P4-25).

Covers the supported STIX 2.x / OpenIOC subset, malformed-bundle
handling (operational error dict, never a crash) and the INTEL-001 /
INTEL-002 / INTEL-003 findings produced when collected data matches a
configured local bundle. The feature is off by default: with no
``intel_bundle_path`` no intel findings are produced.
"""

import json

from sentinelclaw.main import run_scan
from sentinelclaw.tools.intel_loader import (
    check_collected_values,
    connection_remote_ips,
    load_intel_bundle,
)

SHA256_A = "a" * 64
SHA256_B = "b" * 64

STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--00000000-0000-0000-0000-000000000001",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--11111111-1111-1111-1111-111111111111",
            "name": "C2 sinkhole",
            "description": "Known command-and-control address.",
            "pattern": "[ipv4-addr:value = '10.0.0.5']",
        },
        {
            "type": "indicator",
            "id": "indicator--22222222-2222-2222-2222-222222222222",
            "name": "Malware hash",
            "description": "Observed malware payload.",
            "pattern": (
                f"[file:hashes.'SHA-256' = '{SHA256_A}']"
            ),
        },
        {
            "type": "indicator",
            "id": "indicator--33333333-3333-3333-3333-333333333333",
            "name": "Bad domain",
            "description": "Malware staging domain.",
            "pattern": "[domain-name:value = 'evil.example.com']",
        },
        {
            "type": "indicator",
            "id": "indicator--44444444-4444-4444-4444-444444444444",
            "name": "Unsupported pattern",
            "description": "Should be skipped.",
            "pattern": "[url:value = 'http://x']",
        },
        {
            "type": "indicator",
            "id": "indicator--55555555-5555-5555-5555-555555555555",
            "name": "Compound pattern",
            "description": "Should be skipped.",
            "pattern": (
                "[ipv4-addr:value = '10.0.0.5' AND "
                "domain-name:value = 'evil.example.com']"
            ),
        },
    ],
}

OPENIOC_XML = """<?xml version="1.0" encoding="utf-8"?>
<ioc xmlns:xsd="http://www.w3.org/2001/XMLSchema"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     id="4d67c2e2-...">
  <short_description>Test IOC bundle</short_description>
  <description>Fixture bundle for SentinelClaw intel tests.</description>
  <definition>
    <Indicator operator="OR" id="ind-1">
      <IndicatorItem condition="is" id="item-1">
        <Context document="FileItem" search="FileItem/Sha256sum" type="mir" />
        """ + SHA256_B + """
      </IndicatorItem>
      <IndicatorItem condition="is" id="item-2">
        <Context document="PortItem" search="PortItem/RemoteIP" type="mir" />
        10.0.0.5
      </IndicatorItem>
      <IndicatorItem condition="is" id="item-3">
        <Context document="Network" search="Network/DNS" type="mir" />
        evil.example.com
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>
"""


def write_stix(tmp_path) -> str:
    path = tmp_path / "intel.json"

    path.write_text(
        json.dumps(STIX_BUNDLE),
        encoding="utf-8",
    )

    return str(path)


def write_openioc(tmp_path) -> str:
    path = tmp_path / "intel.xml"

    path.write_text(
        OPENIOC_XML,
        encoding="utf-8",
    )

    return str(path)


def test_stix_bundle_loads_supported_subset(tmp_path) -> None:
    result = load_intel_bundle(
        write_stix(tmp_path)
    )

    assert "error" not in result

    assert result["ip"] == [
        {
            "value": "10.0.0.5",
            "source": "C2 sinkhole",
            "description": "Known command-and-control address.",
        }
    ]

    assert result["sha256"] == [
        {
            "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "source": "Malware hash",
            "description": "Observed malware payload.",
        }
    ]

    assert result["domain"] == [
        {
            "value": "evil.example.com",
            "source": "Bad domain",
            "description": "Malware staging domain.",
        }
    ]

    # url:value and compound patterns are unsupported -> skipped.
    assert len(result["ip"]) == 1
    assert len(result["domain"]) == 1


def test_stix_scoped_observable_objects_load(tmp_path) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "file",
                "id": "file--1",
                "hashes": {"SHA-256": SHA256_A},
            },
            {
                "type": "ipv4-addr",
                "id": "ipv4-addr--1",
                "value": "198.51.100.7",
            },
            {
                "type": "domain-name",
                "id": "domain-name--1",
                "value": "EVIl.example.com",
            },
        ],
    }

    path = tmp_path / "sco.json"

    path.write_text(
        json.dumps(bundle),
        encoding="utf-8",
    )

    result = load_intel_bundle(
        str(path)
    )

    assert "error" not in result
    assert result["sha256"][0]["value"] == SHA256_A
    assert result["ip"][0]["value"] == "198.51.100.7"
    assert result["domain"][0]["value"] == "evil.example.com"


def test_openioc_bundle_loads_supported_items(tmp_path) -> None:
    result = load_intel_bundle(
        write_openioc(tmp_path)
    )

    assert "error" not in result

    assert result["sha256"][0]["value"] == SHA256_B
    assert result["ip"][0]["value"] == "10.0.0.5"
    assert result["domain"][0]["value"] == "evil.example.com"

    assert result["sha256"][0]["source"] == "Test IOC bundle"
    assert result["domain"][0]["source"] == "Test IOC bundle"


def test_malformed_bundles_return_error_dict(tmp_path) -> None:
    malformed_json = tmp_path / "bad.json"

    malformed_json.write_text(
        "{ this is not json",
        encoding="utf-8",
    )

    assert "error" in load_intel_bundle(
        str(malformed_json)
    )

    malformed_xml = tmp_path / "bad.xml"

    malformed_xml.write_text(
        "<ioc><definition>",
        encoding="utf-8",
    )

    assert "error" in load_intel_bundle(
        str(malformed_xml)
    )

    not_an_ioc = tmp_path / "notioc.xml"

    not_an_ioc.write_text(
        "<not-ioc><x/></not-ioc>",
        encoding="utf-8",
    )

    assert "error" in load_intel_bundle(
        str(not_an_ioc)
    )

    assert "error" in load_intel_bundle(
        str(tmp_path / "missing.json")
    )

    unknown_format = tmp_path / "bundle.txt"

    unknown_format.write_text(
        "garbage",
        encoding="utf-8",
    )

    assert "error" in load_intel_bundle(
        str(unknown_format)
    )


def test_check_collected_values_emits_intel_findings(tmp_path) -> None:
    intel = load_intel_bundle(
        write_stix(tmp_path)
    )

    hashes = check_collected_values(
        intel,
        hashes=["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    )

    assert len(hashes) == 1
    assert hashes[0]["rule_id"] == "INTEL-001"
    assert hashes[0]["severity"] == "high"
    assert hashes[0]["confidence"] == "high"
    assert hashes[0]["category"] == "file"
    assert hashes[0]["evidence"]["matched_value"] == (
        SHA256_A
    )
    assert hashes[0]["evidence"]["indicators"][0]["source"] == "Malware hash"

    ips = check_collected_values(
        intel,
        ips=["10.0.0.5"],
    )

    assert len(ips) == 1
    assert ips[0]["rule_id"] == "INTEL-002"
    assert ips[0]["category"] == "network"
    assert ips[0]["evidence"]["matched_value"] == "10.0.0.5"

    domains = check_collected_values(
        intel,
        domains=["EVIL.example.com"],
    )

    assert len(domains) == 1
    assert domains[0]["rule_id"] == "INTEL-003"
    assert domains[0]["evidence"]["matched_value"] == "evil.example.com"


def test_check_collected_values_ignores_unmatched_candidates(tmp_path) -> None:
    intel = load_intel_bundle(
        write_stix(tmp_path)
    )

    assert check_collected_values(
        intel,
        ips=["192.0.2.99"],
        hashes=["f" * 64],
        domains=["clean.example.org"],
    ) == []


def test_connection_remote_ips_skips_local_and_error_entries() -> None:
    connections = [
        {
            "remote_address": {
                "ip": "10.0.0.5",
                "port": 4444,
            }
        },
        {
            "remote_address": None,
        },
        {
            "error": "access denied",
        },
    ]

    assert connection_remote_ips(
        connections
    ) == ["10.0.0.5"]


def run_canned_scan(
    monkeypatch,
    processes,
    connections,
    windows_events,
) -> dict:
    monkeypatch.setattr(
        "sentinelclaw.main.get_processes",
        lambda: processes,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_network_connections",
        lambda: connections,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_windows_events",
        lambda **kwargs: windows_events,
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_auth_events",
        lambda: [],
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_persistence_records",
        lambda: [],
    )

    monkeypatch.setattr(
        "sentinelclaw.main.get_system_info",
        lambda: {"hostname": "INTEL-TEST"},
    )

    return run_scan(
        show_progress=False,
    )


def benign_processes() -> list[dict]:
    return [
        {
            "pid": 500,
            "ppid": 4,
            "name": "svchost.exe",
            "parent_name": "services.exe",
            "username": "NT AUTHORITY\SYSTEM",
            "executable": (r"C:\Windows\System32\svchost.exe"),
            "status": "running",
            "memory_percent": 0.4,
            "command_line": [
                "C:\Windows\System32\svchost.exe",
                "-k",
                "netsvcs",
            ],
            "create_time": "2026-09-08T09:00:00+00:00",
        }
    ]


def benign_connections() -> list[dict]:
    return [
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
        }
    ]


def test_stix_bundle_fires_intel_002_via_run_scan(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_INTEL_BUNDLE_PATH",
        write_stix(tmp_path),
    )

    report = run_canned_scan(
        monkeypatch,
        processes=benign_processes(),
        connections=benign_connections(),
        windows_events=[],
    )

    rule_ids = {
        str(finding.get("rule_id"))
        for finding in report["findings"]["all"]
    }

    assert "INTEL-002" in rule_ids
    assert rule_ids == {"INTEL-002"}

    finding = report["findings"]["all"][0]

    assert finding["evidence"]["matched_value"] == "10.0.0.5"
    assert finding["risk"]["score"] > 0
    assert report["risk"]["score"] > 0


def test_openioc_bundle_fires_intel_002_via_run_scan(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_INTEL_BUNDLE_PATH",
        write_openioc(tmp_path),
    )

    report = run_canned_scan(
        monkeypatch,
        processes=benign_processes(),
        connections=benign_connections(),
        windows_events=[],
    )

    rule_ids = {
        str(finding.get("rule_id"))
        for finding in report["findings"]["all"]
    }

    assert "INTEL-002" in rule_ids


def test_malformed_bundle_is_skipped_not_fatal(
    monkeypatch,
    tmp_path,
) -> None:
    bad = tmp_path / "bad.json"

    bad.write_text(
        "{ not json",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_INTEL_BUNDLE_PATH",
        str(bad),
    )

    report = run_canned_scan(
        monkeypatch,
        processes=benign_processes(),
        connections=benign_connections(),
        windows_events=[],
    )

    rule_ids = {
        str(finding.get("rule_id"))
        for finding in report["findings"]["all"]
    }

    assert rule_ids == set()
    assert report["summary"]["total_findings"] == 0
    assert report["risk"]["score"] == 0


def test_no_bundle_configured_means_no_intel_findings(
    monkeypatch,
) -> None:
    report = run_canned_scan(
        monkeypatch,
        processes=benign_processes(),
        connections=benign_connections(),
        windows_events=[],
    )

    assert report["summary"]["total_findings"] == 0

    assert all(
        not str(
            finding.get("rule_id")
        ).startswith("INTEL-")
        for finding in report["findings"]["all"]
    )
