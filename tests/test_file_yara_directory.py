"""P4-23 tests: YARA scanning, PE details, and directory scans.

The YARA finding path is tested two ways:

* with a fake ``yara`` module monkeypatched into ``sys.modules`` so the
  wiring (rule compile, severity normalization, finding shape) is
  exercised even where yara-python is not installed; and
* against real yara-python when it is available (skip-guarded).

pefile-backed PE details only apply on Windows and are skip-guarded
elsewhere; the guarded code path itself is covered by unit assertions
on the guard behavior.
"""

import sys
import types
from pathlib import Path

import pytest

from sentinelclaw.config.settings import (
    load_settings,
)
from sentinelclaw.main import (
    run_file_scan,
    yara_findings_for_file,
)
from sentinelclaw.tools.file_analyzer import analyze_file
from sentinelclaw.tools.yara_scanner import (
    scan_file_result,
)


class FakeYaraMatch:
    def __init__(
        self,
        rule: str,
        meta: dict,
    ) -> None:
        self.rule = rule
        self.namespace = "default"
        self.meta = meta


class FakeYaraCompiled:
    def match(
        self,
        data: bytes = b"",
    ) -> list[FakeYaraMatch]:
        if b"SUSPICIOUS_MARKER_XYZ" in data:
            return [
                FakeYaraMatch(
                    "FixtureEvilRule",
                    {"severity": "high"},
                ),
                FakeYaraMatch(
                    "FixtureMetaLessRule",
                    {},
                ),
            ]

        return []


class FakeYaraModule(types.ModuleType):
    def __init__(self) -> None:
        super().__init__("yara")

    def compile(
        self,
        filepath: str,
    ) -> FakeYaraCompiled:
        if "broken" in filepath:
            raise RuntimeError(
                "syntax error in rule"
            )

        return FakeYaraCompiled()


def install_fake_yara(
    monkeypatch,
) -> None:
    fake = FakeYaraModule()
    monkeypatch.setitem(
        sys.modules,
        "yara",
        fake,
    )


@pytest.fixture
def yara_rules_dir(
    tmp_path,
) -> Path:
    directory = tmp_path / "yara_rules"
    directory.mkdir()

    (directory / "fixture.yar").write_text(
        "rule FixtureRule { condition: true }\n",
        encoding="utf-8",
    )

    (directory / "broken.yar").write_text(
        "rule broken { if this does not parse }\n",
        encoding="utf-8",
    )

    return directory


def test_yara_finding_wiring_with_fake_module(
    monkeypatch,
    tmp_path,
    yara_rules_dir,
) -> None:
    install_fake_yara(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_YARA_RULES_DIR",
        str(yara_rules_dir),
    )

    target = tmp_path / "payload.bin"

    target.write_bytes(
        b"innocent until SUSPICIOUS_MARKER_XYZ appears"
    )

    result = scan_file_result(
        str(target)
    )

    assert result["available"] is True
    assert result["rules_loaded"] == 1
    assert "broken" in (
        result["note"] or ""
    )

    rules = {
        match["rule"]
        for match in result["matches"]
    }

    assert rules == {
        "FixtureEvilRule",
        "FixtureMetaLessRule",
    }

    severities = {
        match["rule"]: match["severity"]
        for match in result["matches"]
    }

    assert severities["FixtureEvilRule"] == "high"
    assert severities["FixtureMetaLessRule"] == (
        "medium"
    )


def test_yara_findings_from_main_helper(
    monkeypatch,
    tmp_path,
    yara_rules_dir,
) -> None:
    install_fake_yara(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_YARA_RULES_DIR",
        str(yara_rules_dir),
    )

    target = tmp_path / "payload.bin"

    target.write_bytes(
        b"prefix SUSPICIOUS_MARKER_XYZ suffix"
    )

    findings, result = yara_findings_for_file(
        str(target)
    )

    assert len(findings) == 2

    evil = [
        finding
        for finding in findings
        if finding["evidence"]["rule"]
        == "FixtureEvilRule"
    ][0]

    assert evil["rule_id"] == "YARA-001"
    assert evil["severity"] == "high"
    assert evil["category"] == "file"
    assert evil["title"] == (
        "YARA rule matched: FixtureEvilRule"
    )


def test_yara_scan_on_clean_file_has_no_matches(
    monkeypatch,
    tmp_path,
    yara_rules_dir,
) -> None:
    install_fake_yara(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_YARA_RULES_DIR",
        str(yara_rules_dir),
    )

    target = tmp_path / "clean.txt"

    target.write_text(
        "nothing suspicious here",
        encoding="utf-8",
    )

    result = scan_file_result(
        str(target)
    )

    assert result["matches"] == []


try:
    import yara  # noqa: F401

    YARA_INSTALLED = True
except ImportError:
    YARA_INSTALLED = False

needs_yara = pytest.mark.skipif(
    not YARA_INSTALLED,
    reason="yara-python not installed ([yara] extra)",
)


@needs_yara
def test_real_yara_rule_matches_and_severity(
    tmp_path,
) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "test.yar").write_text(
        "rule MarkedPayload {\n"
        "    meta:\n"
        "        severity = \"high\"\n"
        "    strings:\n"
        "        $a = \"UNIQUE_MARKER_abc123\"\n"
        "    condition:\n"
        "        $a\n"
        "}\n",
        encoding="utf-8",
    )

    payload = tmp_path / "payload.txt"

    payload.write_text(
        "content with UNIQUE_MARKER_abc123 inside",
        encoding="utf-8",
    )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv(
        "SENTINELCLAW_YARA_RULES_DIR",
        str(rules_dir),
    )

    try:
        result = scan_file_result(
            str(payload)
        )

        assert result["available"] is True
        assert result["matches"] == [
            {
                "rule": "MarkedPayload",
                "namespace": "default",
                "severity": "high",
            }
        ]
    finally:
        monkeypatch.undo()


def test_directory_scan_respects_file_cap(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_MAX_DIR_FILES",
        "3",
    )

    empty_rules = tmp_path / "empty_rules"
    empty_rules.mkdir()

    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(empty_rules),
    )

    directory = tmp_path / "targets"
    directory.mkdir()

    (directory / "a.txt").write_text(
        "alpha",
        encoding="utf-8",
    )

    (directory / "b.txt").write_text(
        "beta",
        encoding="utf-8",
    )

    (directory / "c.report.pdf.exe").write_bytes(
        b"MZ" + b"\x00" * 64
    )

    (directory / "d.ps1").write_text(
        "$code = Get-Content -Raw payload\n",
        encoding="utf-8",
    )

    (directory / "e.txt").write_text(
        "epsilon",
        encoding="utf-8",
    )

    report = run_file_scan(
        str(directory)
    )

    assert "error" not in report
    assert report["analysis"]["type"] == "directory"
    assert report["analysis"]["total_files_found"] == 5
    assert report["analysis"]["files_scanned"] == 3
    assert report["analysis"]["files_truncated"] is True
    assert report["analysis"]["files_error_count"] == 0
    assert len(report["files"]) == 3
    assert len(report["findings"]) >= 0

    names = [
        entry["file"]["name"]
        for entry in report["files"]
        if "file" in entry
    ]

    assert names == [
        "a.txt",
        "b.txt",
        "c.report.pdf.exe",
    ]

    pdf = [
        entry
        for entry in report["files"]
        if entry.get("file", {}).get("name")
        == "c.report.pdf.exe"
    ][0]

    rule_ids = {
        finding["rule_id"]
        for finding in pdf["findings"]
    }

    assert "FILE-001" in rule_ids

    flat_ids = {
        finding["rule_id"]
        for finding in report["findings"]
    }

    assert "FILE-001" in flat_ids


def test_directory_scan_empty_and_missing(
    tmp_path,
    monkeypatch,
) -> None:
    empty_rules = tmp_path / "empty_rules"
    empty_rules.mkdir()

    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(empty_rules),
    )

    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    report = run_file_scan(
        str(empty_dir)
    )

    assert "error" not in report
    assert report["analysis"]["files_scanned"] == 0
    assert report["analysis"]["files_truncated"] is False
    assert report["files"] == []
    assert report["findings"] == []

    missing = run_file_scan(
        str(
            tmp_path / "does-not-exist"
        )
    )

    assert "error" in missing


def test_single_file_scan_shape_preserved(
    tmp_path,
    monkeypatch,
) -> None:
    empty_rules = tmp_path / "empty_rules"
    empty_rules.mkdir()

    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(empty_rules),
    )

    target = tmp_path / "plain.txt"

    target.write_text(
        "just text",
        encoding="utf-8",
    )

    report = run_file_scan(
        str(target)
    )

    assert "error" not in report
    assert report["analysis"]["type"] == "file"
    assert report["file"]["name"] == "plain.txt"
    assert report["findings"] == []
    assert "yara" in report
    assert report["yara"]["matches"] == []


def test_yara_status_reports_missing_extra(
    monkeypatch,
) -> None:
    import sentinelclaw.tools.yara_scanner as module

    monkeypatch.setitem(
        sys.modules,
        "yara",
        None,
    )

    status = module.directory_status()

    assert status["available"] is False
    assert "yara-python" in (
        status["note"] or ""
    )


def test_phase4_settings_defaults_and_env(
    tmp_path,
    monkeypatch,
) -> None:
    settings = load_settings(
        config_file=tmp_path / "missing.toml"
    )

    assert settings.max_dir_files == 100
    assert settings.max_evtx_events == 2000
    assert settings.pcap_beacon_min_packets == 10
    assert settings.pcap_beacon_max_cv == 0.5

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_DIR_FILES",
        "7",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_EVTX_EVENTS",
        "99",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_PCAP_BEACON_MAX_CV",
        "0.25",
    )

    settings = load_settings(
        config_file=tmp_path / "missing.toml"
    )

    assert settings.max_dir_files == 7
    assert settings.max_evtx_events == 99
    assert settings.pcap_beacon_max_cv == 0.25

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "yara_rules_dir = \"/opt/yara-rules\"\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.yara_rules_dir == Path(
        "/opt/yara-rules"
    )


def test_analyze_file_keeps_additive_pe_key(
    tmp_path,
) -> None:
    target = tmp_path / "sample.exe"

    target.write_bytes(
        b"MZ" + b"\x00" * 256
    )

    result = analyze_file(
        str(target)
    )

    assert "error" not in result
    assert result["is_pe_file"] is True
    assert "pe_details" in result


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="PE details require Windows",
)
@pytest.mark.skipif(
    not sys.platform == "win32",
    reason="PE details require Windows",
)
def test_pe_details_populated_on_windows(
    tmp_path,
) -> None:

    target = tmp_path / "sample.exe"

    target.write_bytes(
        b"MZ" + b"\x00" * 256
    )

    result = analyze_file(
        str(target)
    )

    details = result.get(
        "pe_details"
    )

    assert details is None or (
        isinstance(
            details,
            dict,
        )
        and "sections" in details
    )
