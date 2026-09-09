import subprocess
import sys

from sentinelclaw.main import (
    build_parser,
    format_rule_line,
    rules_summary_lines,
)


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelclaw.main",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_parser_accepts_dashboard_command() -> None:
    parser = build_parser()

    args = parser.parse_args(
        ["dashboard"]
    )

    assert args.command == "dashboard"


def test_parser_accepts_report_format() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "report",
            "--format",
            "html",
        ]
    )

    assert args.command == "report"
    assert args.format == "html"


def test_module_help_exits_successfully() -> None:
    result = run_cli("--help")

    assert result.returncode == 0
    assert "SentinelClaw" in result.stdout
    assert "dashboard" in result.stdout
    assert "investigate" in result.stdout
    assert "pcap" in result.stdout


def test_rules_command_exits_successfully() -> None:
    result = run_cli("rules")

    assert result.returncode == 0
    assert "Loaded detection rules" in result.stdout


def test_rules_command_shows_metadata_and_counts() -> None:
    result = run_cli("rules")

    assert result.returncode == 0
    assert "Loaded detection rules" in result.stdout
    assert "[status=" in result.stdout
    assert "Rules by status:" in result.stdout
    assert "Rules by category:" in result.stdout
    assert "proven=" in result.stdout

    if sys.platform.startswith("linux"):
        assert "experimental=" in result.stdout


def test_format_rule_line_appends_metadata_tags() -> None:
    rule = {
        "id": "T-001",
        "title": "Test rule",
        "category": "process",
        "severity": "medium",
        "status": "experimental",
        "noisy": True,
        "level_override": "high",
    }

    line = format_rule_line(rule)

    assert line.startswith("T-001 | HIGH | process | Test rule")
    assert "[status=experimental]" in line
    assert "[noisy]" in line
    assert "[level_override=high]" in line


def test_format_rule_line_without_metadata_matches_base_format() -> None:
    rule = {
        "id": "T-002",
        "title": "Plain rule",
        "category": "file",
        "severity": "low",
    }

    assert format_rule_line(rule) == "T-002 | LOW | file | Plain rule"


def test_rules_summary_lines_groups_by_status_and_category() -> None:
    rules = [
        {"category": "process", "status": "proven"},
        {"category": "process", "status": "experimental"},
        {"category": "file", "status": "proven"},
    ]

    lines = rules_summary_lines(rules)

    assert "Rules by status: experimental=1 proven=2" in lines
    assert "Rules by category: file=1 process=2" in lines


def test_rules_summary_lines_defaults_missing_metadata() -> None:
    rules = [
        {"category": "process"},
    ]

    lines = rules_summary_lines(rules)

    assert "Rules by status: unspecified=1" in lines
    assert "Rules by category: process=1" in lines


def test_missing_file_is_reported_cleanly() -> None:
    result = run_cli(
        "file",
        "__sentinelclaw_missing_test_file__.exe",
    )

    combined = (
        result.stdout
        + result.stderr
    ).lower()

    assert result.returncode != 0
    assert "does not exist" in combined
