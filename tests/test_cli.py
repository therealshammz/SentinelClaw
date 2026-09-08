import subprocess
import sys

from sentinelclaw.main import build_parser


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
