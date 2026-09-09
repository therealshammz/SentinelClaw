import subprocess
import sys

from sentinelclaw.config.logging import configure_logging


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelclaw",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_default_run_has_no_debug_output() -> None:
    result = run_cli("rules")

    assert result.returncode == 0
    assert "DEBUG" not in result.stderr
    assert "Loaded detection rules" in result.stdout


def test_debug_flag_emits_debug_lines_on_stderr() -> None:
    result = run_cli("--debug", "rules")

    assert result.returncode == 0
    assert "DEBUG" in result.stderr
    assert "DEBUG" not in result.stdout
    assert "Loaded detection rules" in result.stdout


def test_stdout_stays_clean_of_log_lines() -> None:
    result = run_cli("rules")

    for line in result.stdout.splitlines():
        assert not line.startswith(
            (
                "DEBUG ",
                "INFO ",
                "WARNING ",
                "ERROR ",
                "CRITICAL ",
            )
        )


def test_configure_logging_is_idempotent() -> None:
    import logging

    root = logging.getLogger()

    configure_logging(
        debug=True
    )

    assert root.level == logging.DEBUG

    handlers_before = set(
        root.handlers
    )

    configure_logging(
        debug=False
    )

    configure_logging(
        debug=False
    )

    assert root.level == logging.WARNING
    assert set(
        root.handlers
    ) == handlers_before
