"""P6-30 tests: command registry, dispatch routing, plugin API, slim main.

Verifies the extracted command layer: every built-in subcommand
parses and prints ``--help`` with exit 0, ``dispatch`` routes each
command to its owning module's ``handle``, the entry-point plugin
contract loads the sample detector, and ``main.py`` stays a thin
facade well under the 400-line target.
"""

import argparse
import importlib.metadata
import subprocess
import sys
from pathlib import Path

import pytest

from sentinelclaw.commands import (
    COMMAND_MODULES,
    dispatch,
    plugin_handlers,
)
from sentinelclaw.main import build_parser

ALL_COMMANDS = (
    "system",
    "processes",
    "network",
    "windows-events",
    "evtx",
    "scan",
    "dashboard",
    "summary",
    "watch",
    "report",
    "rules",
    "incidents",
    "history",
    "diff",
    "search",
    "accounts",
    "tree",
    "stats",
    "timeline",
    "investigate",
    "logs",
    "file",
    "pcap",
)


def registered_commands() -> set[str]:
    return {name for module in COMMAND_MODULES for name in module.COMMANDS}


def test_commands_cover_every_builtin_subcommand() -> None:
    assert registered_commands() == set(ALL_COMMANDS)


def test_main_stays_under_400_lines() -> None:
    main_path = Path(__file__).parents[1] / "sentinelclaw" / "main.py"

    line_count = len(main_path.read_text(encoding="utf-8").splitlines())

    assert line_count < 400


@pytest.mark.parametrize(
    "command",
    ALL_COMMANDS,
)
def test_every_command_help_exits_zero(
    command: str,
) -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(
            [
                command,
                "--help",
            ]
        )

    assert excinfo.value.code == 0


@pytest.mark.parametrize(
    "command",
    ALL_COMMANDS,
)
def test_dispatch_routes_to_owning_module(
    command: str,
    monkeypatch,
) -> None:
    target = next(module for module in COMMAND_MODULES if command in module.COMMANDS)

    called: list[str] = []

    monkeypatch.setattr(
        target,
        "handle",
        lambda args: called.append(args.command),
    )

    dispatch(argparse.Namespace(command=command))

    assert called == [command]


def test_parser_rejects_unknown_command() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["__not_a_command__"])

    assert excinfo.value.code == 2


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


def _sample_plugin_installed() -> bool:
    try:
        discovered = importlib.metadata.entry_points(group="sentinelclaw.detectors")
    except Exception:
        return False

    return any(entry_point.name == "sample" for entry_point in discovered)


requires_sample_plugin = pytest.mark.skipif(
    not _sample_plugin_installed(),
    reason=("sample plugin entry point is not installed (run: pip install -e .)"),
)


@requires_sample_plugin
def test_sample_plugin_registers_through_entry_point() -> None:
    parser = build_parser()

    args = parser.parse_args(["sample-plugin"])

    assert args.command == "sample-plugin"

    assert "sample-plugin" in plugin_handlers()


@requires_sample_plugin
def test_sample_plugin_command_executes() -> None:
    result = run_cli("sample-plugin")

    assert result.returncode == 0
    assert "sample detector plugin loaded" in result.stdout


@requires_sample_plugin
def test_sample_plugin_help_exits_zero() -> None:
    result = run_cli("sample-plugin", "--help")

    assert result.returncode == 0
    assert "sample-plugin" in result.stdout
