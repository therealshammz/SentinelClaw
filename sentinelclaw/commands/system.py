"""Host inspection command module (P6-30).

``system``, ``processes``, ``network``, ``windows-events`` and
``evtx``: raw collector output plus the offline EVTX analysis.
"""

from __future__ import annotations

import argparse

from sentinelclaw.commands._helpers import (
    print_cli_error,
    print_json,
)

from sentinelclaw.commands._scan_core import run_evtx_scan

from sentinelclaw.config.settings import get_settings

from sentinelclaw.tools.network_analyzer import get_network_connections
from sentinelclaw.tools.process_analyzer import get_processes
from sentinelclaw.tools.system_info import get_system_info
from sentinelclaw.tools.windows_event_analyzer import get_windows_events

from sentinelclaw.ui.console import print_evtx_dashboard


COMMANDS = (
    "system",
    "processes",
    "network",
    "windows-events",
    "evtx",
)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    subparsers.add_parser(
        "system",
        help="Show system information",
    )

    subparsers.add_parser(
        "processes",
        help="Show running processes",
    )

    subparsers.add_parser(
        "network",
        help="Show network connections",
    )

    subparsers.add_parser(
        "windows-events",
        help=("Show monitored Windows Security events"),
    )

    evtx_parser = subparsers.add_parser(
        "evtx",
        help=("Analyze an offline Windows Event Log (.evtx) file"),
    )

    evtx_parser.add_argument(
        "path",
        help="Path to the .evtx file",
    )

    evtx_parser.add_argument(
        "--json",
        action="store_true",
        help=("Print complete EVTX analysis as JSON"),
    )

    evtx_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed EVTX findings"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    if args.command == "system":
        print_json(get_system_info())

    elif args.command == "processes":
        print_json(get_processes())

    elif args.command == "network":
        print_json(get_network_connections())

    elif args.command == "windows-events":
        _handle_windows_events()

    elif args.command == "evtx":
        _handle_evtx(args)


def _handle_windows_events() -> None:
    try:
        events = get_windows_events(
            log_name="Security",
            max_events=get_settings().max_events_print,
        )
    except PermissionError:
        print_cli_error(
            "Windows Security log access denied.",
            ("Run PowerShell or VS Code as Administrator."),
        )

        raise SystemExit(1)
    except Exception as exc:
        print_cli_error(
            (f"Unable to read Windows Security events: {exc}"),
            ("Try running the terminal as Administrator."),
        )

        raise SystemExit(1)

    print_json(events)


def _handle_evtx(
    args: argparse.Namespace,
) -> None:
    report = run_evtx_scan(args.path)

    if args.json:
        print_json(report)
    else:
        print_evtx_dashboard(
            report,
            verbose=args.verbose,
        )

    if "error" in report:
        raise SystemExit(1)
