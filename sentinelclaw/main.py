"""SentinelClaw CLI entry point.

P6-30: this module is deliberately thin -- command registration and
dispatch live in :mod:`sentinelclaw.commands`, and the scan pipeline
lives in :mod:`sentinelclaw.commands._scan_core`. The re-exports below
are the stable public surface: tests and callers import collector,
detector, and scan names from here, and runtime overrides applied to
this module (e.g. test monkeypatching) stay visible to the command
layer, which resolves those names through this namespace at call time.
"""

from __future__ import annotations

import argparse

from sentinelclaw.commands import (
    dispatch,
    register_all,
)

from sentinelclaw.commands._helpers import (
    print_cli_error,
    print_json,
)

from sentinelclaw.commands._scan_core import (
    run_directory_scan,
    run_evtx_scan,
    run_file_scan,
    run_log_scan,
    run_pcap_scan,
    run_scan,
    yara_findings_for_file,
)

from sentinelclaw.commands.rules import (
    format_rule_line,
    rules_summary_lines,
)

from sentinelclaw.config.logging import configure_logging

from sentinelclaw.detectors.process_detector import analyze_processes

from sentinelclaw.tools.auth_log_analyzer import get_auth_events
from sentinelclaw.tools.network_analyzer import get_network_connections
from sentinelclaw.tools.persistence_analyzer import get_persistence_records
from sentinelclaw.tools.process_analyzer import get_processes
from sentinelclaw.tools.system_info import get_system_info
from sentinelclaw.tools.windows_event_analyzer import get_windows_events

__all__ = [
    "analyze_processes",
    "build_parser",
    "dispatch",
    "execute_command",
    "format_rule_line",
    "get_auth_events",
    "get_network_connections",
    "get_persistence_records",
    "get_processes",
    "get_system_info",
    "get_windows_events",
    "main",
    "print_json",
    "rules_summary_lines",
    "run_directory_scan",
    "run_evtx_scan",
    "run_file_scan",
    "run_log_scan",
    "run_pcap_scan",
    "run_scan",
    "yara_findings_for_file",
]

execute_command = dispatch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("SentinelClaw - Local defensive cybersecurity CLI")
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help=("Show Python exceptions for development and troubleshooting"),
    )

    register_all(parser)

    return parser


def main() -> None:
    parser = build_parser()

    args = parser.parse_args()

    configure_logging(debug=args.debug)

    try:
        dispatch(args)

    except KeyboardInterrupt:
        print()
        print_cli_error("Operation cancelled by user.")

        raise SystemExit(130)

    except SystemExit:
        raise

    except PermissionError as exc:
        if args.debug:
            raise

        print_cli_error(
            f"Permission denied: {exc}",
            ("Try running the terminal with the required privileges."),
        )

        raise SystemExit(1)

    except FileNotFoundError as exc:
        if args.debug:
            raise

        print_cli_error(f"File not found: {exc}")

        raise SystemExit(1)

    except RuntimeError as exc:
        if args.debug:
            raise

        print_cli_error(str(exc))

        raise SystemExit(1)

    except Exception as exc:
        if args.debug:
            raise

        print_cli_error(
            (f"SentinelClaw encountered an unexpected error: {exc}"),
            ("Run again with --debug to show the Python traceback."),
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
