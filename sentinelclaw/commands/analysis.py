"""Offline artifact analysis command module (P6-30).

``file``, ``pcap`` and ``logs`` run the per-artifact deterministic
pipelines and render their dashboards (or JSON).
"""

from __future__ import annotations

import argparse

from sentinelclaw.commands._helpers import print_json

from sentinelclaw.commands._scan_core import (
    run_file_scan,
    run_log_scan,
    run_pcap_scan,
)

from sentinelclaw.ui.console import (
    print_directory_dashboard,
    print_file_dashboard,
    print_log_dashboard,
    print_pcap_dashboard,
)


COMMANDS = (
    "file",
    "pcap",
    "logs",
)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    logs_parser = subparsers.add_parser(
        "logs",
        help="Analyze a text log file",
    )

    logs_parser.add_argument(
        "file",
        help="Path to the log file",
    )

    logs_parser.add_argument(
        "--json",
        action="store_true",
        help=("Print complete log analysis as JSON"),
    )

    logs_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed log findings"),
    )

    file_parser = subparsers.add_parser(
        "file",
        help="Analyze a local file",
    )

    file_parser.add_argument(
        "path",
        help="Path to the file",
    )

    file_parser.add_argument(
        "--json",
        action="store_true",
        help=("Print complete file analysis as JSON"),
    )

    file_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed file findings"),
    )

    pcap_parser = subparsers.add_parser(
        "pcap",
        help=("Analyze a PCAP or PCAPNG capture"),
    )

    pcap_parser.add_argument(
        "path",
        help="Path to capture file",
    )

    pcap_parser.add_argument(
        "--json",
        action="store_true",
        help=("Print complete PCAP analysis as JSON"),
    )

    pcap_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed PCAP findings"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    if args.command == "logs":
        _handle_logs(args)

    elif args.command == "file":
        _handle_file(args)

    elif args.command == "pcap":
        _handle_pcap(args)


def _handle_logs(
    args: argparse.Namespace,
) -> None:
    report = run_log_scan(args.file)

    if args.json:
        print_json(report)
    else:
        print_log_dashboard(
            report,
            verbose=args.verbose,
        )

    if "error" in report:
        raise SystemExit(1)


def _handle_file(
    args: argparse.Namespace,
) -> None:
    report = run_file_scan(args.path)

    if args.json:
        print_json(report)
    else:
        if (
            report.get(
                "analysis",
                {},
            ).get("type")
            == "directory"
        ):
            print_directory_dashboard(
                report,
                verbose=args.verbose,
            )
        else:
            print_file_dashboard(
                report,
                verbose=args.verbose,
            )

    if "error" in report:
        raise SystemExit(1)


def _handle_pcap(
    args: argparse.Namespace,
) -> None:
    report = run_pcap_scan(args.path)

    if args.json:
        print_json(report)
    else:
        print_pcap_dashboard(
            report,
            verbose=args.verbose,
        )

    if "error" in report:
        raise SystemExit(1)
