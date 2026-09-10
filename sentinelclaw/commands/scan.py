"""``scan``, ``dashboard``, ``summary`` and ``watch`` command module (P6-30).

``scan`` runs the deterministic pipeline and prints machine-readable
JSON (plus optional baseline deltas); ``dashboard``/``summary`` render
the human consoles; ``watch`` loops scans and prints finding deltas.
"""

from __future__ import annotations

import argparse

from sentinelclaw.config.constants import REPORT_SCHEMA_VERSION

from sentinelclaw.commands._helpers import (
    parse_since,
    print_json,
)

from sentinelclaw.reporting.report_generator import (
    generate_jsonl_report,
)

from sentinelclaw.state.hunting import (
    cmd_watch,
    print_scan_delta_vs_baselines,
)

from sentinelclaw.state.store import (
    append_scan_record,
    latest_record,
    record_from_report,
    records_since,
)

from sentinelclaw.ui.console import print_dashboard


COMMANDS = (
    "scan",
    "dashboard",
    "summary",
    "watch",
)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    scan_parser = subparsers.add_parser(
        "scan",
        help=("Run complete scan and print machine-readable JSON"),
    )

    scan_parser.add_argument(
        "--json-raw",
        action="store_true",
        help=("Embed raw collector dumps (processes, network, windows events) in the JSON output"),
    )

    scan_parser.add_argument(
        "--format",
        choices=[
            "json",
            "jsonl",
        ],
        default="json",
        help=(
            "Output format for the scan report "
            "(default: json; jsonl emits one "
            "JSON object per line)"
        ),
    )

    scan_parser.add_argument(
        "--since",
        default=None,
        help=("ISO timestamp; show new/closed findings since records at or after this time"),
    )

    scan_parser.add_argument(
        "--last",
        action="store_true",
        help=("Show new/closed findings versus the previous scan record"),
    )

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help=("Run scan and display the SentinelClaw security console"),
    )

    dashboard_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed evidence, MITRE mappings, processes and IPs"),
    )

    summary_parser = subparsers.add_parser(
        "summary",
        help=("Run scan and show compact security summary"),
    )

    summary_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed findings",
    )

    watch_parser = subparsers.add_parser(
        "watch",
        help=("Run scans in a loop, recording state and printing finding deltas"),
    )

    watch_parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help=("Seconds between scans (default: 30)"),
    )

    watch_parser.add_argument(
        "--count",
        type=int,
        default=0,
        help=("Number of cycles to run (default: 0 = until interrupted)"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    if args.command == "scan":
        _handle_scan(args)

    elif args.command == "watch":
        cmd_watch(args)

    else:
        _handle_dashboard_summary(args)


def _handle_scan(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(
        show_progress=False,
        include_raw=args.json_raw,
    )

    baselines: list[dict] = []

    if getattr(
        args,
        "since",
        None,
    ):
        cutoff = parse_since(args.since)

        baselines = records_since(cutoff)
    elif getattr(
        args,
        "last",
        False,
    ):
        baseline = latest_record()

        if baseline is not None:
            baselines = [baseline]

    # P3-17: persist the bounded scan record (CLI layer, so
    # ``run_scan`` and its tests stay untouched). The baseline is
    # captured before appending so the fresh record never diffs
    # against itself.
    state_record = record_from_report(report)

    record_id = append_scan_record(state_record)

    state_record["record_id"] = record_id

    if (
        getattr(
            args,
            "format",
            None,
        )
        == "jsonl"
    ):
        print(
            generate_jsonl_report(report),
            end="",
        )
    else:
        # P3-18: the printed report carries the schema version on a
        # shallow copy -- ``run_scan``'s own dict keeps its frozen
        # key set (tests assert exact equality).
        export = dict(report)

        export.setdefault(
            "schema_version",
            REPORT_SCHEMA_VERSION,
        )

        print_json(export)

    if baselines:
        print_scan_delta_vs_baselines(
            baselines,
            report,
            target_record=state_record,
        )


def _handle_dashboard_summary(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(show_progress=True)

    print_dashboard(
        report,
        verbose=args.verbose,
    )
