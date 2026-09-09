"""Stateful hunting command module (P6-30).

Wraps the scan-state commands implemented in
``sentinelclaw.state.hunting`` (history, diff, search, accounts, tree,
stats) and the scan-backed ``incidents``/``timeline`` commands.
"""

from __future__ import annotations

import argparse

from sentinelclaw.commands._helpers import print_cli_error

from sentinelclaw.state.hunting import (
    cmd_accounts,
    cmd_diff,
    cmd_history,
    cmd_search,
    cmd_stats,
    cmd_tree,
)

from sentinelclaw.ui.console import print_incidents_dashboard


COMMANDS = (
    "history",
    "diff",
    "search",
    "accounts",
    "tree",
    "stats",
    "timeline",
    "incidents",
)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    incidents_parser = subparsers.add_parser(
        "incidents",
        help=("Run scan and show correlated incidents"),
    )

    incidents_parser.add_argument(
        "--verbose",
        action="store_true",
        help=("Show detailed incident information"),
    )

    subparsers.add_parser(
        "history",
        help=("List scan records from the local scan-state store"),
    )

    diff_parser = subparsers.add_parser(
        "diff",
        help=("Show new/closed findings between two scan records (or the last two)"),
    )

    diff_parser.add_argument(
        "id1",
        nargs="?",
        default=None,
        help="Baseline record id",
    )

    diff_parser.add_argument(
        "id2",
        nargs="?",
        default=None,
        help="Target record id",
    )

    diff_parser.add_argument(
        "--last",
        action="store_true",
        help=("Diff the two most recent records"),
    )

    search_parser = subparsers.add_parser(
        "search",
        help=("Search findings and incidents across scan-state records"),
    )

    search_parser.add_argument(
        "keyword",
        help="Case-insensitive keyword to search for",
    )

    search_parser.add_argument(
        "--state",
        default=None,
        help=("Restrict the search to one record id"),
    )

    subparsers.add_parser(
        "accounts",
        help=("Summarize logon activity from windows events in scan state"),
    )

    tree_parser = subparsers.add_parser(
        "tree",
        help=("Render the process tree for one incident's member findings"),
    )

    tree_parser.add_argument(
        "incident_id",
        help="Incident id to drill into",
    )

    subparsers.add_parser(
        "stats",
        help=("Event-ID frequency and finding-count statistics from scan state"),
    )

    subparsers.add_parser(
        "timeline",
        help=("Run scan and show chronological security timeline"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    if args.command == "history":
        cmd_history()

    elif args.command == "diff":
        _handle_diff(args)

    elif args.command == "search":
        cmd_search(args)

    elif args.command == "accounts":
        cmd_accounts()

    elif args.command == "tree":
        cmd_tree(args)

    elif args.command == "stats":
        cmd_stats()

    elif args.command == "incidents":
        _handle_incidents(args)

    elif args.command == "timeline":
        _handle_timeline(args)


def _handle_diff(
    args: argparse.Namespace,
) -> None:
    if not getattr(
        args,
        "last",
        False,
    ) and (args.id1 is None or args.id2 is None):
        print_cli_error(
            "diff needs two record ids or --last.",
            "List records with 'sentinelclaw history'.",
        )

        raise SystemExit(1)

    cmd_diff(args)


def _handle_incidents(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(show_progress=True)

    print_incidents_dashboard(
        report.get(
            "incidents",
            [],
        ),
        verbose=args.verbose,
    )


def _handle_timeline(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(show_progress=True)

    print_timeline(
        report.get(
            "timeline",
            [],
        )
    )


def print_timeline(
    timeline: list[dict],
) -> None:
    print()
    print("=" * 72)
    print("                    SENTINELCLAW TIMELINE")
    print("=" * 72)

    if not timeline:
        print()
        print("[+] No timeline events available.")
        print()
        print("=" * 72)
        return

    for event in timeline:
        print()

        timestamp = event.get("timestamp")

        timestamp_text = timestamp if timestamp else "TIME UNKNOWN"

        severity = str(
            event.get(
                "severity",
                "info",
            )
        ).upper()

        event_type = str(
            event.get(
                "event_type",
                "event",
            )
        ).upper()

        print(timestamp_text)

        print(f"  [{severity}] [{event_type}] {event.get('title')}")

        rule_id = event.get("rule_id")

        if rule_id:
            print(f"  Rule: {rule_id}")

        incident_id = event.get("incident_id")

        if incident_id:
            print(f"  Incident: {incident_id}")

        description = event.get("description")

        if description:
            print(f"  Reason: {description}")

    print()
    print("=" * 72)
    print(f"Timeline events: {len(timeline)}")
    print("=" * 72)
    print()
