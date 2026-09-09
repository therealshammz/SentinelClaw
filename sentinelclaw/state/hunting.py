"""
CLI command implementations for stateful hunting (P3-17, P3-19).

Each ``cmd_*`` function renders one command's output to stdout (errors
to stderr, exiting 1 on hard failures) and reads scan state from the
store resolved through :func:`sentinelclaw.state.store.store_path`.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from typing import NoReturn

from sentinelclaw.state.analytics import (
    compare_record_sets,
    compare_records,
    event_id_frequencies,
    finding_id,
    finding_stats,
    incident_process_tree_lines,
    search_records,
    summarize_account_events,
    windows_events_from_records,
)
from sentinelclaw.state.store import (
    append_scan_record,
    latest_record,
    list_records,
    read_record,
    record_from_report,
    store_path,
)

WIDTH = 72

MAX_DISPLAY_DELTA_FINDINGS = 25

MAX_DISPLAY_SEARCH_MATCHES = 100


def _cli_error(
    message: str,
    suggestion: str | None = None,
) -> NoReturn:
    print(
        f"[ERROR] {message}",
        file=sys.stderr,
    )

    if suggestion:
        print(
            f"        {suggestion}",
            file=sys.stderr,
        )

    raise SystemExit(1)


def _finding_line(
    finding: dict,
) -> str:
    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).upper()

    rule_id = finding.get(
        "rule_id",
        "UNKNOWN",
    )

    title = finding.get(
        "title",
        "",
    )

    return (
        f"{finding_id(finding)} "
        f"{str(rule_id):<18} "
        f"[{severity:<11}] {title}"
    )


def _print_listing(
    heading: str,
    findings: list[dict],
    count: int,
    limit: int = MAX_DISPLAY_DELTA_FINDINGS,
) -> None:
    print()

    print(
        f"{heading}: {count}"
    )

    if not findings:
        print(
            "  (none)"
        )

        return

    for finding in findings[:limit]:
        print(
            "  " + _finding_line(finding)
        )

    remainder = count - len(
        findings[:limit]
    )

    if remainder > 0:
        print(
            f"  ... and {remainder} more"
        )


def _format_counter(
    counter: dict[str, int],
) -> list[tuple[str, int]]:
    return sorted(
        counter.items(),
        key=lambda item: (
            -item[1],
            str(item[0]),
        ),
    )


def print_delta_summary(
    baseline: dict,
    target: dict,
    scope_label: str | None = None,
) -> None:
    """Print the new/closed finding delta between two records."""
    comparison = compare_records(
        baseline,
        target,
    )

    print()
    print("=" * WIDTH)
    print(
        "SCAN DELTA"
    )
    print("=" * WIDTH)

    if scope_label:
        print(
            f"Scope: {scope_label}"
        )

    print(
        f"Baseline : "
        f"{comparison['baseline_id']} "
        f"({comparison['baseline_timestamp']})"
    )

    print(
        f"Target   : "
        f"{comparison['target_id']} "
        f"({comparison['target_timestamp']})"
    )

    print(
        f"Findings : "
        f"{comparison['baseline_findings']} "
        f"-> {comparison['target_findings']}"
    )

    if (
        comparison["new_count"] == 0
        and comparison["closed_count"] == 0
    ):
        print()
        print(
            "(no changes in findings)"
        )

        print("=" * WIDTH)
        print()

        return

    _print_listing(
        "New findings",
        comparison["new"],
        comparison["new_count"],
    )

    _print_listing(
        "Closed findings",
        comparison["closed"],
        comparison["closed_count"],
    )

    print()
    print("=" * WIDTH)
    print()


def print_scan_delta_vs_baselines(
    baselines: list[dict],
    report: dict,
    target_record: dict | None = None,
) -> None:
    """Print a scan's delta against one or more stored baseline records.

    Used by ``scan --last`` (single baseline) and ``scan --since``
    (every record at/after the cutoff). ``target_record`` is the
    persisted record for the current scan (carrying the assigned
    ``record_id``); when omitted it is derived from the report.
    """
    target = (
        target_record
        if target_record is not None
        else record_from_report(report)
    )

    comparison = compare_record_sets(
        baselines,
        target,
    )

    print()
    print("=" * WIDTH)
    print(
        "SCAN DELTA"
    )
    print("=" * WIDTH)

    if len(
        baselines
    ) == 1:
        scope = (
            "vs previous scan "
            f"{comparison['baseline_ids'][0]}"
        )
    else:
        scope = (
            f"vs {comparison['baseline_count']} "
            "earlier scan(s)"
        )

    print(
        f"Scope    : {scope}"
    )

    print(
        f"Current  : {target.get('record_id')} "
        f"({target.get('timestamp')})"
    )

    print(
        f"Findings : "
        f"{comparison['baseline_findings']} "
        f"(baseline) -> {comparison['target_findings']} "
        "(current)"
    )

    if (
        comparison["new_count"] == 0
        and comparison["closed_count"] == 0
    ):
        print()
        print(
            "(no changes in findings)"
        )

        print("=" * WIDTH)
        print()

        return

    _print_listing(
        "New findings",
        comparison["new"],
        comparison["new_count"],
    )

    _print_listing(
        "Closed findings",
        comparison["closed"],
        comparison["closed_count"],
    )

    print()
    print("=" * WIDTH)
    print()


def cmd_history() -> None:
    """Print the scan-state history table."""
    records = list_records()

    print()
    print("=" * WIDTH)
    print(
        "SCAN HISTORY"
    )
    print("=" * WIDTH)

    if not records:
        print()
        print(
            "(no scan records yet -- run "
            "'sentinelclaw scan' first)"
        )
        print()
        print("=" * WIDTH)
        print()

        return

    print(
        f"Store: {store_path()}"
    )

    rows = []

    for record in records:
        risk = record.get(
            "risk",
            {},
        )

        if not isinstance(
            risk,
            dict,
        ):
            risk = {}

        rows.append(
            (
                str(
                    record.get(
                        "record_id",
                        "?",
                    )
                ),
                str(
                    record.get(
                        "timestamp",
                        "?",
                    )
                ),
                str(
                    record.get(
                        "hostname",
                        "?",
                    )
                ),
                (
                    f"{risk.get('score', 0)} "
                    f"{str(risk.get('level', '')).upper()}"
                ),
                str(
                    len(
                        record.get(
                            "findings",
                            [],
                        )
                    )
                ),
            )
        )

    widths = [
        max(
            len(header),
            *(len(row[index]) for row in rows),
        )
        for index, header in enumerate(
            (
                "RECORD ID",
                "TIMESTAMP",
                "HOSTNAME",
                "RISK",
                "FINDINGS",
            )
        )
    ]

    headers = (
        "RECORD ID",
        "TIMESTAMP",
        "HOSTNAME",
        "RISK",
        "FINDINGS",
    )

    line = " | ".join(
        header.ljust(widths[index])
        for index, header in enumerate(
            headers
        )
    )

    print()
    print(line)

    print(
        "-+-".join(
            "-" * width
            for width in widths
        )
    )

    for row in rows:
        print(
            " | ".join(
                row[index].ljust(widths[index])
                for index in range(len(headers))
            )
        )

    total_findings = sum(
        len(
            record.get(
                "findings",
                [],
            )
        )
        for record in records
    )

    print()
    print(
        f"Records: {len(records)} | "
        f"Findings (all records): {total_findings}"
    )

    print("=" * WIDTH)
    print()


def _resolve_diff_pair(
    args,
) -> tuple[
    dict,
    dict,
]:
    records = list_records()

    if len(records) < 2:
        _cli_error(
            "diff needs at least two scan records in the state "
            "store.",
            "Run 'sentinelclaw scan' twice, then retry.",
        )

    if getattr(
        args,
        "last",
        False,
    ):
        return (
            records[1],
            records[0],
        )

    baseline = read_record(
        args.id1
    )

    target = read_record(
        args.id2
    )

    if baseline is None:
        _cli_error(
            f"Unknown baseline record: {args.id1}",
            "List records with 'sentinelclaw history'.",
        )

    if target is None:
        _cli_error(
            f"Unknown target record: {args.id2}",
            "List records with 'sentinelclaw history'.",
        )

    assert baseline is not None
    assert target is not None

    return (
        baseline,
        target,
    )


def cmd_diff(
    args,
) -> None:
    """Print new/closed findings between two stored records."""
    baseline, target = _resolve_diff_pair(
        args
    )

    print_delta_summary(
        baseline,
        target,
        scope_label=(
            "stored records"
            if getattr(
                args,
                "last",
                False,
            )
            else (
                f"{args.id1} -> {args.id2}"
            )
        ),
    )


def _default_scan() -> dict:
    from sentinelclaw.main import run_scan

    return run_scan(
        show_progress=False,
        include_raw=False,
    )


def _scan_cycle(
    scan_fn: Callable[[], dict],
) -> dict:
    try:
        report = scan_fn()
    except Exception as exc:
        print(
            f"[watch] scan failed: {exc}",
            file=sys.stderr,
        )

        raise SystemExit(1)

    if not isinstance(
        report,
        dict,
    ):
        print(
            "[watch] scan callable did not return a report",
            file=sys.stderr,
        )

        raise SystemExit(1)

    return report


def cmd_watch(
    args,
    scan_fn: Callable[[], dict] | None = None,
) -> None:
    """Run scans in a loop, appending records and printing deltas.

    Ctrl-C stops the loop cleanly (exit 0). ``--count`` bounds the
    number of iterations; the default (0) runs until interrupted.
    ``scan_fn`` is injectable for tests; it defaults to a live scan.
    """
    run_scan_callback = (
        scan_fn
        if scan_fn is not None
        else _default_scan
    )

    interval = max(
        0,
        int(
            getattr(
                args,
                "interval",
                30,
            )
        ),
    )

    max_cycles = max(
        0,
        int(
            getattr(
                args,
                "count",
                0,
            )
        ),
    )

    print()
    print("=" * WIDTH)
    print(
        "WATCH MODE"
    )
    print("=" * WIDTH)

    print(
        f"Interval: {interval}s | "
        f"Cycles: "
        f"{'unlimited' if max_cycles == 0 else max_cycles}"
    )

    if interval == 0:
        print(
            "Note: interval 0 scans continuously."
        )

    print(
        "Ctrl-C stops the watch."
    )

    print("=" * WIDTH)
    print()

    cycle = 0

    try:
        while (
            max_cycles == 0
            or cycle < max_cycles
        ):
            cycle += 1

            baseline = latest_record()

            report = _scan_cycle(
                run_scan_callback
            )

            record = record_from_report(
                report
            )

            record_id = append_scan_record(
                record
            )

            print()
            print(
                f"[watch] cycle {cycle} "
                f"record {record_id}"
            )

            if baseline is None:
                print(
                    "[watch] first scan recorded; "
                    "no baseline to diff against."
                )
            else:
                current = read_record(
                    record_id
                )

                assert current is not None

                comparison = compare_records(
                    baseline,
                    current,
                )

                if (
                    comparison["new_count"] == 0
                    and comparison["closed_count"] == 0
                ):
                    print(
                        "[watch] findings unchanged "
                        f"({comparison['target_findings']} total)."
                    )
                else:
                    print(
                        f"[watch] +{comparison['new_count']} "
                        f"new / -{comparison['closed_count']} "
                        "closed finding(s)"
                    )

                    for finding in comparison["new"]:
                        print(
                            "  + " + _finding_line(finding)
                        )

                    for finding in comparison["closed"]:
                        print(
                            "  - " + _finding_line(finding)
                        )

            if (
                max_cycles == 0
                or cycle < max_cycles
            ):
                if interval > 0:
                    time.sleep(
                        interval
                    )
                else:
                    time.sleep(
                        0.05
                    )
    except KeyboardInterrupt:
        print()

        print(
            "[watch] stopped by user "
            f"after {cycle} cycle(s)."
        )

        print(
            "Records remain in the state store; "
            "run 'sentinelclaw history' to review."
        )


def cmd_search(
    args,
) -> None:
    """Search findings and incidents across scan-state records."""
    records = list_records()

    matches = search_records(
        records,
        args.keyword,
        record_id=getattr(
            args,
            "state",
            None,
        ),
    )

    print()
    print("=" * WIDTH)
    print(
        "SEARCH"
    )
    print("=" * WIDTH)

    print(
        f"Keyword: '{args.keyword}'"
    )

    record_scope = getattr(
        args,
        "state",
        None,
    )

    if record_scope:
        print(
            f"Record : {record_scope}"
        )

    if not matches:
        print()
        print(
            "(no matches)"
        )

        print("=" * WIDTH)
        print()

        return

    print(
        f"Matches: {len(matches)}"
    )

    for match in matches[:MAX_DISPLAY_SEARCH_MATCHES]:
        severity = str(
            match.get(
                "severity",
                "info",
            )
        ).upper()

        if match["kind"] == "finding":
            identity = (
                f"{match['finding_id']} "
                f"{str(match.get('rule_id', ''))}"
            )
        else:
            identity = str(
                match.get(
                    "incident_id",
                    "",
                )
            )

        print(
            f"  {match['record_id']:<28} "
            f"{match['kind']:<8} "
            f"[{severity:<11}] "
            f"{identity:<24} {match['title']}"
        )

    remainder = (
        len(matches)
        - MAX_DISPLAY_SEARCH_MATCHES
    )

    if remainder > 0:
        print(
            f"  ... and {remainder} more"
        )

    print("=" * WIDTH)
    print()


def cmd_accounts() -> None:
    """Summarize logon activity from windows events in scan state."""
    records = list_records()

    events = windows_events_from_records(
        records
    )

    summary = summarize_account_events(
        events
    )

    print()
    print("=" * WIDTH)
    print(
        "ACCOUNTS -- logon activity in scan state"
    )
    print("=" * WIDTH)

    if not events:
        print()
        print(
            "(no windows events in scan state -- run "
            "'sentinelclaw scan --json-raw' to collect them)"
        )

        print("=" * WIDTH)
        print()

        return

    failed = summary["failed_logons"]
    successful = summary[
        "successful_logons"
    ]
    created = summary[
        "account_creations"
    ]

    print(
        f"Windows events analyzed: {len(events)}"
    )

    sections = (
        (
            "Failed logons by account",
            failed,
        ),
        (
            "Successful logons by account",
            successful,
        ),
        (
            "Account creations",
            created,
        ),
    )

    for heading, counter in sections:
        print()
        print(
            f"{heading} (total {sum(counter.values())})"
        )

        rows = _format_counter(
            counter
        )

        if not rows:
            print(
                "  (none)"
            )

            continue

        width = max(
            len(account)
            for account, _ in rows
        )

        for account, count in rows:
            print(
                f"  {account:<{width}} {count}"
            )

    print()
    print(
        f"Failed logons total    : {sum(failed.values())}"
    )

    print(
        f"Successful logons total: "
        f"{sum(successful.values())}"
    )

    print(
        f"Account creations total: "
        f"{sum(created.values())}"
    )

    print("=" * WIDTH)
    print()


def cmd_tree(
    args,
) -> None:
    """Render the process tree for one incident's member findings."""
    records = list_records()

    target_record = None
    incident = None

    for record in records:
        for candidate in record.get(
            "incidents",
            [],
        ):
            if not isinstance(
                candidate,
                dict,
            ):
                continue

            if str(
                candidate.get(
                    "incident_id"
                )
            ) == str(
                args.incident_id
            ):
                incident = candidate
                target_record = record
                break

        if incident is not None:
            break

    if incident is None:
        _cli_error(
            f"Incident not found in scan state: "
            f"{args.incident_id}",
            "List incidents with 'sentinelclaw incidents' or "
            "search state with 'sentinelclaw search'.",
        )

    lines = incident_process_tree_lines(
        incident,
        target_record,
    )

    print()

    for line in lines:
        print(line)

    print()


def cmd_stats() -> None:
    """Print event-ID frequency and finding statistics from state."""
    records = list_records()

    events = windows_events_from_records(
        records
    )

    frequencies = event_id_frequencies(
        events
    )

    stats = finding_stats(
        records
    )

    print()
    print("=" * WIDTH)
    print(
        "STATS -- scan state overview"
    )
    print("=" * WIDTH)

    print()
    print(
        "EVENT ID FREQUENCY (windows events)"
    )

    print("-" * WIDTH)

    if not events:
        print(
            "(no windows events in scan state -- run "
            "'sentinelclaw scan --json-raw' to collect them)"
        )
    else:
        event_width = max(
            len(str(row["event_id"]))
            for row in frequencies
        )

        name_width = max(
            (
                len(row["event_name"])
                for row in frequencies
            ),
            default=0,
        )

        name_width = max(
            name_width,
            len("EVENT NAME"),
        )

        print(
            f"{'EVENT ID':<{event_width}}  "
            f"{'EVENT NAME':<{name_width}}  COUNT"
        )

        for row in frequencies:
            print(
                f"{str(row['event_id']):<{event_width}}  "
                f"{str(row['event_name']):<{name_width}}  "
                f"{row['count']}"
            )

        print(
            f"{'TOTAL':<{event_width}}  "
            f"{'':<{name_width}}  {len(events)}"
        )

    print()
    print(
        "FINDING COUNTS"
    )

    print("-" * WIDTH)

    severity = stats["severity"]

    for level in (
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ):
        count = severity.get(
            level,
            0,
        )

        if count:
            label = (
                level
                if level != "info"
                else "informational"
            )

            print(
                f"  {label:<13} {count}"
            )

    if not any(
        severity.values()
    ):
        print(
            "  (no findings in scan state)"
        )

    print()
    print(
        "FINDING COUNTS BY CATEGORY"
    )

    print("-" * WIDTH)

    categories = stats["category"]

    if not categories:
        print(
            "  (none)"
        )
    else:
        width = max(
            len(category)
            for category in categories
        )

        for category, count in sorted(
            categories.items()
        ):
            print(
                f"  {category:<{width}} {count}"
            )

    print("=" * WIDTH)
    print()
