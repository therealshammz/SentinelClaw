"""``report`` command module (P6-30).

Runs the scan and writes JSON/text/HTML/CSV/JSONL report files into
the resolved reports directory.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinelclaw.config.settings import get_settings

from sentinelclaw.reporting.report_generator import (
    save_report_formats,
)


COMMANDS = ("report",)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    report_parser = subparsers.add_parser(
        "report",
        help=("Generate SentinelClaw security assessment reports"),
    )

    report_parser.add_argument(
        "--format",
        choices=[
            "json",
            "text",
            "html",
            "csv",
            "jsonl",
            "all",
        ],
        default="all",
        help=("Report format to generate (default: all)"),
    )

    report_parser.add_argument(
        "--json-raw",
        action="store_true",
        help=("Embed raw collector dumps in the JSON report"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    from sentinelclaw import main as cli

    report = cli.run_scan(
        show_progress=True,
        include_raw=args.json_raw,
    )

    created_files = save_requested_report_formats(
        report,
        args.format,
    )

    print_report_result(
        report,
        created_files,
    )


def save_requested_report_formats(
    report: dict,
    requested_format: str,
) -> dict[str, Path]:
    formats: tuple[str, ...]

    if requested_format == "all":
        formats = (
            "json",
            "text",
            "html",
        )
    else:
        formats = (requested_format,)

    try:
        return save_report_formats(
            report=report,
            output_directory=get_settings().resolved_report_dir,
            formats=formats,
        )
    except PermissionError as exc:
        raise RuntimeError("Permission denied while writing reports.") from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to write reports: {exc}") from exc


def print_report_result(
    report: dict,
    created_files: dict[str, Path],
) -> None:
    print()
    print("=" * 72)
    print("                  SENTINELCLAW REPORT COMPLETE")
    print("=" * 72)

    print()

    print(f"Risk Score     : {report['risk']['score']}/100")

    print(f"Risk Level     : {report['risk']['level'].upper()}")

    print(f"Findings       : {report['summary']['total_findings']}")

    print(f"Incidents      : {report['summary']['incidents']}")

    print(f"Timeline Events: {report['summary']['timeline_events']}")

    print()
    print("Generated files")
    print("-" * 72)

    for report_type, path in created_files.items():
        print(f"{report_type.upper():<8}: {path}")

    print()
    print("=" * 72)
    print()
