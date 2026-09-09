from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelclaw.ai.qwen_analyzer import analyze_report_with_qwen

from sentinelclaw.config.logging import configure_logging

from sentinelclaw.config.paths import PACKAGE_DIRECTORY

from sentinelclaw.config.constants import REPORT_SCHEMA_VERSION

from sentinelclaw.config.settings import get_settings

from sentinelclaw.detectors.auth_detector import analyze_auth_events
from sentinelclaw.detectors.file_detector import analyze_file_findings
from sentinelclaw.detectors.log_detector import (
    analyze_log_events,
    analyze_windows_events,
)
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.pcap_detector import analyze_pcap_findings
from sentinelclaw.detectors.persistence_detector import (
    analyze_persistence_records,
)
from sentinelclaw.detectors.process_detector import analyze_processes

from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.engine.rule_engine import (
    load_rules_from_directory,
    run_rules,
)
from sentinelclaw.engine.timeline_engine import build_timeline

from sentinelclaw.models.findings import calculate_risk_score

from sentinelclaw.reporting.report_generator import (
    generate_jsonl_report,
    save_report_formats,
)

from sentinelclaw.sigma.importer import (
    SIGMA_RELEASE_TAG,
    download_release_zip,
    import_into,
    prepare_source_directory,
    release_tag_from_env,
    tally_by_reason,
)

from sentinelclaw.tools.auth_log_analyzer import get_auth_events
from sentinelclaw.tools.file_analyzer import analyze_file
from sentinelclaw.tools.log_analyzer import analyze_log_file
from sentinelclaw.tools.network_analyzer import get_network_connections
from sentinelclaw.tools.persistence_analyzer import (
    get_persistence_records,
)
from sentinelclaw.tools.process_analyzer import get_processes
from sentinelclaw.tools.system_info import get_system_info
from sentinelclaw.tools.windows_event_analyzer import get_windows_events

from sentinelclaw.ui.console import (
    print_dashboard,
    print_file_dashboard,
    print_incidents_dashboard,
    print_log_dashboard,
    print_pcap_dashboard,
)

from sentinelclaw.state.hunting import (
    cmd_accounts,
    cmd_diff,
    cmd_history,
    cmd_search,
    cmd_stats,
    cmd_tree,
    cmd_watch,
    print_scan_delta_vs_baselines,
)
from sentinelclaw.state.store import (
    append_scan_record,
    latest_record,
    record_from_report,
    records_since,
)

from sentinelclaw.ui.progress import ScanProgress


logger = logging.getLogger(
    __name__
)


def print_json(data: Any) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            default=str,
        )
    )


def parse_since(value: str) -> datetime:
    """Parse a ``--since`` ISO timestamp into a tz-aware datetime."""
    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(
            text
        )
    except ValueError as exc:
        raise RuntimeError(
            f"Invalid --since timestamp: {value}"
        ) from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed


def print_cli_error(
    message: str,
    suggestion: str | None = None,
) -> None:
    print(
        f"[ERROR] {message}",
        file=sys.stderr,
    )

    if suggestion:
        print(
            f"        {suggestion}",
            file=sys.stderr,
        )


def get_rules() -> list[dict]:
    try:
        return load_rules_from_directory(
            get_settings().resolved_rules_dir
        )
    except Exception as exc:
        raise RuntimeError(
            f"Unable to load detection rules: {exc}"
        ) from exc


def rule_destination_directories(
    cli_destination: str | None,
) -> list[Path]:
    """Return the rule directories a Sigma import writes into.

    The primary destination is the resolved runtime rules directory (or
    an explicit ``--dest``). When the runtime directory is the packaged
    copy inside a repository checkout, the repo's sibling ``rules/``
    directory receives the identical tree so the two shipped copies stay
    in sync. Environment-overridden directories never trigger the
    mirror (the override owns the layout).
    """
    settings = get_settings()

    if cli_destination:
        return [
            Path(cli_destination).expanduser().resolve()
        ]

    primary = settings.resolved_rules_dir

    destinations = [
        primary
    ]

    packaged = PACKAGE_DIRECTORY / "rules"

    repo_rules = PACKAGE_DIRECTORY.parent / "rules"

    if (
        primary == packaged
        and repo_rules.is_dir()
        and repo_rules.resolve() != packaged.resolve()
    ):
        destinations.append(
            repo_rules.resolve()
        )

    return destinations


def run_rules_import(args: argparse.Namespace) -> dict:
    """Run the user-invoked SigmaHQ import (P2-14).

    Downloads the pinned SigmaHQ release (unless ``--source`` names a
    local checkout or zip), converts every supported rule into the
    internal format, and writes identical copies into the destination
    rule directories. No network access happens unless this command is
    invoked without ``--source``.
    """
    import tempfile

    release = (
        args.release
        if args.release
        else release_tag_from_env()
    )

    destinations = rule_destination_directories(
        args.dest
    )

    with tempfile.TemporaryDirectory(
        prefix="sentinelclaw-sigma-"
    ) as temporary:
        work_directory = Path(temporary)

        if args.source:
            print(
                f"[sigma] converting from local source: "
                f"{args.source}"
            )

            sigma_rules_directory = prepare_source_directory(
                Path(args.source).expanduser(),
                work_directory,
            )
        else:
            print(
                f"[sigma] downloading SigmaHQ release "
                f"{release}..."
            )

            archive = download_release_zip(
                release,
                work_directory / "sigma-release.zip",
            )

            sigma_rules_directory = prepare_source_directory(
                archive,
                work_directory,
            )

        summary = import_into(
            sigma_rules_directory,
            destinations,
            refresh=True,
        )

    print()
    print(
        f"Imported Sigma rules: "
        f"{summary.converted_count} converted, "
        f"{summary.skipped_count} skipped"
    )

    if summary.skipped:
        print()
        print(
            "Skip reasons (rule isolation; "
            "see SUPPORTED_SUBSET.md):"
        )

        for reason, count in tally_by_reason(
            summary.skipped
        ):
            print(
                f"  - {reason}: {count}"
            )

    print()
    print(
        "Written to:"
    )

    for destination in destinations:
        print(
            f"  - {destination / 'sigma'}"
        )

    print()
    print(
        "Re-run 'sentinelclaw rules' to list the "
        "loaded converted rules."
    )

    return {
        "release": release,
        "converted": summary.converted_count,
        "skipped": summary.skipped_count,
        "destinations": [
            str(destination / "sigma")
            for destination in destinations
        ],
        "skip_reasons": dict(
            summary.skipped
        ),
    }


def format_rule_line(
    rule: dict,
) -> str:
    """Render one rule as ``ID | SEVERITY | CATEGORY | title [tags]``.

    The severity column shows the effective severity at match time; a
    rule-level ``level_override`` (P2-15) wins over the base severity.
    Optional metadata is appended as bracketed tags so the base format
    stays backward-compatible with parsers of the ``rules`` command.
    """
    effective_severity = (
        rule.get(
            "level_override"
        )
        or rule.get(
            "severity",
            "info",
        )
    )

    line = (
        f"{rule.get('id')} | "
        f"{str(effective_severity).upper()} | "
        f"{rule.get('category')} | "
        f"{rule.get('title')}"
    )

    tags = []

    status = rule.get("status")

    if status:
        tags.append(
            f"status={str(status).lower()}"
        )

    if rule.get("noisy"):
        tags.append("noisy")

    level_override = rule.get(
        "level_override"
    )

    if level_override:
        tags.append(
            f"level_override={str(level_override).lower()}"
        )

    if tags:
        line += " " + " ".join(
            f"[{tag}]"
            for tag in tags
        )

    return line


def rules_summary_lines(
    rules: list[dict],
) -> list[str]:
    """Return deterministic count lines grouped by status and category."""
    status_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}

    for rule in rules:
        status = str(
            rule.get(
                "status",
                "unspecified",
            )
        ).lower()
        category = str(
            rule.get(
                "category",
                "unknown",
            )
        ).lower()

        status_counts[status] = (
            status_counts.get(status, 0) + 1
        )
        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )

    return [
        "Rules by status: "
        + " ".join(
            f"{status}={count}"
            for status, count in sorted(
                status_counts.items()
            )
        ),
        "Rules by category: "
        + " ".join(
            f"{category}={count}"
            for category, count in sorted(
                category_counts.items()
            )
        ),
    ]


def add_source(
    findings: list[dict],
    source: str,
) -> list[dict]:
    result = []

    for finding in findings:
        item = dict(finding)
        item["source"] = source
        result.append(item)

    return result


def calculate_incident_risk(
    incidents: list[dict],
) -> dict:
    weights = {
        "info": 0,
        "low": 1,
        "medium": 5,
        "high": 12,
        "critical": 20,
    }

    score = 0

    for incident in incidents:
        severity = str(
            incident.get(
                "severity",
                "info",
            )
        ).lower()

        score += weights.get(
            severity,
            0,
        )

    score = min(
        score,
        100,
    )

    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "informational"

    return {
        "score": score,
        "level": level,
    }


def calculate_overall_risk(
    findings: list[dict],
    incidents: list[dict],
) -> dict:
    finding_risk = calculate_risk_score(
        findings
    )

    incident_risk = calculate_incident_risk(
        incidents
    )

    overall_score = max(
        finding_risk["score"],
        incident_risk["score"],
    )

    if overall_score >= 70:
        overall_level = "critical"
    elif overall_score >= 40:
        overall_level = "high"
    elif overall_score >= 20:
        overall_level = "medium"
    elif overall_score >= 1:
        overall_level = "low"
    else:
        overall_level = "informational"

    return {
        "score": overall_score,
        "level": overall_level,
        "finding_risk": finding_risk,
        "incident_risk": incident_risk,
    }


def run_scan(
    show_progress: bool = False,
    include_raw: bool = False,
) -> dict:
    progress = ScanProgress(
        enabled=show_progress,
        total_steps=6,
    )

    scan_timestamp = (
        datetime.now()
        .astimezone()
        .isoformat()
    )

    collector_status = {
        "process_error": None,
        "network_error": None,
        "windows_event_error": None,
        "system_info_error": None,
    }

    progress.step(
        "Collecting running processes..."
    )

    try:
        processes = get_processes()
    except Exception as exc:
        processes = []
        collector_status["process_error"] = str(exc)

        logger.warning(
            "Process collection failed: %s",
            exc,
        )

        progress.warning(
            "Process collection failed. "
            "Continuing with remaining collectors."
        )

    progress.step(
        "Collecting network connections..."
    )

    try:
        network = get_network_connections()
    except Exception as exc:
        network = []
        collector_status["network_error"] = str(exc)

        logger.warning(
            "Network collection failed: %s",
            exc,
        )

        progress.warning(
            "Network collection failed. "
            "Continuing with remaining collectors."
        )

    progress.step(
        "Reading Windows Security events..."
    )

    try:
        windows_events = get_windows_events(
            log_name="Security",
            max_events=get_settings().max_windows_events,
        )
    except Exception as exc:
        windows_events = []
        collector_status["windows_event_error"] = str(exc)

        logger.warning(
            "Windows Security event collection failed: %s",
            exc,
        )

        progress.warning(
            "Windows Security events are unavailable. "
            "Run the terminal as Administrator "
            "for Security log access."
        )

    auth_events: list[dict] = []
    persistence_records: list[dict] = []

    if sys.platform.startswith(
        "linux"
    ):
        try:
            auth_events = get_auth_events()
        except Exception as exc:
            auth_events = []

            logger.warning(
                "Auth log collection failed: %s",
                exc,
            )

        try:
            persistence_records = get_persistence_records()
        except Exception as exc:
            persistence_records = []

            logger.warning(
                "Persistence collection failed: %s",
                exc,
            )

    progress.step(
        "Running detection rules..."
    )

    rules = get_rules()

    built_in_process_findings = add_source(
        analyze_processes(
            processes
        ),
        "builtin",
    )

    built_in_network_findings = add_source(
        analyze_network(
            network
        ),
        "builtin",
    )

    built_in_windows_findings = add_source(
        analyze_windows_events(
            windows_events
        ),
        "builtin",
    )

    built_in_auth_findings = add_source(
        analyze_auth_events(
            auth_events
        ),
        "builtin",
    )

    built_in_persistence_findings = add_source(
        analyze_persistence_records(
            persistence_records
        ),
        "builtin",
    )

    yaml_process_findings = add_source(
        run_rules(
            rules,
            processes,
            category="process",
        ),
        "yaml",
    )

    yaml_windows_findings = add_source(
        run_rules(
            rules,
            windows_events,
            category="windows_event",
        ),
        "yaml",
    )

    yaml_auth_findings = add_source(
        run_rules(
            rules,
            auth_events,
            category="auth",
        ),
        "yaml",
    )

    yaml_persistence_findings = add_source(
        run_rules(
            rules,
            persistence_records,
            category="persistence",
        ),
        "yaml",
    )

    process_results = process_findings(
        built_in_process_findings
        + yaml_process_findings
    )

    network_results = process_findings(
        built_in_network_findings
    )

    windows_results = process_findings(
        built_in_windows_findings
        + yaml_windows_findings
    )

    auth_results = process_findings(
        built_in_auth_findings
        + yaml_auth_findings
    )

    persistence_results = process_findings(
        built_in_persistence_findings
        + yaml_persistence_findings
    )

    all_findings = process_findings(
        process_results
        + network_results
        + windows_results
        + auth_results
        + persistence_results
    )

    progress.step(
        "Correlating security incidents..."
    )

    incidents = correlate_findings(
        all_findings
    )

    progress.step(
        "Building investigation timeline..."
    )

    timeline = build_timeline(
        findings=all_findings,
        incidents=incidents,
        scan_timestamp=scan_timestamp,
    )

    risk = calculate_overall_risk(
        all_findings,
        incidents,
    )

    try:
        system_info = get_system_info()
    except Exception as exc:
        system_info = {}
        collector_status["system_info_error"] = str(exc)

        logger.warning(
            "System information collection failed: %s",
            exc,
        )

        progress.warning(
            "System information collection failed."
        )

    progress.complete()

    result = {
        "scan": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
        },
        "risk": risk,
        "summary": {
            "rules_loaded": len(rules),
            "processes_scanned": len(
                processes
            ),
            "network_connections_scanned": len(
                network
            ),
            "windows_events_scanned": len(
                windows_events
            ),
            "auth_events_scanned": len(
                auth_events
            ),
            "persistence_records_scanned": len(
                persistence_records
            ),
            "process_findings": len(
                process_results
            ),
            "network_findings": len(
                network_results
            ),
            "windows_findings": len(
                windows_results
            ),
            "auth_findings": len(
                auth_results
            ),
            "persistence_findings": len(
                persistence_results
            ),
            "total_findings": len(
                all_findings
            ),
            "incidents": len(
                incidents
            ),
            "timeline_events": len(
                timeline
            ),
        },
        "findings": {
            "processes": process_results,
            "network": network_results,
            "windows_events": windows_results,
            "auth": auth_results,
            "persistence": persistence_results,
            "all": all_findings,
        },
        "incidents": incidents,
        "timeline": timeline,
        "collector_status": collector_status,
        "system": system_info,
    }

    if include_raw:
        result["processes"] = processes
        result["network"] = network
        result["windows_events"] = windows_events

    return result


def run_file_scan(
    file_path: str,
) -> dict:
    path = Path(
        file_path
    )

    if not path.exists():
        return {
            "error": (
                f"File does not exist: "
                f"{path}"
            )
        }

    if not path.is_file():
        return {
            "error": (
                f"Path is not a file: "
                f"{path}"
            )
        }

    try:
        file_info = analyze_file(
            str(path)
        )
    except PermissionError:
        return {
            "error": (
                "Permission denied while "
                f"reading file: {path}"
            )
        }
    except Exception as exc:
        return {
            "error": (
                f"Unable to analyze file: "
                f"{exc}"
            )
        }

    if "error" in file_info:
        return file_info

    try:
        rules = get_rules()

        built_in_findings = add_source(
            analyze_file_findings(
                file_info
            ),
            "builtin",
        )

        yaml_findings = add_source(
            run_rules(
                rules,
                [file_info],
                category="file",
            ),
            "yaml",
        )

        findings = process_findings(
            built_in_findings
            + yaml_findings
        )
    except Exception as exc:
        return {
            "error": (
                "File detection failed: "
                f"{exc}"
            )
        }

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": (
                datetime.now()
                .astimezone()
                .isoformat()
            ),
            "type": "file",
        },
        "rules_loaded": len(
            rules
        ),
        "risk": calculate_risk_score(
            findings
        ),
        "file": file_info,
        "findings": findings,
    }


def run_pcap_scan(
    file_path: str,
) -> dict:
    try:
        from sentinelclaw.tools.pcap_analyzer import analyze_pcap
    except ImportError:
        return {
            "error": (
                "PCAP support is not installed. "
                "Install it with: pip install -e .[pcap]"
            )
        }

    path = Path(
        file_path
    )

    if not path.exists():
        return {
            "error": (
                f"Capture file does not exist: "
                f"{path}"
            )
        }

    if not path.is_file():
        return {
            "error": (
                f"Capture path is not a file: "
                f"{path}"
            )
        }

    try:
        pcap_data = analyze_pcap(
            str(path)
        )
    except PermissionError:
        return {
            "error": (
                "Permission denied while "
                f"reading capture: {path}"
            )
        }
    except Exception as exc:
        return {
            "error": (
                f"Unable to analyze capture: "
                f"{exc}"
            )
        }

    if "error" in pcap_data:
        return pcap_data

    try:
        findings = process_findings(
            add_source(
                analyze_pcap_findings(
                    pcap_data
                ),
                "builtin",
            )
        )

        incidents = correlate_findings(
            findings
        )

        scan_timestamp = (
            datetime.now()
            .astimezone()
            .isoformat()
        )

        timeline = build_timeline(
            findings=findings,
            incidents=incidents,
            scan_timestamp=scan_timestamp,
        )

        risk = calculate_overall_risk(
            findings,
            incidents,
        )
    except Exception as exc:
        return {
            "error": (
                "PCAP detection pipeline failed: "
                f"{exc}"
            )
        }

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
            "type": "pcap",
        },
        "risk": risk,
        "pcap": pcap_data,
        "findings": findings,
        "incidents": incidents,
        "timeline": timeline,
    }

def run_log_scan(
    file_path: str,
) -> dict:
    path = Path(
        file_path
    )

    if not path.exists():
        return {
            "error": (
                f"Log file does not exist: "
                f"{path}"
            )
        }

    if not path.is_file():
        return {
            "error": (
                f"Log path is not a file: "
                f"{path}"
            )
        }

    try:
        log_data = analyze_log_file(
            str(path)
        )
    except PermissionError:
        return {
            "error": (
                "Permission denied while "
                f"reading log: {path}"
            )
        }
    except Exception as exc:
        return {
            "error": (
                f"Unable to analyze log file: "
                f"{exc}"
            )
        }

    if "error" in log_data:
        return log_data

    try:
        findings = process_findings(
            add_source(
                analyze_log_events(
                    log_data.get(
                        "events",
                        [],
                    )
                ),
                "builtin",
            )
        )

        incidents = correlate_findings(
            findings
        )

        scan_timestamp = (
            datetime.now()
            .astimezone()
            .isoformat()
        )

        timeline = build_timeline(
            findings=findings,
            incidents=incidents,
            scan_timestamp=scan_timestamp,
        )

        risk = calculate_overall_risk(
            findings,
            incidents,
        )
    except Exception as exc:
        return {
            "error": (
                "Log detection pipeline failed: "
                f"{exc}"
            )
        }

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
            "type": "log",
        },
        "risk": risk,
        "log": log_data,
        "findings": findings,
        "incidents": incidents,
        "timeline": timeline,
    }


def print_timeline(
    timeline: list[dict],
) -> None:
    print()
    print("=" * 72)
    print(
        "                    SENTINELCLAW TIMELINE"
    )
    print("=" * 72)

    if not timeline:
        print()
        print(
            "[+] No timeline events available."
        )
        print()
        print("=" * 72)
        return

    for event in timeline:
        print()

        timestamp = event.get(
            "timestamp"
        )

        timestamp_text = (
            timestamp
            if timestamp
            else "TIME UNKNOWN"
        )

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

        print(
            timestamp_text
        )

        print(
            f"  [{severity}] "
            f"[{event_type}] "
            f"{event.get('title')}"
        )

        rule_id = event.get(
            "rule_id"
        )

        if rule_id:
            print(
                f"  Rule: {rule_id}"
            )

        incident_id = event.get(
            "incident_id"
        )

        if incident_id:
            print(
                f"  Incident: {incident_id}"
            )

        description = event.get(
            "description"
        )

        if description:
            print(
                f"  Reason: {description}"
            )

    print()
    print("=" * 72)
    print(
        f"Timeline events: "
        f"{len(timeline)}"
    )
    print("=" * 72)
    print()


def print_ai_investigation(
    report: dict,
    model: str,
) -> None:
    print()
    print(
        "Deterministic scan complete."
    )

    print(
        f"Findings: "
        f"{report['summary']['total_findings']}"
    )

    print(
        f"Incidents: "
        f"{report['summary']['incidents']}"
    )

    print(
        f"Risk: "
        f"{report['risk']['score']}/100 "
        f"({report['risk']['level'].upper()})"
    )

    print()
    print(
        f"Starting optional local AI analysis "
        f"with {model}..."
    )

    try:
        ai_result = analyze_report_with_qwen(
            report,
            model=model,
        )
    except RuntimeError as exc:
        print()
        print(
            "[AI UNAVAILABLE]"
        )

        print(
            str(exc)
        )

        print()
        print(
            "The SentinelClaw deterministic "
            "security scan completed successfully."
        )

        print(
            "Start Ollama and ensure the requested "
            "model is installed to use AI analysis."
        )

        return
    except Exception as exc:
        print()
        print(
            f"[AI ERROR] {exc}"
        )

        print(
            "The deterministic scan results "
            "remain valid."
        )

        return

    print()
    print("=" * 72)
    print(
        "                 SENTINELCLAW AI INVESTIGATION"
    )
    print("=" * 72)
    print()

    print(
        f"Model: {ai_result['model']}"
    )

    print()
    print(
        ai_result["analysis"]
    )

    print()
    print("=" * 72)
    print(
        "AI analysis is advisory. "
        "Detections come from SentinelClaw's "
        "deterministic engine."
    )
    print("=" * 72)
    print()


def save_requested_report_formats(
    report: dict,
    requested_format: str,
) -> dict[str, Path]:
    if requested_format == "all":
        formats = (
            "json",
            "text",
            "html",
        )
    else:
        formats = (
            requested_format,
        )

    try:
        return save_report_formats(
            report=report,
            output_directory=get_settings().resolved_report_dir,
            formats=formats,
        )
    except PermissionError as exc:
        raise RuntimeError(
            "Permission denied while writing reports."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Unable to write reports: {exc}"
        ) from exc


def print_report_result(
    report: dict,
    created_files: dict[str, Path],
) -> None:
    print()
    print("=" * 72)
    print(
        "                  SENTINELCLAW REPORT COMPLETE"
    )
    print("=" * 72)

    print()

    print(
        f"Risk Score     : "
        f"{report['risk']['score']}/100"
    )

    print(
        f"Risk Level     : "
        f"{report['risk']['level'].upper()}"
    )

    print(
        f"Findings       : "
        f"{report['summary']['total_findings']}"
    )

    print(
        f"Incidents      : "
        f"{report['summary']['incidents']}"
    )

    print(
        f"Timeline Events: "
        f"{report['summary']['timeline_events']}"
    )

    print()
    print(
        "Generated files"
    )
    print(
        "-" * 72
    )

    for report_type, path in created_files.items():
        print(
            f"{report_type.upper():<8}: {path}"
        )

    print()
    print("=" * 72)
    print()


def execute_command(
    args: argparse.Namespace,
) -> None:
    if args.command == "system":
        print_json(
            get_system_info()
        )

    elif args.command == "processes":
        print_json(
            get_processes()
        )

    elif args.command == "network":
        print_json(
            get_network_connections()
        )

    elif args.command == "windows-events":
        try:
            events = get_windows_events(
                log_name="Security",
                max_events=get_settings().max_events_print,
            )
        except PermissionError:
            print_cli_error(
                "Windows Security log access denied.",
                (
                    "Run PowerShell or VS Code "
                    "as Administrator."
                ),
            )

            raise SystemExit(1)
        except Exception as exc:
            print_cli_error(
                (
                    "Unable to read Windows "
                    f"Security events: {exc}"
                ),
                (
                    "Try running the terminal "
                    "as Administrator."
                ),
            )

            raise SystemExit(1)

        print_json(
            events
        )

    elif args.command == "logs":
        report = run_log_scan(
            args.file
        )

        if args.json:
            print_json(
                report
            )
        else:
            print_log_dashboard(
                report,
                verbose=args.verbose,
            )

        if "error" in report:
            raise SystemExit(1)

    elif args.command == "file":
        report = run_file_scan(
            args.path
        )

        if args.json:
            print_json(
                report
            )
        else:
            print_file_dashboard(
                report,
                verbose=args.verbose,
            )

        if "error" in report:
            raise SystemExit(1)

    elif args.command == "pcap":
        report = run_pcap_scan(
            args.path
        )

        if args.json:
            print_json(
                report
            )
        else:
            print_pcap_dashboard(
                report,
                verbose=args.verbose,
            )

        if "error" in report:
            raise SystemExit(1)

    elif args.command == "scan":
        report = run_scan(
            show_progress=False,
            include_raw=args.json_raw,
        )

        baselines: list[dict] = []

        if getattr(
            args,
            "since",
            None,
        ):
            cutoff = parse_since(
                args.since
            )

            baselines = records_since(
                cutoff
            )
        elif getattr(
            args,
            "last",
            False,
        ):
            baseline = latest_record()

            if baseline is not None:
                baselines = [
                    baseline
                ]

        # P3-17: persist the bounded scan record (CLI layer, so
        # ``run_scan`` and its tests stay untouched). The baseline is
        # captured before appending so the fresh record never diffs
        # against itself.
        state_record = record_from_report(
            report
        )

        record_id = append_scan_record(
            state_record
        )

        state_record["record_id"] = record_id

        if getattr(
            args,
            "format",
            None,
        ) == "jsonl":
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

            print_json(
                export
            )

        if baselines:
            print_scan_delta_vs_baselines(
                baselines,
                report,
                target_record=state_record,
            )

    elif args.command in {
        "summary",
        "dashboard",
    }:
        report = run_scan(
            show_progress=True
        )

        print_dashboard(
            report,
            verbose=args.verbose,
        )

    elif args.command == "report":
        report = run_scan(
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

    elif args.command == "history":
        cmd_history()

    elif args.command == "diff":
        if not getattr(
            args,
            "last",
            False,
        ) and (
            args.id1 is None
            or args.id2 is None
        ):
            print_cli_error(
                "diff needs two record ids or --last.",
                "List records with 'sentinelclaw history'.",
            )

            raise SystemExit(1)

        cmd_diff(args)

    elif args.command == "watch":
        cmd_watch(args)

    elif args.command == "search":
        cmd_search(args)

    elif args.command == "accounts":
        cmd_accounts()

    elif args.command == "tree":
        cmd_tree(args)

    elif args.command == "stats":
        cmd_stats()

    elif args.command == "rules":
        if getattr(args, "rules_subcommand", None) == "import":
            run_rules_import(args)

            return

        rules = get_rules()

        print()
        print(
            f"Loaded detection rules: "
            f"{len(rules)}"
        )
        print()

        for rule in rules:
            print(
                format_rule_line(rule)
            )

        print()

        for summary_line in rules_summary_lines(
            rules
        ):
            print(
                summary_line
            )

    elif args.command == "incidents":
        report = run_scan(
            show_progress=True
        )

        print_incidents_dashboard(
            report.get(
                "incidents",
                [],
            ),
            verbose=args.verbose,
        )

    elif args.command == "timeline":
        report = run_scan(
            show_progress=True
        )

        print_timeline(
            report.get(
                "timeline",
                [],
            )
        )

    elif args.command == "investigate":
        report = run_scan(
            show_progress=True
        )

        print_ai_investigation(
            report,
            model=(
                args.model
                or get_settings().ollama_model
            ),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "SentinelClaw - Local defensive "
            "cybersecurity CLI"
        )
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help=(
            "Show Python exceptions for "
            "development and troubleshooting"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

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
        help=(
            "Show monitored Windows "
            "Security events"
        ),
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help=(
            "Run complete scan and print "
            "machine-readable JSON"
        ),
    )

    scan_parser.add_argument(
        "--json-raw",
        action="store_true",
        help=(
            "Embed raw collector dumps "
            "(processes, network, windows events) "
            "in the JSON output"
        ),
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
        help=(
            "ISO timestamp; show new/closed findings "
            "since records at or after this time"
        ),
    )

    scan_parser.add_argument(
        "--last",
        action="store_true",
        help=(
            "Show new/closed findings versus the "
            "previous scan record"
        ),
    )

    dashboard_parser = (
        subparsers.add_parser(
            "dashboard",
            help=(
                "Run scan and display "
                "the SentinelClaw security console"
            ),
        )
    )

    dashboard_parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show detailed evidence, "
            "MITRE mappings, processes and IPs"
        ),
    )

    summary_parser = (
        subparsers.add_parser(
            "summary",
            help=(
                "Run scan and show compact "
                "security summary"
            ),
        )
    )

    summary_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed findings",
    )

    report_parser = (
        subparsers.add_parser(
            "report",
            help=(
                "Generate SentinelClaw "
                "security assessment reports"
            ),
        )
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
        help=(
            "Report format to generate "
            "(default: all)"
        ),
    )

    report_parser.add_argument(
        "--json-raw",
        action="store_true",
        help=(
            "Embed raw collector dumps in the "
            "JSON report"
        ),
    )

    rules_parser = subparsers.add_parser(
        "rules",
        help=(
            "Show loaded detection rules"
        ),
    )

    rules_subparsers = rules_parser.add_subparsers(
        dest="rules_subcommand",
    )

    import_parser = rules_subparsers.add_parser(
        "import",
        help=(
            "Import SigmaHQ rules into the internal format "
            "(user-invoked; downloads the pinned release unless "
            "--source is given)"
        ),
    )

    import_parser.add_argument(
        "--source",
        default=None,
        help=(
            "Path to a local SigmaHQ checkout directory or a "
            "release zip to convert offline"
        ),
    )

    import_parser.add_argument(
        "--release",
        default=None,
        help=(
            f"SigmaHQ release tag to download (default: "
            f"{SIGMA_RELEASE_TAG}, override with "
            f"SENTINELCLAW_SIGMA_RELEASE)"
        ),
    )

    import_parser.add_argument(
        "--dest",
        default=None,
        help=(
            "Rule directory to write the converted sigma/ tree into "
            "(default: the resolved rules directory)"
        ),
    )

    incidents_parser = (
        subparsers.add_parser(
            "incidents",
            help=(
                "Run scan and show correlated "
                "incidents"
            ),
        )
    )

    incidents_parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show detailed incident information"
        ),
    )

    subparsers.add_parser(
        "history",
        help=(
            "List scan records from the local "
            "scan-state store"
        ),
    )

    diff_parser = subparsers.add_parser(
        "diff",
        help=(
            "Show new/closed findings between two "
            "scan records (or the last two)"
        ),
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
        help=(
            "Diff the two most recent records"
        ),
    )

    watch_parser = subparsers.add_parser(
        "watch",
        help=(
            "Run scans in a loop, recording state "
            "and printing finding deltas"
        ),
    )

    watch_parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help=(
            "Seconds between scans (default: 30)"
        ),
    )

    watch_parser.add_argument(
        "--count",
        type=int,
        default=0,
        help=(
            "Number of cycles to run "
            "(default: 0 = until interrupted)"
        ),
    )

    search_parser = subparsers.add_parser(
        "search",
        help=(
            "Search findings and incidents across "
            "scan-state records"
        ),
    )

    search_parser.add_argument(
        "keyword",
        help="Case-insensitive keyword to search for",
    )

    search_parser.add_argument(
        "--state",
        default=None,
        help=(
            "Restrict the search to one record id"
        ),
    )

    subparsers.add_parser(
        "accounts",
        help=(
            "Summarize logon activity from windows "
            "events in scan state"
        ),
    )

    tree_parser = subparsers.add_parser(
        "tree",
        help=(
            "Render the process tree for one "
            "incident's member findings"
        ),
    )

    tree_parser.add_argument(
        "incident_id",
        help="Incident id to drill into",
    )

    subparsers.add_parser(
        "stats",
        help=(
            "Event-ID frequency and finding-count "
            "statistics from scan state"
        ),
    )

    subparsers.add_parser(
        "timeline",
        help=(
            "Run scan and show chronological "
            "security timeline"
        ),
    )

    investigate_parser = (
        subparsers.add_parser(
            "investigate",
            help=(
                "Run scan and analyze results "
                "using optional local Qwen"
            ),
        )
    )

    investigate_parser.add_argument(
        "--model",
        default=None,
        help=(
            "Ollama model to use "
            "(default: qwen3:14b or "
            "configured model)"
        ),
    )

    logs_parser = (
        subparsers.add_parser(
            "logs",
            help="Analyze a text log file",
        )
    )

    logs_parser.add_argument(
        "file",
        help="Path to the log file",
    )

    logs_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print complete log analysis "
            "as JSON"
        ),
    )

    logs_parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show detailed log findings"
        ),
    )

    file_parser = (
        subparsers.add_parser(
            "file",
            help="Analyze a local file",
        )
    )

    file_parser.add_argument(
        "path",
        help="Path to the file",
    )

    file_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print complete file analysis "
            "as JSON"
        ),
    )

    file_parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show detailed file findings"
        ),
    )

    pcap_parser = (
        subparsers.add_parser(
            "pcap",
            help=(
                "Analyze a PCAP or "
                "PCAPNG capture"
            ),
        )
    )

    pcap_parser.add_argument(
        "path",
        help="Path to capture file",
    )

    pcap_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print complete PCAP analysis "
            "as JSON"
        ),
    )

    pcap_parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show detailed PCAP findings"
        ),
    )

    return parser


def main() -> None:
    parser = build_parser()

    args = parser.parse_args()

    configure_logging(
        debug=args.debug
    )

    try:
        execute_command(
            args
        )

    except KeyboardInterrupt:
        print()
        print_cli_error(
            "Operation cancelled by user."
        )

        raise SystemExit(130)

    except SystemExit:
        raise

    except PermissionError as exc:
        if args.debug:
            raise

        print_cli_error(
            f"Permission denied: {exc}",
            (
                "Try running the terminal "
                "with the required privileges."
            ),
        )

        raise SystemExit(1)

    except FileNotFoundError as exc:
        if args.debug:
            raise

        print_cli_error(
            f"File not found: {exc}"
        )

        raise SystemExit(1)

    except RuntimeError as exc:
        if args.debug:
            raise

        print_cli_error(
            str(exc)
        )

        raise SystemExit(1)

    except Exception as exc:
        if args.debug:
            raise

        print_cli_error(
            (
                "SentinelClaw encountered an "
                f"unexpected error: {exc}"
            ),
            (
                "Run again with --debug "
                "to show the Python traceback."
            ),
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()

