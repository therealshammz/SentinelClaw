from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelclaw.ai.qwen_analyzer import analyze_report_with_qwen

from sentinelclaw.config.paths import (
    get_report_directory,
    get_rules_directory,
)

from sentinelclaw.detectors.file_detector import analyze_file_findings
from sentinelclaw.detectors.log_detector import analyze_windows_events
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.pcap_detector import analyze_pcap_findings
from sentinelclaw.detectors.process_detector import analyze_processes

from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.engine.rule_engine import (
    load_rules_from_directory,
    run_rules,
)
from sentinelclaw.engine.timeline_engine import build_timeline

from sentinelclaw.models.findings import calculate_risk_score

from sentinelclaw.reporting.report_generator import save_report_formats

from sentinelclaw.tools.file_analyzer import analyze_file
from sentinelclaw.tools.log_analyzer import analyze_log_file
from sentinelclaw.tools.network_analyzer import get_network_connections
from sentinelclaw.tools.process_analyzer import get_processes
from sentinelclaw.tools.system_info import get_system_info
from sentinelclaw.tools.windows_event_analyzer import get_windows_events

from sentinelclaw.ui.console import (
    print_dashboard,
    print_file_dashboard,
    print_incidents_dashboard,
    print_pcap_dashboard,
)

from sentinelclaw.ui.progress import ScanProgress


REPORT_DIRECTORY = get_report_directory()
RULE_DIRECTORY = get_rules_directory()


def print_json(data: Any) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            default=str,
        )
    )


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
            RULE_DIRECTORY
        )
    except Exception as exc:
        raise RuntimeError(
            f"Unable to load detection rules: {exc}"
        ) from exc


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
            max_events=200,
        )
    except Exception as exc:
        windows_events = []
        collector_status["windows_event_error"] = str(exc)

        progress.warning(
            "Windows Security events are unavailable. "
            "Run the terminal as Administrator "
            "for Security log access."
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

    all_findings = process_findings(
        process_results
        + network_results
        + windows_results
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

        progress.warning(
            "System information collection failed."
        )

    progress.complete()

    return {
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
            "process_findings": len(
                process_results
            ),
            "network_findings": len(
                network_results
            ),
            "windows_findings": len(
                windows_results
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
            "all": all_findings,
        },
        "incidents": incidents,
        "timeline": timeline,
        "collector_status": collector_status,
        "system": system_info,
        "processes": processes,
        "network": network,
        "windows_events": windows_events,
    }


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
            output_directory=REPORT_DIRECTORY,
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
                max_events=100,
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
        path = Path(
            args.file
        )

        if not path.exists():
            print_cli_error(
                f"Log file does not exist: {path}"
            )

            raise SystemExit(1)

        if not path.is_file():
            print_cli_error(
                f"Log path is not a file: {path}"
            )

            raise SystemExit(1)

        print_json(
            analyze_log_file(
                str(path)
            )
        )

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
            show_progress=False
        )

        print_json(
            report
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
            show_progress=True
        )

        created_files = save_requested_report_formats(
            report,
            args.format,
        )

        print_report_result(
            report,
            created_files,
        )

    elif args.command == "rules":
        rules = get_rules()

        print()
        print(
            f"Loaded detection rules: "
            f"{len(rules)}"
        )
        print()

        for rule in rules:
            print(
                f"{rule.get('id')} | "
                f"{rule.get('severity', 'info').upper()} | "
                f"{rule.get('category')} | "
                f"{rule.get('title')}"
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
            model=args.model,
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

    subparsers.add_parser(
        "scan",
        help=(
            "Run complete scan and print "
            "machine-readable JSON"
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
            "all",
        ],
        default="all",
        help=(
            "Report format to generate "
            "(default: all)"
        ),
    )

    subparsers.add_parser(
        "rules",
        help=(
            "Show loaded detection rules"
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
        default="qwen3:14b",
        help=(
            "Ollama model to use "
            "(default: qwen3:14b)"
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

