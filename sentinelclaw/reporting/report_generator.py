from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}


def _safe(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(
        str(severity).lower(),
        0,
    )


def _get_findings(report: dict) -> list[dict]:
    findings = report.get("findings", {})

    if isinstance(findings, dict):
        result = findings.get("all", [])
        return result if isinstance(result, list) else []

    if isinstance(findings, list):
        return findings

    return []


def _finding_counts(findings: list[dict]) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).lower()

        if severity == "informational":
            severity = "info"

        if severity not in counts:
            severity = "info"

        counts[severity] += 1

    return counts


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda item: _severity_rank(
            item.get("severity", "info")
        ),
        reverse=True,
    )


def build_executive_assessment(report: dict) -> dict:
    findings = _get_findings(report)
    incidents = report.get("incidents", [])
    risk = report.get("risk", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    sorted_findings = _sorted_findings(findings)

    score = int(risk.get("score", 0) or 0)
    level = str(
        risk.get("level", "informational")
    ).lower()

    observations: list[str] = []
    recommendations: list[str] = []

    if counts["critical"]:
        observations.append(
            f"{counts['critical']} critical-severity "
            "finding(s) require immediate investigation."
        )

    if counts["high"]:
        observations.append(
            f"{counts['high']} high-severity finding(s) "
            "were detected."
        )

    if counts["medium"]:
        observations.append(
            f"{counts['medium']} medium-severity finding(s) "
            "require review."
        )

    if not counts["critical"] and not counts["high"]:
        observations.append(
            "No critical or high-severity findings were detected."
        )

    if incidents:
        observations.append(
            f"{len(incidents)} correlated security incident(s) "
            "were identified."
        )
    else:
        observations.append(
            "No correlated security incidents were identified."
        )

    failed_collectors = [
        name
        for name, error in collector_status.items()
        if error
    ]

    if failed_collectors:
        observations.append(
            "One or more collectors were unavailable, so scan "
            "coverage may be incomplete."
        )
    else:
        observations.append(
            "All configured collectors completed without "
            "recorded errors."
        )

    if level in {"critical", "high"}:
        assessment = (
            "SentinelClaw identified significant security "
            "indicators requiring prioritized investigation. "
            "The results should be validated against system "
            "context before any remediation decision is made."
        )

    elif level == "medium":
        assessment = (
            "SentinelClaw identified security indicators that "
            "warrant investigation. No conclusion of compromise "
            "should be made without validating the associated "
            "process, network, file, and event evidence."
        )

    elif level == "low":
        assessment = (
            "SentinelClaw identified a limited number of "
            "lower-risk security indicators. The current scan "
            "does not establish evidence of compromise, but the "
            "flagged activity should be reviewed for legitimacy."
        )

    else:
        assessment = (
            "SentinelClaw did not identify material security "
            "indicators during this scan. This does not guarantee "
            "that the system is free from malicious activity."
        )

    if sorted_findings:
        top = sorted_findings[0]

        recommendations.append(
            "Review the highest-priority finding: "
            f"{top.get('rule_id', 'Unknown')} - "
            f"{top.get('title', 'Unknown finding')}."
        )

    process_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "process"
    ]

    network_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "network"
    ]

    windows_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() in {
            "windows",
            "windows_event",
            "windows_events",
        }
    ]

    file_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "file"
    ]

    if process_findings:
        recommendations.append(
            "Validate flagged processes against their executable "
            "paths, command lines, parent processes, and expected "
            "user activity."
        )

    if network_findings:
        recommendations.append(
            "Review flagged network connections and verify that "
            "the destination addresses, ports, and owning "
            "processes are expected."
        )

    if windows_findings:
        recommendations.append(
            "Review the relevant Windows Security events and "
            "correlate them with user logons, process execution, "
            "and administrative activity."
        )

    if file_findings:
        recommendations.append(
            "Validate flagged files using their hashes, digital "
            "signatures, locations, metadata, and known source."
        )

    if incidents:
        recommendations.append(
            "Investigate correlated incidents before reviewing "
            "isolated findings because correlation may indicate "
            "a broader activity chain."
        )

    if failed_collectors:
        recommendations.append(
            "Restore unavailable collectors and repeat the scan "
            "before treating this assessment as complete."
        )

    recommendations.append(
        "Confirm suspicious indicators with additional evidence "
        "before containment, deletion, or other remediation."
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "assessment": assessment,
        "observations": observations,
        "recommendations": recommendations,
    }


def generate_json_report(report: dict) -> str:
    return json.dumps(
        report,
        indent=2,
        default=str,
    )


def generate_text_report(report: dict) -> str:
    findings = _get_findings(report)
    findings = _sorted_findings(findings)

    incidents = report.get("incidents", [])
    timeline = report.get("timeline", [])
    summary = report.get("summary", {})
    risk = report.get("risk", {})
    system = report.get("system", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    executive = build_executive_assessment(report)

    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("SENTINELCLAW SECURITY ASSESSMENT")
    lines.append("=" * 80)
    lines.append("")

    lines.append("SCAN OVERVIEW")
    lines.append("-" * 80)

    lines.append(
        "Application       : "
        + _safe(
            report.get(
                "scan", {}
            ).get(
                "application",
                "SentinelClaw",
            )
        )
    )

    lines.append(
        "Scan Timestamp    : "
        + _safe(
            report.get(
                "scan", {}
            ).get(
                "timestamp",
                "Unknown",
            )
        )
    )

    lines.append(
        f"Risk Score        : {risk.get('score', 0)}/100"
    )

    lines.append(
        "Risk Level        : "
        + str(
            risk.get(
                "level",
                "informational",
            )
        ).upper()
    )

    lines.append(
        f"Rules Loaded      : {summary.get('rules_loaded', 0)}"
    )

    lines.append(
        "Processes Scanned : "
        f"{summary.get('processes_scanned', 0)}"
    )

    lines.append(
        "Connections       : "
        f"{summary.get('network_connections_scanned', 0)}"
    )

    lines.append(
        "Windows Events    : "
        f"{summary.get('windows_events_scanned', 0)}"
    )

    lines.append("")
    lines.append("EXECUTIVE ASSESSMENT")
    lines.append("-" * 80)
    lines.append(executive["assessment"])

    lines.append("")
    lines.append("Key Observations")

    for observation in executive["observations"]:
        lines.append(
            f"- {observation}"
        )

    lines.append("")
    lines.append("Prioritized Investigation")

    for index, recommendation in enumerate(
        executive["recommendations"],
        start=1,
    ):
        lines.append(
            f"{index}. {recommendation}"
        )

    lines.append("")
    lines.append("FINDING STATISTICS")
    lines.append("-" * 80)

    lines.append(
        f"Total Findings    : {len(findings)}"
    )

    lines.append(
        f"Critical          : {counts['critical']}"
    )

    lines.append(
        f"High              : {counts['high']}"
    )

    lines.append(
        f"Medium            : {counts['medium']}"
    )

    lines.append(
        f"Low               : {counts['low']}"
    )

    lines.append(
        f"Informational     : {counts['info']}"
    )

    lines.append(
        f"Incidents         : {len(incidents)}"
    )

    lines.append("")
    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 80)

    if system:
        for key, value in system.items():
            lines.append(
                f"{key:<22}: {_safe(value)}"
            )
    else:
        lines.append(
            "System information unavailable."
        )

    lines.append("")
    lines.append("SECURITY FINDINGS")
    lines.append("-" * 80)

    if not findings:
        lines.append(
            "No findings detected."
        )

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        lines.append("")

        lines.append(
            f"[{index}] "
            f"{finding.get('title', 'Unknown Finding')}"
        )

        lines.append(
            "Severity   : "
            + str(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()
        )

        lines.append(
            "Rule ID    : "
            + _safe(
                finding.get(
                    "rule_id",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Category   : "
            + _safe(
                finding.get(
                    "category",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Confidence : "
            + _safe(
                finding.get(
                    "confidence",
                    "Unknown",
                )
            )
        )

        description = (
            finding.get("description")
            or finding.get("reason")
        )

        if description:
            lines.append(
                "Description: "
                + _safe(description)
            )

        mitre = finding.get("mitre")

        if mitre:
            lines.append(
                "MITRE      : "
                + _safe(mitre)
            )

        evidence = finding.get("evidence")

        if evidence:
            lines.append(
                "Evidence    : "
                + json.dumps(
                    evidence,
                    ensure_ascii=False,
                    default=str,
                )
            )

    lines.append("")
    lines.append("CORRELATED INCIDENTS")
    lines.append("-" * 80)

    if not incidents:
        lines.append(
            "No correlated incidents detected."
        )

    for index, incident in enumerate(
        incidents,
        start=1,
    ):
        lines.append("")

        lines.append(
            f"[{index}] "
            f"{incident.get('title', 'Unknown Incident')}"
        )

        lines.append(
            "Incident ID : "
            + _safe(
                incident.get(
                    "incident_id",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Severity    : "
            + str(
                incident.get(
                    "severity",
                    "info",
                )
            ).upper()
        )

        lines.append(
            "Confidence  : "
            + _safe(
                incident.get(
                    "confidence",
                    "Unknown",
                )
            )
        )

    lines.append("")
    lines.append("INVESTIGATION TIMELINE")
    lines.append("-" * 80)

    if not timeline:
        lines.append(
            "No timeline events available."
        )

    for event in timeline:
        lines.append(
            f"{event.get('timestamp', 'TIME UNKNOWN')} | "
            f"{str(event.get('severity', 'info')).upper()} | "
            f"{event.get('title', 'Unknown Event')}"
        )

    lines.append("")
    lines.append("COLLECTOR STATUS")
    lines.append("-" * 80)

    collector_errors = False

    for key, value in collector_status.items():
        if value:
            collector_errors = True
            lines.append(
                f"{key}: {value}"
            )

    if not collector_errors:
        lines.append(
            "All collectors completed without recorded errors."
        )

    lines.append("")
    lines.append("METHODOLOGY AND LIMITATIONS")
    lines.append("-" * 80)

    lines.append(
        "SentinelClaw uses local deterministic collection, "
        "rule-based detection, normalization, correlation, "
        "risk scoring, and timeline analysis."
    )

    lines.append(
        "A finding represents a security indicator and does "
        "not by itself prove malware infection or compromise."
    )

    lines.append(
        "Optional local AI analysis is advisory and is not "
        "required for SentinelClaw detection."
    )

    lines.append("")
    lines.append("=" * 80)

    return "\n".join(lines)


def generate_html_report(report: dict) -> str:
    findings = _sorted_findings(
        _get_findings(report)
    )

    incidents = report.get("incidents", [])
    timeline = report.get("timeline", [])
    summary = report.get("summary", {})
    risk = report.get("risk", {})
    system = report.get("system", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    executive = build_executive_assessment(report)

    def esc(value: Any) -> str:
        return html.escape(
            _safe(value)
        )

    observation_html = "".join(
        f"<li>{esc(item)}</li>"
        for item in executive["observations"]
    )

    recommendation_html = "".join(
        f"<li>{esc(item)}</li>"
        for item in executive["recommendations"]
    )

    finding_rows: list[str] = []

    for finding in findings:
        evidence = finding.get("evidence")

        evidence_text = (
            json.dumps(
                evidence,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
            if evidence
            else ""
        )

        finding_rows.append(
            f"""
            <tr>
                <td>{esc(finding.get("rule_id", "Unknown"))}</td>
                <td>
                    <span class="severity {esc(str(finding.get("severity", "info")).lower())}">
                        {esc(str(finding.get("severity", "info")).upper())}
                    </span>
                </td>
                <td>{esc(finding.get("title", "Unknown Finding"))}</td>
                <td>{esc(finding.get("confidence", "Unknown"))}</td>
                <td>{esc(finding.get("mitre", ""))}</td>
                <td><pre>{esc(evidence_text)}</pre></td>
            </tr>
            """
        )

    incident_rows: list[str] = []

    for incident in incidents:
        incident_rows.append(
            f"""
            <tr>
                <td>{esc(incident.get("incident_id", "Unknown"))}</td>
                <td>{esc(str(incident.get("severity", "info")).upper())}</td>
                <td>{esc(incident.get("title", "Unknown Incident"))}</td>
                <td>{esc(incident.get("confidence", "Unknown"))}</td>
            </tr>
            """
        )

    timeline_rows: list[str] = []

    for event in timeline:
        timeline_rows.append(
            f"""
            <tr>
                <td>{esc(event.get("timestamp", "TIME UNKNOWN"))}</td>
                <td>{esc(str(event.get("severity", "info")).upper())}</td>
                <td>{esc(event.get("event_type", "event"))}</td>
                <td>{esc(event.get("title", "Unknown Event"))}</td>
            </tr>
            """
        )

    system_rows = "".join(
        f"<tr><td>{esc(key)}</td><td>{esc(value)}</td></tr>"
        for key, value in system.items()
    )

    collector_rows = "".join(
        (
            f"<tr><td>{esc(key)}</td>"
            f"<td>{esc(value or 'OK')}</td></tr>"
        )
        for key, value in collector_status.items()
    )

    scan_timestamp = (
        report.get(
            "scan",
            {},
        ).get(
            "timestamp",
            "Unknown",
        )
    )

    generated_timestamp = (
        datetime.now()
        .astimezone()
        .isoformat()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelClaw Security Assessment</title>

<style>
body {{
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #0b1020;
    color: #e5e7eb;
}}

.container {{
    width: 92%;
    max-width: 1400px;
    margin: 30px auto;
}}

.card {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 18px;
}}

h1, h2, h3 {{
    margin-top: 0;
}}

.small {{
    color: #9ca3af;
    font-size: 0.9rem;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(
        auto-fit,
        minmax(160px, 1fr)
    );
    gap: 12px;
}}

.metric {{
    background: #182235;
    border-radius: 8px;
    padding: 15px;
}}

.metric strong {{
    display: block;
    margin-top: 6px;
    font-size: 1.5rem;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th,
td {{
    border-bottom: 1px solid #2d3748;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #182235;
}}

pre {{
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
    font-size: 0.82rem;
}}

.severity {{
    font-weight: bold;
}}

.critical {{
    color: #ff6b6b;
}}

.high {{
    color: #ff9f43;
}}

.medium {{
    color: #feca57;
}}

.low {{
    color: #54a0ff;
}}

.info,
.informational {{
    color: #c8d6e5;
}}

.assessment {{
    font-size: 1.05rem;
    line-height: 1.6;
}}

li {{
    margin-bottom: 8px;
}}

.footer {{
    color: #9ca3af;
    font-size: 0.85rem;
    margin: 25px 0;
}}
</style>
</head>

<body>

<div class="container">

<div class="card">
    <h1>SentinelClaw Security Assessment</h1>

    <div class="small">
        Scan: {esc(scan_timestamp)}
        <br>
        Report generated: {esc(generated_timestamp)}
    </div>
</div>

<div class="card">
    <h2>Risk Overview</h2>

    <div class="grid">
        <div class="metric">
            Risk Score
            <strong>{esc(risk.get("score", 0))}/100</strong>
        </div>

        <div class="metric">
            Risk Level
            <strong>{esc(str(risk.get("level", "informational")).upper())}</strong>
        </div>

        <div class="metric">
            Findings
            <strong>{len(findings)}</strong>
        </div>

        <div class="metric">
            Incidents
            <strong>{len(incidents)}</strong>
        </div>
    </div>
</div>

<div class="card">
    <h2>Executive Assessment</h2>

    <p class="assessment">
        {esc(executive["assessment"])}
    </p>

    <h3>Key Observations</h3>
    <ul>
        {observation_html}
    </ul>

    <h3>Prioritized Investigation</h3>
    <ol>
        {recommendation_html}
    </ol>
</div>

<div class="card">
    <h2>Finding Statistics</h2>

    <div class="grid">
        <div class="metric">
            Critical
            <strong>{counts["critical"]}</strong>
        </div>

        <div class="metric">
            High
            <strong>{counts["high"]}</strong>
        </div>

        <div class="metric">
            Medium
            <strong>{counts["medium"]}</strong>
        </div>

        <div class="metric">
            Low
            <strong>{counts["low"]}</strong>
        </div>

        <div class="metric">
            Informational
            <strong>{counts["info"]}</strong>
        </div>
    </div>
</div>

<div class="card">
    <h2>Scan Statistics</h2>

    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>

        <tr>
            <td>Rules Loaded</td>
            <td>{summary.get("rules_loaded", 0)}</td>
        </tr>

        <tr>
            <td>Processes Scanned</td>
            <td>{summary.get("processes_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Network Connections</td>
            <td>{summary.get("network_connections_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Windows Events</td>
            <td>{summary.get("windows_events_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Timeline Events</td>
            <td>{summary.get("timeline_events", 0)}</td>
        </tr>
    </table>
</div>

<div class="card">
    <h2>System Information</h2>

    <table>
        <tr>
            <th>Field</th>
            <th>Value</th>
        </tr>

        {system_rows}
    </table>
</div>

<div class="card">
    <h2>Security Findings</h2>

    <table>
        <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Finding</th>
            <th>Confidence</th>
            <th>MITRE ATT&amp;CK</th>
            <th>Evidence</th>
        </tr>

        {
            "".join(finding_rows)
            if finding_rows
            else '<tr><td colspan="6">No findings detected.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Correlated Incidents</h2>

    <table>
        <tr>
            <th>Incident ID</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Confidence</th>
        </tr>

        {
            "".join(incident_rows)
            if incident_rows
            else '<tr><td colspan="4">No correlated incidents detected.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Investigation Timeline</h2>

    <table>
        <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Event</th>
        </tr>

        {
            "".join(timeline_rows)
            if timeline_rows
            else '<tr><td colspan="4">No timeline events available.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Collector Status</h2>

    <table>
        <tr>
            <th>Collector</th>
            <th>Status</th>
        </tr>

        {collector_rows}
    </table>
</div>

<div class="card">
    <h2>Methodology &amp; Limitations</h2>

    <p>
        SentinelClaw performs local deterministic security
        collection, rule-based detection, normalization,
        correlation, risk scoring, and timeline construction.
    </p>

    <p>
        Findings represent security indicators requiring
        investigation and do not independently prove compromise.
    </p>

    <p>
        Optional local AI analysis is advisory and is not required
        for SentinelClaw detection.
    </p>
</div>

<div class="footer">
    Generated locally by SentinelClaw.
</div>

</div>

</body>
</html>
"""


def save_report_formats(
    report: dict,
    output_directory: str | Path = "reports",
    formats: tuple[str, ...] = (
        "json",
        "text",
        "html",
    ),
) -> dict[str, Path]:
    output_path = Path(
        output_directory
    )

    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    created: dict[str, Path] = {}

    if "json" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.json"
        )

        path.write_text(
            generate_json_report(report),
            encoding="utf-8",
        )

        created["json"] = path

    if "text" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.txt"
        )

        path.write_text(
            generate_text_report(report),
            encoding="utf-8",
        )

        created["text"] = path

    if "html" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.html"
        )

        path.write_text(
            generate_html_report(report),
            encoding="utf-8",
        )

        created["html"] = path

    return created
