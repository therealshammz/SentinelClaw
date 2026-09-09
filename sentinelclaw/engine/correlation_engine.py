from __future__ import annotations

import logging
from collections import defaultdict
from copy import deepcopy

from sentinelclaw.config.constants import SEVERITY_RANK

logger = logging.getLogger(
    __name__
)


def highest_severity(
    findings: list[dict],
) -> str:
    highest = "info"
    highest_rank = 0

    for finding in findings:
        severity = (
            finding.get(
                "severity",
                "info",
            )
            .lower()
        )

        rank = SEVERITY_RANK.get(
            severity,
            0,
        )

        if rank > highest_rank:
            highest = severity
            highest_rank = rank

    return highest


def collect_mitre(
    findings: list[dict],
) -> list[dict]:
    seen = set()
    results = []

    for finding in findings:
        mitre = finding.get("mitre")

        if not isinstance(
            mitre,
            dict,
        ):
            continue

        technique = mitre.get(
            "technique"
        )

        tactic = mitre.get(
            "tactic"
        )

        name = mitre.get(
            "name"
        )

        key = (
            technique,
            tactic,
            name,
        )

        if key in seen:
            continue

        seen.add(key)

        results.append(
            {
                "technique": technique,
                "tactic": tactic,
                "name": name,
            }
        )

    return results


def collect_rule_ids(
    findings: list[dict],
) -> list[str]:
    rule_ids = set()

    for finding in findings:
        rule_id = finding.get(
            "rule_id"
        )

        if rule_id:
            rule_ids.add(
                str(rule_id)
            )

        related = finding.get(
            "related_rule_ids"
        )

        if isinstance(
            related,
            list,
        ):
            rule_ids.update(
                str(item)
                for item in related
            )

    return sorted(
        rule_ids
    )


def incident_confidence(
    findings: list[dict],
) -> str:
    score = 0

    for finding in findings:
        severity = (
            finding.get(
                "severity",
                "info",
            )
            .lower()
        )

        confidence = (
            finding.get(
                "confidence"
            )
            or ""
        ).lower()

        if severity in {
            "high",
            "critical",
        }:
            score += 3
        elif severity == "medium":
            score += 2
        elif severity == "low":
            score += 1

        if confidence == "high":
            score += 2
        elif confidence == "medium":
            score += 1

    if score >= 8:
        return "high"

    if score >= 4:
        return "medium"

    return "low"


def create_incident(
    incident_id: str,
    title: str,
    description: str,
    findings: list[dict],
    related_pids: list[int] | None = None,
    related_ips: list[str] | None = None,
) -> dict:
    return {
        "incident_id": incident_id,
        "title": title,
        "description": description,
        "severity": highest_severity(
            findings
        ),
        "confidence": incident_confidence(
            findings
        ),
        "finding_count": len(
            findings
        ),
        "related_rule_ids": collect_rule_ids(
            findings
        ),
        "related_pids": sorted(
            set(
                related_pids
                or []
            )
        ),
        "related_ips": sorted(
            set(
                related_ips
                or []
            )
        ),
        "mitre": collect_mitre(
            findings
        ),
        "findings": deepcopy(
            findings
        ),
    }


def correlate_process_activity(
    findings: list[dict],
) -> list[dict]:
    incidents = []

    grouped = defaultdict(
        list
    )

    for finding in findings:
        pid = finding.get(
            "pid"
        )

        if pid is None:
            continue

        grouped[pid].append(
            finding
        )

    counter = 1

    for pid, group in grouped.items():
        if len(group) < 2:
            continue

        severities = {
            (
                item.get(
                    "severity",
                    "info",
                )
                .lower()
            )
            for item in group
        }

        if not (
            "high" in severities
            or "critical" in severities
            or "medium" in severities
        ):
            continue

        process_name = None

        for item in group:
            if item.get(
                "process_name"
            ):
                process_name = item[
                    "process_name"
                ]
                break

        title = (
            "Correlated suspicious "
            "process activity"
        )

        if process_name:
            title = (
                f"Correlated activity for "
                f"{process_name}"
            )

        incidents.append(
            create_incident(
                incident_id=(
                    f"INC-PROC-{counter:03d}"
                ),
                title=title,
                description=(
                    "Multiple findings are associated "
                    "with the same process identifier."
                ),
                findings=group,
                related_pids=[
                    pid
                ],
            )
        )

        counter += 1

    return incidents


def correlate_network_process(
    findings: list[dict],
) -> list[dict]:
    incidents = []

    process_findings = defaultdict(
        list
    )

    network_findings = defaultdict(
        list
    )

    for finding in findings:
        pid = finding.get(
            "pid"
        )

        if pid is None:
            continue

        category = (
            finding.get(
                "category",
                ""
            )
            .lower()
        )

        rule_id = (
            finding.get(
                "rule_id",
                ""
            )
            .upper()
        )

        if (
            category == "process"
            or rule_id.startswith(
                "PROC"
            )
        ):
            process_findings[
                pid
            ].append(
                finding
            )

        if (
            category == "network"
            or rule_id.startswith(
                "NET"
            )
        ):
            network_findings[
                pid
            ].append(
                finding
            )

    counter = 1

    common_pids = (
        set(
            process_findings
        )
        & set(
            network_findings
        )
    )

    for pid in sorted(
        common_pids
    ):
        process_group = (
            process_findings[
                pid
            ]
        )

        network_group = (
            network_findings[
                pid
            ]
        )

        combined = (
            process_group
            + network_group
        )

        significant = any(
            (
                finding.get(
                    "severity",
                    "info",
                )
                .lower()
            )
            in {
                "medium",
                "high",
                "critical",
            }
            for finding in process_group
        )

        if not significant:
            continue

        related_ips = []

        for finding in network_group:
            remote_ip = finding.get(
                "remote_ip"
            )

            if remote_ip:
                related_ips.append(
                    remote_ip
                )

        incidents.append(
            create_incident(
                incident_id=(
                    f"INC-NET-{counter:03d}"
                ),
                title=(
                    "Suspicious process with "
                    "network activity"
                ),
                description=(
                    "A process with a significant "
                    "security finding also has "
                    "network-related findings."
                ),
                findings=combined,
                related_pids=[
                    pid
                ],
                related_ips=related_ips,
            )
        )

        counter += 1

    return incidents


def correlate_mitre_chain(
    findings: list[dict],
) -> list[dict]:
    technique_map = defaultdict(
        list
    )

    for finding in findings:
        mitre = finding.get(
            "mitre"
        )

        if not isinstance(
            mitre,
            dict,
        ):
            continue

        tactic = mitre.get(
            "tactic"
        )

        if not tactic:
            continue

        technique_map[
            tactic
        ].append(
            finding
        )

    interesting_tactics = {
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Command and Control",
    }

    matched_tactics = [
        tactic
        for tactic in interesting_tactics
        if tactic in technique_map
    ]

    if len(
        matched_tactics
    ) < 2:
        return []

    correlated = []

    for tactic in matched_tactics:
        correlated.extend(
            technique_map[
                tactic
            ]
        )

    unique = []
    seen = set()

    for finding in correlated:
        key = id(
            finding
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(
            finding
        )

    return [
        create_incident(
            incident_id="INC-MITRE-001",
            title=(
                "Multiple MITRE ATT&CK "
                "tactics observed"
            ),
            description=(
                "Findings span multiple MITRE "
                "ATT&CK tactics and may represent "
                "a broader activity chain."
            ),
            findings=unique,
            related_pids=[
                finding.get(
                    "pid"
                )  # type: ignore[misc]  # pid is an optional field on heterogeneous finding dicts
                for finding in unique
                if finding.get(
                    "pid"
                )
                is not None
            ],
            related_ips=[
                finding.get(
                    "remote_ip"
                )  # type: ignore[misc]  # remote_ip is an optional field on heterogeneous finding dicts
                for finding in unique
                if finding.get(
                    "remote_ip"
                )
            ],
        )
    ]


def deduplicate_incidents(
    incidents: list[dict],
) -> list[dict]:
    results = []
    seen = set()

    for incident in incidents:
        key = (
            incident.get(
                "title"
            ),
            tuple(
                incident.get(
                    "related_pids",
                    []
                )
            ),
            tuple(
                incident.get(
                    "related_rule_ids",
                    []
                )
            ),
        )

        if key in seen:
            continue

        seen.add(key)
        results.append(
            incident
        )

    return results


def correlate_findings(
    findings: list[dict],
) -> list[dict]:
    incidents = []

    incidents.extend(
        correlate_process_activity(
            findings
        )
    )

    incidents.extend(
        correlate_network_process(
            findings
        )
    )

    incidents.extend(
        correlate_mitre_chain(
            findings
        )
    )

    incidents = deduplicate_incidents(
        incidents
    )

    logger.debug(
        "Correlation engine produced "
        "%d incident(s) from %d finding(s)",
        len(incidents),
        len(findings),
    )

    return incidents
