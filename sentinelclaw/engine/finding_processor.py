from __future__ import annotations

import json
from copy import deepcopy
from typing import Any


VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def normalize_severity(value: Any) -> str:
    severity = str(value or "info").lower()

    if severity not in VALID_SEVERITIES:
        return "info"

    return severity


def normalize_confidence(value: Any) -> str | None:
    if value is None:
        return None

    confidence = str(value).lower()

    valid = {
        "low",
        "medium",
        "high",
    }

    if confidence not in valid:
        return None

    return confidence


def normalize_mitre(mitre: Any) -> dict | None:
    if not isinstance(mitre, dict):
        return None

    tactic = mitre.get("tactic")
    technique = mitre.get("technique")
    name = mitre.get("name")

    if not tactic and not technique and not name:
        return None

    return {
        "tactic": tactic,
        "technique": technique,
        "name": name,
    }


def normalize_evidence(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, dict):
        return value

    if isinstance(value, list):
        return value

    return {
        "value": value,
    }


def normalize_finding(
    finding: dict,
    source: str | None = None,
) -> dict:
    result = deepcopy(finding)

    result["rule_id"] = str(
        result.get(
            "rule_id",
            "UNKNOWN",
        )
    )

    result["severity"] = normalize_severity(
        result.get("severity")
    )

    result["title"] = str(
        result.get(
            "title",
            "Unknown finding",
        )
    )

    result["description"] = str(
        result.get(
            "description",
            "",
        )
    )

    result["category"] = str(
        result.get(
            "category",
            "unknown",
        )
    )

    result["confidence"] = normalize_confidence(
        result.get("confidence")
    )

    result["mitre"] = normalize_mitre(
        result.get("mitre")
    )

    result["evidence"] = normalize_evidence(
        result.get("evidence")
    )

    if source:
        result["source"] = source
    elif "source" not in result:
        result["source"] = "unknown"

    return result


def normalize_findings(
    findings: list[dict],
    source: str | None = None,
) -> list[dict]:
    return [
        normalize_finding(
            finding,
            source=source,
        )
        for finding in findings
    ]


def canonical_evidence(
    evidence: Any,
) -> str:
    try:
        return json.dumps(
            evidence,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return str(evidence)


def finding_fingerprint(
    finding: dict,
) -> tuple:
    rule_id = finding.get(
        "rule_id",
        "UNKNOWN",
    )

    title = finding.get(
        "title",
        "",
    )

    category = finding.get(
        "category",
        "unknown",
    )

    pid = finding.get("pid")
    process_name = finding.get(
        "process_name"
    )

    remote_ip = finding.get(
        "remote_ip"
    )

    remote_port = finding.get(
        "remote_port"
    )

    evidence = canonical_evidence(
        finding.get("evidence")
    )

    return (
        rule_id,
        title,
        category,
        pid,
        process_name,
        remote_ip,
        remote_port,
        evidence,
    )


def equivalent_behavior_key(
    finding: dict,
) -> tuple:
    title = (
        finding.get(
            "title",
            "",
        )
        .strip()
        .lower()
    )

    category = (
        finding.get(
            "category",
            "unknown",
        )
        .strip()
        .lower()
    )

    pid = finding.get("pid")

    process_name = (
        finding.get(
            "process_name",
            "",
        )
        or ""
    ).lower()

    mitre = finding.get(
        "mitre"
    ) or {}

    technique = (
        mitre.get(
            "technique",
            "",
        )
        or ""
    ).upper()

    return (
        category,
        title,
        pid,
        process_name,
        technique,
    )


def merge_findings(
    existing: dict,
    incoming: dict,
) -> dict:
    existing_rank = SEVERITY_RANK.get(
        existing.get(
            "severity",
            "info",
        ),
        0,
    )

    incoming_rank = SEVERITY_RANK.get(
        incoming.get(
            "severity",
            "info",
        ),
        0,
    )

    if incoming_rank > existing_rank:
        primary = deepcopy(incoming)
        secondary = existing
    else:
        primary = deepcopy(existing)
        secondary = incoming

    sources = set()

    for item in (
        existing,
        incoming,
    ):
        source = item.get(
            "source"
        )

        if isinstance(
            source,
            list,
        ):
            sources.update(source)
        elif source:
            sources.add(source)

    primary["source"] = sorted(
        sources
    )

    rule_ids = set()

    for item in (
        existing,
        incoming,
    ):
        rule_id = item.get(
            "rule_id"
        )

        if rule_id:
            rule_ids.add(
                str(rule_id)
            )

    primary["related_rule_ids"] = sorted(
        rule_ids
    )

    if (
        not primary.get("mitre")
        and secondary.get("mitre")
    ):
        primary["mitre"] = deepcopy(
            secondary["mitre"]
        )

    if (
        not primary.get("confidence")
        and secondary.get("confidence")
    ):
        primary["confidence"] = (
            secondary["confidence"]
        )

    return primary


def deduplicate_findings(
    findings: list[dict],
) -> list[dict]:
    exact_seen = {}
    exact_results = []

    for finding in findings:
        fingerprint = finding_fingerprint(
            finding
        )

        if fingerprint in exact_seen:
            index = exact_seen[
                fingerprint
            ]

            exact_results[index] = (
                merge_findings(
                    exact_results[index],
                    finding,
                )
            )
        else:
            exact_seen[
                fingerprint
            ] = len(
                exact_results
            )

            exact_results.append(
                deepcopy(
                    finding
                )
            )

    behavior_seen = {}
    results = []

    for finding in exact_results:
        key = equivalent_behavior_key(
            finding
        )

        if key in behavior_seen:
            index = behavior_seen[
                key
            ]

            results[index] = (
                merge_findings(
                    results[index],
                    finding,
                )
            )
        else:
            behavior_seen[
                key
            ] = len(
                results
            )

            results.append(
                deepcopy(
                    finding
                )
            )

    return results


def sort_findings(
    findings: list[dict],
) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK.get(
                finding.get(
                    "severity",
                    "info",
                ),
                0,
            ),
            finding.get(
                "rule_id",
                "",
            ),
        ),
    )


def process_findings(
    findings: list[dict],
) -> list[dict]:
    normalized = normalize_findings(
        findings
    )

    deduplicated = deduplicate_findings(
        normalized
    )

    return sort_findings(
        deduplicated
    )
