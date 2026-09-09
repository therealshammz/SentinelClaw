from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinelclaw.config.constants import SEVERITY_RANK


TIMESTAMP_FIELDS = (
    "timestamp",
    "time",
    "time_generated",
    "time_created",
    "event_time",
    "created_at",
    "create_time",
)


def parse_timestamp(
    value: Any,
) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value

    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            )
        except (
            ValueError,
            OSError,
            OverflowError,
        ):
            return None

    elif isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        if text.endswith("Z"):
            text = (
                text[:-1]
                + "+00:00"
            )

        try:
            dt = datetime.fromisoformat(
                text
            )
        except ValueError:
            formats = (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
            )

            dt = None

            for date_format in formats:
                try:
                    dt = datetime.strptime(
                        text,
                        date_format,
                    )
                    break
                except ValueError:
                    continue

            if dt is None:
                return None

    else:
        return None

    # mypy cannot narrow dt across the if/elif join above.
    assert dt is not None

    if dt.tzinfo is None:
        dt = dt.replace(
            tzinfo=timezone.utc
        )

    return dt


def find_timestamp(
    data: Any,
) -> datetime | None:
    if not isinstance(
        data,
        dict,
    ):
        return None

    for field in TIMESTAMP_FIELDS:
        if field not in data:
            continue

        timestamp = parse_timestamp(
            data.get(field)
        )

        if timestamp is not None:
            return timestamp

    for nested_key in (
        "evidence",
        "event",
        "process",
        "network",
    ):
        nested = data.get(
            nested_key
        )

        if isinstance(
            nested,
            dict,
        ):
            timestamp = find_timestamp(
                nested
            )

            if timestamp is not None:
                return timestamp

    return None


def extract_pid(
    finding: dict,
) -> int | None:
    pid = finding.get(
        "pid"
    )

    if pid is not None:
        return pid

    evidence = finding.get(
        "evidence"
    )

    if isinstance(
        evidence,
        dict,
    ):
        return evidence.get(
            "pid"
        )

    return None


def extract_process_name(
    finding: dict,
) -> str | None:
    process_name = finding.get(
        "process_name"
    )

    if process_name:
        return str(
            process_name
        )

    evidence = finding.get(
        "evidence"
    )

    if isinstance(
        evidence,
        dict,
    ):
        name = evidence.get(
            "name"
        )

        if name:
            return str(
                name
            )

    return None


def extract_remote_ip(
    finding: dict,
) -> str | None:
    remote_ip = finding.get(
        "remote_ip"
    )

    if remote_ip:
        return str(
            remote_ip
        )

    evidence = finding.get(
        "evidence"
    )

    if isinstance(
        evidence,
        dict,
    ):
        remote_ip = evidence.get(
            "remote_ip"
        )

        if remote_ip:
            return str(
                remote_ip
            )

    return None


def finding_to_timeline_event(
    finding: dict,
    sequence: int,
) -> dict:
    timestamp = find_timestamp(
        finding
    )

    mitre = finding.get(
        "mitre"
    )

    if not isinstance(
        mitre,
        dict,
    ):
        mitre = None

    return {
        "timeline_id": (
            f"TL-FIND-{sequence:04d}"
        ),
        "event_type": "finding",
        "timestamp": (
            timestamp.isoformat()
            if timestamp
            else None
        ),
        "severity": finding.get(
            "severity",
            "info",
        ),
        "title": finding.get(
            "title",
            "Security finding",
        ),
        "description": finding.get(
            "description",
            "",
        ),
        "rule_id": finding.get(
            "rule_id"
        ),
        "category": finding.get(
            "category"
        ),
        "pid": extract_pid(
            finding
        ),
        "process_name": extract_process_name(
            finding
        ),
        "remote_ip": extract_remote_ip(
            finding
        ),
        "mitre": mitre,
        "source": finding.get(
            "source"
        ),
    }


def incident_to_timeline_event(
    incident: dict,
    sequence: int,
    fallback_timestamp: datetime,
) -> dict:
    timestamps = []

    findings = incident.get(
        "findings",
        [],
    )

    for finding in findings:
        timestamp = find_timestamp(
            finding
        )

        if timestamp is not None:
            timestamps.append(
                timestamp
            )

    if timestamps:
        incident_time = min(
            timestamps
        )
    else:
        incident_time = fallback_timestamp

    return {
        "timeline_id": (
            f"TL-INC-{sequence:04d}"
        ),
        "event_type": "incident",
        "timestamp": (
            incident_time.isoformat()
        ),
        "severity": incident.get(
            "severity",
            "info",
        ),
        "title": incident.get(
            "title",
            "Correlated incident",
        ),
        "description": incident.get(
            "description",
            "",
        ),
        "incident_id": incident.get(
            "incident_id"
        ),
        "confidence": incident.get(
            "confidence"
        ),
        "related_pids": incident.get(
            "related_pids",
            [],
        ),
        "related_ips": incident.get(
            "related_ips",
            [],
        ),
        "mitre": incident.get(
            "mitre",
            [],
        ),
    }


def timestamp_sort_value(
    event: dict,
) -> datetime:
    timestamp = parse_timestamp(
        event.get(
            "timestamp"
        )
    )

    if timestamp is None:
        return datetime.max.replace(
            tzinfo=timezone.utc
        )

    return timestamp.astimezone(
        timezone.utc
    )


def build_timeline(
    findings: list[dict],
    incidents: list[dict] | None = None,
    scan_timestamp: str | None = None,
) -> list[dict]:
    timeline = []

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        timeline.append(
            finding_to_timeline_event(
                finding,
                index,
            )
        )

    fallback_timestamp = (
        parse_timestamp(
            scan_timestamp
        )
        or datetime.now(
            timezone.utc
        )
    )

    for index, incident in enumerate(
        incidents or [],
        start=1,
    ):
        timeline.append(
            incident_to_timeline_event(
                incident,
                index,
                fallback_timestamp,
            )
        )

    timeline.sort(
        key=lambda event: (
            timestamp_sort_value(
                event
            ),
            -SEVERITY_RANK.get(
                str(
                    event.get(
                        "severity",
                        "info",
                    )
                ).lower(),
                0,
            ),
            event.get(
                "timeline_id",
                "",
            ),
        )
    )

    return timeline
