import logging
from collections import Counter

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)


HIGH_RISK_EVENT_IDS = {
    1102: (
        "high",
        "Windows audit log cleared",
        "The Windows Security audit log was cleared.",
    ),
    4697: (
        "high",
        "New Windows service installed",
        "A new service was installed on the system.",
    ),
    4720: (
        "medium",
        "New user account created",
        "A new Windows user account was created.",
    ),
    4728: (
        "medium",
        "User added to global security group",
        "A member was added to a global security group.",
    ),
    4732: (
        "medium",
        "User added to local security group",
        "A member was added to a local security group.",
    ),
}


def analyze_windows_events(events: list[dict]) -> list[dict]:
    findings = []

    event_counts = Counter(
        event.get("event_id")
        for event in events
    )

    failed_logons = event_counts.get(4625, 0)

    if failed_logons >= get_settings().logon_failure_threshold:
        findings.append(
            {
                "severity": "medium",
                "rule_id": "WIN-001",
                "title": "Multiple failed Windows logons",
                "description": (
                    f"{failed_logons} failed logon events were observed "
                    "in the collected event window."
                ),
                "evidence": {
                    "event_id": 4625,
                    "count": failed_logons,
                },
            }
        )

    for event in events:
        event_id = event.get("event_id")

        if event_id in HIGH_RISK_EVENT_IDS:
            severity, title, description = HIGH_RISK_EVENT_IDS[event_id]

            findings.append(
                {
                    "severity": severity,
                    "rule_id": f"WIN-{event_id}",
                    "title": title,
                    "description": description,
                    "evidence": {
                        "event_id": event_id,
                        "timestamp": event.get("timestamp"),
                        "source": event.get("source"),
                        "message_data": event.get("message_data"),
                    },
                }
            )

    logger.debug(
        "Windows event detector produced %d finding(s) "
        "from %d event(s)",
        len(findings),
        len(events),
    )

    return findings
