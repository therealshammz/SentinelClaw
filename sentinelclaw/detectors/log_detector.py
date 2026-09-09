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

LOG_CLASS_FINDINGS: dict[
    str,
    tuple[str, str, str, str, str, dict | None],
] = {
    "command_and_control": (
        "high",
        "LOG-002",
        "Command-and-control activity in log",
        "A log line indicates reverse-shell "
        "or command-and-control activity.",
        "medium",
        {
            "technique": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
        },
    ),
    "credential_access": (
        "high",
        "LOG-003",
        "Credential access activity in log",
        "A log line indicates credential-dumping "
        "or credential-access activity.",
        "medium",
        {
            "technique": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
        },
    ),
    "execution": (
        "medium",
        "LOG-004",
        "Scripted or obfuscated execution in log",
        "A log line indicates scripted or "
        "obfuscated command execution.",
        "medium",
        {
            "technique": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
        },
    ),
    "persistence": (
        "medium",
        "LOG-005",
        "Persistence-related activity in log",
        "A log line indicates persistence "
        "mechanism activity.",
        "medium",
        {
            "technique": "T1053.005",
            "name": "Scheduled Task",
            "tactic": "Persistence",
        },
    ),
    "reconnaissance": (
        "low",
        "LOG-006",
        "Reconnaissance activity in log",
        "A log line indicates scanning or "
        "reconnaissance activity.",
        "low",
        {
            "technique": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
        },
    ),
    "privilege_escalation": (
        "medium",
        "LOG-007",
        "Privilege escalation activity in log",
        "A log line indicates privilege "
        "escalation activity.",
        "medium",
        {
            "technique": "T1068",
            "name": "Exploitation for "
            "Privilege Escalation",
            "tactic": "Privilege Escalation",
        },
    ),
    "generic": (
        "info",
        "LOG-008",
        "Suspicious content indicator in log",
        "A log line matched a suspicious "
        "content keyword.",
        "low",
        None,
    ),
}


def analyze_log_events(
    events: list[dict],
) -> list[dict]:
    findings: list[dict] = []

    auth_events = [
        event
        for event in events
        if event.get(
            "event_class"
        )
        == "authentication"
    ]

    if (
        len(auth_events)
        >= get_settings().logon_failure_threshold
    ):
        findings.append(
            {
                "severity": "medium",
                "rule_id": "LOG-001",
                "title": (
                    "Multiple failed authentication "
                    "attempts in log"
                ),
                "description": (
                    f"{len(auth_events)} failed "
                    "authentication events were "
                    "observed in the analyzed "
                    "log file."
                ),
                "category": "log",
                "confidence": "medium",
                "evidence": {
                    "count": len(
                        auth_events
                    ),
                    "line_numbers": [
                        event.get(
                            "line_number"
                        )
                        for event in auth_events
                    ][:20],
                    "ips": sorted(
                        {
                            str(event.get("ip"))
                            for event in auth_events
                            if event.get("ip")
                        }
                    ),
                    "hosts": sorted(
                        {
                            str(event.get("host"))
                            for event in auth_events
                            if event.get("host")
                        }
                    ),
                    "usernames": sorted(
                        {
                            str(event.get("username"))
                            for event in auth_events
                            if event.get("username")
                        }
                    ),
                },
                "mitre": {
                    "technique": "T1110",
                    "name": "Brute Force",
                    "tactic": "Credential Access",
                },
            }
        )

    for event in events:
        event_class = event.get(
            "event_class"
        )

        if not event_class:
            continue

        if event_class == "authentication":
            continue

        template = LOG_CLASS_FINDINGS.get(
            event_class
        )

        if template is None:
            continue

        (
            severity,
            rule_id,
            title,
            description,
            confidence,
            mitre,
        ) = template

        findings.append(
            {
                "severity": severity,
                "rule_id": rule_id,
                "title": title,
                "description": description,
                "category": "log",
                "confidence": confidence,
                "evidence": {
                    "line_number": event.get(
                        "line_number"
                    ),
                    "message": event.get(
                        "message"
                    ),
                    "timestamp": event.get(
                        "timestamp"
                    ),
                    "ip": event.get("ip"),
                    "host": event.get("host"),
                    "username": event.get(
                        "username"
                    ),
                    "matched_keywords": event.get(
                        "matched_keywords"
                    ),
                },
                "mitre": mitre,
            }
        )

    logger.debug(
        "Log event detector produced %d "
        "finding(s) from %d event(s)",
        len(findings),
        len(events),
    )

    return findings


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
