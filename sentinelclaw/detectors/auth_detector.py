import logging

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(__name__)

FAILED_PASSWORD_TYPES = {
    "failed_password",
}


def analyze_auth_events(
    events: list[dict],
) -> list[dict]:
    """Analyze structured Linux auth events into AUTH-* findings."""
    findings: list[dict] = []

    threshold = get_settings().logon_failure_threshold

    failed = [event for event in events if event.get("event_type") in FAILED_PASSWORD_TYPES]

    if len(failed) >= threshold:
        findings.append(
            {
                "severity": "medium",
                "rule_id": "AUTH-001",
                "title": ("Multiple failed SSH authentication attempts"),
                "description": (
                    f"{len(failed)} failed SSH password "
                    "authentication attempts were observed "
                    "in the local auth logs."
                ),
                "confidence": "medium",
                "evidence": {
                    "count": len(failed),
                    "ips": sorted({str(event.get("ip")) for event in failed if event.get("ip")}),
                    "usernames": sorted(
                        {str(event.get("username")) for event in failed if event.get("username")}
                    ),
                    "sources": sorted(
                        {str(event.get("source")) for event in failed if event.get("source")}
                    ),
                },
                "mitre": {
                    "technique": "T1110",
                    "name": "Brute Force",
                    "tactic": "Credential Access",
                },
            }
        )

    accepted = [
        event
        for event in events
        if event.get("event_type")
        in {
            "accepted_password",
            "accepted_publickey",
        }
    ]

    for event in accepted:
        username = str(event.get("username") or "")

        passwordless = event.get("event_type") == "accepted_publickey"

        privileged = username in {
            "root",
            "toor",
            "admin",
        }

        if passwordless or privileged:
            severity = "high" if privileged else "low"

            findings.append(
                {
                    "severity": severity,
                    "rule_id": "AUTH-002",
                    "title": ("Passwordless or privileged SSH login"),
                    "description": (
                        f"SSH login accepted for "
                        f"{username or 'unknown user'} "
                        "via passwordless or privileged "
                        "authentication."
                    ),
                    "confidence": "medium",
                    "evidence": {
                        "username": username,
                        "ip": event.get("ip"),
                        "auth_method": event.get("detail"),
                        "source": event.get("source"),
                        "timestamp": event.get("timestamp"),
                        "message": event.get("message"),
                    },
                    "mitre": {
                        "technique": "T1078",
                        "name": "Valid Accounts",
                        "tactic": "Persistence",
                    },
                }
            )

    sudo_failures = [event for event in events if event.get("event_type") == "sudo_failure"]

    if sudo_failures:
        findings.append(
            {
                "severity": "medium",
                "rule_id": "AUTH-003",
                "title": ("Sudo authentication failure"),
                "description": (
                    "One or more sudo authentication "
                    "failures were observed, which may "
                    "indicate password guessing against "
                    "a privileged account."
                ),
                "confidence": "medium",
                "evidence": {
                    "count": len(sudo_failures),
                    "usernames": sorted(
                        {
                            str(event.get("username"))
                            for event in sudo_failures
                            if event.get("username")
                        }
                    ),
                    "sources": sorted(
                        {str(event.get("source")) for event in sudo_failures if event.get("source")}
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
        if event.get("event_type") != "new_user":
            continue

        findings.append(
            {
                "severity": "medium",
                "rule_id": "AUTH-004",
                "title": ("New local user account created"),
                "description": ("A new local user account was created on the system."),
                "confidence": "medium",
                "evidence": {
                    "username": event.get("username"),
                    "source": event.get("source"),
                    "timestamp": event.get("timestamp"),
                    "message": event.get("message"),
                },
                "mitre": {
                    "technique": "T1136.001",
                    "name": "Local Account",
                    "tactic": "Persistence",
                },
            }
        )

    logger.debug(
        "Auth detector produced %d finding(s) from %d event(s)",
        len(findings),
        len(events),
    )

    return findings
