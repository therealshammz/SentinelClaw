import logging
import re

logger = logging.getLogger(__name__)

_DOWNLOAD_EXEC_PATTERN = re.compile(
    r"(?:curl|wget|nc)\s+"
    r"\S+.*\|\s*"
    r"(?:ba|d|k|z)?sh\b"
)

_TMP_PATH_MARKERS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def _references_tmp(
    text: str,
) -> bool:
    return any(marker in text for marker in _TMP_PATH_MARKERS)


def analyze_persistence_records(
    records: list[dict],
) -> list[dict]:
    """Analyze Linux persistence records into PERS-* findings."""
    findings: list[dict] = []

    for record in records:
        mechanism = record.get("mechanism")

        if mechanism == "cron":
            command = str(record.get("command") or "")

            content = str(record.get("content") or "")

            if _DOWNLOAD_EXEC_PATTERN.search(content):
                findings.append(
                    {
                        "severity": "high",
                        "rule_id": "PERS-001",
                        "title": ("Cron job downloads and executes content"),
                        "description": (
                            "A cron entry pipes downloaded content into a shell interpreter."
                        ),
                        "confidence": "high",
                        "evidence": {
                            "path": record.get("path"),
                            "user": record.get("user"),
                            "line": record.get("line"),
                            "command": command,
                        },
                        "mitre": {
                            "technique": "T1053.003",
                            "name": "Cron",
                            "tactic": "Persistence",
                        },
                    }
                )
            elif _references_tmp(content):
                findings.append(
                    {
                        "severity": "medium",
                        "rule_id": "PERS-001",
                        "title": ("Cron job references temporary directory"),
                        "description": (
                            "A cron entry executes or references a temporary directory."
                        ),
                        "confidence": "medium",
                        "evidence": {
                            "path": record.get("path"),
                            "user": record.get("user"),
                            "line": record.get("line"),
                            "command": command,
                        },
                        "mitre": {
                            "technique": "T1053.003",
                            "name": "Cron",
                            "tactic": "Persistence",
                        },
                    }
                )

        elif mechanism == "systemd_unit":
            if record.get("writable_by_others"):
                findings.append(
                    {
                        "severity": "medium",
                        "rule_id": "PERS-002",
                        "title": ("Systemd unit file writable by others"),
                        "description": (
                            "A systemd unit file is writable "
                            "by group or other users and "
                            "could be modified to gain "
                            "persistence."
                        ),
                        "confidence": "high",
                        "evidence": {
                            "path": record.get("path"),
                            "exec_start": record.get("exec_start"),
                        },
                        "mitre": {
                            "technique": "T1543.002",
                            "name": "Systemd Service",
                            "tactic": "Persistence",
                        },
                    }
                )

            exec_start = str(record.get("exec_start") or "")

            if _references_tmp(exec_start):
                findings.append(
                    {
                        "severity": "medium",
                        "rule_id": "PERS-003",
                        "title": ("Systemd service executes from temporary path"),
                        "description": (
                            "A systemd unit executes a "
                            "binary from a user-writable "
                            "temporary location."
                        ),
                        "confidence": "medium",
                        "evidence": {
                            "path": record.get("path"),
                            "exec_start": exec_start,
                        },
                        "mitre": {
                            "technique": "T1543.002",
                            "name": "Systemd Service",
                            "tactic": "Persistence",
                        },
                    }
                )

        elif mechanism == "rc_script":
            if record.get("world_writable"):
                findings.append(
                    {
                        "severity": "medium",
                        "rule_id": "PERS-004",
                        "title": ("Startup script in world-writable location"),
                        "description": (
                            "A boot or run-level script, or "
                            "the directory containing it, is "
                            "world-writable and could be "
                            "replaced by an attacker."
                        ),
                        "confidence": "medium",
                        "evidence": {
                            "path": record.get("path"),
                            "target": record.get("target"),
                        },
                        "mitre": {
                            "technique": "T1037",
                            "name": "Boot or Logon Autostart Execution",
                            "tactic": "Persistence",
                        },
                    }
                )

        elif mechanism == "at_job":
            command = str(record.get("command") or "")

            if (
                record.get("world_writable")
                or _DOWNLOAD_EXEC_PATTERN.search(command)
                or _references_tmp(command)
            ):
                findings.append(
                    {
                        "severity": "medium",
                        "rule_id": "PERS-005",
                        "title": ("Suspicious scheduled at job"),
                        "description": (
                            "An at job is world-writable or "
                            "references temporary or "
                            "download-and-execute content."
                        ),
                        "confidence": "medium",
                        "evidence": {
                            "path": record.get("path"),
                            "command": command,
                        },
                        "mitre": {
                            "technique": "T1053.002",
                            "name": "At",
                            "tactic": "Persistence",
                        },
                    }
                )

    logger.debug(
        "Persistence detector produced %d finding(s) from %d record(s)",
        len(findings),
        len(records),
    )

    return findings
