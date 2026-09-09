"""
Linux authentication log collector (P1-10).

Reads SSH, sudo and account-management entries from ``/var/log/auth.log``
and ``/var/log/secure`` in a read-only, bounded fashion. On non-Linux
systems, or when the files are absent, the collector returns an empty list
rather than raising: a missing file is an operational note, not an error.

The parser produces structured auth events consumed by
``sentinelclaw.detectors.auth_detector.analyze_auth_events``. journald
messages are only covered when they are forwarded to the syslog files that
this module reads; reading the journal directly would require privileged
subprocess access that this local-first, read-only tool intentionally
avoids.
"""

import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

AUTH_LOG_PATHS = (
    "/var/log/auth.log",
    "/var/log/secure",
)

MAX_TAIL_BYTES = 256 * 1024

MAX_AUTH_EVENTS = 500

_SSHD_FAILED_PATTERN = re.compile(
    r"sshd\[\d+\]:\s+"
    r"Failed\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(\S+)\s+"
    r"from\s+([0-9A-Fa-f:.]+)\s+"
    r"port\s+(\d+)"
)

_SSHD_ACCEPTED_PATTERN = re.compile(
    r"sshd\[\d+\]:\s+"
    r"Accepted\s+(password|publickey|"
    r"keyboard-interactive)\s+"
    r"for\s+(\S+)\s+from\s+"
    r"([0-9A-Fa-f:.]+)"
)

_SUDO_FAILURE_PATTERN = re.compile(
    r"sudo(?:\[\d+\])?:\s+"
    r"(?:pam_unix\(sudo:auth\):\s*)?"
    r"authentication\s+failure;\s*.*?"
    r"(?:user=(\S+))?"
)

_SUDO_CMD_PATTERN = re.compile(
    r"sudo(?:\[\d+\])?:\s+(\S+)\s+:\s+.*?"
    r"USER=(\S+)\s+.*?COMMAND=(.*)$"
)

_NEW_USER_PATTERN = re.compile(
    r"useradd(?:\[\d+\])?:\s+"
    r"new\s+user:\s+name=(\S+)"
)

_SESSION_OPENED_PATTERN = re.compile(r"session\s+opened\s+for\s+user\s+(\S+)")

_TIMESTAMP_PATTERN = re.compile(r"^\S+\s+\d+\s+\d{2}:\d{2}:\d{2}")


def read_tail_text(
    path: Path,
    max_bytes: int = MAX_TAIL_BYTES,
) -> str:
    """Return the trailing ``max_bytes`` of a text file (bounded read)."""
    size = path.stat().st_size

    with path.open("rb") as file:
        if size <= max_bytes:
            data = file.read()

            return data.decode(
                "utf-8",
                errors="ignore",
            )

        file.seek(size - max_bytes)

        data = file.read()

    text = data.decode(
        "utf-8",
        errors="ignore",
    )

    # Drop the partially-read first line so we never evaluate a
    # torn record, then append the file's final newline if missing.
    first_newline = text.find("\n")

    if first_newline != -1:
        text = text[first_newline + 1 :]

    return text


def classify_auth_line(
    line: str,
) -> dict | None:
    """Parse a single auth log line into a structured event (or ``None``)."""
    message = line.strip()

    if not message:
        return None

    lower = message.lower()

    if "sshd" in lower:
        accepted = _SSHD_ACCEPTED_PATTERN.search(message)

        if accepted:
            auth_method = accepted.group(1)
            username = accepted.group(2)
            ip = accepted.group(3)

            event_type = "accepted_publickey" if auth_method == "publickey" else "accepted_password"

            return {
                "program": "sshd",
                "event_type": event_type,
                "username": username,
                "ip": ip,
                "port": None,
                "detail": auth_method,
                "message": message,
            }

        failed = _SSHD_FAILED_PATTERN.search(message)

        if failed:
            return {
                "program": "sshd",
                "event_type": "failed_password",
                "username": failed.group(1),
                "ip": failed.group(2),
                "port": int(failed.group(3)),
                "detail": ("invalid_user" if "invalid user" in lower else "password"),
                "message": message,
            }

    if "sudo" in lower:
        failure = _SUDO_FAILURE_PATTERN.search(message)

        if failure:
            return {
                "program": "sudo",
                "event_type": "sudo_failure",
                "username": failure.group(1),
                "ip": None,
                "port": None,
                "detail": None,
                "message": message,
            }

        command = _SUDO_CMD_PATTERN.search(message)

        if command:
            return {
                "program": "sudo",
                "event_type": "sudo_success",
                "username": command.group(1),
                "ip": None,
                "port": None,
                "detail": {
                    "user": command.group(2),
                    "command": command.group(3).strip(),
                },
                "message": message,
            }

    if "useradd" in lower:
        new_user = _NEW_USER_PATTERN.search(message)

        if new_user:
            return {
                "program": "useradd",
                "event_type": "new_user",
                "username": new_user.group(1),
                "ip": None,
                "port": None,
                "detail": None,
                "message": message,
            }

    if "sshd" in lower:
        session = _SESSION_OPENED_PATTERN.search(message)

        if session:
            return {
                "program": "sshd",
                "event_type": "session_opened",
                "username": session.group(1),
                "ip": None,
                "port": None,
                "detail": None,
                "message": message,
            }

    return None


def parse_auth_text(
    text: str,
    source: str = "auth.log",
) -> list[dict]:
    """Parse auth log text into a deterministic list of structured events."""
    events: list[dict] = []

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        event = classify_auth_line(line)

        if event is None:
            continue

        timestamp_match = _TIMESTAMP_PATTERN.match(line)

        event["timestamp"] = timestamp_match.group(0) if timestamp_match else None

        event["source"] = source
        event["line"] = line_number

        events.append(event)

        if len(events) >= MAX_AUTH_EVENTS:
            break

    logger.debug(
        "Parsed %d auth event(s) from %s (%d line(s))",
        len(events),
        source,
        len(text.splitlines()),
    )

    return events


def read_auth_log_file(
    path: str | Path,
) -> list[dict]:
    """Read and parse a single auth log file (bounded; empty when missing)."""
    log_path = Path(path)

    if not log_path.is_file() or not log_path.exists():
        logger.debug(
            "Auth log %s not present; returning no events",
            log_path,
        )

        return []

    try:
        text = read_tail_text(log_path)
    except OSError as exc:
        logger.warning(
            "Unable to read auth log %s: %s",
            log_path,
            exc,
        )

        return []

    return parse_auth_text(
        text,
        source=log_path.name,
    )


def get_auth_events(
    paths: tuple[str, ...] | None = None,
) -> list[dict]:
    """Collect structured authentication events for the current host.

    On non-Linux platforms, or when none of the auth log files exist,
    an empty list is returned (missing files are an operational note,
    not an error).
    """
    if not sys.platform.startswith("linux"):
        return []

    candidate_paths = paths if paths is not None else AUTH_LOG_PATHS

    events: list[dict] = []

    for candidate in candidate_paths:
        events.extend(read_auth_log_file(candidate))

        if len(events) >= MAX_AUTH_EVENTS:
            break

    logger.debug(
        "Collected %d auth event(s) from %d source(s)",
        len(events),
        len(candidate_paths),
    )

    return events
