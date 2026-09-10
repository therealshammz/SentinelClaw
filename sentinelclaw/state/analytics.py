"""
Pure data functions for stateful hunting (P3-19).

Everything here operates on scan-state records (see
:mod:`sentinelclaw.state.store`) and returns plain data structures:
no output is written and no live collection happens. The CLI layer in
:mod:`sentinelclaw.state.hunting` renders these structures.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any

from sentinelclaw.config.constants import SEVERITY_RANK

# Windows Security event ids grouped by logon outcome for the
# ``accounts`` command. 4625 is a failed logon, 4624 a successful one,
# and 4720 an account creation; 4771/4776 are additional failure
# sources and 4647 a logoff event that still confirms an interactive
# session existed.
FAILED_LOGON_EVENT_IDS = frozenset(
    {
        4625,
        4771,
        4776,
    }
)

SUCCESSFUL_LOGON_EVENT_IDS = frozenset(
    {
        4624,
        4647,
    }
)

ACCOUNT_CREATION_EVENT_IDS = frozenset(
    {
        4720,
    }
)

# Human-readable names for the event-id frequency table (``stats``).
EVENT_ID_NAMES = {
    1102: "Audit log cleared",
    4624: "Successful logon",
    4625: "Failed logon",
    4647: "User initiated logoff",
    4672: "Special privileges assigned",
    4697: "New service installed",
    4720: "User account created",
    4728: "Member added to global group",
    4732: "Member added to local group",
    4771: "Kerberos pre-authentication failed",
    4776: "Credential validation failed",
}

# Maximum depth for the rendered process tree; a cycle guard is used
# on top of the cap so malformed pid/ppid evidence cannot hang output.
MAX_TREE_DEPTH = 32


def _severity_rank(
    severity: Any,
) -> int:
    return SEVERITY_RANK.get(
        str(severity or "info").lower(),
        0,
    )


def canonical_finding_text(
    finding: dict,
) -> str:
    """Canonical JSON text identifying one finding's behavior."""
    try:
        return json.dumps(
            (
                finding.get(
                    "rule_id",
                    "UNKNOWN",
                ),
                finding.get(
                    "title",
                    "",
                ),
                finding.get(
                    "category",
                    "unknown",
                ),
                finding.get("pid"),
                finding.get("process_name"),
                finding.get("remote_ip"),
                finding.get("remote_port"),
                finding.get("evidence"),
            ),
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return str(finding)


def finding_id(
    finding: dict,
) -> str:
    """Return a stable deterministic id for a finding.

    The id is derived from the same fingerprint fields the finding
    processor uses to deduplicate, so an identical detection across two
    scans shares one id and ``diff`` sees no churn.
    """
    digest = hashlib.sha256(canonical_finding_text(finding).encode("utf-8")).hexdigest()

    return "F-" + digest[:12]


def _finding_sort_key(
    finding: dict,
) -> tuple:
    return (
        -_severity_rank(finding.get("severity")),
        str(
            finding.get(
                "rule_id",
                "",
            )
        ),
        str(
            finding.get(
                "title",
                "",
            )
        ),
    )


def _sorted_findings(
    findings: list[dict],
) -> list[dict]:
    return sorted(
        findings,
        key=_finding_sort_key,
    )


def compare_record_sets(
    baselines: list[dict],
    target: dict,
) -> dict:
    """Compare one record against a set of baseline records.

    ``--since`` semantics: a finding is ``new`` when the target scan
    shows it and none of the baseline records (the state accumulated
    since the cutoff) did; ``closed`` when at least one baseline
    recorded it and the target scan no longer does.
    """
    baseline_findings: list[dict] = []

    for baseline in baselines:
        baseline_findings.extend(
            baseline.get(
                "findings",
                [],
            )
        )

    baseline_ids = {finding_id(finding) for finding in baseline_findings}

    target_findings = target.get(
        "findings",
        [],
    )

    target_ids = {finding_id(finding) for finding in target_findings}

    new = [finding for finding in target_findings if finding_id(finding) not in baseline_ids]

    closed = [finding for finding in baseline_findings if finding_id(finding) not in target_ids]

    return {
        "baseline_ids": [str(baseline.get("record_id")) for baseline in baselines],
        "baseline_count": len(baselines),
        "baseline_findings": len(baseline_findings),
        "target_id": target.get("record_id"),
        "target_timestamp": target.get("timestamp"),
        "target_findings": len(target_findings),
        "new": _sorted_findings(new),
        "closed": _sorted_findings(closed),
        "new_count": len(new),
        "closed_count": len(closed),
    }


def compare_records(
    baseline: dict,
    target: dict,
) -> dict:
    """Compare two records' findings by stable finding id.

    Returns ``new`` (present in ``target`` but not ``baseline``) and
    ``closed`` (present in ``baseline`` but not ``target``) finding
    lists, each ordered by severity then rule id, plus record metadata.
    """
    baseline_findings = baseline.get(
        "findings",
        [],
    )

    target_findings = target.get(
        "findings",
        [],
    )

    baseline_ids = {finding_id(finding) for finding in baseline_findings}

    target_ids = {finding_id(finding) for finding in target_findings}

    new = [finding for finding in target_findings if finding_id(finding) not in baseline_ids]

    closed = [finding for finding in baseline_findings if finding_id(finding) not in target_ids]

    return {
        "baseline_id": baseline.get("record_id"),
        "baseline_timestamp": baseline.get("timestamp"),
        "target_id": target.get("record_id"),
        "target_timestamp": target.get("timestamp"),
        "baseline_findings": len(baseline_findings),
        "target_findings": len(target_findings),
        "new": _sorted_findings(new),
        "closed": _sorted_findings(closed),
        "new_count": len(new),
        "closed_count": len(closed),
    }


def _record_matches(
    record: dict,
    keyword: str,
) -> list[dict]:
    """Return match descriptors for one record."""
    needle = keyword.lower()

    matches: list[dict] = []

    record_id = record.get("record_id")

    for finding in record.get(
        "findings",
        [],
    ):
        if not isinstance(
            finding,
            dict,
        ):
            continue

        haystack = canonical_finding_text(finding)

        if needle not in haystack.lower():
            continue

        matches.append(
            {
                "record_id": record_id,
                "kind": "finding",
                "finding_id": finding_id(finding),
                "incident_id": None,
                "severity": finding.get(
                    "severity",
                    "info",
                ),
                "rule_id": finding.get(
                    "rule_id",
                    "",
                ),
                "title": finding.get(
                    "title",
                    "",
                ),
            }
        )

    for incident in record.get(
        "incidents",
        [],
    ):
        if not isinstance(
            incident,
            dict,
        ):
            continue

        haystack = json.dumps(
            incident,
            ensure_ascii=False,
            default=str,
        )

        if needle not in haystack.lower():
            continue

        matches.append(
            {
                "record_id": record_id,
                "kind": "incident",
                "finding_id": None,
                "incident_id": incident.get("incident_id"),
                "severity": incident.get(
                    "severity",
                    "info",
                ),
                "rule_id": None,
                "title": incident.get(
                    "title",
                    "",
                ),
            }
        )

    return matches


def search_records(
    records: list[dict],
    keyword: str,
    record_id: str | None = None,
) -> list[dict]:
    """Case-insensitive substring search over scan-state records.

    Findings are matched across their full canonical content (title,
    description, rule metadata, evidence); incidents across theirs.
    Matches keep the newest-first record order of ``records``.
    """
    results: list[dict] = []

    for record in records:
        if record_id and str(record.get("record_id")) != record_id:
            continue

        results.extend(
            _record_matches(
                record,
                keyword,
            )
        )

    return results


def process_info_from_finding(
    finding: dict,
) -> dict | None:
    """Extract process context (pid/ppid/names) from a finding.

    YAML-rule process findings promote pid and process_name to the
    finding top level and keep the full record under ``evidence``;
    built-in findings vary. The best-effort extraction tolerates both
    layouts and returns ``None`` when no pid is available.
    """
    evidence = finding.get("evidence")

    if not isinstance(
        evidence,
        dict,
    ):
        evidence = {}

    pid = finding.get("pid")

    if pid is None:
        pid = evidence.get("pid")

    if pid is None:
        return None

    name = finding.get("process_name") or evidence.get("name") or evidence.get("process_name")

    return {
        "pid": pid,
        "ppid": evidence.get("ppid"),
        "name": (str(name) if name else None),
        "parent_name": (evidence.get("parent_name")),
    }


def _record_process_index(
    record: dict | None,
) -> dict[Any, dict[str, Any]]:
    """Map pid -> process context for every pid in a record's findings."""
    if record is None:
        return {}

    index: dict[
        Any,
        dict[str, Any],
    ] = {}

    for finding in record.get(
        "findings",
        [],
    ):
        if not isinstance(
            finding,
            dict,
        ):
            continue

        info = process_info_from_finding(finding)

        if info is None:
            continue

        pid = info["pid"]

        if pid in index:
            continue

        index[pid] = info

    return index


def incident_process_tree_lines(
    incident: dict,
    record: dict | None = None,
) -> list[str]:
    """Render the process tree (ppid chains) for an incident.

    Nodes come from the incident's member findings; when a member's
    evidence names a parent process, a synthetic ancestor node is added
    so the chain reads completely. Member findings are listed beneath
    their process node, one line per finding. ``record`` optionally
    provides the owning scan record so ancestor chains can be extended
    through record-level process context.
    """
    lines: list[str] = []

    incident_id = incident.get(
        "incident_id",
        "?",
    )

    title = incident.get(
        "title",
        "",
    )

    lines.append(f"[Incident {incident_id}] {title}")

    member_findings = incident.get(
        "findings",
        [],
    )

    nodes: dict[
        Any,
        dict[str, Any],
    ] = {}

    for finding in member_findings:
        if not isinstance(
            finding,
            dict,
        ):
            continue

        info = process_info_from_finding(finding)

        pid = info.get("pid") if info else None

        if pid is None:
            node = nodes.setdefault(
                None,
                {
                    "pid": None,
                    "ppid": None,
                    "name": None,
                    "parent_name": None,
                    "findings": [],
                },
            )

            node["findings"].append(finding)

            continue

        node = nodes.setdefault(
            pid,
            {
                "pid": pid,
                "ppid": (info.get("ppid") if info else None),
                "name": (info.get("name") if info else None),
                "parent_name": (info.get("parent_name") if info else None),
                "findings": [],
            },
        )

        node["findings"].append(finding)

    record_index = _record_process_index(record)

    # Walk each member's ancestry upward: the member's evidence names
    # one ancestor level; the record's own findings may extend the
    # chain further (record findings carry process records even when
    # the ancestor itself produced no finding).
    changed = True

    while changed:
        changed = False

        for pid, node in list(nodes.items()):
            ppid = node.get("ppid")

            if pid is None or ppid is None or ppid == pid or ppid in nodes:
                continue

            ancestor = record_index.get(ppid)

            if ancestor is None:
                parent_name = node.get("parent_name")

                if not parent_name:
                    node["ppid"] = None

                    changed = True

                continue

            nodes[ppid] = {
                "pid": ppid,
                "ppid": ancestor.get("ppid"),
                "name": ancestor.get("name"),
                "parent_name": ancestor.get("parent_name"),
                "findings": [],
            }

            changed = True

    if not nodes:
        lines.append("(no process context in member findings)")

        return lines

    children: dict[
        Any,
        list[Any],
    ] = {}

    for pid, node in nodes.items():
        ppid = node.get("ppid")

        if pid is None or ppid is None or ppid == pid or ppid not in nodes:
            continue

        children.setdefault(
            ppid,
            [],
        ).append(pid)

    for child_list in children.values():
        child_list.sort()

    roots = [
        pid
        for pid, node in nodes.items()
        if (pid is not None and (node.get("ppid") is None or node.get("ppid") not in nodes))
    ]

    if not roots:
        pid_nodes = [node for node in nodes.values() if node.get("pid") is not None]

        roots = [
            node["pid"]
            for node in sorted(
                pid_nodes,
                key=lambda node: str(node["pid"]),
            )
        ]

    unparented = nodes.get(None)

    if unparented is not None:
        for finding in unparented.get(
            "findings",
            [],
        ):
            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()

            rule_id = finding.get(
                "rule_id",
                "UNKNOWN",
            )

            lines.append(
                f"  (no pid) finding {finding_id(finding)} "
                f"[{severity}] {rule_id} - "
                f"{finding.get('title', '')}"
            )

    visited: set[Any] = set()

    def add_node(
        pid: Any,
        depth: int,
    ) -> None:
        if pid in visited or depth > MAX_TREE_DEPTH:
            return

        visited.add(pid)

        node = nodes[pid]

        label = str(node.get("name")) if node.get("name") else "process"

        lines.append(f"{'  ' * depth}{label} (pid={pid})")

        for finding in node.get(
            "findings",
            [],
        ):
            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()

            rule_id = finding.get(
                "rule_id",
                "UNKNOWN",
            )

            finding_title = finding.get(
                "title",
                "",
            )

            lines.append(
                f"{'  ' * (depth + 1)}"
                f"finding {finding_id(finding)} "
                f"[{severity}] {rule_id} - "
                f"{finding_title}"
            )

        for child in children.get(
            pid,
            [],
        ):
            add_node(
                child,
                depth + 1,
            )

    for root in roots:
        add_node(
            root,
            1,
        )

    return lines


def windows_events_from_records(
    records: list[dict],
) -> list[dict]:
    """Flatten windows events across records (newest record first)."""
    events: list[dict] = []

    for record in records:
        record_events = record.get(
            "windows_events",
            [],
        )

        if not isinstance(
            record_events,
            list,
        ):
            continue

        events.extend(
            event
            for event in record_events
            if isinstance(
                event,
                dict,
            )
        )

    return events


def event_id_frequencies(
    events: list[dict],
) -> list[dict]:
    """Event-ID frequency table over windows events.

    Returns rows ordered by count (descending) then event id.
    """
    counts: Counter[Any] = Counter()

    for event in events:
        event_id = event.get("event_id")

        if event_id is None:
            continue

        counts[event_id] += 1

    rows = []

    for event_id, count in counts.items():
        try:
            sort_id = int(event_id)
        except (
            TypeError,
            ValueError,
        ):
            sort_id = 0

        rows.append(
            {
                "event_id": event_id,
                "event_name": EVENT_ID_NAMES.get(
                    sort_id,
                    "",
                ),
                "count": count,
                "_sort": (
                    -count,
                    sort_id,
                ),
            }
        )

    rows.sort(key=lambda row: row["_sort"])

    for row in rows:
        row.pop("_sort")

    return rows


def finding_stats(
    records: list[dict],
) -> dict:
    """Finding counts by severity and category across records."""
    severity_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for record in records:
        for finding in record.get(
            "findings",
            [],
        ):
            if not isinstance(
                finding,
                dict,
            ):
                continue

            severity = str(
                finding.get(
                    "severity",
                    "info",
                )
            ).lower()

            if severity == "informational":
                severity = "info"

            severity_counts[severity] += 1

            category = str(
                finding.get(
                    "category",
                    "unknown",
                )
            ).lower()

            category_counts[category] += 1

    return {
        "severity": dict(severity_counts),
        "category": dict(category_counts),
    }


def _sid_token(
    token: str,
) -> bool:
    normalized = token.lower()

    if normalized.startswith("s-1-"):
        return True

    if normalized.startswith("sid:"):
        return True

    if "well-known" in normalized:
        return True

    return False


def _account_from_message(
    message_data: Any,
) -> str | None:
    """Extract an account name from Windows event message data.

    Three layouts are recognized, in order:

    1. an ``Account Name:`` label (raw Windows event text);
    2. ``domain\\account`` tokens (fixture/tool message_data);
    3. bare account tokens (e.g. account-management events whose first
       field is the target account).
    """
    if message_data is None:
        return None

    text = str(message_data).strip()

    if not text:
        return None

    label_match = re.search(
        r"Account\s+Name:\s*(\S+)",
        text,
        re.IGNORECASE,
    )

    if label_match:
        return label_match.group(1).rsplit(
            "\\",
            1,
        )[-1]

    tokens = [token.strip() for token in text.split("|")]

    for token in tokens:
        if not token:
            continue

        if _sid_token(token):
            continue

        lowered = token.lower()

        if "logontype" in lowered or "logon type" in lowered or token.isdigit():
            continue

        if "\\" in token:
            return token.rsplit(
                "\\",
                1,
            )[-1]

        return token

    return None


def _account_for_event(
    event: dict,
) -> str:
    account = _account_from_message(event.get("message_data"))

    if account:
        return account

    return "unknown"


def summarize_account_events(
    events: list[dict],
) -> dict[str, Counter]:
    """Summarize logon activity from windows events.

    Returns counters keyed by account name under ``failed_logons``,
    ``successful_logons`` and ``account_creations``. Accounts that
    cannot be parsed from the message data are bucketed as
    ``unknown``.
    """
    failed: Counter[str] = Counter()
    successful: Counter[str] = Counter()
    created: Counter[str] = Counter()

    for event in events:
        event_id = event.get("event_id")

        if event_id is None:
            continue

        try:
            numeric_id = int(event_id)
        except (
            TypeError,
            ValueError,
        ):
            continue

        account = _account_for_event(event)

        if numeric_id in FAILED_LOGON_EVENT_IDS:
            failed[account] += 1
        elif numeric_id in SUCCESSFUL_LOGON_EVENT_IDS:
            successful[account] += 1
        elif numeric_id in ACCOUNT_CREATION_EVENT_IDS:
            created[account] += 1

    return {
        "failed_logons": failed,
        "successful_logons": successful,
        "account_creations": created,
    }
