"""
Offline Windows Event Log (.evtx) analysis (P4-22).

``analyze_evtx`` parses a Windows ``.evtx`` file into the same event
dict shape the live Windows Event Log collector produces, plus parsed
fields pulled from the event XML (``target_user``, ``ip_address``,
``new_process_id``, ``script_block``, ...).

python-evtx is an optional dependency: it is imported lazily so this
module loads everywhere. Without it the analyzer returns an
operational note dict instead of raising, keeping the CLI usable on
installations that never requested the ``[evtx]`` extra.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

from sentinelclaw.config.settings import get_settings
from sentinelclaw.tools.windows_event_analyzer import DEFAULT_EVENT_IDS

logger = logging.getLogger(
    __name__
)

EVTX_NOT_INSTALLED_NOTE = (
    "python-evtx not installed "
    "(pip install sentinelclaw[evtx])"
)

# TimeCreated SystemTime appears in two shapes depending on the
# python-evtx renderer: with or without a trailing UTC offset, and
# with a space instead of the ISO ``T`` separator.
_SYSTEM_TIME_PATTERN = re.compile(
    r'<TimeCreated\s+SystemTime="([^"]+)"'
)

_EVENT_ID_PATTERN = re.compile(
    r"<EventID[^>]*>(\d+)</EventID>"
)

# Windows filetime values can precede the Unix epoch by a few
# decades; anything outside a sane range is treated as unusable.
_MIN_TIMESTAMP_YEAR = 1990
_MAX_TIMESTAMP_YEAR = 2200

# EventData payloads worth echoing into findings are capped so a
# pathological log cannot balloon the report.
SCRIPT_BLOCK_CAP = 2000

_PARSED_DATA_FIELDS = {
    "TargetUserName": "target_user",
    "TargetDomainName": "target_domain",
    "IpAddress": "ip_address",
    "IpPort": "ip_port",
    "LogonType": "logon_type",
    "NewProcessId": "new_process_id",
    "NewProcessName": "new_process_name",
    "ParentProcessName": "parent_process_name",
    "ScriptBlockText": "script_block",
}


def _localname(
    tag: str,
) -> str:
    """Strip a ``{namespace}`` prefix from an XML tag name."""
    if "}" in tag:
        return tag.rsplit(
            "}",
            1,
        )[1]

    return tag


def _clean_field_value(
    value: str,
) -> str | None:
    value = value.strip()

    if not value:
        return None

    if value in {
        "-",
        "{00000000-0000-0000-0000-000000000000}",
    }:
        return None

    return value


def _normalize_timestamp(
    raw: str,
) -> str | None:
    """Normalize an evtx ``SystemTime`` value to ISO-8601.

    python-evtx renders the value like ``2019-10-30 21:53:01.720799``
    or ``2017-06-23 05:31:19.787264+00:00``. The timeline engine
    expects ISO timestamps, so the space separator is replaced and
    bare values are assumed to be UTC.
    """
    raw = raw.strip()

    if not raw:
        return None

    text = raw.replace(
        " ",
        "T",
        1,
    )

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        year = int(
            text[:4]
        )
    except ValueError:
        return None

    if not (
        _MIN_TIMESTAMP_YEAR
        <= year
        <= _MAX_TIMESTAMP_YEAR
    ):
        return None

    if text.endswith(
        "+00:00"
    ):
        return text

    if "+" in text:
        return None

    return text + "+00:00"


def parse_windows_event_xml(
    xml_text: str,
    default_name: str = "Monitored Windows event",
) -> dict:
    """Parse one rendered evtx record's XML into an event dict.

    Pure function over the XML string produced by python-evtx
    (``record.xml()``) so it is unit-testable on canned XML without
    python-evtx installed.

    Extracted keys match the live collector's shape (event_id,
    event_name, source, computer, timestamp, event_type,
    record_number, message_data) and add parsed EventData fields
    (target_user, ip_address, new_process_id, script_block, ...).
    """
    event: dict = {}

    try:
        root = ElementTree.fromstring(
            xml_text
        )
    except ElementTree.ParseError:
        logger.debug(
            "Unable to parse evtx record XML; "
            "falling back to regex extraction"
        )

        return _parse_windows_event_xml_fallback(
            xml_text,
            default_name,
        )

    data_values: list[str] = []
    parsed_fields: dict[str, str] = {}

    parsed_event_id: int | None = None

    for element in root.iter():
        tag = _localname(
            element.tag
        )

        if tag == "EventID":
            try:
                parsed_event_id = int(
                    (element.text or "").strip()
                )
            except ValueError:
                parsed_event_id = None

        elif tag == "TimeCreated":
            raw = element.get(
                "SystemTime"
            )

            if raw:
                event["timestamp"] = _normalize_timestamp(
                    raw
                )

        elif tag == "Computer":
            text = (element.text or "").strip()

            if text:
                event["computer"] = text

        elif tag == "Channel":
            text = (element.text or "").strip()

            if text:
                event["channel"] = text

        elif tag == "Provider":
            name = element.get(
                "Name"
            )

            if name:
                event["source"] = name

        elif tag == "EventRecordID":
            try:
                event["record_number"] = int(
                    (element.text or "").strip()
                )
            except ValueError:
                event["record_number"] = None

        elif tag == "Data":
            value = _clean_field_value(
                element.text or ""
            )

            if value is None:
                continue

            data_values.append(
                value
            )

            field_name = element.get(
                "Name"
            )

            if field_name is None:
                continue

            mapped = _PARSED_DATA_FIELDS.get(
                field_name
            )

            if mapped is not None:
                parsed_fields[mapped] = value

    if parsed_event_id is not None:
        event["event_id"] = parsed_event_id

    if "source" not in event:
        event["source"] = None

    if "computer" not in event:
        event["computer"] = None

    if "record_number" not in event:
        event["record_number"] = None

    if "timestamp" not in event:
        event["timestamp"] = None

    event["event_name"] = (
        DEFAULT_EVENT_IDS.get(
            parsed_event_id,
            default_name,
        )
        if parsed_event_id is not None
        else default_name
    )

    event["event_type"] = 0
    event["message_data"] = " | ".join(
        data_values
    )

    for field, value in parsed_fields.items():
        event[field] = value

    script_block = event.get(
        "script_block"
    )

    if isinstance(
        script_block,
        str,
    ) and len(script_block) > SCRIPT_BLOCK_CAP:
        event["script_block"] = (
            script_block[:SCRIPT_BLOCK_CAP]
            + "..."
        )

    return event


def _parse_windows_event_xml_fallback(
    xml_text: str,
    default_name: str,
) -> dict:
    """Best-effort regex extraction when the XML is not well-formed."""
    event: dict = {}

    parsed_event_id: int | None = None

    event_id_match = _EVENT_ID_PATTERN.search(
        xml_text
    )

    if event_id_match:
        try:
            parsed_event_id = int(
                event_id_match.group(1)
            )
        except ValueError:
            parsed_event_id = None

    timestamp_match = _SYSTEM_TIME_PATTERN.search(
        xml_text
    )

    if timestamp_match:
        event["timestamp"] = _normalize_timestamp(
            timestamp_match.group(1)
        )

    computer_match = re.search(
        r"<Computer>([^<]+)</Computer>",
        xml_text,
    )

    if computer_match:
        event["computer"] = (
            computer_match.group(1).strip()
        )

    source_match = re.search(
        r'<Provider\s+Name="([^"]+)"',
        xml_text,
    )

    if source_match:
        event["source"] = (
            source_match.group(1).strip()
        )

    if parsed_event_id is not None:
        event["event_id"] = parsed_event_id

    event["event_name"] = (
        DEFAULT_EVENT_IDS.get(
            parsed_event_id,
            default_name,
        )
        if parsed_event_id is not None
        else default_name
    )

    event["event_type"] = 0
    event["record_number"] = None
    event["message_data"] = ""

    return event


def analyze_evtx(file_path: str) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        return {
            "error": f"EVTX file not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    if path.suffix.lower() != ".evtx":
        return {
            "error": (
                "Unsupported file type. "
                "Expected a .evtx file"
            )
        }

    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return {
            "error": EVTX_NOT_INSTALLED_NOTE
        }

    settings = get_settings()

    max_events = settings.max_evtx_events

    events: list[dict] = []

    truncated = False
    skipped_records = 0
    records_total = 0

    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                records_total += 1

                if len(events) >= max_events:
                    truncated = True
                    break

                try:
                    xml_text = record.xml()
                except Exception as exc:
                    logger.debug(
                        "Unable to render evtx record: %s",
                        exc,
                    )

                    skipped_records += 1
                    continue

                event = parse_windows_event_xml(
                    xml_text
                )

                if event.get(
                    "record_number"
                ) is None:
                    try:
                        event["record_number"] = (
                            record.record_num()
                        )
                    except Exception:
                        event["record_number"] = None

                events.append(
                    event
                )
    except Exception as exc:
        logger.warning(
            "EVTX parsing failed for %s: %s",
            path,
            exc,
        )

        if not events:
            return {
                "error": (
                    "Could not parse EVTX file: "
                    f"{exc}"
                )
            }

    truncation_reason = None

    if truncated:
        truncation_reason = (
            f"event limit reached ({max_events})"
        )

    logger.debug(
        "Analyzed %d event(s) from %s "
        "(%d record(s), %d skipped)",
        len(events),
        path.name,
        records_total,
        skipped_records,
    )

    return {
        "path": str(
            path.resolve()
        ),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "events_returned": len(
            events
        ),
        "records_total": records_total,
        "skipped_records": skipped_records,
        "events": events,
        "truncated": truncated,
        "truncation_reason": truncation_reason,
    }
