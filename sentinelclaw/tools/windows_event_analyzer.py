import argparse
import json
from datetime import timezone

# Conditionally import win32evtlog to avoid ImportError on non-Windows systems
try:
    import win32evtlog
    HAS_WIN32EVTLOG = True
except ImportError:
    win32evtlog = None
    HAS_WIN32EVTLOG = False


DEFAULT_EVENT_IDS = {
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4648: "Logon using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "New process created",
    4697: "Service installed",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempt",
    4728: "Member added to global security group",
    4732: "Member added to local security group",
    4740: "User account locked out",
    1102: "Audit log cleared",
}


def safe_format_message(event) -> str:
    try:
        inserts = event.StringInserts or []
        return " | ".join(str(item) for item in inserts)
    except Exception:
        return ""


def get_windows_events(
    log_name: str = "Security",
    max_events: int = 200,
    event_ids: set[int] | None = None,
) -> list[dict]:
    if not HAS_WIN32EVTLOG:
        # Return empty list on non-Windows systems where win32evtlog is not available
        return []

    if event_ids is None:
        event_ids = set(DEFAULT_EVENT_IDS.keys())

    events = []

    handle = win32evtlog.OpenEventLog(None, log_name)

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    try:
        while len(events) < max_events:
            batch = win32evtlog.ReadEventLog(
                handle,
                flags,
                0,
            )

            if not batch:
                break

            for event in batch:
                event_id = event.EventID & 0xFFFF

                if event_id not in event_ids:
                    continue

                timestamp = event.TimeGenerated

                if timestamp is not None:
                    try:
                        timestamp = (
                            timestamp.replace(tzinfo=timezone.utc)
                            .astimezone()
                            .isoformat()
                        )
                    except Exception:
                        timestamp = str(timestamp)

                events.append(
                    {
                        "event_id": event_id,
                        "event_name": DEFAULT_EVENT_IDS.get(
                            event_id,
                            "Monitored Windows event",
                        ),
                        "source": event.SourceName,
                        "computer": event.ComputerName,
                        "timestamp": timestamp,
                        "event_type": event.EventType,
                        "record_number": event.RecordNumber,
                        "message_data": safe_format_message(event),
                    }
                )

                if len(events) >= max_events:
                    break

    finally:
        win32evtlog.CloseEventLog(handle)

    return events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read selected Windows Event Log events."
    )

    parser.add_argument(
        "--log",
        default="Security",
        help="Windows Event Log name. Default: Security",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of matching events to return.",
    )

    args = parser.parse_args()

    try:
        result = get_windows_events(
            log_name=args.log,
            max_events=args.limit,
        )

        print(
            json.dumps(
                {
                    "log": args.log,
                    "events_returned": len(result),
                    "events": result,
                },
                indent=2,
            )
        )

    except PermissionError:
        print(
            json.dumps(
                {
                    "error": (
                        "Access denied. Reading the Security log may "
                        "require running PowerShell or VS Code as Administrator."
                    )
                },
                indent=2,
            )
        )

    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": str(exc),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()