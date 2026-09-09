import json
import logging
from datetime import datetime

import psutil

logger = logging.getLogger(
    __name__
)


def safe_parent_name(process: psutil.Process) -> str | None:
    try:
        parent = process.parent()

        if parent is None:
            return None

        return parent.name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return None


def safe_command_line(info: dict) -> list[str]:
    cmdline = info.get("cmdline")

    if not cmdline:
        return []

    return [
        str(item)
        for item in cmdline
        if item is not None
    ]


def safe_create_time(timestamp) -> str | None:
    if not timestamp:
        return None

    try:
        return (
            datetime.fromtimestamp(timestamp)
            .astimezone()
            .isoformat()
        )

    except Exception:
        return None


def get_processes() -> list[dict]:
    processes = []

    skipped = 0

    attributes = [
        "pid",
        "ppid",
        "name",
        "username",
        "exe",
        "status",
        "memory_percent",
        "cmdline",
        "create_time",
    ]

    for process in psutil.process_iter(attributes):

        try:
            info = process.info

            processes.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "parent_name": safe_parent_name(process),
                    "username": info.get("username"),
                    "executable": info.get("exe"),
                    "status": info.get("status"),
                    "memory_percent": round(
                        info.get("memory_percent") or 0,
                        2,
                    ),
                    "command_line": safe_command_line(info),
                    "create_time": safe_create_time(
                        info.get("create_time")
                    ),
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            skipped += 1
            continue

    logger.debug(
        "Collected %d process(es) "
        "(%d skipped)",
        len(processes),
        skipped,
    )

    return processes


def main() -> None:
    print(
        json.dumps(
            get_processes(),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
