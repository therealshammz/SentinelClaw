import json
import logging
import os
from datetime import datetime
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)


def probe_deleted_executable(
    pid: int,
    executable: str | None,
) -> bool:
    """Return whether a running process's binary was unlinked from disk.

    On POSIX systems this resolves ``/proc/<pid>/exe``; a missing or
    ``(deleted)``-suffixed link indicates the executable was removed while
    still running (a common evasion technique). On non-POSIX platforms or
    when ``/proc`` is unavailable the check returns ``False``.
    """
    if os.name != "posix":
        return False

    if not pid:
        return False

    if not Path("/proc").is_dir():
        return False

    if executable and executable.endswith(" (deleted)"):
        return True

    try:
        target = os.readlink(f"/proc/{pid}/exe")
    except FileNotFoundError:
        return True
    except OSError:
        return False

    return target.endswith(" (deleted)")


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

    return [str(item) for item in cmdline if item is not None]


def safe_create_time(timestamp) -> str | None:
    if not timestamp:
        return None

    try:
        return datetime.fromtimestamp(timestamp).astimezone().isoformat()

    except Exception:
        return None


def safe_executable(
    process: psutil.Process,
) -> tuple[str | None, str | None]:
    """Resolve a process's executable path, distinguishing failure modes.

    Returns ``(executable, error)`` where ``error`` is ``"access_denied"``
    when the path is unreadable due to a permission boundary (e.g. a
    root-owned daemon inspected by an unprivileged user — expected, not
    suspicious) and ``None`` otherwise. Kernel threads resolve to an
    empty executable with no error.
    """
    try:
        executable = process.exe()

    except (
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return (
            None,
            "access_denied",
        )

    except psutil.NoSuchProcess:
        raise

    except Exception:
        return (
            None,
            "unavailable",
        )

    return (
        executable or None,
        None,
    )


def get_processes() -> list[dict]:
    processes = []

    skipped = 0

    attributes = [
        "pid",
        "ppid",
        "name",
        "username",
        "status",
        "memory_percent",
        "cmdline",
        "create_time",
    ]

    for process in psutil.process_iter(attributes):
        try:
            info = process.info

            executable, exe_error = safe_executable(process)

            processes.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "parent_name": safe_parent_name(process),
                    "username": info.get("username"),
                    "executable": executable,
                    "exe_error": exe_error,
                    "exe_deleted": probe_deleted_executable(
                        info.get("pid") or 0,
                        executable,
                    ),
                    "status": info.get("status"),
                    "memory_percent": round(
                        info.get("memory_percent") or 0,
                        2,
                    ),
                    "command_line": safe_command_line(info),
                    "create_time": safe_create_time(info.get("create_time")),
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
        "Collected %d process(es) (%d skipped)",
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
