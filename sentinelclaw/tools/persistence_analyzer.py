"""
Linux persistence mechanism collector (P1-10).

Reads, in a read-only and bounded fashion, the common Linux persistence
locations: cron jobs, systemd unit files, init/rc scripts and ``at`` jobs.
Records describe each mechanism so that
``sentinelclaw.detectors.persistence_detector.analyze_persistence_records``
can flag suspicious content and insecure permissions.

Missing files or directories are treated as an operational note, never an
error; on non-Linux platforms the collector returns an empty list.
"""

import logging
import re
import stat
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

CRON_DIRECTORIES = (
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
)

CRON_FILES = ("/etc/crontab",)

SPOOL_CRON_DIRECTORIES = (
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
)

SYSTEMD_DIRECTORIES = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)

RC_DIRECTORIES = (
    "/etc/rc0.d",
    "/etc/rc1.d",
    "/etc/rc2.d",
    "/etc/rc3.d",
    "/etc/rc4.d",
    "/etc/rc5.d",
    "/etc/rc6.d",
    "/etc/rcS.d",
)

AT_DIRECTORIES = (
    "/var/spool/at",
    "/var/spool/cron/atjobs",
)

MAX_FILE_BYTES = 256 * 1024

MAX_RECORDS = 2000

_INITD_ROOT = "/etc/init.d"

_CRON_COMMAND_PATTERN = re.compile(
    r"^\s*"
    r"(?:\d+|\*|[0-9,\-*/]+)\s+"
    r"(?:\d+|\*|[0-9,\-*/]+)\s+"
    r"(?:\d+|\*|[0-9,\-*/]+)\s+"
    r"(?:\d+|\*|[0-9,\-*/]+)\s+"
    r"(?:\d+|\*|[0-9,\-*/]+)\s+"
    r"(?:(\S+)\s+)?"
    r"(.*)$"
)


def file_mode(
    path: Path,
) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def world_writable(
    path: Path,
) -> bool:
    mode = file_mode(path)

    if mode is None:
        return False

    return bool(mode & 0o002)


def writable_by_others(
    path: Path,
) -> bool:
    mode = file_mode(path)

    if mode is None:
        return False

    return bool(mode & 0o022)


def read_bounded(
    path: Path,
) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return ""

    if size > MAX_FILE_BYTES:
        size = MAX_FILE_BYTES

    try:
        with path.open("rb") as file:
            data = file.read(size)
    except OSError:
        return ""

    return data.decode(
        "utf-8",
        errors="ignore",
    )


def parse_crontab(
    text: str,
    path: Path,
    default_user: str | None,
) -> list[dict]:
    """Parse crontab text into per-line persistence records."""
    records: list[dict] = []

    mode = file_mode(path)

    ww = bool(mode is not None and mode & 0o022)

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("#"):
            continue

        if "=" in stripped:
            continue

        match = _CRON_COMMAND_PATTERN.match(line)

        command = match.group(2).strip() if match else stripped

        user = match.group(1) if (match and match.group(1)) else default_user

        records.append(
            {
                "mechanism": "cron",
                "path": str(path),
                "user": user,
                "line": line_number,
                "command": command,
                "content": stripped,
                "world_writable": ww,
            }
        )

        if len(records) >= MAX_RECORDS:
            break

    return records


def safe_dir_listing(
    directory: Path,
) -> list[Path]:
    """Return sorted directory entries, tolerating unreadable locations."""
    try:
        if not directory.is_dir():
            return []

        return sorted(
            directory.iterdir()
        )
    except OSError as exc:
        logger.warning(
            "Unable to read persistence directory %s: %s",
            directory,
            exc,
        )

        return []


def safe_is_file(
    path: Path,
) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        logger.warning(
            "Unable to inspect persistence entry %s: %s",
            path,
            exc,
        )

        return False


def collect_cron(
    base_directories: tuple[str, ...] = CRON_DIRECTORIES,
    base_files: tuple[str, ...] = CRON_FILES,
) -> list[dict]:
    records: list[dict] = []

    for directory_name in base_directories:
        directory = Path(
            directory_name
        )

        for path in safe_dir_listing(
            directory
        ):
            if not safe_is_file(
                path
            ):
                continue

            records.extend(
                parse_crontab(
                    read_bounded(
                        path
                    ),
                    path,
                    default_user=None,
                )
            )

    for file_name in base_files:
        path = Path(
            file_name
        )

        if not safe_is_file(
            path
        ):
            continue

        records.extend(
            parse_crontab(
                read_bounded(
                    path
                ),
                path,
                default_user="root",
            )
        )

    return records


def collect_spool_cron(
    directories: tuple[str, ...] = SPOOL_CRON_DIRECTORIES,
) -> list[dict]:
    records: list[dict] = []

    for directory_name in directories:
        directory = Path(
            directory_name
        )

        for path in safe_dir_listing(
            directory
        ):
            if not safe_is_file(
                path
            ):
                continue

            records.extend(
                parse_crontab(
                    read_bounded(
                        path
                    ),
                    path,
                    default_user=path.name,
                )
            )

    return records


def collect_systemd_units(
    directories: tuple[str, ...] = SYSTEMD_DIRECTORIES,
) -> list[dict]:
    records: list[dict] = []

    seen: set[str] = set()

    for directory_name in directories:
        directory = Path(
            directory_name
        )

        try:
            candidates = sorted(
                directory.rglob(
                    "*.service"
                )
            )
        except OSError as exc:
            logger.warning(
                "Unable to walk systemd directory %s: %s",
                directory,
                exc,
            )

            candidates = []

        for path in candidates:
            if not safe_is_file(
                path
            ):
                continue

            if str(path) in seen:
                continue

            seen.add(str(path))

            exec_starts: list[str] = []

            for line in read_bounded(path).splitlines():
                stripped = line.strip()

                if stripped.startswith("ExecStart="):
                    exec_starts.append(stripped[len("ExecStart=") :])

            records.append(
                {
                    "mechanism": "systemd_unit",
                    "path": str(path),
                    "exec_start": " ".join(exec_starts),
                    "world_writable": world_writable(path),
                    "writable_by_others": writable_by_others(path),
                }
            )

            if len(records) >= MAX_RECORDS:
                return records

    return records


def collect_rc_scripts(
    directories: tuple[str, ...] = RC_DIRECTORIES,
) -> list[dict]:
    records: list[dict] = []

    for directory_name in directories:
        directory = Path(
            directory_name
        )

        directory_world_writable = world_writable(
            directory
        )

        for entry in safe_dir_listing(
            directory
        ):
            try:
                target = entry.readlink()
            except OSError:
                target = None

            if target is None:
                continue

            resolved = target

            if not resolved.is_absolute():
                resolved = Path(_INITD_ROOT) / resolved

            records.append(
                {
                    "mechanism": "rc_script",
                    "path": str(entry),
                    "target": str(target),
                    "world_writable": (directory_world_writable or world_writable(resolved)),
                }
            )

    return records


def collect_at_jobs(
    directories: tuple[str, ...] = AT_DIRECTORIES,
) -> list[dict]:
    records: list[dict] = []

    for directory_name in directories:
        directory = Path(
            directory_name
        )

        for path in safe_dir_listing(
            directory
        ):
            if not safe_is_file(
                path
            ):
                continue

            text = read_bounded(path)

            records.append(
                {
                    "mechanism": "at_job",
                    "path": str(path),
                    "command": text.strip(),
                    "world_writable": world_writable(path),
                }
            )

            if len(records) >= MAX_RECORDS:
                return records

    return records


def get_persistence_records() -> list[dict]:
    """Collect Linux persistence records for the current host.

    Non-Linux platforms and missing locations yield an empty list.
    """
    if not sys.platform.startswith("linux"):
        return []

    records: list[dict] = []

    records.extend(collect_cron())

    records.extend(collect_spool_cron())

    records.extend(collect_systemd_units())

    records.extend(collect_rc_scripts())

    records.extend(collect_at_jobs())

    logger.debug(
        "Collected %d persistence record(s)",
        len(records),
    )

    return records
