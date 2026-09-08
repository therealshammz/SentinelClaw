from __future__ import annotations

import os
from pathlib import Path


PACKAGE_DIRECTORY = Path(__file__).resolve().parent.parent
PROJECT_DIRECTORY = PACKAGE_DIRECTORY.parent


def get_rules_directory() -> Path:
    """
    Return SentinelClaw's detection-rule directory.

    SENTINELCLAW_RULES_DIR can override the default location.

    Rules are stored inside the installed Python package so they
    remain available in editable installs, wheel installs, and
    normal site-packages installations.
    """
    override = os.environ.get("SENTINELCLAW_RULES_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return PACKAGE_DIRECTORY / "rules"


def get_report_directory() -> Path:
    """
    Return the directory used for generated reports.

    SENTINELCLAW_REPORT_DIR can override the default location.

    Reports are written to a user-writable directory rather than
    inside the installed Python package.
    """
    override = os.environ.get("SENTINELCLAW_REPORT_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return Path.cwd() / "reports"


def get_data_directory() -> Path:
    """
    Return SentinelClaw's data directory.

    SENTINELCLAW_DATA_DIR can override the default location.
    """
    override = os.environ.get("SENTINELCLAW_DATA_DIR")

    if override:
        return Path(override).expanduser().resolve()

    return Path.cwd() / "data"
