"""
SentinelClaw logging configuration.

All SentinelClaw log output goes to ``stderr`` so that machine-readable
or console output on ``stdout`` is never polluted by log lines.

Log levels:
- WARNING by default (errors and notable problems only).
- DEBUG when the CLI ``--debug`` flag is passed.

:func:`configure_logging` is idempotent: it installs a stderr handler
on the root logger once and adjusts the root level on later calls so
``--debug`` can be toggled without duplicating handlers.
"""

from __future__ import annotations

import logging
import sys

DEFAULT_LOG_FORMAT = "%(levelname)s %(name)s: %(message)s"
DEFAULT_LOG_LEVEL = logging.WARNING


def configure_logging(
    debug: bool = False,
) -> None:
    """Configure root logging on stderr; DEBUG level when ``debug``."""
    root_logger = logging.getLogger()

    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))

        root_logger.addHandler(handler)

    root_logger.setLevel(logging.DEBUG if debug else DEFAULT_LOG_LEVEL)
