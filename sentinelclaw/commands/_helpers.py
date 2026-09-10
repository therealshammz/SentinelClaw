"""Shared CLI helpers for the command modules (P6-30).

``print_json`` and ``print_cli_error`` are the stdout/stderr renderers
every command module uses; ``parse_since`` converts the ``--since``
CLI timestamp used by ``scan``.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any


def print_json(
    data: Any,
) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            default=str,
        )
    )


def parse_since(
    value: str,
) -> datetime:
    """Parse a ``--since`` ISO timestamp into a tz-aware datetime."""
    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise RuntimeError(f"Invalid --since timestamp: {value}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def print_cli_error(
    message: str,
    suggestion: str | None = None,
) -> None:
    print(
        f"[ERROR] {message}",
        file=sys.stderr,
    )

    if suggestion:
        print(
            f"        {suggestion}",
            file=sys.stderr,
        )
