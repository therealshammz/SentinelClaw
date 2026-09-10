"""
Optional YARA scanning support (P4-23).

The ``yara`` module (yara-python, a C extension) is imported lazily so
this module loads on any install. When yara-python is missing, every
entry point reports an operational note (not an error) and returns no
matches, keeping the ``file`` command fully usable without the extra.

Rules are loaded from a rules directory (one file per compile unit);
files with ``.yar``/``.yara`` extensions are compiled individually so
one broken rule cannot disable the rest. Rule severity is read from
the rule's ``severity`` metadata when present and normalized to the
SentinelClaw severity vocabulary (default: ``medium``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)

YARA_NOT_INSTALLED_NOTE = (
    "yara-python not installed "
    "(pip install sentinelclaw[yara])"
)

RULE_EXTENSIONS = (
    "*.yar",
    "*.yara",
)

VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


def yara_available() -> bool:
    """True when the optional yara-python module is importable."""
    try:
        import yara  # noqa: F401
    except ImportError:
        return False

    return True


def _import_yara():
    import yara

    return yara


def _normalize_severity(
    meta: Any,
) -> str:
    value = meta.get(
        "severity"
    )

    if value is None:
        return "medium"

    text = str(value).strip().lower()

    if text not in VALID_SEVERITIES:
        return "medium"

    return text


def compile_rules(
    rules_dir: Path | None = None,
) -> tuple[list[Any], str | None]:
    """Compile every rule file under ``rules_dir``.

    Returns ``(compiled_rules, note)``. A ``note`` is set (never an
    exception) when yara-python is missing, the directory does not
    exist or holds no rule files, or individual rule files fail to
    compile.
    """
    if not yara_available():
        return (
            [],
            YARA_NOT_INSTALLED_NOTE,
        )

    directory = (
        rules_dir
        if rules_dir is not None
        else get_settings().resolved_yara_rules_dir
    )

    rule_files = []

    for pattern in RULE_EXTENSIONS:
        rule_files.extend(
            sorted(
                directory.glob(pattern)
            )
        )

    if not rule_files:
        return (
            [],
            (
                f"no YARA rules found in "
                f"{directory}"
            ),
        )

    yara = _import_yara()

    compiled = []
    notes = []

    for rule_file in rule_files:
        try:
            compiled.append(
                yara.compile(
                    filepath=str(
                        rule_file
                    )
                )
            )
        except Exception as exc:
            logger.warning(
                "Unable to compile YARA rule "
                "%s: %s",
                rule_file.name,
                exc,
            )

            notes.append(
                f"failed to compile {rule_file.name}"
            )

    note = (
        "; ".join(
            notes
        )
        if notes
        else None
    )

    return (
        compiled,
        note,
    )


def _match_rules(
    compiled_rules: list[Any],
    payload: bytes,
) -> list[dict]:
    matches = []

    for compiled in compiled_rules:
        try:
            rule_matches = compiled.match(
                data=payload
            )
        except Exception as exc:
            logger.debug(
                "YARA match failed: %s",
                exc,
            )

            continue

        for match in rule_matches:
            meta = getattr(
                match,
                "meta",
                {},
            )

            matches.append(
                {
                    "rule": str(
                        getattr(
                            match,
                            "rule",
                            "unknown",
                        )
                    ),
                    "namespace": str(
                        getattr(
                            match,
                            "namespace",
                            "default",
                        )
                    ),
                    "severity": _normalize_severity(
                        meta
                    ),
                }
            )

    return matches


def scan_file_result(
    file_path: str,
) -> dict:
    """Scan one file against the configured YARA rules.

    The returned dict is an operational result, never an exception:
    ``available`` reflects yara-python presence, ``note`` explains why
    nothing matched (missing extra, empty rules dir, oversized file,
    broken rules), and ``matches`` lists matched rule names with their
    normalized severities.
    """
    path = Path(
        file_path
    )

    if not yara_available():
        return {
            "path": str(path),
            "available": False,
            "rules_loaded": 0,
            "note": YARA_NOT_INSTALLED_NOTE,
            "matches": [],
        }

    compiled_rules, compile_note = compile_rules()

    if not compiled_rules:
        return {
            "path": str(path),
            "available": True,
            "rules_loaded": 0,
            "note": compile_note,
            "matches": [],
        }

    try:
        stat = path.stat()
    except OSError as exc:
        return {
            "path": str(path),
            "available": True,
            "rules_loaded": len(
                compiled_rules
            ),
            "note": f"unable to stat file: {exc}",
            "matches": [],
        }

    max_size = (
        get_settings().max_file_analysis_size
    )

    if stat.st_size > max_size:
        return {
            "path": str(path),
            "available": True,
            "rules_loaded": len(
                compiled_rules
            ),
            "note": (
                "file exceeds the maximum analysis "
                "size; YARA scan skipped"
            ),
            "matches": [],
        }

    try:
        payload = path.read_bytes()
    except OSError as exc:
        return {
            "path": str(path),
            "available": True,
            "rules_loaded": len(
                compiled_rules
            ),
            "note": f"unable to read file: {exc}",
            "matches": [],
        }

    matches = _match_rules(
        compiled_rules,
        payload,
    )

    return {
        "path": str(path),
        "available": True,
        "rules_loaded": len(
            compiled_rules
        ),
        "note": compile_note,
        "matches": matches,
    }


def directory_status() -> dict:
    """Operational YARA status for aggregate reporting."""
    if not yara_available():
        return {
            "available": False,
            "rules_loaded": 0,
            "note": YARA_NOT_INSTALLED_NOTE,
        }

    compiled_rules, note = compile_rules()

    return {
        "available": True,
        "rules_loaded": len(
            compiled_rules
        ),
        "note": note,
    }
