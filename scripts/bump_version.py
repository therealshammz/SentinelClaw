#!/usr/bin/env python3
"""Bump the SentinelClaw project version in ``pyproject.toml`` (P6-29).

Usage:

    python scripts/bump_version.py --patch     # 0.1.0 -> 0.1.1
    python scripts/bump_version.py --minor     # 0.1.0 -> 0.2.0
    python scripts/bump_version.py --major     # 0.1.0 -> 1.0.0
    python scripts/bump_version.py 1.2.3       # explicit target

Only the ``[project]`` table's ``version`` field is rewritten; the rest
of the file (comments, formatting, other tables) is preserved verbatim.
The old and new versions are printed to stdout as ``old -> new``.

Versions must be plain ``X.Y.Z`` numeric triples; pre-release /
build-metadata suffixes are not handled.
"""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

PROJECT_FILE = Path(__file__).resolve().parent.parent / "pyproject.toml"

_VERSION_RE = re.compile(r"^(\s*)version(\s*=\s*\")([^\"]+)(\")")


def current_version(
    pyproject: Path,
) -> str:
    """Return the ``[project]`` version from a pyproject.toml file."""
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)

    try:
        return str(data["project"]["version"])
    except KeyError:
        raise SystemExit(f"error: no [project] version field in {pyproject}") from None


def _project_version_line(
    lines: list[str],
    pyproject: Path,
) -> tuple[int, str]:
    """Find the ``version = \"...\"`` line inside the ``[project]`` table.

    Returns ``(line_index, current_value)``. The first matching line
    after the ``[project]`` header wins; other tables are skipped.
    """
    in_project = False

    for index, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith("["):
            in_project = stripped == "[project]"

            continue

        if not in_project:
            continue

        match = _VERSION_RE.match(line)

        if match:
            return index, match.group(3)

    raise SystemExit(f"error: no version line under [project] in {pyproject}")


def parse_version(
    value: str,
) -> tuple[int, int, int]:
    """Parse and validate a ``X.Y.Z`` version triple."""
    parts = value.split(".")

    if (
        len(parts) != 3
        or any(not part.isdigit() for part in parts)
        or any(int(part) < 0 for part in parts)
    ):
        raise SystemExit(
            f"error: invalid version {value!r}; expected X.Y.Z with non-negative integer components"
        )

    return (int(parts[0]), int(parts[1]), int(parts[2]))


def format_version(
    parts: tuple[int, int, int],
) -> str:
    """Render a version triple back into ``X.Y.Z`` form."""
    return ".".join(str(part) for part in parts)


def bump_version(
    pyproject: Path,
    new_version: str,
) -> str:
    """Rewrite the version in place; return the previous version."""
    lines = pyproject.read_text(encoding="utf-8").splitlines(keepends=True)

    line_index, previous = _project_version_line(
        lines,
        pyproject,
    )

    lines[line_index] = _VERSION_RE.sub(
        rf"\g<1>version\g<2>{new_version}\g<4>",
        lines[line_index],
    )

    pyproject.write_text(
        "".join(lines),
        encoding="utf-8",
    )

    return previous


def main(
    argv: list[str] | None = None,
) -> None:
    parser = argparse.ArgumentParser(
        description=("Bump the SentinelClaw version in pyproject.toml")
    )

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument(
        "--major",
        action="store_true",
        help="Bump the major component (X.0.0)",
    )

    mode.add_argument(
        "--minor",
        action="store_true",
        help="Bump the minor component (0.X.0)",
    )

    mode.add_argument(
        "--patch",
        action="store_true",
        help="Bump the patch component (0.0.X)",
    )

    mode.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Explicit X.Y.Z version to set",
    )

    parser.add_argument(
        "--pyproject",
        default=str(PROJECT_FILE),
        help=("Path to the pyproject.toml to update (default: repo root)"),
    )

    args = parser.parse_args(argv)

    pyproject = Path(args.pyproject).expanduser().resolve()

    old_version = current_version(pyproject)

    if args.target is not None:
        parse_version(args.target)

        new_version = args.target
    else:
        major, minor, patch = parse_version(old_version)

        if args.major:
            major += 1

            minor = 0

            patch = 0

        elif args.minor:
            minor += 1

            patch = 0
        else:
            patch += 1

        new_version = format_version((major, minor, patch))

    previous = bump_version(
        pyproject,
        new_version,
    )

    print(f"{previous} -> {new_version}")


if __name__ == "__main__":
    main()
