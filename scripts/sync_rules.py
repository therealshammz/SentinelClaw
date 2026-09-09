#!/usr/bin/env python3
"""Keep the two shipped rule copies in sync (P2-16).

``rules/`` is the source of truth (the human-edited copy);
``sentinelclaw/rules/`` is the copy the runtime loads and that ships
inside the package. Rule edits must land in ``rules/`` and then be
copied over so the two copies stay byte-identical.

Usage:
    python scripts/sync_rules.py --check [--source DIR] [--dest DIR]
    python scripts/sync_rules.py --sync [--source DIR] [--dest DIR]

``--check`` exits 0 when the copies match and 1 otherwise, printing a
per-file drift list. ``--sync`` copies every rule file from the source
directory into the destination (creating the destination if needed) and
removes destination-only rule files so the copies fully converge.

The default source/destination are derived from the repository root,
which is enough for CI and local use. ``--source``/``--dest`` exist so
the script is testable against throwaway directories.
"""

import argparse
import sys
from pathlib import Path

RULE_GLOBS = ("*.yaml", "*.yml")


def resolve_paths(
    args: argparse.Namespace,
) -> tuple[Path, Path]:
    repository_root = (
        Path(__file__)
        .resolve()
        .parent.parent
    )
    source = (
        Path(args.source)
        if args.source
        else repository_root / "rules"
    )
    destination = (
        Path(args.dest)
        if args.dest
        else repository_root
        / "sentinelclaw"
        / "rules"
    )
    return (
        source,
        destination,
    )


def collect_rule_files(
    directory: Path,
) -> dict[str, Path]:
    files: dict[str, Path] = {}

    if not directory.exists():
        return files

    # P2-14: rule trees are recursive (``rules/sigma/`` mirrors the
    # layout of imported Sigma rules), so sync walks subdirectories and
    # keys files by their path relative to the root.
    for pattern in RULE_GLOBS:
        for path in sorted(
            directory.rglob(pattern)
        ):
            relative = path.relative_to(
                directory
            )
            files[str(relative)] = path

    return files


def report_drift(
    source: Path,
    destination: Path,
) -> list[str]:
    """Return a per-file list of differences between two rule copies."""
    source_files = collect_rule_files(
        source
    )
    destination_files = collect_rule_files(
        destination
    )

    differences: list[str] = []

    for name in sorted(
        set(source_files)
        | set(destination_files)
    ):
        if name not in source_files:
            differences.append(
                f"only in destination: {name}"
            )
        elif name not in destination_files:
            differences.append(
                f"missing in destination: {name}"
            )
        elif (
            source_files[name].read_bytes()
            != destination_files[name].read_bytes()
        ):
            differences.append(
                f"content differs: {name}"
            )

    return differences


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check or sync the two shipped rule copies (P2-16)."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 0 if the copies match, 1 otherwise",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="copy rule files from source into destination",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="source rules directory (default: <repo>/rules)",
    )
    parser.add_argument(
        "--dest",
        default=None,
        help="destination rules directory "
        "(default: <repo>/sentinelclaw/rules)",
    )

    args = parser.parse_args()

    if args.check == args.sync:
        parser.error(
            "exactly one of --check or --sync is required"
        )

    source, destination = resolve_paths(
        args
    )

    if not source.exists():
        print(
            f"error: source rules directory "
            f"does not exist: {source}"
        )
        return 2

    if args.sync:
        destination.mkdir(
            parents=True,
            exist_ok=True,
        )
        source_files = collect_rule_files(
            source
        )

        for name, path in source_files.items():
            target = destination / name

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            target.write_bytes(
                path.read_bytes()
            )

        for name in sorted(
            collect_rule_files(
                destination
            )
        ):
            if name not in source_files:
                (destination / name).unlink()
                print(
                    f"removed destination-only rule file: "
                    f"{name}"
                )

        print(
            f"synced {len(source_files)} rule file(s) "
            f"to {destination}"
        )

    differences = report_drift(
        source,
        destination,
    )

    if not differences:
        print(
            f"rule copies in sync: {source} == {destination}"
        )
        return 0

    print(
        f"rule copies out of sync between "
        f"{source} and {destination}:"
    )

    for difference in differences:
        print(
            f"  - {difference}"
        )

    return 1


if __name__ == "__main__":
    sys.exit(main())