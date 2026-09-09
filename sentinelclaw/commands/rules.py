"""``rules`` command module (P6-30).

Lists the loaded detection rules and runs the user-invoked SigmaHQ
import (P2-14). Rule loading shared with the scan pipeline lives here
too (``get_rules``) so the scan core and the rules listing agree on
one loading path.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinelclaw.config.paths import PACKAGE_DIRECTORY

from sentinelclaw.config.settings import get_settings

from sentinelclaw.engine.rule_engine import (
    load_rules_from_directory,
)

from sentinelclaw.sigma.importer import (
    SIGMA_RELEASE_TAG,
    download_release_zip,
    import_into,
    prepare_source_directory,
    release_tag_from_env,
    tally_by_reason,
)


COMMANDS = ("rules",)


def get_rules() -> list[dict]:
    try:
        return load_rules_from_directory(get_settings().resolved_rules_dir)
    except Exception as exc:
        raise RuntimeError(f"Unable to load detection rules: {exc}") from exc


def rule_destination_directories(
    cli_destination: str | None,
) -> list[Path]:
    """Return the rule directories a Sigma import writes into.

    The primary destination is the resolved runtime rules directory (or
    an explicit ``--dest``). When the runtime directory is the packaged
    copy inside a repository checkout, the repo's sibling ``rules/``
    directory receives the identical tree so the two shipped copies stay
    in sync. Environment-overridden directories never trigger the
    mirror (the override owns the layout).
    """
    settings = get_settings()

    if cli_destination:
        return [Path(cli_destination).expanduser().resolve()]

    primary = settings.resolved_rules_dir

    destinations = [primary]

    packaged = PACKAGE_DIRECTORY / "rules"

    repo_rules = PACKAGE_DIRECTORY.parent / "rules"

    if primary == packaged and repo_rules.is_dir() and repo_rules.resolve() != packaged.resolve():
        destinations.append(repo_rules.resolve())

    return destinations


def run_rules_import(args: argparse.Namespace) -> dict:
    """Run the user-invoked SigmaHQ import (P2-14).

    Downloads the pinned SigmaHQ release (unless ``--source`` names a
    local checkout or zip), converts every supported rule into the
    internal format, and writes identical copies into the destination
    rule directories. No network access happens unless this command is
    invoked without ``--source``.
    """
    import tempfile

    release = args.release if args.release else release_tag_from_env()

    destinations = rule_destination_directories(args.dest)

    with tempfile.TemporaryDirectory(prefix="sentinelclaw-sigma-") as temporary:
        work_directory = Path(temporary)

        if args.source:
            print(f"[sigma] converting from local source: {args.source}")

            sigma_rules_directory = prepare_source_directory(
                Path(args.source).expanduser(),
                work_directory,
            )
        else:
            print(f"[sigma] downloading SigmaHQ release {release}...")

            archive = download_release_zip(
                release,
                work_directory / "sigma-release.zip",
            )

            sigma_rules_directory = prepare_source_directory(
                archive,
                work_directory,
            )

        summary = import_into(
            sigma_rules_directory,
            destinations,
            refresh=True,
        )

    print()
    print(
        f"Imported Sigma rules: "
        f"{summary.converted_count} converted, "
        f"{summary.skipped_count} skipped"
    )

    if summary.skipped:
        print()
        print("Skip reasons (rule isolation; see SUPPORTED_SUBSET.md):")

        for reason, count in tally_by_reason(summary.skipped):
            print(f"  - {reason}: {count}")

    print()
    print("Written to:")

    for destination in destinations:
        print(f"  - {destination / 'sigma'}")

    print()
    print("Re-run 'sentinelclaw rules' to list the loaded converted rules.")

    return {
        "release": release,
        "converted": summary.converted_count,
        "skipped": summary.skipped_count,
        "destinations": [str(destination / "sigma") for destination in destinations],
        "skip_reasons": dict(summary.skipped),
    }


def format_rule_line(
    rule: dict,
) -> str:
    """Render one rule as ``ID | SEVERITY | CATEGORY | title [tags]``.

    The severity column shows the effective severity at match time; a
    rule-level ``level_override`` (P2-15) wins over the base severity.
    Optional metadata is appended as bracketed tags so the base format
    stays backward-compatible with parsers of the ``rules`` command.
    """
    effective_severity = rule.get("level_override") or rule.get(
        "severity",
        "info",
    )

    line = (
        f"{rule.get('id')} | "
        f"{str(effective_severity).upper()} | "
        f"{rule.get('category')} | "
        f"{rule.get('title')}"
    )

    tags = []

    status = rule.get("status")

    if status:
        tags.append(f"status={str(status).lower()}")

    if rule.get("noisy"):
        tags.append("noisy")

    level_override = rule.get("level_override")

    if level_override:
        tags.append(f"level_override={str(level_override).lower()}")

    if tags:
        line += " " + " ".join(f"[{tag}]" for tag in tags)

    return line


def rules_summary_lines(
    rules: list[dict],
) -> list[str]:
    """Return deterministic count lines grouped by status and category."""
    status_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}

    for rule in rules:
        status = str(
            rule.get(
                "status",
                "unspecified",
            )
        ).lower()
        category = str(
            rule.get(
                "category",
                "unknown",
            )
        ).lower()

        status_counts[status] = status_counts.get(status, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    return [
        "Rules by status: "
        + " ".join(f"{status}={count}" for status, count in sorted(status_counts.items())),
        "Rules by category: "
        + " ".join(f"{category}={count}" for category, count in sorted(category_counts.items())),
    ]


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    rules_parser = subparsers.add_parser(
        "rules",
        help=("Show loaded detection rules"),
    )

    rules_subparsers = rules_parser.add_subparsers(
        dest="rules_subcommand",
    )

    import_parser = rules_subparsers.add_parser(
        "import",
        help=(
            "Import SigmaHQ rules into the internal format "
            "(user-invoked; downloads the pinned release unless "
            "--source is given)"
        ),
    )

    import_parser.add_argument(
        "--source",
        default=None,
        help=("Path to a local SigmaHQ checkout directory or a release zip to convert offline"),
    )

    import_parser.add_argument(
        "--release",
        default=None,
        help=(
            f"SigmaHQ release tag to download (default: "
            f"{SIGMA_RELEASE_TAG}, override with "
            f"SENTINELCLAW_SIGMA_RELEASE)"
        ),
    )

    import_parser.add_argument(
        "--dest",
        default=None,
        help=(
            "Rule directory to write the converted sigma/ tree into "
            "(default: the resolved rules directory)"
        ),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    if getattr(args, "rules_subcommand", None) == "import":
        run_rules_import(args)

        return

    rules = get_rules()

    print()
    print(f"Loaded detection rules: {len(rules)}")
    print()

    for rule in rules:
        print(format_rule_line(rule))

    print()

    for summary_line in rules_summary_lines(rules):
        print(summary_line)
