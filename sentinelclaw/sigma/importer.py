"""
Sigma import pipeline (P2-14).

Turns a SigmaHQ checkout (a directory tree or a release zip) into
converted internal-format rules written under the ``sigma/``
subdirectory of the rule copies.

The import is strictly user-invoked: nothing in this module runs during
scans, and network access happens only when the CLI ``rules import``
command downloads the pinned release. Offline conversions use
``--source <dir-or-zip>`` and are what the test-suite exercises.

Pipeline shape:

1. :func:`collect_sigma_sources` walks a Sigma ``rules/`` directory for
   ``*.yml`` files (recursively).
2. :func:`convert_directory` converts every file through
   ``sigma.reader.convert_sigma_rule``; per-file failures raise
   :class:`~sentinelclaw.sigma.reader.SigmaRuleError` and are tallied
   under their ``reason_code`` instead of aborting the import.
3. :func:`write_converted_directory` clears the destination ``sigma/``
   directory (``refresh``) and mirrors the source layout underneath,
   writing one internal YAML file per converted Sigma file.
4. The CLI writes the identical tree to both rule copies so
   ``scripts/sync_rules.py --check`` stays green.

The default release is a pinned quarterly SigmaHQ snapshot tag
(:data:`SIGMA_RELEASE_TAG`). Override it with ``--release`` on the CLI
or the ``SENTINELCLAW_SIGMA_RELEASE`` environment variable.
"""

from __future__ import annotations

import logging
import os
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinelclaw.sigma.reader import (
    SigmaRuleError,
    convert_sigma_rule,
)

logger = logging.getLogger(__name__)

#: Pinned SigmaHQ release downloaded by ``sentinelclaw rules import``.
#: SigmaHQ snapshots use immutable ``rYYYY-MM-DD`` tags, so imports stay
#: reproducible.
SIGMA_RELEASE_TAG = "r2026-07-01"

SIGMA_RELEASE_ENV = "SENTINELCLAW_SIGMA_RELEASE"

DEFAULT_NETWORK_TIMEOUT_SECONDS = 120

RELEASE_ZIP_URL = "https://github.com/SigmaHQ/sigma/archive/refs/tags/{tag}.zip"

MAX_SIGMA_FILES = 20_000


class SigmaImportError(Exception):
    """The import as a whole failed (network, extraction, I/O)."""


def release_tag_from_env() -> str:
    """Return the effective release tag (env override or pinned)."""
    return os.environ.get(
        SIGMA_RELEASE_ENV,
        SIGMA_RELEASE_TAG,
    )


def download_release_zip(
    tag: str,
    destination: Path,
    timeout: int = DEFAULT_NETWORK_TIMEOUT_SECONDS,
) -> Path:
    """Download the SigmaHQ release zip for ``tag`` to ``destination``.

    Raises :class:`SigmaImportError` on any network failure.
    """
    url = RELEASE_ZIP_URL.format(tag=tag)

    try:
        with urllib.request.urlopen(
            url,
            timeout=timeout,
        ) as response:
            destination.write_bytes(response.read())
    except OSError as exc:
        raise SigmaImportError(f"Unable to download {url}: {exc}") from exc

    return destination


def extract_rules_directory(
    zip_path: Path,
    work_directory: Path,
) -> Path:
    """Extract a release zip's ``rules/**/*.yml`` tree.

    Returns the extracted ``rules/`` directory. Works for GitHub
    ``archive/refs/tags`` zips (which nest under a ``sigma-<tag>/``
    prefix) and for any zip that carries a ``rules/`` tree.
    """
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise SigmaImportError(f"Invalid Sigma release zip {zip_path}: {exc}") from exc

    rules_root = work_directory / "rules"
    extracted = 0

    with archive:
        for info in archive.infolist():
            name = info.filename

            if info.is_dir() or not name.endswith(".yml"):
                continue

            marker = "/rules/"

            marker_index = name.find(marker)

            if marker_index < 0:
                continue

            relative = Path(name[marker_index + len(marker) :])

            destination = rules_root / relative

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(info) as source:
                destination.write_bytes(source.read())

            extracted += 1

            if extracted >= MAX_SIGMA_FILES:
                break

    if extracted == 0:
        raise SigmaImportError(f"No 'rules/**/*.yml' files inside {zip_path}")

    return rules_root


def prepare_source_directory(
    source: Path,
    work_directory: Path,
) -> Path:
    """Return the Sigma ``rules/`` directory for a source path.

    A path to a ``rules`` directory (or the checkout root that contains
    one) is used as-is; a ``.zip`` archive is extracted into
    ``work_directory`` first.
    """
    if source.is_dir():
        candidate = source / "rules" if (source / "rules").is_dir() else source

        if not candidate.is_dir():
            raise SigmaImportError(f"Sigma source directory contains no rules/ tree: {source}")

        return candidate

    if source.is_file() and source.suffix.lower() == ".zip":
        return extract_rules_directory(
            source,
            work_directory,
        )

    raise SigmaImportError(f"Sigma source is neither a directory nor a zip: {source}")


def collect_sigma_sources(
    rules_directory: Path,
) -> list[Path]:
    """Return the sorted ``*.yml`` rule files under a rules directory."""
    if not rules_directory.exists():
        raise SigmaImportError(f"Sigma rules directory does not exist: {rules_directory}")

    sources = sorted(rules_directory.glob("**/*.yml"))

    if not sources:
        raise SigmaImportError(f"No Sigma rule files (*.yml) under {rules_directory}")

    return sources


@dataclass
class ConversionSummary:
    """Outcome tally for one import run."""

    converted: dict[Path, dict[str, Any]] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    skip_messages: list[str] = field(default_factory=list)

    @property
    def converted_count(self) -> int:
        return len(self.converted)

    @property
    def skipped_count(self) -> int:
        return sum(self.skipped.values())

    def record_skip(
        self,
        reason_code: str,
        message: str,
    ) -> None:
        self.skipped[reason_code] = self.skipped.get(reason_code, 0) + 1

        if len(self.skip_messages) < 20:
            self.skip_messages.append(message)


def convert_sigma_file(
    file_path: Path,
    summary: ConversionSummary,
) -> dict[str, Any] | None:
    """Convert one Sigma file; tally failures onto ``summary``."""
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        summary.record_skip(
            "read-error",
            f"{file_path}: {exc}",
        )

        return None

    try:
        return convert_sigma_rule(
            yaml.safe_load(text),
            source=str(file_path),
        )
    except SigmaRuleError as exc:
        summary.record_skip(
            exc.reason_code,
            exc.message,
        )

        return None
    except yaml.YAMLError as exc:
        summary.record_skip(
            "invalid-yaml",
            f"{file_path}: {exc}",
        )

        return None


def convert_directory(
    rules_directory: Path,
    summary: ConversionSummary | None = None,
) -> ConversionSummary:
    """Convert every Sigma file under a directory (see module docs)."""
    result = summary if summary is not None else ConversionSummary()

    for source_file in collect_sigma_sources(rules_directory):
        rule = convert_sigma_file(
            source_file,
            result,
        )

        if rule is not None:
            result.converted[source_file] = rule

    return result


def _dump_internal_rules(
    rules: list[dict[str, Any]],
) -> str:
    return yaml.safe_dump(
        {"rules": rules},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )


def _clear_sigma_directory(
    destination: Path,
) -> None:
    if not destination.exists():
        return

    for stale in destination.rglob("*"):
        if stale.is_file():
            stale.unlink()

    for stale in sorted(
        destination.rglob("*"),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if stale.is_dir():
            try:
                stale.rmdir()
            except OSError:
                logger.debug(
                    "Unable to remove directory %s",
                    stale,
                )


def write_converted_directory(
    rules_directory: Path,
    destination_root: Path,
    summary: ConversionSummary,
    refresh: bool = False,
) -> list[Path]:
    """Write converted rules under ``destination_root/sigma``.

    Files mirror the source tree relative to ``rules_directory`` and use
    the ``.yaml`` extension (one internal rule file per Sigma file).
    With ``refresh`` the destination ``sigma/`` subtree is replaced.
    """
    destination = destination_root / "sigma"

    if refresh:
        _clear_sigma_directory(destination)

    written: list[Path] = []

    for source_file, rule in sorted(summary.converted.items()):
        try:
            relative = source_file.relative_to(rules_directory)
        except ValueError:
            relative = Path(source_file.name)

        target = destination / relative.with_suffix(".yaml")

        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        target.write_text(
            _dump_internal_rules([rule]),
            encoding="utf-8",
        )

        written.append(target)

    return written


def import_into(
    sigma_rules_directory: Path,
    destination_roots: list[Path],
    refresh: bool = True,
) -> ConversionSummary:
    """Convert a Sigma source and write identical copies everywhere.

    ``destination_roots`` are rule directories (the packaged runtime
    copy and its repo sibling, usually two entries); each receives an
    identical ``sigma/`` subtree.
    """
    summary = convert_directory(sigma_rules_directory)

    if not summary.converted:
        return summary

    seen: set[Path] = set()

    for root in destination_roots:
        resolved_root = root.resolve()

        if resolved_root in seen:
            continue

        seen.add(resolved_root)

        write_converted_directory(
            rules_directory=sigma_rules_directory,
            destination_root=root,
            summary=summary,
            refresh=refresh,
        )

    return summary


def tally_by_reason(
    skipped: dict[str, int],
) -> list[tuple[str, int]]:
    """Return skip reasons sorted by frequency for the CLI summary."""
    return sorted(
        skipped.items(),
        key=lambda item: (-item[1], item[0]),
    )
