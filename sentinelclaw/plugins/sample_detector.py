"""Sample detector plugin (P6-30).

Demonstrates the SentinelClaw plugin contract: a ``register``
function that adds a subcommand, a ``handle`` function that executes
it, and a ``COMMANDS`` tuple naming the added subcommand. Wired in
through the ``sentinelclaw.detectors`` entry-point group in
``pyproject.toml``; the output is fully deterministic so the plugin
path can be smoke-tested.
"""

from __future__ import annotations

import argparse


COMMANDS = ("sample-plugin",)


def register(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    subparsers.add_parser(
        "sample-plugin",
        help=("Sample plugin command demonstrating the SentinelClaw plugin API"),
    )


def handle(
    args: argparse.Namespace,
) -> None:
    print("[plugin] SentinelClaw sample detector plugin loaded and executed.")

    print("Plugin entry points: sentinelclaw.detectors")
