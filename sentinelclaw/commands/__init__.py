"""SentinelClaw command registry and dispatch (P6-30).

Each command module under :mod:`sentinelclaw.commands` exposes the
same contract:

* ``register(subparsers)`` -- adds its subparser(s) to the main
  argument parser;
* ``handle(args)`` -- executes the command(s) it registered;
* ``COMMANDS`` -- tuple of subcommand names it handles, used by
  :func:`dispatch` to route.

``register_all`` additionally registers entry-point plugins (see
:mod:`sentinelclaw.plugins`); :func:`dispatch` routes a parsed
argument namespace to the owning module's handler.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Callable

from sentinelclaw.commands import (
    analysis,
    hunting,
    investigate,
    report,
    rules,
    scan,
    system,
)

from sentinelclaw.plugins import (
    PluginHandler,
    register_plugin_commands,
)

logger = logging.getLogger(__name__)

COMMAND_MODULES = (
    system,
    scan,
    report,
    rules,
    hunting,
    investigate,
    analysis,
)

_PLUGIN_HANDLERS: dict[
    str,
    PluginHandler,
] = {}


def register_all(
    parser: argparse.ArgumentParser,
) -> None:
    """Register every built-in command and installed plugin."""
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for module in COMMAND_MODULES:
        module.register(subparsers)

    _PLUGIN_HANDLERS.update(register_plugin_commands(subparsers))


def dispatch(
    args: argparse.Namespace,
) -> None:
    """Execute the parsed command through its owning module."""
    for module in COMMAND_MODULES:
        if args.command in module.COMMANDS:
            module.handle(args)

            return

    plugin_handler = _PLUGIN_HANDLERS.get(args.command)

    if plugin_handler is not None:
        plugin_handler(args)

        return

    raise RuntimeError(f"Unknown command: {args.command}")


def plugin_handlers() -> dict[
    str,
    Callable[
        [argparse.Namespace],
        None,
    ],
]:
    """Return the currently registered plugin command handlers."""
    return dict(_PLUGIN_HANDLERS)
