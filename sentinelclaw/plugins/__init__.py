"""Entry-point plugin discovery for SentinelClaw (P6-30).

External packages contribute detector/collector plugins through the
``sentinelclaw.detectors`` entry-point group. Each plugin module
exposes:

* ``register(subparsers)`` -- adds one or more subcommands to the CLI;
* ``handle(args)`` -- executes those subcommands;
* ``COMMANDS`` (optional) -- tuple of subcommand names it registers,
  used to route dispatch (defaults to the entry-point name).

Discovery is best-effort: a missing group, an unloadable module, or a
malformed plugin is logged and skipped. Built-in commands never depend
on plugin availability.

Built-in plugin implementations live in
:mod:`sentinelclaw.plugins.sample_detector`.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import logging
from collections.abc import Callable
from typing import Any, cast

logger = logging.getLogger(__name__)

PLUGIN_GROUP = "sentinelclaw.detectors"

PluginHandler = Callable[
    [argparse.Namespace],
    None,
]


def discover_plugin_entry_points() -> list[Any]:
    """Return installed entry points for the plugin group.

    Never raises: any metadata failure yields an empty list so the
    plugin layer degrades gracefully when entry points are missing.
    """
    try:
        discovered = importlib.metadata.entry_points(group=PLUGIN_GROUP)
    except Exception as exc:
        logger.warning(
            "Plugin entry-point discovery failed: %s",
            exc,
        )

        return []

    return list(discovered)


def register_plugin_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> dict[str, PluginHandler]:
    """Load and register every installed plugin.

    Returns a mapping of subcommand name to the plugin's ``handle``
    callable, consumed by the command dispatcher. Broken plugins are
    skipped with a logged warning.
    """
    handlers: dict[str, PluginHandler] = {}

    for entry_point in discover_plugin_entry_points():
        try:
            module = entry_point.load()
        except Exception as exc:
            logger.warning(
                "Plugin %s skipped (load failed): %s",
                entry_point.name,
                exc,
            )

            continue

        register = getattr(
            module,
            "register",
            None,
        )

        if not callable(register):
            logger.warning(
                "Plugin %s skipped (no register function)",
                entry_point.name,
            )

            continue

        try:
            register(subparsers)
        except Exception as exc:
            logger.warning(
                "Plugin %s skipped (register failed): %s",
                entry_point.name,
                exc,
            )

            continue

        handle: Any = getattr(
            module,
            "handle",
            None,
        )

        if not callable(handle):
            logger.warning(
                "Plugin %s skipped (no handle function)",
                entry_point.name,
            )

            continue

        command_names = getattr(
            module,
            "COMMANDS",
            None,
        ) or (entry_point.name,)

        for name in command_names:
            handlers[str(name)] = cast(
                PluginHandler,
                handle,
            )

    return handlers
