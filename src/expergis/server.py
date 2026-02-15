"""
Expergis MCP Server.

Plugin-based event watcher for Claude Code. Detects system events and
dispatches them to Velle's HTTP sidecar for agent injection.

Exposes 4 MCP tools:
  - expergis_watch: Register a watcher
  - expergis_unwatch: Remove a watcher
  - expergis_list: List active watchers
  - expergis_check: Poll recent events
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from expergis.config import load_config
from expergis.dispatcher import Dispatcher
from expergis.plugins import PLUGIN_REGISTRY
from expergis.plugins.base import Event, WatcherPlugin

logger = logging.getLogger("expergis")


class WatcherEntry:
    """Tracks a running watcher and its metadata."""

    def __init__(
        self,
        watcher_id: str,
        plugin: WatcherPlugin,
        plugin_type: str,
        prompt_template: str,
        config: dict[str, Any],
    ):
        self.watcher_id = watcher_id
        self.plugin = plugin
        self.plugin_type = plugin_type
        self.prompt_template = prompt_template
        self.config = config
        self.task: asyncio.Task | None = None
        self.event_count: int = 0
        self.last_event: str | None = None
        self.created_at: str = datetime.now(timezone.utc).isoformat()


# Module-level state
_config = load_config()
_dispatcher = Dispatcher(_config)
_watchers: dict[str, WatcherEntry] = {}


async def _emit_event(entry: WatcherEntry, event: Event) -> None:
    """Callback passed to plugins. Routes events to the dispatcher."""
    entry.event_count += 1
    entry.last_event = event.timestamp
    await _dispatcher.dispatch(event, entry.prompt_template)


async def _run_watcher(entry: WatcherEntry) -> None:
    """Run a watcher plugin's watch loop with error handling."""
    try:
        async def emit(event: Event) -> None:
            await _emit_event(entry, event)

        await entry.plugin.watch(emit)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Watcher '{entry.watcher_id}' crashed: {e}", exc_info=True)


def _create_server() -> Server:
    server = Server("expergis")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="expergis_watch",
                description=(
                    "Register an event watcher. Supported plugin types: "
                    "file_watcher (file/dir changes), schedule_watcher (cron triggers), "
                    "process_watcher (process start/stop). When events fire, "
                    "the prompt_template is formatted with the event and injected via Velle."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "watcher_id": {
                            "type": "string",
                            "description": "Unique ID for this watcher",
                        },
                        "plugin_type": {
                            "type": "string",
                            "enum": list(PLUGIN_REGISTRY.keys()),
                            "description": "Type of watcher plugin",
                        },
                        "config": {
                            "type": "object",
                            "description": (
                                "Plugin-specific configuration. "
                                "file_watcher: {paths, patterns, events, debounce_ms}. "
                                "schedule_watcher: {cron}. "
                                "process_watcher: {process_names, poll_interval_ms}."
                            ),
                        },
                        "prompt_template": {
                            "type": "string",
                            "description": (
                                "Template for the prompt injected when event fires. "
                                "Use {event.summary}, {event.event_type}, {event.details}."
                            ),
                            "default": "Event detected: {event.summary}. Review and decide if action needed.",
                        },
                    },
                    "required": ["watcher_id", "plugin_type", "config"],
                },
            ),
            Tool(
                name="expergis_unwatch",
                description="Remove an active watcher by its ID.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "watcher_id": {
                            "type": "string",
                            "description": "ID of the watcher to remove",
                        },
                    },
                    "required": ["watcher_id"],
                },
            ),
            Tool(
                name="expergis_list",
                description="List all active watchers with their stats.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            Tool(
                name="expergis_check",
                description="Poll recent events from the event buffer. Includes events that were rate-limited or deduped.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "since": {
                            "type": "string",
                            "description": "ISO timestamp — only return events after this time",
                        },
                        "watcher_id": {
                            "type": "string",
                            "description": "Filter events by watcher ID",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max events to return (default 20)",
                            "default": 20,
                        },
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name == "expergis_watch":
            return await _handle_watch(arguments)
        elif name == "expergis_unwatch":
            return await _handle_unwatch(arguments)
        elif name == "expergis_list":
            return await _handle_list(arguments)
        elif name == "expergis_check":
            return await _handle_check(arguments)
        else:
            return [TextContent(type="text", text=json.dumps({
                "status": "error",
                "error": f"Unknown tool: {name}",
            }))]

    return server


async def _handle_watch(args: dict) -> list[TextContent]:
    """Register a new watcher."""
    watcher_id = args["watcher_id"]
    plugin_type = args["plugin_type"]
    config = args.get("config", {})
    prompt_template = args.get(
        "prompt_template",
        "Event detected: {event.summary}. Review and decide if action needed.",
    )

    if watcher_id in _watchers:
        return [TextContent(type="text", text=json.dumps({
            "status": "error",
            "error": f"Watcher '{watcher_id}' already exists. Unwatch first.",
        }))]

    if plugin_type not in PLUGIN_REGISTRY:
        return [TextContent(type="text", text=json.dumps({
            "status": "error",
            "error": f"Unknown plugin type: {plugin_type}. Available: {list(PLUGIN_REGISTRY.keys())}",
        }))]

    plugin_cls = PLUGIN_REGISTRY[plugin_type]
    plugin = plugin_cls(watcher_id, config)

    try:
        await plugin.setup()
    except (ValueError, OSError) as e:
        return [TextContent(type="text", text=json.dumps({
            "status": "error",
            "error": f"Plugin setup failed: {e}",
        }))]

    entry = WatcherEntry(watcher_id, plugin, plugin_type, prompt_template, config)
    entry.task = asyncio.create_task(_run_watcher(entry))
    _watchers[watcher_id] = entry

    return [TextContent(type="text", text=json.dumps({
        "status": "watching",
        "watcher_id": watcher_id,
        "plugin_type": plugin_type,
        "config": config,
    }))]


async def _handle_unwatch(args: dict) -> list[TextContent]:
    """Remove a watcher."""
    watcher_id = args["watcher_id"]

    if watcher_id not in _watchers:
        return [TextContent(type="text", text=json.dumps({
            "status": "error",
            "error": f"No watcher with ID '{watcher_id}'",
        }))]

    entry = _watchers.pop(watcher_id)
    await entry.plugin.teardown()
    if entry.task and not entry.task.done():
        entry.task.cancel()
        try:
            await entry.task
        except asyncio.CancelledError:
            pass

    return [TextContent(type="text", text=json.dumps({
        "status": "unwatched",
        "watcher_id": watcher_id,
        "events_processed": entry.event_count,
    }))]


async def _handle_list(args: dict) -> list[TextContent]:
    """List all active watchers."""
    watchers = []
    for wid, entry in _watchers.items():
        watchers.append({
            "watcher_id": wid,
            "plugin_type": entry.plugin_type,
            "config": entry.config,
            "event_count": entry.event_count,
            "last_event": entry.last_event,
            "created_at": entry.created_at,
            "running": entry.task is not None and not entry.task.done(),
        })

    return [TextContent(type="text", text=json.dumps({
        "watchers": watchers,
        "total": len(watchers),
        "dispatcher_stats": _dispatcher.stats,
    }, indent=2))]


async def _handle_check(args: dict) -> list[TextContent]:
    """Poll recent events."""
    since = args.get("since")
    watcher_id = args.get("watcher_id")
    limit = args.get("limit", 20)

    events = _dispatcher.get_recent_events(since=since, watcher_id=watcher_id, limit=limit)

    return [TextContent(type="text", text=json.dumps({
        "events": events,
        "count": len(events),
        "dispatcher_stats": _dispatcher.stats,
    }, indent=2))]


async def _start_config_watchers() -> None:
    """Start watchers defined in the config file."""
    for watcher_def in _config.get("watchers", []):
        if not watcher_def.get("enabled", True):
            continue

        watcher_id = watcher_def.get("watcher_id")
        plugin_type = watcher_def.get("plugin_type")
        config = watcher_def.get("config", {})
        prompt_template = watcher_def.get(
            "prompt_template",
            "Event detected: {event.summary}. Review and decide if action needed.",
        )

        if not watcher_id or not plugin_type:
            logger.warning(f"Skipping invalid watcher config: {watcher_def}")
            continue

        if plugin_type not in PLUGIN_REGISTRY:
            logger.warning(f"Unknown plugin type in config: {plugin_type}")
            continue

        plugin_cls = PLUGIN_REGISTRY[plugin_type]
        plugin = plugin_cls(watcher_id, config)

        try:
            await plugin.setup()
        except (ValueError, OSError) as e:
            logger.warning(f"Failed to setup config watcher '{watcher_id}': {e}")
            continue

        entry = WatcherEntry(watcher_id, plugin, plugin_type, prompt_template, config)
        entry.task = asyncio.create_task(_run_watcher(entry))
        _watchers[watcher_id] = entry
        logger.info(f"Started config watcher: {watcher_id} ({plugin_type})")


async def _run():
    server = _create_server()

    # Start config-defined watchers
    await _start_config_watchers()

    try:
        async with stdio_server() as (read_stream, write_stream):
            logger.info("Expergis MCP server starting")
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        # Teardown all watchers
        for entry in _watchers.values():
            await entry.plugin.teardown()
            if entry.task and not entry.task.done():
                entry.task.cancel()
        await _dispatcher.close()


def main():
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_run())


if __name__ == "__main__":
    main()
