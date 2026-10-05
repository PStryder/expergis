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
import time
import contextlib
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
        self.status = "watching"
        self.coalesced_count = 0
        self._recent = {}
        self.event_count: int = 0
        self.last_event: str | None = None
        self.created_at: str = datetime.now(timezone.utc).isoformat()


# Module-level state
_config = load_config()
_dispatcher = Dispatcher(_config)
_watchers: dict[str, WatcherEntry] = {}


async def _emit_event(entry: WatcherEntry, event: Event) -> None:
    """Callback passed to plugins. Routes events to the dispatcher."""
    if entry.config.get("_monitoring_v2"):
        if time.time() >= entry.config["_expires_at"]:
            return
        service = _dispatcher.event_service
        if service and not service.authorize(_dispatcher.owner, entry.watcher_id):
            return
        now = time.monotonic()
        window = entry.config["coalesce_seconds"]
        entry._recent = {k:v for k,v in entry._recent.items() if now-v < window}
        # Coalesce repeated file modifications; retain distinct lifecycle transitions.
        key = json.dumps([event.event_type, event.summary,
            {} if event.plugin_type == "file_watcher" and event.event_type == "modified" else event.details], sort_keys=True)
        if key in entry._recent:
            entry.coalesced_count += 1
            return
        if len(entry._recent) >= 128:
            entry._recent.pop(next(iter(entry._recent)))
        entry._recent[key] = now
    entry.event_count += 1
    entry.last_event = event.timestamp
    event.context = entry.config.get("context", {})
    await _dispatcher.dispatch(event, entry.prompt_template)


async def _run_watcher(entry: WatcherEntry) -> None:
    """Run a watcher plugin's watch loop with error handling."""
    try:
        async def emit(event: Event) -> None:
            await _emit_event(entry, event)

        if entry.config.get("_monitoring_v2"):
            child = asyncio.create_task(entry.plugin.watch(emit))
            try:
                while not child.done():
                    remaining = entry.config["_expires_at"] - time.time()
                    service = _dispatcher.event_service
                    if remaining <= 0:
                        entry.status = "expired"
                        break
                    if service and not service.authorize(_dispatcher.owner, entry.watcher_id):
                        entry.status = "revoked"
                        break
                    await asyncio.wait({child}, timeout=min(1, remaining))
                if child.done():
                    await child
            finally:
                child.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await child
                await entry.plugin.teardown()
        else:
            await entry.plugin.watch(emit)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        entry.status = "failed"
        logger.error("Watcher stopped after %s", type(e).__name__)


async def _list_tools() -> list[Tool]:
    return [
        Tool(
            name="expergis_watch",
            description=(
                "Register an event watcher. Supported plugin types: "
                "file_watcher (file/dir changes), schedule_watcher (cron triggers), "
                "process_watcher (process start/stop), service_watcher (SemSearch status). When events fire, "
                "the selected adapter receives observations and config.context. Legacy Velle uses prompt_template."
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
                            "file_watcher: {paths, patterns, events, debounce_ms, backend}. Optional context is a JSON object. "
                            "schedule_watcher: {cron}. "
                            "process_watcher: {process_names, processes: [{pid, creation_time}], poll_interval_ms}. "
                            "service_watcher: {service_names: [SemSearch], poll_interval_ms}. "
                            "job_event_watcher: {inbox}; requires separate explicit structured-content permission. "
                            "Task monitoring accepts ttl_seconds (60..604800, default 86400), coalesce_seconds (1..60)."
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
                        "description": "ISO timestamp - only return events after this time",
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


async def _call_tool(name: str, arguments: dict) -> list[TextContent]:
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



def _create_server() -> Server:
    server = Server("expergis")
    if hasattr(server, "list_tools"):
        server.list_tools()(_list_tools)
        server.call_tool()(_call_tool)
    else:
        from mcp.types import ListToolsResult, CallToolResult, PaginatedRequestParams, CallToolRequestParams
        async def listing(ctx, params):
            return ListToolsResult(tools=await _list_tools())
        async def calling(ctx, params):
            return CallToolResult(content=await _call_tool(params.name, params.arguments or {}))
        server.add_request_handler("tools/list", PaginatedRequestParams, listing)
        server.add_request_handler("tools/call", CallToolRequestParams, calling)
    return server


async def _handle_watch(args: dict) -> list[TextContent]:
    """Register a new watcher."""
    from expergis.events_security import json_bytes
    try:
        if not isinstance(args, dict):
            raise ValueError("Expected an object")
        if (not isinstance(args.get("watcher_id"), str) or not 1 <= len(args["watcher_id"]) <= 128
                or not isinstance(args.get("plugin_type"), str) or not isinstance(args.get("config", {}), dict)
                or len(_watchers) >= 32):
            raise ValueError("Invalid watcher or capacity reached")
        json_bytes(args, 65536)
        if not isinstance(args.get("prompt_template", ""), str):
            raise ValueError("Invalid template")
        context = args.get("config", {}).get("context", {})
        if not isinstance(context, dict):
            raise ValueError("Context must be an object")
        json_bytes(context, 16384)
    except ValueError:
        return [TextContent(type="text", text=json.dumps({"status": "error", "error": "Invalid watcher input"}))]
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
    if plugin_type == "job_event_watcher":
        service = _dispatcher.event_service
        if (service is None or _config.get("mcp_events", {}).get("allow_job_event_contents") is not True
                or any(e.plugin_type == plugin_type for e in _watchers.values())):
            return [TextContent(type="text", text=json.dumps({"status":"error",
                "error":"Explicit event inbox permission and a single consumer are required"}))]
        plugin.bind(service.store, _dispatcher.owner, service.authorize)

    try:
        expired = config.get("_monitoring_v2") and config["_expires_at"] <= time.time()
        if not expired:
            await plugin.setup()
    except (ValueError, TypeError, OSError) as e:
        await plugin.teardown()
        return [TextContent(type="text", text=json.dumps({
            "status": "error",
            "error": "Plugin setup failed: invalid configuration or inaccessible resource",
        }))]

    entry = WatcherEntry(watcher_id, plugin, plugin_type, prompt_template, config)
    if _dispatcher.event_service:
        try:
            _dispatcher.event_service.store.save_watcher(_dispatcher.owner, watcher_id, args)
        except (ValueError, OSError):
            await plugin.teardown()
            return [TextContent(type="text", text=json.dumps({"status": "error", "error": "Cannot persist watcher"}))]
    if expired:
        entry.status = "expired"
    else:
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

    if _dispatcher.event_service:
        _dispatcher.event_service.store.remove_watcher(_dispatcher.owner, watcher_id)
    entry = _watchers.pop(watcher_id)
    if entry.task and not entry.task.done():
        entry.task.cancel()
        try:
            await entry.task
        except asyncio.CancelledError:
            pass
    await entry.plugin.teardown()

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
            "status": entry.status,
            "expires_at": entry.config.get("_expires_at"),
            "coalesced_count": entry.coalesced_count,
            "source_stats": getattr(entry.plugin, "source_stats", {}),
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
    if type(limit) is not int or not 1 <= limit <= 200:
        return [TextContent(type="text", text=json.dumps({"status": "error", "error": "limit must be 1..200"}))]

    events = _dispatcher.get_recent_events(since=since, watcher_id=watcher_id, limit=limit)

    return [TextContent(type="text", text=json.dumps({
        "events": events,
        "count": len(events),
        "delivery_receipts": (_dispatcher.event_service.store.receipts(_dispatcher.owner, limit)
                              if _dispatcher.event_service else []),
        "dispatcher_stats": _dispatcher.stats,
    }, indent=2))]


async def _start_config_watchers() -> None:
    definitions = {w.get("watcher_id"): w for w in _config.get("watchers", [])}
    if _dispatcher.event_service:
        for w in _dispatcher.event_service.store.watchers(_dispatcher.owner):
            definitions.setdefault(w["watcher_id"], w)
    for definition in definitions.values():
        if definition.get("enabled", True) and definition.get("watcher_id") not in _watchers:
            if _config.get("mcp_events", {}).get("monitoring_policy_version") == 2:
                from expergis.monitoring_scope import validate_watch
                validate_watch(definition, _config["mcp_events"], restore=True)
            result = await _handle_watch(definition)
            if json.loads(result[0].text).get("status") != "watching":
                logger.warning("A configured watcher could not start")


async def _run():
    server = _create_server()

    if _dispatcher.adapter == "mcp_events":
        raise RuntimeError("Use the authenticated MCP Events application factory for event delivery")
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
