"""Opt-in MCP 2.3 application factory. No listener, credentials or watcher at import.

The deployment supplies an OAuth TokenVerifier and AuthSettings. Existing stdio
MCP 1.x configuration remains valid. Do not run alongside a live stdio watcher.
"""
import asyncio
import contextlib
import json
from pathlib import Path

from expergis.dispatcher import Dispatcher
from expergis.event_service import EventService
from expergis.event_store import EventStore
from expergis.events_security import CallbackError
from expergis.runtime_lock import RuntimeLock


class BoundedRequestsMiddleware:
    def __init__(self, app):
        self.app, self.active = app, 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.active >= 16:
            from starlette.responses import Response
            return await Response(status_code=503)(scope, receive, send)
        self.active += 1
        try:
            await self.app(scope, receive, send)
        finally:
            self.active -= 1


class EventDiscoveryMiddleware:
    """Preserve the documented events capability through SDK 2.3's schema filter.

    SDK 2.3 supports the 2026 transport and custom methods but its generated
    discovery schema drops `events` and Tool drops `securitySchemes`. Add these
    documented metadata fields to an already
    authenticated, SDK-validated successful discovery response. All transport,
    envelope and error handling stays with the SDK; remove when its schema adds
    MCP Events and OAuth tool metadata. No legacy response is modified.
    """
    def __init__(self, app, scopes):
        self.app, self.scopes = app, scopes

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers", []))
        if (scope["type"] != "http" or headers.get(b"mcp-method") not in (b"server/discover", b"tools/list")
                or headers.get(b"mcp-protocol-version") != b"2026-07-28"):
            return await self.app(scope, receive, send)
        start = None
        async def outgoing(message):
            nonlocal start
            if message["type"] == "http.response.start" and message["status"] == 200:
                start = message
                return
            if start is not None and message["type"] == "http.response.body":
                if message.get("more_body"):
                    raise RuntimeError("Discovery must use a single JSON response")
                payload = json.loads(message["body"])
                if headers.get(b"mcp-method") == b"tools/list":
                    for tool in payload.get("result", {}).get("tools", []):
                        tool["securitySchemes"] = [{"type": "oauth2", "scopes": self.scopes}]
                if "2026-07-28" in payload.get("result", {}).get("supportedVersions", []):
                    payload["result"]["capabilities"]["events"] = {}
                body = json.dumps(payload, separators=(",", ":")).encode()
                start["headers"] = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
                start["headers"].append((b"content-length", str(len(body)).encode()))
                await send(start)
                start = None
                await send({**message, "body": body})
                return
            await send(message)
        await self.app(scope, receive, outgoing)


def create_app(config, token_verifier, auth_settings, *, authorize, store=None, sender=None):
    from mcp.server import Server
    if not hasattr(Server, "add_request_handler"):
        raise RuntimeError("The event endpoint requires a separate mcp==2.3.0 environment")
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.transport_security import TransportSecuritySettings
    from mcp.shared.exceptions import MCPError
    from mcp.types import RequestParams, ListToolsResult, CallToolResult
    from pydantic import ConfigDict
    from expergis import server as runtime

    options = config.get("mcp_events", {})
    owner = options.get("owner")
    if config.get("delivery_adapter") != "mcp_events" or not isinstance(owner, str) or not owner:
        raise ValueError("Explicit mcp_events adapter and owner subject are required")
    if (not callable(authorize) or token_verifier is None or auth_settings is None or not auth_settings.resource_server_url
            or not auth_settings.validate_token_resource or not auth_settings.required_scopes
            or str(auth_settings.resource_server_url).split(":", 1)[0] != "https"
            or str(auth_settings.issuer_url).split(":", 1)[0] != "https"):
        raise ValueError("A resource-bound OAuth verifier, HTTPS issuer/resource and required scopes are required")
    if store is None and not options.get("database"):
        raise ValueError("An explicit private database path is required")

    class Params(RequestParams):
        model_config = ConfigDict(extra="allow")

    def principal():
        token = get_access_token()
        if token is None or token.subject != owner or not authorize(owner, None):
            raise MCPError(code=-32001, message="Access denied")
        return token.subject

    def service():
        principal()
        if runtime._dispatcher.event_service is None:
            raise MCPError(code=-32603, message="Event runtime unavailable")
        return runtime._dispatcher.event_service

    async def boundary(operation):
        try:
            return await operation
        except CallbackError as exc:
            raise MCPError(code=-32015, message="Callback verification failed",
                           data={"reason": exc.reason}) from None
        except PermissionError:
            raise MCPError(code=-32001, message="Access denied") from None
        except ValueError:
            raise MCPError(code=-32602, message="Invalid event parameters") from None

    def values(params):
        return params.model_dump(by_alias=True, exclude_unset=True, exclude={"meta"})

    def modern(ctx):
        if ctx.protocol_version != "2026-07-28":
            raise MCPError(code=-32600, message="MCP Events requires protocol 2026-07-28")

    async def discover(ctx, params):
        principal()
        return {"resultType": "complete", "supportedVersions": ["2026-07-28"],
                "cacheScope": "private", "ttlMs": 0,
                "capabilities": {"tools": {}, "events": {}}}

    async def events_list(ctx, params):
        modern(ctx)
        if values(params):
            raise MCPError(code=-32602, message="This catalog has no additional pages")
        return service().list_events(principal())

    async def subscribe(ctx, params):
        modern(ctx)
        return await boundary(service().subscribe(principal(), values(params)))

    async def unsubscribe(ctx, params):
        modern(ctx)
        return await boundary(service().unsubscribe(principal(), values(params)))

    async def listing(ctx, params):
        principal()
        return ListToolsResult(tools=await runtime._list_tools())

    def validate_remote_watch(args):
        """Remote registration stays inside operator-selected monitoring scope."""
        def local_path(value):
            if (not isinstance(value, str) or not value or len(value) > 32768
                    or value.startswith(("\\\\", "//")) or not Path(value).is_absolute()):
                raise PermissionError("An absolute local path is required")
            return Path(value).resolve()
        plugin, settings = args.get("plugin_type"), args.get("config", {})
        if not isinstance(settings, dict):
            raise ValueError("Invalid watcher configuration")
        if plugin == "file_watcher":
            roots = [local_path(p) for p in options.get("allowed_roots", [])]
            paths = settings.get("paths", [])
            if not isinstance(paths, list) or not 1 <= len(paths) <= 32:
                raise ValueError("Invalid paths")
            for value in paths:
                path = local_path(value)
                if not any(path == root or root in path.parents for root in roots):
                    raise PermissionError("Path outside configured scope")
        elif plugin == "process_watcher":
            allowed = {name.lower() for name in options.get("allowed_process_names", [])}
            names = settings.get("process_names", [])
            if not isinstance(names, list) or not names or any(n.lower() not in allowed for n in names):
                raise PermissionError("Process outside configured scope")
        elif plugin != "schedule_watcher":
            raise ValueError("Unknown watcher type")

    async def calling(ctx, params):
        principal()
        args = params.arguments or {}
        try:
            if params.name == "expergis_watch":
                validate_remote_watch(args)
            if params.name in ("expergis_watch", "expergis_unwatch") and not authorize(owner, args.get("watcher_id")):
                raise PermissionError("Watcher access denied")
            result = await runtime._call_tool(params.name, args)
            if params.name in ("expergis_list", "expergis_check"):
                payload = json.loads(result[0].text)
                for key in ("watchers", "events", "delivery_receipts"):
                    if key in payload:
                        payload[key] = [row for row in payload[key] if authorize(owner, row["watcher_id"])]
                if "watchers" in payload:
                    payload["total"] = len(payload["watchers"])
                if "events" in payload:
                    payload["count"] = len(payload["events"])
                result[0].text = json.dumps(payload)
        except (ValueError, TypeError, KeyError, AttributeError, PermissionError, OSError):
            raise MCPError(code=-32602, message="Tool input rejected") from None
        return CallToolResult(content=result)

    server = Server("expergis", on_list_tools=listing, on_call_tool=calling)
    for name, handler in (("server/discover", discover), ("events/list", events_list),
                          ("events/subscribe", subscribe), ("events/unsubscribe", unsubscribe)):
        server.add_request_handler(name, Params, handler)
    host = auth_settings.resource_server_url.host
    app = server.streamable_http_app(
        json_response=True, stateless_http=True, max_request_body_size=65536,
        token_verifier=token_verifier, auth=auth_settings,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
            allowed_hosts=[host, host + ":443", "127.0.0.1:*", "localhost:*"],
            allowed_origins=[str(auth_settings.resource_server_url).rstrip("/")]))
    sdk_lifespan = app.router.lifespan_context
    app.add_middleware(EventDiscoveryMiddleware, scopes=auth_settings.required_scopes)
    app.add_middleware(BoundedRequestsMiddleware)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        if runtime._watchers or runtime._dispatcher.event_service is not None:
            raise RuntimeError("An Expergis runtime is already active in this process")
        previous_config, previous_dispatcher = runtime._config, runtime._dispatcher
        lock = RuntimeLock(options["database"]) if store is None else None
        try:
            database = store or EventStore(options["database"])
        except BaseException:
            if lock:
                lock.close()
            raise
        runtime._config, runtime._dispatcher = config, Dispatcher(config)
        runtime._dispatcher.event_service = EventService(database,
            lambda user, watcher: user == owner and authorize(user, watcher)
            and (watcher is None or watcher in runtime._watchers), sender=sender)
        worker = None
        try:
            for definition in config.get("watchers", []) + database.watchers(owner):
                if definition.get("enabled", True):
                    validate_remote_watch(definition)
                    if not authorize(owner, definition.get("watcher_id")):
                        raise PermissionError("Saved watcher access revoked")
            await runtime._start_config_watchers()
            worker = asyncio.create_task(runtime._dispatcher.event_service.run())
            async with sdk_lifespan(app):
                yield
        finally:
            if worker:
                worker.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await worker
            for entry in list(runtime._watchers.values()):
                if entry.task:
                    entry.task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await entry.task
                with contextlib.suppress(Exception):
                    await entry.plugin.teardown()
            runtime._watchers.clear()
            try:
                await runtime._dispatcher.close()
            finally:
                database.close()
                if lock:
                    lock.close()
                runtime._config, runtime._dispatcher = previous_config, previous_dispatcher

    app.router.lifespan_context = lifespan
    return app
