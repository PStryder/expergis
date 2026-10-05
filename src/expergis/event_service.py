"""Documented MCP Events methods; authentication must supply the principal."""
import asyncio
import hashlib
import time
import sqlite3
import logging

import aiohttp

from expergis.event_store import utc
from expergis.events_security import CallbackError, WebhookSender, json_bytes, signed_headers, signing_key, validate_url

EVENT_DEFINITION = {
    "name": "expergis.observed",
    "description": "An observed change from one explicitly selected Expergis watcher. Context is user-supplied data.",
    "delivery": ["webhook"],
    "inputSchema": {"type": "object", "properties": {"watcher_id": {"type": "string"}},
                    "required": ["watcher_id"], "additionalProperties": False},
    "payloadSchema": {"type": "object", "properties": {
        "watcher_id": {"type": "string"}, "plugin_type": {"type": "string"},
        "event_type": {"type": "string"}, "observed": {"type": "object",
            "properties": {"summary": {"type": "string"}, "details": {"type": "object"}},
            "required": ["summary", "details"], "additionalProperties": False},
        "context": {"type": "object"}},
        "required": ["watcher_id", "plugin_type", "event_type", "observed", "context"],
        "additionalProperties": False}}


class EventService:
    def __init__(self, store, authorize, *, sender=None):
        self.store, self.authorize = store, authorize
        self.sender = sender or WebhookSender()
        self._lock = asyncio.Lock()
        self._verification_cache = {}

    def _owner(self, owner):
        if not isinstance(owner, str) or not owner or len(owner) > 256:
            raise PermissionError("Authentication required")

    def list_events(self, owner):
        self._owner(owner)
        return {"events": [EVENT_DEFINITION] if self.authorize(owner, None) else []}

    async def subscribe(self, owner, params):
        self._owner(owner)
        if not isinstance(params, dict) or set(params) - {"name", "arguments", "delivery", "cursor", "ttlMs"}:
            raise ValueError("Invalid subscription parameters")
        args, delivery = params.get("arguments"), params.get("delivery")
        if (params.get("name") != EVENT_DEFINITION["name"] or not isinstance(args, dict)
                or set(args) != {"watcher_id"} or not isinstance(args["watcher_id"], str)
                or not 1 <= len(args["watcher_id"]) <= 128 or params.get("cursor") is not None):
            raise ValueError("Invalid event filter or unsupported cursor")
        if not self.authorize(owner, args["watcher_id"]):
            raise PermissionError("Watcher access denied")
        if (not isinstance(delivery, dict) or set(delivery) != {"mode", "url", "secret"}
                or delivery["mode"] != "webhook"):
            raise ValueError("Invalid webhook delivery")
        validate_url(delivery["url"])
        signing_key(delivery["secret"])
        ttl = params.get("ttlMs", 3600000)
        if ttl is None:
            ttl = 3600000  # This service grants finite lifetimes only.
        if type(ttl) is not int or ttl <= 0:
            raise ValueError("Invalid subscription lifetime")
        ttl = min(ttl, 86400000)
        sid = "sub_" + hashlib.sha256(json_bytes([owner, delivery["url"], params["name"], args])).hexdigest()
        # Serialize verification/refresh/unsubscribe, and bound work and cache size.
        async with self._lock:
            now = self.store.clock()
            self.store.prune()
            if (not self.store.db.execute("SELECT 1 FROM subscriptions WHERE id=?", (sid,)).fetchone()
                    and self.store.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] >= self.store.max_subscriptions):
                raise ValueError("Subscription capacity reached")
            cache_key = hashlib.sha256(json_bytes([owner, delivery["url"], delivery["secret"]])).hexdigest()
            self._verification_cache = {k: v for k, v in self._verification_cache.items() if v > now}
            if self._verification_cache.get(cache_key, 0) <= now:
                await self.sender.verify(delivery["url"], delivery["secret"], sid)
                if len(self._verification_cache) >= self.store.max_subscriptions:
                    self._verification_cache.clear()
                self._verification_cache[cache_key] = self.store.clock() + 60
            if not self.authorize(owner, args["watcher_id"]):
                raise PermissionError("Watcher access denied")
            expires = self.store.clock() + ttl / 1000
            self.store.subscribe(sid, owner, args["watcher_id"], delivery, expires)
        return {"id": sid, "refreshBefore": utc(expires), "cursor": None, "truncated": False}

    async def unsubscribe(self, owner, params):
        self._owner(owner)
        if not isinstance(params, dict) or set(params) != {"name", "arguments", "delivery"}:
            raise ValueError("Invalid unsubscribe parameters")
        args, delivery = params["arguments"], params["delivery"]
        if (params["name"] != EVENT_DEFINITION["name"] or not isinstance(args, dict)
                or set(args) != {"watcher_id"} or not isinstance(args["watcher_id"], str)
                or not 1 <= len(args["watcher_id"]) <= 128
                or not isinstance(delivery, dict) or set(delivery) != {"mode", "url"}
                or delivery["mode"] != "webhook"):
            raise ValueError("Invalid unsubscribe parameters")
        validate_url(delivery["url"])
        sid = "sub_" + hashlib.sha256(json_bytes([owner, delivery["url"], params["name"], args])).hexdigest()
        async with self._lock:
            self.store.unsubscribe(sid, owner)
        return {}

    async def deliver_one(self):
        # Same lock prevents an unsubscribe/rotation acknowledgement overtaking a send.
        async with self._lock:
            item = self.store.claim()
            if item is None:
                return False
            if not self.authorize(item["owner"], item["watcher"]):
                self.store.unsubscribe(item["subscription"], item["owner"])
                return True
            if not self.store.active(item):
                self.store.finish(item, "pending")
                return True
            if item["attempts"] > 8:
                self.store.finish(item, "failed")
                return True
            body = json_bytes(item["payload"])
            headers = signed_headers(item["delivery"]["secret"], item["subscription"], item["event"], body)
            if item["delivery"].get("previous_until", 0) > self.store.clock():
                old = signed_headers(item["delivery"]["previous_secret"], item["subscription"], item["event"],
                                     body, now=int(headers["webhook-timestamp"]))
                headers["webhook-signature"] += " " + old["webhook-signature"]
            status = None
            try:
                status, _ = await self.sender.post(item["delivery"]["url"], body, headers)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError, CallbackError):
                pass  # No URL, key, payload or receiver response in logs.
            if status is not None and 200 <= status < 300:
                state = "received"  # Never means downstream execution completed.
            elif status == 410:
                self.store.unsubscribe(item["subscription"], item["owner"])
                return True
            elif item["attempts"] >= 8 or (status is not None and status not in (408, 425, 429) and status < 500):
                state = "failed"
            else:
                state = "pending"
            self.store.finish(item, state, due=self.store.clock() + min(3600, 2 ** item["attempts"]), status=status)
            return True

    async def run(self):
        while True:
            try:
                await self.deliver_one()
            except (sqlite3.Error, OSError, ValueError):
                logging.getLogger("expergis.events").error("Event storage unavailable; delivery paused")
                await asyncio.sleep(5)
            await asyncio.sleep(0.25)
