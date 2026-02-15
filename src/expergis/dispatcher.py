"""Event dispatcher — rate limiting, dedup, and HTTP dispatch to Velle."""

import asyncio
import logging
import time
from collections import deque
from typing import Any

import aiohttp

from expergis.audit import audit_log
from expergis.plugins.base import Event

logger = logging.getLogger("expergis.dispatcher")


class Dispatcher:
    """Receives events from plugins, applies rate limiting and dedup, dispatches to Velle."""

    def __init__(self, config: dict[str, Any]):
        self.velle_endpoint: str = config["velle_endpoint"]

        rl = config.get("rate_limit", {})
        self.min_interval_ms: int = rl.get("min_interval_ms", 5000)
        self.max_events_per_minute: int = rl.get("max_events_per_minute", 6)
        self.burst_size: int = rl.get("burst_size", 2)

        self.dedup_window_ms: int = config.get("dedup_window_ms", 10000)

        # Dedup state: key -> timestamp
        self._dedup_cache: dict[str, float] = {}

        # Rate limit state: token bucket
        self._tokens: float = float(self.burst_size)
        self._last_refill: float = time.monotonic()
        self._last_dispatch: float = 0.0

        # Ring buffer for expergis_check
        self._event_buffer: deque[dict[str, Any]] = deque(maxlen=200)

        # Stats
        self._stats = {
            "total_events": 0,
            "dispatched": 0,
            "deduped": 0,
            "rate_limited": 0,
            "dispatch_errors": 0,
        }

        # HTTP session (created lazily)
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._session

    async def dispatch(self, event: Event, prompt_template: str) -> None:
        """Process an event: dedup, rate limit, format, and dispatch."""
        self._stats["total_events"] += 1

        # Store in ring buffer regardless
        event_record = {
            "plugin_type": event.plugin_type,
            "watcher_id": event.watcher_id,
            "event_type": event.event_type,
            "summary": event.summary,
            "details": event.details,
            "timestamp": event.timestamp,
            "dispatched": False,
            "reason_skipped": None,
        }

        # Dedup check
        now = time.monotonic()
        self._cleanup_dedup(now)
        if event.dedup_key in self._dedup_cache:
            self._stats["deduped"] += 1
            event_record["reason_skipped"] = "dedup"
            self._event_buffer.append(event_record)
            logger.debug(f"Dedup: {event.dedup_key}")
            return
        self._dedup_cache[event.dedup_key] = now

        # Rate limit check
        if not self._try_consume_token():
            self._stats["rate_limited"] += 1
            event_record["reason_skipped"] = "rate_limited"
            self._event_buffer.append(event_record)
            logger.debug(f"Rate limited: {event.summary}")
            return

        # Min interval check
        if (now - self._last_dispatch) * 1000 < self.min_interval_ms:
            self._stats["rate_limited"] += 1
            event_record["reason_skipped"] = "min_interval"
            self._event_buffer.append(event_record)
            logger.debug(f"Min interval: {event.summary}")
            return

        # Format prompt
        prompt = prompt_template.format(event=event)

        # Dispatch to Velle
        try:
            session = await self._get_session()
            async with session.post(
                self.velle_endpoint,
                json={
                    "text": prompt,
                    "reason": f"expergis:{event.watcher_id}:{event.event_type}",
                },
            ) as resp:
                if resp.status == 200:
                    self._stats["dispatched"] += 1
                    self._last_dispatch = now
                    event_record["dispatched"] = True
                    logger.info(f"Dispatched: {event.summary}")
                else:
                    body = await resp.text()
                    self._stats["dispatch_errors"] += 1
                    event_record["reason_skipped"] = f"http_{resp.status}"
                    logger.warning(f"Dispatch failed ({resp.status}): {body}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self._stats["dispatch_errors"] += 1
            event_record["reason_skipped"] = f"error:{type(e).__name__}"
            logger.warning(f"Dispatch error: {e}")

        self._event_buffer.append(event_record)

        # Audit
        audit_log({
            "action": "dispatch",
            "watcher_id": event.watcher_id,
            "event_type": event.event_type,
            "summary": event.summary,
            "dispatched": event_record["dispatched"],
            "reason_skipped": event_record["reason_skipped"],
        })

    def get_recent_events(
        self,
        since: str | None = None,
        watcher_id: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return recent events from the ring buffer, optionally filtered."""
        events = list(self._event_buffer)

        if since:
            events = [e for e in events if e["timestamp"] >= since]

        if watcher_id:
            events = [e for e in events if e["watcher_id"] == watcher_id]

        return events[-limit:]

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    def _cleanup_dedup(self, now: float) -> None:
        """Remove expired dedup entries."""
        window_sec = self.dedup_window_ms / 1000.0
        expired = [k for k, t in self._dedup_cache.items() if now - t > window_sec]
        for k in expired:
            del self._dedup_cache[k]

    def _try_consume_token(self) -> bool:
        """Token bucket rate limiter. Returns True if a token was consumed."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now

        # Refill tokens based on max_events_per_minute
        refill_rate = self.max_events_per_minute / 60.0
        self._tokens = min(float(self.burst_size), self._tokens + elapsed * refill_rate)

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
