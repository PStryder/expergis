"""Tests for expergis.dispatcher — Dispatcher rate limiting, dedup, ring buffer."""

import time
from unittest.mock import AsyncMock, patch

import pytest

from expergis.dispatcher import Dispatcher
from expergis.plugins.base import Event


def _make_config(**overrides):
    config = {
        "velle_endpoint": "http://localhost:7839/velle_prompt",
        "rate_limit": {
            "min_interval_ms": 0,  # disable for most tests
            "max_events_per_minute": 60,  # generous for tests
            "burst_size": 10,
        },
        "dedup_window_ms": 5000,
    }
    config.update(overrides)
    return config


def _make_event(watcher_id="w1", event_type="modified", summary="file.py", dedup_key=""):
    return Event(
        plugin_type="file_watcher",
        watcher_id=watcher_id,
        event_type=event_type,
        summary=summary,
        dedup_key=dedup_key,
    )


TEMPLATE = "Event: {event.summary}"


class TestDedup:
    @pytest.mark.asyncio
    async def test_dedup_blocks_duplicate(self):
        d = Dispatcher(_make_config())
        # Mock HTTP so we don't actually call Velle
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        event = _make_event()
        await d.dispatch(event, TEMPLATE)
        await d.dispatch(event, TEMPLATE)  # same dedup_key

        assert d.stats["deduped"] == 1
        assert d.stats["dispatched"] == 1
        await d.close()

    @pytest.mark.asyncio
    async def test_dedup_allows_after_window(self):
        d = Dispatcher(_make_config(dedup_window_ms=100))
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        event = _make_event()
        await d.dispatch(event, TEMPLATE)

        # Advance monotonic clock past dedup window
        original_monotonic = time.monotonic
        offset = 0.2  # 200ms > 100ms window
        with patch("time.monotonic", side_effect=lambda: original_monotonic() + offset):
            await d.dispatch(event, TEMPLATE)

        assert d.stats["deduped"] == 0
        assert d.stats["dispatched"] == 2
        await d.close()


class TestRateLimit:
    @pytest.mark.asyncio
    async def test_rate_limit_token_bucket(self):
        d = Dispatcher(_make_config(
            rate_limit={"min_interval_ms": 0, "max_events_per_minute": 60, "burst_size": 2}
        ))
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        # Freeze time so token refill doesn't happen between dispatches
        frozen_time = time.monotonic()
        with patch("time.monotonic", return_value=frozen_time):
            d._last_refill = frozen_time
            d._tokens = 2.0  # Reset to exactly burst_size
            for i in range(3):
                e = _make_event(summary=f"file{i}.py")
                await d.dispatch(e, TEMPLATE)

        # 2 should dispatch (burst_size), 1 should be rate limited
        assert d.stats["dispatched"] == 2
        assert d.stats["rate_limited"] == 1
        await d.close()

    @pytest.mark.asyncio
    async def test_min_interval_blocks(self):
        d = Dispatcher(_make_config(
            rate_limit={"min_interval_ms": 5000, "max_events_per_minute": 600, "burst_size": 100}
        ))
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        e1 = _make_event(summary="a.py")
        e2 = _make_event(summary="b.py")
        await d.dispatch(e1, TEMPLATE)
        await d.dispatch(e2, TEMPLATE)

        assert d.stats["dispatched"] == 1
        assert d.stats["rate_limited"] == 1
        await d.close()


class TestRingBuffer:
    @pytest.mark.asyncio
    async def test_ring_buffer_stores_all(self):
        d = Dispatcher(_make_config())
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        for i in range(5):
            await d.dispatch(_make_event(summary=f"f{i}.py"), TEMPLATE)

        events = d.get_recent_events()
        assert len(events) == 5
        await d.close()

    @pytest.mark.asyncio
    async def test_ring_buffer_max_size(self):
        d = Dispatcher(_make_config())
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        for i in range(250):
            await d.dispatch(_make_event(summary=f"f{i}.py"), TEMPLATE)

        events = d.get_recent_events(limit=300)
        assert len(events) <= 200  # maxlen=200
        await d.close()

    @pytest.mark.asyncio
    async def test_get_recent_events_filtering(self):
        d = Dispatcher(_make_config())
        d._session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)
        d._session.post = AsyncMock(return_value=mock_resp)

        await d.dispatch(_make_event(watcher_id="w1", summary="a.py"), TEMPLATE)
        await d.dispatch(_make_event(watcher_id="w2", summary="b.py"), TEMPLATE)
        await d.dispatch(_make_event(watcher_id="w1", summary="c.py"), TEMPLATE)

        filtered = d.get_recent_events(watcher_id="w1")
        assert len(filtered) == 2
        assert all(e["watcher_id"] == "w1" for e in filtered)
        await d.close()
