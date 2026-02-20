"""Tests for expergis.server — MCP tool handlers."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from expergis import server as srv
from expergis.plugins.base import WatcherPlugin, Event


class FakePlugin(WatcherPlugin):
    """Minimal plugin for testing."""
    async def setup(self):
        pass

    async def watch(self, emit):
        # Just sit idle
        import asyncio
        try:
            while True:
                await asyncio.sleep(100)
        except asyncio.CancelledError:
            pass

    async def teardown(self):
        pass


def _parse(result):
    return json.loads(result[0].text)


@pytest.fixture(autouse=True)
def clean_watchers():
    """Reset watchers between tests."""
    srv._watchers.clear()
    yield
    # Cancel any leftover tasks
    import asyncio
    for entry in list(srv._watchers.values()):
        if entry.task and not entry.task.done():
            entry.task.cancel()
    srv._watchers.clear()


class TestHandleWatch:
    @pytest.mark.asyncio
    async def test_watch_registers_watcher(self):
        with patch.dict(srv.PLUGIN_REGISTRY, {"fake": FakePlugin}):
            result = await srv._handle_watch({
                "watcher_id": "w1",
                "plugin_type": "fake",
                "config": {},
            })
        data = _parse(result)
        assert data["status"] == "watching"
        assert "w1" in srv._watchers

    @pytest.mark.asyncio
    async def test_watch_duplicate_error(self):
        with patch.dict(srv.PLUGIN_REGISTRY, {"fake": FakePlugin}):
            await srv._handle_watch({
                "watcher_id": "w1", "plugin_type": "fake", "config": {}
            })
            result = await srv._handle_watch({
                "watcher_id": "w1", "plugin_type": "fake", "config": {}
            })
        data = _parse(result)
        assert data["status"] == "error"
        assert "already exists" in data["error"]

    @pytest.mark.asyncio
    async def test_watch_unknown_plugin_error(self):
        result = await srv._handle_watch({
            "watcher_id": "w1",
            "plugin_type": "bogus_plugin",
            "config": {},
        })
        data = _parse(result)
        assert data["status"] == "error"
        assert "Unknown plugin type" in data["error"]


class TestHandleUnwatch:
    @pytest.mark.asyncio
    async def test_unwatch_removes_watcher(self):
        with patch.dict(srv.PLUGIN_REGISTRY, {"fake": FakePlugin}):
            await srv._handle_watch({
                "watcher_id": "w1", "plugin_type": "fake", "config": {}
            })
            assert "w1" in srv._watchers
            result = await srv._handle_unwatch({"watcher_id": "w1"})
        data = _parse(result)
        assert data["status"] == "unwatched"
        assert "w1" not in srv._watchers


class TestHandleList:
    @pytest.mark.asyncio
    async def test_list_returns_metadata(self):
        with patch.dict(srv.PLUGIN_REGISTRY, {"fake": FakePlugin}):
            await srv._handle_watch({
                "watcher_id": "w1", "plugin_type": "fake", "config": {}
            })
            result = await srv._handle_list({})
        data = _parse(result)
        assert data["total"] == 1
        assert data["watchers"][0]["watcher_id"] == "w1"
        assert "dispatcher_stats" in data


class TestHandleCheck:
    @pytest.mark.asyncio
    async def test_check_returns_events(self):
        result = await srv._handle_check({"limit": 10})
        data = _parse(result)
        assert "events" in data
        assert "count" in data
        assert "dispatcher_stats" in data
