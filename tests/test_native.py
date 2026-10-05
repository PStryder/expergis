import asyncio
import contextlib
import os

import pytest

from expergis.plugins.file_watcher import FileWatcherPlugin


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "nt", reason="Windows native notifications")
async def test_native_directory_event_and_cleanup(tmp_path):
    watcher = FileWatcherPlugin("test", {"paths": [str(tmp_path)], "backend": "native", "debounce_ms": 0})
    await watcher.setup()
    observed = asyncio.Queue()
    task = asyncio.create_task(watcher.watch(observed.put))
    try:
        await asyncio.sleep(0.05)
        (tmp_path / "harmless.txt").write_text("synthetic")
        event = await asyncio.wait_for(observed.get(), 5)
        assert event.event_type == "created"
        assert event.plugin_type == "file_watcher" and event.event_id.startswith("evt_")
        assert "synthetic" not in event.details.values()
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await watcher.teardown()
    assert watcher._signals is None


@pytest.mark.asyncio
async def test_polling_default_unchanged(tmp_path):
    watcher = FileWatcherPlugin("test", {"paths": [str(tmp_path)]})
    await watcher.setup()
    assert watcher._signals is None
    await watcher.teardown()
