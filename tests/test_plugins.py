"""Tests for Expergis plugins — file_watcher, schedule_watcher, process_watcher."""

import asyncio
import os
import tempfile
import time
from unittest.mock import patch, MagicMock

import pytest

from expergis.plugins.file_watcher import FileWatcherPlugin
from expergis.plugins.schedule_watcher import ScheduleWatcherPlugin
from expergis.plugins.process_watcher import ProcessWatcherPlugin


# ---------------------------------------------------------------------------
# FileWatcherPlugin
# ---------------------------------------------------------------------------

class TestFileWatcher:
    @pytest.mark.asyncio
    async def test_setup_no_paths_error(self):
        plugin = FileWatcherPlugin("fw1", {"paths": []})
        with pytest.raises(ValueError, match="no paths configured"):
            await plugin.setup()

    def test_matches_pattern(self):
        plugin = FileWatcherPlugin("fw1", {})
        plugin.patterns = ["*.py", "*.ts"]
        assert plugin._matches("foo.py") is True
        assert plugin._matches("bar.ts") is True
        assert plugin._matches("baz.rs") is False

    @pytest.mark.asyncio
    async def test_scan_finds_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            open(os.path.join(tmpdir, "test.py"), "w").close()
            open(os.path.join(tmpdir, "test.txt"), "w").close()

            plugin = FileWatcherPlugin("fw1", {
                "paths": [tmpdir],
                "patterns": ["*.py"],
            })
            await plugin.setup()

            scan = plugin._scan()
            paths = list(scan.keys())
            assert len(paths) == 1
            assert paths[0].endswith("test.py")

    @pytest.mark.asyncio
    async def test_detects_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "watch.py")
            with open(filepath, "w") as f:
                f.write("original")

            plugin = FileWatcherPlugin("fw1", {
                "paths": [tmpdir],
                "patterns": ["*.py"],
                "poll_interval_ms": 50,
            })
            await plugin.setup()

            emitted = []

            async def mock_emit(event):
                emitted.append(event)
                plugin._running = False  # stop after first detection

            # Modify file after a brief delay
            await asyncio.sleep(0.05)
            time.sleep(0.01)  # ensure mtime changes
            with open(filepath, "w") as f:
                f.write("modified")

            # Run one watch cycle
            task = asyncio.create_task(plugin.watch(mock_emit))
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except asyncio.TimeoutError:
                plugin._running = False

            assert len(emitted) >= 1
            assert emitted[0].event_type == "modified"


# ---------------------------------------------------------------------------
# ScheduleWatcherPlugin
# ---------------------------------------------------------------------------

class TestScheduleWatcher:
    @pytest.mark.asyncio
    async def test_setup_invalid_cron(self):
        plugin = ScheduleWatcherPlugin("sw1", {"cron": "not a cron"})
        with pytest.raises(ValueError, match="invalid cron"):
            await plugin.setup()

    @pytest.mark.asyncio
    async def test_setup_valid(self):
        plugin = ScheduleWatcherPlugin("sw1", {"cron": "*/5 * * * *"})
        await plugin.setup()
        assert plugin._cron is not None
        assert plugin.cron_expr == "*/5 * * * *"


# ---------------------------------------------------------------------------
# ProcessWatcherPlugin
# ---------------------------------------------------------------------------

class TestProcessWatcher:
    @pytest.mark.asyncio
    async def test_setup_no_names_error(self):
        plugin = ProcessWatcherPlugin("pw1", {"process_names": []})
        with pytest.raises(ValueError, match="no process_names configured"):
            await plugin.setup()

    def test_scan_parsing(self):
        """Mock tasklist output and verify PID extraction."""
        mock_output = (
            '"notepad.exe","1234","Console","1","10,000 K"\n'
            '"python.exe","5678","Console","1","50,000 K"\n'
            '"notepad.exe","9012","Console","1","10,000 K"\n'
        )
        plugin = ProcessWatcherPlugin("pw1", {"process_names": ["notepad", "python"]})
        plugin.process_names = ["notepad", "python"]

        with patch("subprocess.check_output", return_value=mock_output):
            result = plugin._scan_processes()

        assert result["notepad"] == {"1234", "9012"}
        assert result["python"] == {"5678"}
