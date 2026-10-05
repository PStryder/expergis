"""File/directory change detection via polling."""

import asyncio
import fnmatch
import logging
import os
from pathlib import Path
from typing import Any

from expergis.plugins.base import EmitFn, Event, WatcherPlugin

logger = logging.getLogger("expergis.file_watcher")


class FileWatcherPlugin(WatcherPlugin):
    """Watches files/directories for changes by polling modification times."""

    def __init__(self, watcher_id: str, config: dict[str, Any]):
        super().__init__(watcher_id, config)
        self.paths: list[Path] = []
        self.patterns: list[str] = []
        self.events: set[str] = set()
        self.debounce_ms: int = 1000
        self.poll_interval_ms: int = 2000
        self._snapshot: dict[str, float] = {}  # path -> mtime
        self._running = False
        self._signals = None

    async def setup(self) -> None:
        raw_paths = self.config.get("paths", [])
        if not isinstance(raw_paths, list) or any(not isinstance(p, str) or not p for p in raw_paths):
            raise ValueError("paths must be a list of nonempty strings")
        self.paths = [Path(p) for p in raw_paths]
        self.patterns = self.config.get("patterns", ["*"])
        raw_events = self.config.get("events", ["modified", "created", "deleted"])
        if (not isinstance(self.patterns, list) or not 1 <= len(self.patterns) <= 32
                or any(not isinstance(p, str) or len(p) > 256 for p in self.patterns)
                or not isinstance(raw_events, list) or any(e not in ("modified", "created", "deleted") for e in raw_events)):
            raise ValueError("Invalid patterns or event types")
        self.events = set(raw_events)
        self.debounce_ms = self.config.get("debounce_ms", 1000)
        self.poll_interval_ms = self.config.get("poll_interval_ms", 2000)

        if not self.paths:
            raise ValueError(f"file_watcher '{self.watcher_id}': no paths configured")

        backend = self.config.get("backend", "polling")
        if backend not in ("polling", "native", "auto"):
            raise ValueError("Unknown file watcher backend")
        if (type(self.poll_interval_ms) is not int or type(self.debounce_ms) is not int
                or not 50 <= self.poll_interval_ms <= 3600000 or not 0 <= self.debounce_ms <= 60000):
            raise ValueError("Invalid watcher timing")
        if len(self.paths) > 32:
            raise ValueError("At most 32 paths per watcher")
        if backend == "native" or (backend == "auto" and os.name == "nt"):
            from expergis.plugins.native_files import DirectorySignals
            self._signals = DirectorySignals(self.paths)
        # Take initial snapshot
        try:
            self._snapshot = self._scan()
        except BaseException:
            await self.teardown()
            raise
        logger.info(
            f"FileWatcher '{self.watcher_id}' initialized: "
            f"{len(self._snapshot)} files across {len(self.paths)} paths"
        )

    async def watch(self, emit: EmitFn) -> None:
        self._running = True
        while self._running:
            if self._signals:
                await self._signals.wait(30)  # Periodic reconciliation after lost/coalesced signals.
                if self.debounce_ms:
                    await asyncio.sleep(self.debounce_ms / 1000.0)
            else:
                await asyncio.sleep(self.poll_interval_ms / 1000.0)
            if not self._running:
                break

            current = self._scan()
            old_keys = set(self._snapshot.keys())
            new_keys = set(current.keys())

            # Created files
            if "created" in self.events:
                for path in new_keys - old_keys:
                    await emit(Event(
                        plugin_type="file_watcher",
                        watcher_id=self.watcher_id,
                        event_type="created",
                        summary=path,
                        details={"mtime": current[path]},
                        dedup_key=f"{self.watcher_id}:created:{path}",
                    ))

            # Deleted files
            if "deleted" in self.events:
                for path in old_keys - new_keys:
                    await emit(Event(
                        plugin_type="file_watcher",
                        watcher_id=self.watcher_id,
                        event_type="deleted",
                        summary=path,
                        details={},
                        dedup_key=f"{self.watcher_id}:deleted:{path}",
                    ))

            # Modified files
            if "modified" in self.events:
                for path in old_keys & new_keys:
                    if current[path] != self._snapshot[path]:
                        await emit(Event(
                            plugin_type="file_watcher",
                            watcher_id=self.watcher_id,
                            event_type="modified",
                            summary=path,
                            details={
                                "old_mtime": self._snapshot[path],
                                "new_mtime": current[path],
                            },
                            dedup_key=f"{self.watcher_id}:modified:{path}",
                        ))

            self._snapshot = current

    async def teardown(self) -> None:
        self._running = False
        if self._signals:
            await self._signals.close()
            self._signals = None

    def _scan(self) -> dict[str, float]:
        """Scan configured paths and return {filepath: mtime} for matching files."""
        result: dict[str, float] = {}
        scanned = 0
        for base in self.paths:
            if not base.exists():
                continue
            if base.is_file():
                if self._matches(base.name):
                    try:
                        result[str(base)] = os.path.getmtime(base)
                    except OSError:
                        pass
            else:
                try:
                    for entry in os.scandir(base):
                        scanned += 1
                        if scanned > 10000:
                            raise ValueError("Watcher exceeds 10000 directory entries")
                        if entry.is_file() and self._matches(entry.name):
                            try:
                                result[entry.path] = entry.stat().st_mtime
                            except OSError:
                                pass
                except OSError:
                    pass
        return result

    def _matches(self, filename: str) -> bool:
        """Check if filename matches any of the configured patterns."""
        return any(fnmatch.fnmatch(filename, p) for p in self.patterns)
