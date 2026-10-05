"""Process start/stop detection via polling."""

import asyncio
import logging
import os
import csv
from pathlib import Path
import subprocess
from typing import Any

from expergis.plugins.base import EmitFn, Event, WatcherPlugin

logger = logging.getLogger("expergis.process_watcher")


class ProcessWatcherPlugin(WatcherPlugin):
    """Watches for process start/stop by polling the process list."""

    def __init__(self, watcher_id: str, config: dict[str, Any]):
        super().__init__(watcher_id, config)
        self.process_names: list[str] = []
        self.poll_interval_ms: int = 5000
        self._known_pids: dict[str, set[str]] = {}  # name -> set of PIDs
        self._running = False

    async def setup(self) -> None:
        if self.config.get("_monitoring_v2"):
            self.poll_interval_ms = self.config.get("poll_interval_ms", 5000)
            self._selected = self._scan_selected()
            return
        names = self.config.get("process_names", [])
        if (not isinstance(names, list) or len(names) > 32
                or any(not isinstance(n, str) or not n or len(n) > 256 for n in names)):
            raise ValueError("Invalid process names")
        self.process_names = [n.lower() for n in names]
        self.poll_interval_ms = self.config.get("poll_interval_ms", 5000)

        if not self.process_names:
            raise ValueError(f"process_watcher '{self.watcher_id}': no process_names configured")

        if type(self.poll_interval_ms) is not int or not 50 <= self.poll_interval_ms <= 3600000:
            raise ValueError("Invalid process polling interval")

        # Take initial snapshot
        self._known_pids = self._scan_processes()
        total = sum(len(v) for v in self._known_pids.values())
        logger.info(
            f"ProcessWatcher '{self.watcher_id}' initialized: "
            f"tracking {len(self.process_names)} names, {total} current PIDs"
        )

    async def watch(self, emit: EmitFn) -> None:
        if self.config.get("_monitoring_v2"):
            await self._watch_selected(emit)
            return
        self._running = True
        while self._running:
            await asyncio.sleep(self.poll_interval_ms / 1000.0)
            if not self._running:
                break

            current = self._scan_processes()

            for name in self.process_names:
                old_pids = self._known_pids.get(name, set())
                new_pids = current.get(name, set())

                # Started processes
                for pid in new_pids - old_pids:
                    await emit(Event(
                        plugin_type="process_watcher",
                        watcher_id=self.watcher_id,
                        event_type="process_started",
                        summary=f"Process started: {name} (PID {pid})",
                        details={"process_name": name, "pid": pid},
                        dedup_key=f"{self.watcher_id}:started:{name}:{pid}",
                    ))

                # Stopped processes
                for pid in old_pids - new_pids:
                    await emit(Event(
                        plugin_type="process_watcher",
                        watcher_id=self.watcher_id,
                        event_type="process_stopped",
                        summary=f"Process stopped: {name} (PID {pid})",
                        details={"process_name": name, "pid": pid},
                        dedup_key=f"{self.watcher_id}:stopped:{name}:{pid}",
                    ))

            self._known_pids = current

    def _scan_selected(self):
        from expergis.windows_observers import selected_processes
        return selected_processes(self.config.get("process_names", []), self.config.get("processes", []))

    async def _watch_selected(self, emit):
        self._running = True
        while self._running:
            await asyncio.sleep(self.poll_interval_ms / 1000)
            current = self._scan_selected()
            for event_type, keys, snapshot in (
                ("process_started", current.keys() - self._selected.keys(), current),
                ("process_stopped", self._selected.keys() - current.keys(), self._selected)):
                for key in sorted(keys):
                    item = snapshot[key]
                    await emit(Event(plugin_type="process_watcher", watcher_id=self.watcher_id,
                        event_type=event_type, summary=item["process_name"] + ": " + event_type,
                        details=item, dedup_key=f"{self.watcher_id}:{event_type}:{key}"))
            self._selected = current

    async def teardown(self) -> None:
        self._running = False

    def _scan_processes(self) -> dict[str, set[str]]:
        """Scan running processes using tasklist (Windows)."""
        result: dict[str, set[str]] = {name: set() for name in self.process_names}
        try:
            output = subprocess.check_output(
                (["tasklist", "/FO", "CSV", "/NH"] if os.name == "nt" else ["ps", "-A", "-o", "pid=,comm="]),
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            for line in output.strip().splitlines():
                if os.name == "nt":
                    parts = next(csv.reader([line]))
                    if len(parts) < 2:
                        continue
                    proc_name, pid = parts[0].lower(), parts[1]
                else:
                    parts = line.strip().split(None, 1)
                    if len(parts) < 2:
                        continue
                    pid, proc_name = parts[0], Path(parts[1]).name.lower()
                for watched_name in self.process_names:
                    if proc_name == watched_name or proc_name == watched_name + ".exe":
                        result[watched_name].add(pid)
        except (subprocess.SubprocessError, OSError) as e:
            logger.warning("Process scan unavailable: %s", type(e).__name__)
            return {name: set(pids) for name, pids in self._known_pids.items()}

        return result
