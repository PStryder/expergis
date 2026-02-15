"""Process start/stop detection via polling."""

import asyncio
import logging
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
        self.process_names = [n.lower() for n in self.config.get("process_names", [])]
        self.poll_interval_ms = self.config.get("poll_interval_ms", 5000)

        if not self.process_names:
            raise ValueError(f"process_watcher '{self.watcher_id}': no process_names configured")

        # Take initial snapshot
        self._known_pids = self._scan_processes()
        total = sum(len(v) for v in self._known_pids.values())
        logger.info(
            f"ProcessWatcher '{self.watcher_id}' initialized: "
            f"tracking {len(self.process_names)} names, {total} current PIDs"
        )

    async def watch(self, emit: EmitFn) -> None:
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

    async def teardown(self) -> None:
        self._running = False

    def _scan_processes(self) -> dict[str, set[str]]:
        """Scan running processes using tasklist (Windows)."""
        result: dict[str, set[str]] = {name: set() for name in self.process_names}
        try:
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
            )
            for line in output.strip().splitlines():
                parts = line.split('","')
                if len(parts) < 2:
                    continue
                proc_name = parts[0].strip('"').lower()
                pid = parts[1].strip('"')
                for watched_name in self.process_names:
                    if proc_name == watched_name or proc_name == watched_name + ".exe":
                        result[watched_name].add(pid)
        except (subprocess.SubprocessError, OSError) as e:
            logger.warning(f"Failed to scan processes: {e}")

        return result
