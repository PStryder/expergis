"""Expergis plugin discovery and loading."""

from expergis.plugins.base import Event, WatcherPlugin
from expergis.plugins.file_watcher import FileWatcherPlugin
from expergis.plugins.schedule_watcher import ScheduleWatcherPlugin
from expergis.plugins.process_watcher import ProcessWatcherPlugin

PLUGIN_REGISTRY: dict[str, type[WatcherPlugin]] = {
    "file_watcher": FileWatcherPlugin,
    "schedule_watcher": ScheduleWatcherPlugin,
    "process_watcher": ProcessWatcherPlugin,
}

__all__ = [
    "Event",
    "WatcherPlugin",
    "FileWatcherPlugin",
    "ScheduleWatcherPlugin",
    "ProcessWatcherPlugin",
    "PLUGIN_REGISTRY",
]
