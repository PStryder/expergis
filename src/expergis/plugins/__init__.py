"""Expergis plugin discovery and loading."""

from expergis.plugins.base import Event, WatcherPlugin
from expergis.plugins.file_watcher import FileWatcherPlugin
from expergis.plugins.schedule_watcher import ScheduleWatcherPlugin
from expergis.plugins.process_watcher import ProcessWatcherPlugin

from expergis.plugins.service_watcher import ServiceWatcherPlugin

from expergis.plugins.job_event_watcher import JobEventWatcherPlugin

PLUGIN_REGISTRY: dict[str, type[WatcherPlugin]] = {
    "file_watcher": FileWatcherPlugin,
    "schedule_watcher": ScheduleWatcherPlugin,
    "process_watcher": ProcessWatcherPlugin,
    "service_watcher": ServiceWatcherPlugin,
    "job_event_watcher": JobEventWatcherPlugin,
}

__all__ = [
    "Event",
    "WatcherPlugin",
    "FileWatcherPlugin",
    "ScheduleWatcherPlugin",
    "ProcessWatcherPlugin",
    "PLUGIN_REGISTRY",
]
