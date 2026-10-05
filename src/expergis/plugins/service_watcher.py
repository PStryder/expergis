"""Bounded, read-only SemSearch status polling through the native Windows SCM."""
import asyncio
from expergis.plugins.base import Event, WatcherPlugin


class ServiceWatcherPlugin(WatcherPlugin):
    async def setup(self):
        if self.config.get('service_names') != ['SemSearch']:
            raise PermissionError('Only SemSearch is supported')
        self.interval = self.config.get('poll_interval_ms', 5000)
        if type(self.interval) is not int or not 1000 <= self.interval <= 3600000:
            raise ValueError('Service interval must be at least one second')
        self.previous = self.scan()

    def scan(self):
        from expergis.windows_observers import service_status
        return service_status('SemSearch')

    async def watch(self, emit):
        while True:
            await asyncio.sleep(self.interval / 1000)
            # Failure stops the watcher; access errors are never reported as service failure.
            current = self.scan()
            if current != self.previous:
                await emit(Event(plugin_type='service_watcher', watcher_id=self.watcher_id,
                    event_type='service_state_changed', summary='SemSearch: ' + current['state'],
                    details={**current, 'previous_state': self.previous['state']}))
            self.previous = current

    async def teardown(self):
        pass
