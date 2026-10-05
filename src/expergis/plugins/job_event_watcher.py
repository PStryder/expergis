"""Separate explicitly permitted content consumer; ordinary file watchers stay metadata-only."""
import asyncio
import os

from expergis.plugins.base import WatcherPlugin
from expergis.watch_scope import checked_local_path
from expergis.inbox_files import read_event_file
from expergis.job_event_contract import parse_event


class JobEventWatcherPlugin(WatcherPlugin):
    def bind(self, store, owner, authorize):
        self.store, self.owner, self.authorize = store, owner, authorize

    async def setup(self):
        if not hasattr(self,'store'):
            raise ValueError('Explicit authenticated content consumer required')
        self.inbox = checked_local_path(self.config['inbox'])
        if not self.inbox.is_dir():
            raise ValueError('Inbox must already exist')
        from expergis.job_inbox import JobInbox
        self.ledger = JobInbox(self.store,self.owner,self.watcher_id)
        self.cursor = 0
        self.invalid = self.transient = 0

    def scan(self):
        checked_local_path(str(self.inbox))
        names=[]
        with os.scandir(self.inbox) as entries:
            for count, entry in enumerate(entries,1):
                if count > 4096:
                    raise ValueError('Inbox exceeds flat entry cap')
                if entry.name.endswith('.json'):
                    names.append(entry.name)
        names.sort()
        if not names:
            return
        self.cursor %= len(names)
        selected=names[self.cursor:self.cursor+64]
        # Round-robin batches ensure a malformed early filename cannot starve later events.
        self.cursor = (self.cursor+len(selected)) % len(names)
        for name in selected:
            if not self.authorize(self.owner,self.watcher_id):
                break
            try:
                body=read_event_file(self.inbox,name)
                data=parse_event(body,name)
            except (ValueError,TypeError,KeyError):
                self.invalid=min(2**31-1,self.invalid+1)
                continue
            except OSError:
                self.transient=min(2**31-1,self.transient+1)
                continue
            self.ledger.accept(data,self.config.get('context',{}))

    async def watch(self, emit):
        # Direct atomic ledger/queue handoff; the generic transient event ring is not an intake log.
        while True:
            if self.authorize(self.owner,self.watcher_id):
                self.scan()
                try:
                    self.ledger.flush(self.authorize)
                except (ValueError,OSError):
                    self.transient=min(2**31-1,self.transient+1)
            await asyncio.sleep(2)

    @property
    def source_stats(self):
        if not hasattr(self,'ledger'):
            return {}
        return {**self.ledger.stats(),'invalid_reads':self.invalid,'transient_reads':self.transient}

    async def teardown(self):
        pass
