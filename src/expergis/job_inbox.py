"""Durable source-ID ledger and atomic handoff into the existing signed delivery queue."""
import hashlib

from expergis.events_security import json_bytes
from expergis.plugins.base import Event
from expergis.job_event_contract import uuid_text


class JobInbox:
    def __init__(self, store, owner, watcher, *, limit=10000):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError('Invalid ledger bound')
        self.store, self.owner, self.watcher, self.limit = store, owner, watcher, limit
        store.db.execute('''CREATE TABLE IF NOT EXISTS job_inbox (
            owner TEXT NOT NULL, id TEXT NOT NULL, watcher TEXT NOT NULL,
            fingerprint TEXT NOT NULL, instance TEXT NOT NULL, run TEXT NOT NULL, job TEXT NOT NULL,
            sequence INTEGER NOT NULL, state TEXT NOT NULL, conflict INTEGER NOT NULL DEFAULT 0,
            private BLOB NOT NULL, PRIMARY KEY(owner,id))''')
        store.db.execute('CREATE INDEX IF NOT EXISTS job_inbox_runs ON job_inbox(owner,instance,run,sequence)')
        store.db.commit()

    def accept(self, data, context):
        body = json_bytes(data,16384)
        fingerprint = hashlib.sha256(body).hexdigest()
        event_id = uuid_text(data['event_id'])
        instance, run = uuid_text(data['instance_id']), uuid_text(data['run_id'])
        job = uuid_text(data['job_id'])
        db = self.store.db
        with db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT fingerprint FROM job_inbox WHERE owner=? AND id=?',
                (self.owner,event_id)).fetchone()
            if old:
                if old['fingerprint'] != fingerprint:
                    db.execute('UPDATE job_inbox SET conflict=1 WHERE owner=? AND id=?',(self.owner,event_id))
                    return 'conflict'
                return 'duplicate'
            if db.execute('SELECT count(*) FROM job_inbox').fetchone()[0] >= self.limit:
                raise ValueError('Inbox ledger capacity reached')
            previous = db.execute('SELECT max(sequence) FROM job_inbox WHERE owner=? AND instance=? AND run=? AND state!=?',
                (self.owner,instance,run,'conflict')).fetchone()[0]
            collision = db.execute('SELECT id FROM job_inbox WHERE owner=? AND instance=? AND run=? AND sequence=?',
                (self.owner,instance,run,data['sequence'])).fetchone()
            collision = collision or db.execute('SELECT id FROM job_inbox WHERE owner=? AND instance=? AND run=? AND job!=?',
                (self.owner,instance,run,job)).fetchone()
            relation = 'first' if previous is None else ('advance' if data['sequence'] > previous else 'historical')
            # The source envelope remains data; no reference is opened and no instruction is executed.
            stable = 'evt_arbitrium_' + hashlib.sha256(json_bytes([self.owner,self.watcher,event_id])).hexdigest()
            payload = dict(plugin_type='job_event_watcher',watcher_id=self.watcher,
                event_type='job_status_observed',summary='Arbitrium job status: '+data['status'],
                details={'job_event':data,'sequence_relation':relation},
                timestamp=data['observed_at'],event_id=stable,context=context)
            db.execute('INSERT INTO job_inbox(owner,id,watcher,fingerprint,instance,run,job,sequence,state,private) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (self.owner,event_id,self.watcher,fingerprint,instance,run,job,data['sequence'],
                 'conflict' if collision else 'pending',self.store.pack(payload)))
            return 'conflict' if collision else 'accepted'

    def flush(self, authorize, *, batch=32):
        if not authorize(self.owner,self.watcher):
            return 0
        self.store.prune()
        db = self.store.db
        rows = db.execute('SELECT id,private FROM job_inbox WHERE owner=? AND watcher=? AND state=? AND conflict=0 ORDER BY rowid LIMIT ?',
            (self.owner,self.watcher,'pending',min(32,max(1,batch)))).fetchall()
        count = 0
        for row in rows:
            if not authorize(self.owner,self.watcher):
                break
            event = Event(**self.store.unpack(row['private']))
            # Queue insertion and ledger advancement commit together. Crash => both or neither.
            with db:
                db.execute('BEGIN IMMEDIATE')
                if not db.execute('SELECT 1 FROM subscriptions WHERE owner=? AND watcher=? AND expires>?',
                        (self.owner,self.watcher,self.store.clock())).fetchone():
                    break
                self.store.enqueue(self.owner,event,event.context,_transaction=True,_require_subscription=True)
                db.execute('UPDATE job_inbox SET state=? WHERE owner=? AND id=?',('queued',self.owner,row['id']))
            count += 1
        return count

    def stats(self):
        result = {'pending':0,'queued':0,'conflict':0}
        for row in self.store.db.execute('SELECT state,conflict,count(*) AS n FROM job_inbox WHERE owner=? AND watcher=? GROUP BY state,conflict',
                (self.owner,self.watcher)):
            result['conflict' if row['conflict'] else row['state']] += row['n']
        return result
