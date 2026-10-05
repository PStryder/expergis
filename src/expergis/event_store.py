"""Bounded, encrypted SQLite outbox. Calls are short and confined to one thread."""
import hashlib
import json
import contextlib
import sqlite3
import re
import time
import uuid
from datetime import datetime, timezone

from expergis.events_security import json_bytes
from expergis.protected_store import DPAPIProtector


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


class EventStore:
    def __init__(self, path, *, protector=None, clock=time.time, max_events=1000,
                 max_subscriptions=100, max_jobs=10000, retention=86400):
        if not (1 <= max_events <= 10000 and 1 <= max_subscriptions <= 1000
                and 1 <= max_jobs <= 100000 and 60 <= retention <= 604800):
            raise ValueError("Invalid store limits")
        self.protector = protector or DPAPIProtector()
        self.clock = clock
        self.max_events, self.max_subscriptions, self.max_jobs = max_events, max_subscriptions, max_jobs
        self.retention = retention
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA foreign_keys=ON;
            PRAGMA secure_delete=ON;
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, watcher TEXT NOT NULL,
                expires REAL NOT NULL, generation TEXT NOT NULL, private BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, watcher TEXT NOT NULL,
                created REAL NOT NULL, private BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
                event TEXT REFERENCES events(id) ON DELETE CASCADE,
                subscription TEXT REFERENCES subscriptions(id) ON DELETE CASCADE,
                state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                due REAL NOT NULL, lease TEXT, receipt INTEGER,
                PRIMARY KEY(event, subscription));
            CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state, due);
            CREATE TABLE IF NOT EXISTS watchers (
                owner TEXT NOT NULL, id TEXT NOT NULL, private BLOB NOT NULL,
                PRIMARY KEY(owner,id));
        """)

    def pack(self, value):
        return self.protector.seal(json_bytes(value))

    def unpack(self, value):
        return json.loads(self.protector.open(value))

    def prune(self):
        now = self.clock()
        with self.db:
            self.db.execute("DELETE FROM subscriptions WHERE expires<=?", (now,))
            self.db.execute("DELETE FROM events WHERE created<=?", (now - self.retention,))

    def subscribe(self, sid, owner, watcher, delivery, expires):
        self.prune()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            old = self.db.execute("SELECT owner,private FROM subscriptions WHERE id=?", (sid,)).fetchone()
            if old and old["owner"] != owner:
                raise PermissionError("Subscription owner mismatch")
            if not old and self.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0] >= self.max_subscriptions:
                raise ValueError("Subscription capacity reached")
            delivery = dict(delivery)
            if old:
                previous = self.unpack(old["private"])
                if previous["secret"] != delivery["secret"]:
                    delivery.update(previous_secret=previous["secret"], previous_until=self.clock() + 60)
                elif previous.get("previous_until", 0) > self.clock():
                    delivery.update(previous_secret=previous["previous_secret"], previous_until=previous["previous_until"])
            private = self.pack(delivery)
            self.db.execute("""INSERT INTO subscriptions VALUES (?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET expires=excluded.expires,
                generation=excluded.generation, private=excluded.private""",
                (sid, owner, watcher, expires, uuid.uuid4().hex, private))

    def unsubscribe(self, sid, owner):
        with self.db:
            # Do not disclose whether someone else's ID exists.
            self.db.execute("DELETE FROM subscriptions WHERE id=? AND owner=?", (sid, owner))

    def enqueue(self, owner, event, context, *, _transaction=False, _require_subscription=False):
        if _transaction:
            if not self.db.in_transaction:
                raise RuntimeError("Caller-owned transaction required")
        else:
            self.prune()
        if not isinstance(owner, str) or not owner or len(owner) > 256:
            raise ValueError("Invalid owner")
        if not isinstance(context, dict):
            raise ValueError("Context must be a JSON object")
        json_bytes(context, 16384)
        stamp = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("Event timestamp requires timezone")
        if (not isinstance(event.event_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", event.event_id)):
            raise ValueError("Invalid event ID")
        if (any(not isinstance(value, str) or not value or len(value) > 128
                for value in (event.watcher_id, event.plugin_type, event.event_type))
                or not isinstance(event.summary, str) or not isinstance(event.details, dict)):
            raise ValueError("Invalid observed event")
        payload = {"eventId": event.event_id, "name": "expergis.observed", "timestamp": event.timestamp,
                   "data": {"watcher_id": event.watcher_id, "plugin_type": event.plugin_type,
                            "event_type": event.event_type, "observed": {"summary": event.summary,
                            "details": event.details}, "context": context}, "cursor": None}
        private = self.pack(payload)
        with (contextlib.nullcontext() if _transaction else self.db):
            if not _transaction:
                self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT owner,private FROM events WHERE id=?", (event.event_id,)).fetchone()
            if existing:
                if existing["owner"] != owner or self.unpack(existing["private"]) != payload:
                    raise ValueError("Event ID conflict")
                return False
            subs = self.db.execute("SELECT id FROM subscriptions WHERE owner=? AND watcher=? AND expires>?",
                                   (owner, event.watcher_id, self.clock())).fetchall()
            if _require_subscription and not subs:
                raise ValueError("Active subscription required for inbox handoff")
            if self.db.execute("SELECT count(*) FROM events").fetchone()[0] >= self.max_events:
                raise ValueError("Event capacity reached")
            if self.db.execute("SELECT count(*) FROM jobs").fetchone()[0] + len(subs) > self.max_jobs:
                raise ValueError("Delivery capacity reached")
            self.db.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                            (event.event_id, owner, event.watcher_id, self.clock(), private))
            self.db.executemany("INSERT INTO jobs(event,subscription,state,due) VALUES (?,?,'pending',?)",
                               [(event.event_id, row["id"], self.clock()) for row in subs])
        return True

    def claim(self):
        self.prune()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("""SELECT j.*, s.owner,s.watcher,s.expires,s.generation,
                s.private AS delivery,e.private AS payload FROM jobs j
                JOIN subscriptions s ON s.id=j.subscription JOIN events e ON e.id=j.event
                WHERE j.state IN ('pending','sending') AND j.due<=? AND s.expires>?
                ORDER BY j.due,e.created LIMIT 1""", (self.clock(), self.clock())).fetchone()
            if row is None:
                return None
            item = dict(row)
            item["lease"] = uuid.uuid4().hex
            item["attempts"] += 1
            self.db.execute("UPDATE jobs SET state='sending',lease=?,attempts=?,due=? WHERE event=? AND subscription=?",
                            (item["lease"], item["attempts"], self.clock() + 30, item["event"], item["subscription"]))
        item["delivery"] = self.unpack(item["delivery"])
        item["payload"] = self.unpack(item["payload"])
        return item

    def finish(self, item, state, *, due=None, status=None):
        with self.db:
            self.db.execute("""UPDATE jobs SET state=?,due=?,receipt=?,lease=NULL
                WHERE event=? AND subscription=? AND lease=?""",
                (state, self.clock() if due is None else due, status,
                 item["event"], item["subscription"], item["lease"]))

    def active(self, item):
        row = self.db.execute("SELECT generation,expires FROM subscriptions WHERE id=?",
                              (item["subscription"],)).fetchone()
        return bool(row and row["generation"] == item["generation"] and row["expires"] > self.clock())

    def receipts(self, owner, limit=20):
        limit = max(1, min(200, int(limit)))
        return [dict(row) for row in self.db.execute("""SELECT j.event AS event_id,j.subscription,e.watcher AS watcher_id,
            j.state,j.attempts,j.receipt AS http_status FROM jobs j JOIN events e ON e.id=j.event
            WHERE e.owner=? ORDER BY e.created DESC LIMIT ?""", (owner, limit))]

    def close(self):
        self.db.close()

    def save_watcher(self, owner, watcher, definition):
        private = self.pack(definition)
        with self.db:
            if (not self.db.execute("SELECT 1 FROM watchers WHERE owner=? AND id=?", (owner, watcher)).fetchone()
                    and self.db.execute("SELECT count(*) FROM watchers").fetchone()[0] >= 32):
                raise ValueError("Watcher capacity reached")
            self.db.execute("INSERT INTO watchers VALUES (?,?,?) ON CONFLICT(owner,id) DO UPDATE SET private=excluded.private",
                            (owner, watcher, private))

    def remove_watcher(self, owner, watcher):
        with self.db:
            self.db.execute("DELETE FROM watchers WHERE owner=? AND id=?", (owner, watcher))
            self.db.execute("DELETE FROM subscriptions WHERE owner=? AND watcher=?", (owner, watcher))

    def watchers(self, owner):
        return [self.unpack(row[0]) for row in self.db.execute("SELECT private FROM watchers WHERE owner=?", (owner,))]
