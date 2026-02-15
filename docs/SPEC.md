# Expergis Specification

## Event Flow

```
Plugin.watch() loop
  -> Detects change
  -> Calls emit(Event)
  -> Dispatcher.dispatch(event, prompt_template)
    1. Dedup check (TTL dict, configurable window)
    2. Rate limit check (token bucket)
    3. Min interval check
    4. Format prompt from template
    5. POST to Velle sidecar
    6. Audit log
    7. Store in ring buffer
```

## Event Dataclass

```python
@dataclass
class Event:
    plugin_type: str      # "file_watcher", "schedule_watcher", "process_watcher"
    watcher_id: str       # User-assigned ID
    event_type: str       # "modified", "created", "deleted", "scheduled", "process_started", "process_stopped"
    summary: str          # Human-readable summary
    details: dict         # Plugin-specific details
    dedup_key: str        # Key for deduplication (auto-generated if empty)
    timestamp: str        # ISO 8601 UTC
```

## Plugin Contract

```python
class WatcherPlugin(ABC):
    async def setup(self) -> None         # Validate config, init state
    async def watch(self, emit) -> None   # Long-running loop, call emit(Event)
    async def teardown(self) -> None      # Cleanup
```

## Rate Limiting

Token bucket algorithm:
- Bucket size = `burst_size` (default 2)
- Refill rate = `max_events_per_minute / 60` tokens/second
- Min interval between dispatches = `min_interval_ms`
- Rate-limited events stored in ring buffer but not dispatched

## Dedup

- TTL-based: events with the same `dedup_key` within `dedup_window_ms` are suppressed
- Dedup key auto-generated as `{watcher_id}:{event_type}:{summary}` if not specified

## Ring Buffer

- Fixed size: 200 events
- Stores all events (dispatched + skipped)
- Queryable via `expergis_check` with filters: since, watcher_id, limit

## Config-Defined Watchers

Watchers in `expergis.json` are started automatically on server launch.
Set `"enabled": false` to disable without removing.

## Velle Integration

Expergis POSTs to Velle's HTTP sidecar at `velle_endpoint`.
All Velle guardrails (turn limits, cooldown, audit) apply to dispatched prompts.
If Velle is unreachable, the event is stored with an error status.
