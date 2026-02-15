# Expergis

> *From Latin **expergīscī** &mdash; to wake up, to be roused from sleep. From **ex-** (out of) + **pergere** (to go forward). Where Velle is the will to act, Expergis is the moment of waking.*

**Plugin-based event watcher for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).**

Expergis detects system events and wakes the agent when they fire. It is the perception complement to [Velle](https://github.com/PStryder/Velle)'s volition &mdash; together they create a fully event-driven agent. Velle pushes (self-prompting), Expergis pulls (event detection).

When an event fires, Expergis formats a prompt and POSTs it to Velle's HTTP sidecar, which injects it into the Claude Code session. All of Velle's guardrails (turn limits, cooldown, audit) apply.

## How It Works

```
Plugin detects event
  -> emit(Event)
  -> Dispatcher (dedup + rate limit + audit)
  -> POST http://127.0.0.1:7839/velle_prompt
  -> Velle injects prompt into Claude Code
  -> Agent wakes up with event context
```

Expergis runs as an MCP server alongside Claude Code. Plugins run long-lived watch loops and call `emit(Event)` when something happens. The dispatcher deduplicates, rate-limits, and dispatches to Velle.

## MCP Tools

| Tool | Description |
|------|-------------|
| `expergis_watch` | Register a watcher at runtime (file, schedule, or process) |
| `expergis_unwatch` | Remove an active watcher by ID |
| `expergis_list` | List active watchers with stats |
| `expergis_check` | Poll recent events from the ring buffer (including rate-limited ones) |

## Plugins

### file_watcher

Detects file and directory changes via polling. Tracks creation, modification, and deletion.

```json
{
  "paths": ["/path/to/watch"],
  "patterns": ["*.py", "*.ts"],
  "events": ["modified", "created", "deleted"],
  "debounce_ms": 1000,
  "poll_interval_ms": 2000
}
```

### schedule_watcher

Fires events on a cron schedule using [croniter](https://github.com/kiorky/croniter).

```json
{
  "cron": "*/5 * * * *"
}
```

### process_watcher

Detects process start and stop events via polling. Windows only (uses `tasklist`).

```json
{
  "process_names": ["notepad", "python"],
  "poll_interval_ms": 5000
}
```

## Installation

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/PStryder/expergis.git
cd expergis
uv sync
```

### Claude Code MCP Config

Add to your Claude Code configuration (`~/.claude.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "expergis": {
      "command": "/path/to/expergis/.venv/Scripts/python",
      "args": ["-m", "expergis.server"],
      "cwd": "/path/to/expergis"
    }
  }
}
```

Or use the CLI:

```bash
claude mcp add -s user expergis -- /path/to/expergis/.venv/Scripts/python -m expergis.server
```

## Configuration

Edit `expergis.json` in the project root:

```json
{
  "velle_endpoint": "http://127.0.0.1:7839/velle_prompt",
  "rate_limit": {
    "min_interval_ms": 5000,
    "max_events_per_minute": 6,
    "burst_size": 2
  },
  "dedup_window_ms": 10000,
  "watchers": []
}
```

### Pre-configured Watchers

Watchers defined in `expergis.json` start automatically when the server launches:

```json
{
  "watchers": [
    {
      "watcher_id": "watch-src",
      "plugin_type": "file_watcher",
      "enabled": true,
      "prompt_template": "File changed: {event.summary}. Review and decide if action needed.",
      "config": {
        "paths": ["/my/project/src"],
        "patterns": ["*.py"],
        "events": ["modified", "created"]
      }
    }
  ]
}
```

### Rate Limiting

The dispatcher uses a token bucket algorithm:

- **`burst_size`** &mdash; max events dispatched in a burst (default: 2)
- **`max_events_per_minute`** &mdash; sustained rate (default: 6/min)
- **`min_interval_ms`** &mdash; minimum gap between dispatches (default: 5000ms)
- **`dedup_window_ms`** &mdash; suppress duplicate events within this window (default: 10000ms)

Rate-limited events are stored in the ring buffer and retrievable via `expergis_check`.

## Prerequisites

[Velle](https://github.com/PStryder/Velle) must be installed with its HTTP sidecar enabled:

```json
// velle.json
{
  "sidecar_enabled": true,
  "sidecar_port": 7839
}
```

## Writing Custom Plugins

Implement the `WatcherPlugin` ABC:

```python
from expergis.plugins.base import WatcherPlugin, Event, EmitFn

class MyPlugin(WatcherPlugin):
    async def setup(self) -> None:
        # Validate self.config, initialize state
        pass

    async def watch(self, emit: EmitFn) -> None:
        # Long-running loop
        while True:
            await asyncio.sleep(5)
            await emit(Event(
                plugin_type="my_plugin",
                watcher_id=self.watcher_id,
                event_type="something_happened",
                summary="Description of what happened",
            ))

    async def teardown(self) -> None:
        # Cleanup
        pass
```

Register it in `src/expergis/plugins/__init__.py` by adding it to `PLUGIN_REGISTRY`.

## License

[Apache 2.0](LICENSE)
