# Expergis MCP Events MVP

The upgrade is **opt-in**. The existing `expergis` stdio command, four tool names,
configuration keys, polling defaults, UTC cron behavior and optional Velle path
remain available. `expergis.json`, the installed `.venv`, CC configuration, sibling
projects and live deployments were not changed. No tunnel, service, credentials
or live ChatGPT subscription were created.

## Status and evidence

| Capability | Implementation / verification | Limit |
|---|---|---|
| Existing tools/config | Original tests plus SDK 1.26 and 2.3 suites | No live Velle success claim |
| Selected context | `config.context` JSON object, separate from observed facts | No automatic file contents; 16 KiB context |
| Durable subscriptions | SQLite owner/filter/expiry, deterministic identity, encrypted callback material | One owner per installation |
| Durable events | Stable IDs, transactional fanout, duplicate/conflict detection, leases, restart replay | 24-hour retention; no historical protocol cursor |
| Dynamic watchers | Encrypted registration persistence and restoration in event mode | Legacy registrations remain process-local |
| Native Windows files | `FindFirstChangeNotificationW`, scoped roots, snapshot reconciliation; real temporary-directory test | Non-recursive, metadata only; transient create/delete pairs can be missed |
| Process watcher | Existing polling, hidden tasklist, POSIX `ps` fallback; failed scans retain previous state | Native process start/stop events deferred |
| Schedule watcher | Existing UTC cron behavior retained | No catch-up of schedules missed while stopped/asleep |
| MCP transport | Official MCP 2.3.0 SDK, protocol `2026-07-28`, authenticated in-process tests | Narrow discovery schema adapter described below |
| Callback contract | Signed challenge, HMAC, exact serialized bytes, rotation overlap; real loopback mock | Public HTTPS/ChatGPT receiver not exercised |
| Security | Scope checks, ongoing authorization, connection-time SSRF rejection, no redirects/proxy env, input/resource caps | Operator must supply a trustworthy verifier and live access policy |
| Receipts | `expergis_check.delivery_receipts`: pending/sending/received/failed | Receipt is not downstream execution |
| Locked-PC delivery | Not tested | Pending authorized setup; PC must remain awake and online |

Validation: 76 passed and 1 SDK-specific skip on installed MCP 1.26; 77 passed in
a disposable MCP 2.3 environment. Tests include a separate Python-process replay
with DPAPI, duplicate/out-of-order events, retry exhaustion, stale leases,
subscription filters, expiry, revocation, unsubscribe during delivery, rotation,
malformed input, callback errors, network security policy, and invalid signatures.

## Configuration and behavior

`delivery_adapter` selects exactly one path:

* Omitted or `"velle"`: legacy rate limits/dedup and prompt formatting. HTTP 200
  JSON errors, false success flags and malformed responses are now rejected.
  Legacy delivery is best effort; it does not acquire durable retries.
* `"buffer"`: process-local ring only; no outbound dispatch.
* `"mcp_events"`: enqueue structured observations for active matching
  subscriptions. This requires the separate authenticated application factory;
  the stdio launcher refuses this setting rather than imply it can wake a dot.

Example **future event-mode configuration** (do not overwrite a live config):

```json
{
  "delivery_adapter": "mcp_events",
  "velle_endpoint": "http://127.0.0.1:7839/velle_prompt",
  "mcp_events": {
    "owner": "<verified OAuth subject>",
    "database": "C:/Users/<user>/AppData/Local/Expergis/events.sqlite",
    "allowed_roots": ["C:/Users/<user>/ExpergisDemo"],
    "allowed_process_names": []
  },
  "watchers": [{
    "watcher_id": "demo-file",
    "plugin_type": "file_watcher",
    "config": {
      "paths": ["C:/Users/<user>/ExpergisDemo"],
      "patterns": ["harmless.txt"],
      "backend": "native",
      "debounce_ms": 250,
      "context": {"label": "Harmless locked-PC delivery test"}
    }
  }]
}
```

`backend` is `polling` by default. `native` explicitly requires Windows and an
existing watchable directory; `auto` uses native signals on Windows and polling
elsewhere. Signals wake a metadata snapshot; a 30-second reconciliation scan
handles coalesced/lost notifications. Existing modified/created/deleted semantics
are retained. No recursion, machine-wide ETW collection or file-content reads.

Context is literal user-selected JSON data. It is not a system prompt, permission,
or new instruction source. The legacy `prompt_template` is never copied into MCP
event payloads. Actions requested of the dot belong in the subscribed chat.

## Authenticated application factory

Use a **separate** Python 3.11 environment for MCP 2.3; preserve the live venv.
For a development environment only:

```powershell
python -m venv .venv-events
.\.venv-events\Scripts\python -m pip install -e . "mcp==2.3.0" pytest pytest-asyncio
.\.venv-events\Scripts\python -m pytest tests -q -p no:cacheprovider
```

The factory `expergis.mcp_events_app.create_app(config, token_verifier,
auth_settings, authorize=policy)` returns an ASGI application. It does not bind a
port. A deployment wrapper must supply:

1. An existing OAuth `TokenVerifier` that actually verifies issuer, signature,
   audience/resource, expiry, subject and scopes. No production bearer-token
   stub is supplied. Never use the synthetic test verifier in a deployment.
2. SDK `AuthSettings` with HTTPS issuer/resource URLs, nonempty required scopes
   and `validate_token_resource=True`.
3. A synchronous, fast, fail-closed `policy(subject, watcher_id)` that reflects
   current account/resource access; `watcher_id=None` checks account access.
   It is called on requests and again before every queued delivery. Token
   verification on an old subscribe request alone cannot detect later revocation.
4. An existing private data directory and approved allowlisted monitoring scope.
   Configured and restored watchers are scope-checked before startup.

The event app supports one explicitly configured owner. It checks the verified
token's subject, keeps read tools filtered by resource policy, and runs the
existing tools and event methods on the same authenticated `/mcp` endpoint.
It refuses a second runtime in the same process and holds an OS lock for its
database across the runtime's lifetime. A crash releases that lock.

**Do not start this alongside a legacy stdio watcher process.** Separate stores
or legacy runtimes cannot share this lock. Consolidate the watcher owner during
an authorized deployment transition. No existing processes were stopped here.

MCP 2.3 implements the required transport, envelope validation, OAuth middleware
and custom request handlers, but its generated discovery model drops `events`.
`EventDiscoveryMiddleware` restores only this documented capability after a
successful, authenticated, SDK-validated 2026 discovery response. The SDK handles
all other framing. This adapter is covered by the contract test and should be
removed when the SDK's native event schema supports the field. This is a tested
implementation of the documented event subset, not a claim of formal MCP
certification or verified real ChatGPT interoperability.

## Delivery, recovery and privacy

Subscriptions default to one hour and are capped at 24 hours. A requested shorter
positive `ttlMs` is honored; `null` still receives a finite lifetime. The original
owner, event name, canonical filter and callback URL identify a subscription.
Unsubscribe uses that same identity, not an invented ID-only request. It is
idempotent. Removing a watcher removes its subscriptions. Refresh is idempotent;
secret changes require verification and use both keys for 60 seconds.

Events observed for active subscriptions are transactionally enqueued. Retryable
network/408/425/429/5xx failures use bounded exponential backoff, up to eight
attempts. IDs and payloads remain stable; signing time/signatures are regenerated.
410 removes the subscription; 413 and other permanent failures are not retried.
An ambiguous response may cause duplicate receipt after replay: delivery is at
least once. A 30-second lease recovers an interrupted send. Ordering is not
guaranteed. Acknowledged unsubscribe waits behind an in-flight send; a receiver
may already have accepted an event before unsubscribe was requested.

`cursor` is always null: the server replays its durable pending outbox, but does
not offer historical event replay for new/expired subscriptions. Filesystem or
schedule events that were never observed while the process was stopped are not
reconstructed. Expired subscriptions and events older than retention are purged.

Default limits: 32 watchers, 32 paths/names per watcher, 100 subscriptions,
1,000 retained events, 10,000 delivery rows, 256 KiB complete event bodies,
16 KiB selected context, 64 KiB inbound requests, 16 concurrent HTTP requests,
4 KiB callback responses, 10-second callback timeout, 10,000 scanned directory
entries per watcher, and one rotated 1 MiB audit backup. Full queues reject new
events visibly (`queue_rejected`) rather than evict pending work. Retention is
24 hours. Store constructor limits may be lowered by the deployment wrapper.

Windows DPAPI encrypts callback URL/secrets, event payloads and saved watcher
definitions under the runtime user. No secret key is created in the repository.
The same Windows account/profile must reopen the database. Linux polling remains
usable; private durable storage on non-Windows requires an explicitly supplied
secure protector (the production default refuses plaintext fallback). The
test-only protector is deliberately not suitable for production.

Database metadata (IDs, owner, watcher IDs, timing and receipt status) is not
encrypted. Keep the database in the user's existing private directory. Logs do
not include callback URLs, signing keys, response bodies or event summaries.
The local ring and authenticated tools do contain selected context. Database,
audit and environment files are ignored by Git; do not add live configs or data
to commits. No permissions were altered by this work.

Callback URLs must be HTTPS, port 443, with no credentials or fragment. Each
connection resolves and validates public destination addresses, then connects
to those addresses while retaining the hostname for TLS checks. Private/local,
multicast and IPv6 transition/translation ranges are rejected. Redirects, DNS
caching, environment proxies and cookies are disabled for callback requests.

## First harmless real event in this dot (pending)

The next approval should be one bounded setup bundle: choose the existing OAuth
provider/verifier and live access policy, approve a private database directory
and one demo directory, choose a supported HTTPS endpoint or Secure MCP Tunnel,
then connect/rescan the plugin and subscribe this dot only to `demo-file`.
Credential creation, tunnel/service installation, persistent access and live
subscription registration remain outside this implementation's authorization.

After authorized setup: keep one runtime awake and online, ask this dot to
acknowledge the harmless event without taking action, lock Windows, and create
or change only `harmless.txt` through a separately authorized test action.
Check both the persisted webhook receipt and the actual message in this dot.
Then unsubscribe and confirm that a second file change produces no delivery.
Locking need not stop a background process; sleeping/offline operation is not
promised. Already queued events can replay when service/connectivity resumes,
subject to expiration and retention.

## Test safety note

The initial baseline run exposed an existing test bug: a mock session's truthy
`closed` field caused real localhost Velle requests, which returned HTTP 500.
Downstream effects cannot be determined from those responses. The first
checkpoint fixed the mock and denied real aiohttp sessions by default. Later
tests use only synthetic events, temporary databases/directories, in-process
ASGI requests and one explicit ephemeral loopback receiver. Production watchers
were never launched; no subsequent test contacted real agents.

## References

* [Official MCP Events contract](https://developers.openai.com/plugins/build/mcp-events)
* [Connect and test a plugin](https://developers.openai.com/plugins/deploy/connect-chatgpt)
* [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
* [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
