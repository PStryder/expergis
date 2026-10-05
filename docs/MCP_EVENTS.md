# MCP Events upgrade status

Development checkpoint, disabled by default. Existing stdio tools/configuration
and the default legacy Velle adapter remain available. Do not run an event runtime
alongside existing production watchers. No live subscription or tunnel was created.

Implemented: encrypted SQLite subscriptions/outbox and watcher definitions;
structured observations/context; stable event IDs, bounded retries and receipt
states; Standard Webhooks signing, callback challenge verification, HTTPS-only
connection-time address filtering; owner/filter checks, expiry, unsubscribe and
key rotation; opt-in Windows directory change signals; authenticated MCP 2.3
application factory exposing the documented event methods and existing tools.

The factory requires an externally supplied resource-bound OAuth verifier,
authorization policy and AuthSettings. It does not create credentials or start a
listener. SDK 2.3 drops the draft Events capability from discovery, so a narrow
ASGI adapter restores that documented field after successful SDK validation.
This is tested against the SDK, not yet against ChatGPT.

Validation at this checkpoint: 55 tests pass using a disposable MCP 2.3.0
Python environment; legacy MCP 1.26 tests also exercised. Real ChatGPT reception,
real authentication setup, public TLS transport and locked-PC end-to-end delivery
remain pending. Native directory notifications were tested only in a temporary
folder. Process monitoring remains polling; cron retains UTC behavior.

Known baseline test incident: the original dispatcher tests used a malformed
mock whose truthy `closed` attribute opened real localhost Velle connections.
The initial baseline received HTTP 500 responses. Downstream effects are unknown.
The first committed fix forbids real aiohttp sessions in tests, repairs the mock,
and redirects audit files to temporary directories. No production watchers were
started. Subsequent tests are isolated.

Contract: https://developers.openai.com/plugins/build/mcp-events
