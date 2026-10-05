# Authenticated catalog diagnostics

`expergis_list` on the authenticated MCP Events endpoint now adds
`catalog_diagnostics`. Its input schema and all registration/authentication rules
are unchanged. No new endpoint, unauthenticated health data, request logging or
heartbeat mirror is added. Legacy stdio output is unchanged.

Fields:

- `diagnostic_revision`: 1, identifying this observation format.
- `process_id` and `observer_started_at`: live process/app provenance. These are
  not a Git commit claim; the pinned updater separately verifies installed files.
- `live_catalog.plugin_types` and `schema_sha256`: generated now through the same
  `runtime._list_tools()` function used by the authenticated catalog handler.
- `successful_tools_list_count`: number of observed successful responses since
  this app started, capped at 2^63−1.
- `last_successful_tools_list`: null before observation, otherwise the emitted
  response's plugin types, schema hash, protocol and UTC emission timestamp.

The hash is SHA-256 of compact, sorted-key ASCII JSON containing tool names and
their complete `inputSchema` objects, sorted by tool name. Top-level tool
descriptions, authentication metadata and annotations are excluded. Schema-internal
descriptions remain part of `inputSchema`. Both generated and emitted summaries
use this exact projection.

The observer sees only the existing JSON response path for protocol `2026-07-28`
and MCP method `tools/list`. It records a response only after its final body has
been handed successfully to ASGI `send`. This is server emission evidence, not
proof that the remote client received it. Unsupported protocol/transport paths
are not counted. Zero means no supported successful response was observed in
this process; it does not prove that the connector never requested discovery.

Only one bounded last summary is retained in memory. No request bodies, OAuth
headers, tokens, callback material, event contents, watcher configuration or
referenced files are retained. Authentication failures and MCP error responses
do not generate observations. Failed sends do not increment the counter.

## Reading the result

1. Invoke the already-declared authenticated `expergis_list` tool.
2. If `catalog_diagnostics` is absent, this response is not from the new diagnostic
   handler. Compare task/package/tunnel provenance before changing anything.
3. Five live types prove the running handler currently generates the new catalog.
4. A non-null last emitted summary with the same five types/hash proves that this
   process also serialized/emitted that schema on its supported `tools/list` path.
5. If the connector declaration still has three types, retain both observations
   for connector/catalog troubleshooting. Do not invoke undeclared enum values,
   repurpose metadata-only watchers, disable auth, or assume another reinstall
   will force discovery.

## Deployment and rollback

The offline updater profile `catalog_diagnostics_only` starts from pinned
`346ad16aa3fd6f62fa1512f2d3b13a2fa626ba52`, verifies the already approved v2 roots,
process/service policy and exact enabled `ExpergisSignals/job-events` inbox,
and preserves configuration. It does not rewrite unchanged configuration on
installation. It creates no inbox, watcher, subscription, event, credentials or
task definition. Normal-user interactive execution remains required. Rollback
uses the retained 346ad16 wheel and private pre-update configuration backup.

Tests exercise the actual authenticated SDK/ASGI serialization, compare its
response hash to the next `expergis_list` result, and verify exclusion of token,
auth-metadata and response sentinels. They also cover authentication failures,
MCP errors, send failures, unsupported protocol and updater scope preservation.
