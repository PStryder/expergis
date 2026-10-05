# Task monitoring policy v2

This opt-in policy applies to authenticated MCP Events deployments with
`mcp_events.monitoring_policy_version: 2`. Legacy stdio configuration and its
optional Velle adapter retain their previous behavior. No schedule execution or
command execution API is added. Keep `allow_schedules: false`.

## Approved deployment scope

Example roots, which require explicit operator approval, are `C:\Projects`, `C:\Data`, `C:\Downloads`
and `C:\Users\<user>\ExpergisSignals`. Register specific files or nonrecursive
subdirectories. A root itself requires literal filenames in `patterns`; wildcard
root watches and recursive traversal are rejected. No watchers are created by
enabling this policy.

The built-in exclusions cover named credential/private-key files, `.env*`,
common browser/profile and credential directories, ExpergisRuntime, reparse
paths, UNC/device/alternate-stream paths and hard-linked files. The same checks
apply while scanning. This is a metadata-only boundary, not content-based secret
classification: a secret given an innocuous filename cannot be identified without
reading it. File contents are never opened. Choose narrow task paths and context.

Example file registration (the subdirectory must exist):

```json
{"watcher_id":"job-build-output","plugin_type":"file_watcher","config":{
  "paths":["C:\\Projects\\Expergis\\dist"],"patterns":["*.whl"],
  "events":["created","modified"],"backend":"native","ttl_seconds":3600,
  "context":{"task":"Report when the selected build artifact changes"}}}
```

Enable `allow_selected_processes: true` for selected executable basenames or
`processes: [{"pid":1234,"creation_time":"133000000000000000"}]`.
`creation_time` is the decimal Windows FILETIME, available to the user with
`(Get-Process -Id 1234).StartTime.ToFileTimeUtc().ToString()`.
Generic runtimes/shells (Python, Node, PowerShell, Java, dotnet, etc.) require
PID plus creation time; a name-only blanket watch is rejected. A PID alone is
insufficient. Windows process ownership must match the runtime user. Names use
filtered tasklist queries, then limited-query process handles verify owner,
basename and creation time. No command lines, environment or memory are read.
Access errors stop the watcher as `failed`, rather than falsely reporting exit.

Enable `allowed_service_names: ["SemSearch"]` for this registration:

```json
{"watcher_id":"job-semsearch-status","plugin_type":"service_watcher","config":{
  "service_names":["SemSearch"],"poll_interval_ms":5000,"ttl_seconds":3600}}
```

Only SCM CONNECT and SERVICE_QUERY_STATUS rights are requested. Events report
state transitions and, when stopped, Windows/service-specific exit codes. Access
failure is not a service fault. This code cannot start, stop or configure services.

## Lifecycle and delivery

All v2 watches default to 24 hours; `ttl_seconds` accepts 60 through 604800.
Absolute expiry is persisted and never extended by a restart. Internal underscore
keys are rejected from remote callers. Startup revalidates saved paths and scope.
Owner/prefix revocation stops monitoring within the supervisor interval when the
event loop is available. Expired/failed/revoked entries remain in the inventory
for audit and still occupy one of 32 slots; use `expergis_unwatch` after job
completion. Unwatch removes subscriptions too. Already queued events can finish
delivery after monitoring expires, subject to subscription expiry/authorization.

`expergis_list` includes status, expiry and coalesced count. Repeated file
modifications and identical other observations within `coalesce_seconds`
(default 5, range 1..60) are suppressed after the first; counts remain visible.
Distinct lifecycle transitions are retained. Coalescing is bounded, in-memory and
resets at restart. It is not an exactly-once delivery guarantee. Existing durable
event IDs, signed callbacks, queue caps and retry behavior remain unchanged.

## Implementation/status matrix

| Capability | Status | Limitation |
|---|---|---|
| Selected file/directory changes | Native Windows directory notifications plus metadata reconciliation | Nonrecursive; signal coalescing can miss very brief create/delete cycles |
| Selected processes | Native limited-query identity/state checks; filtered name discovery | Polling, minimum 1 second; transitions while stopped/offline can be missed |
| SemSearch service | Native SCM read-only status query | Polling, minimum 1 second; APC notifications deferred |
| Durable registrations/expiry | Implemented; restart validation and expiry tests | Missed OS observations are not reconstructed from queue storage |
| Context + MCP Events | Existing signed, authenticated durable delivery | HTTP receipt differs from conversation execution |
| Legacy tools/config/Velle | Preserved and regression tested | Velle repair and CC injection out of scope |
| Normal and locked-PC event receipt | Validated by parent for prior installed checkpoint | New policy/package needs user-operated update and verification |
| Schedules/command execution | Disabled for this deployment | Requires separate concrete design and approval |

Run `PYTHONPATH=src python -m pytest -q` in the isolated MCP 2.3 environment
(PowerShell: `$env:PYTHONPATH='src'`). Tests use temporary paths, synthetic data,
mock service queries, and one short-lived synthetic child process. They do not
contact live agents, query SemSearch or read real credentials. Test legacy MCP
1.26 separately; event-endpoint tests are intentionally skipped there.

The updater is user-operated from a normal, non-admin terminal. It verifies its
hash-pinned offline bundle, the existing Interactive/Limited task and installed
package, preserves credentials/database/policy, backs up only the nonsecret
runtime configuration, and can restore the previous wheel/config. It creates
no watchers or subscriptions. A fresh READY heartbeat is local readiness only;
the parent verifies authenticated connector access and any explicitly authorized
test event. Locking is supported while Windows stays awake and online; sleeping
or offline operation is limited to later queue replay of already observed events.
