# Arbitrium job-event consumer (deployment disabled)

This is a separate structured-content consumer, not an extension of metadata-only
file watching. The installed monitoring policy remains unchanged. No production
inbox, watcher, subscription or event is created by this source change.

The canonical v1 producer envelope is implemented without adding producer fields:
`schema_version`, `event_id`, `source`, `instance_id`, `job_id`, `run_id`, `status`,
`observed_at`, `sequence`, `context`, `log_refs`, `result_refs`.
Shared synthetic fixtures are in `tests/job_contract_cases.py`; run them against both
producer runtime/schema and the consumer before preparing a deployment bundle.

## Canonical parser rules

- Every envelope field is required; unknown and duplicate JSON keys are rejected.
- UTF-8 JSON, at most 16 KiB; version is integer 1 and source is `arbitrium`.
- IDs are canonical lowercase hyphenated UUID strings. The basename
  is the matching UUID plus `.json` (no nested directories).
- Status is queued/running/completed/failed/canceled/interrupted/unknown.
- Timestamp is RFC3339 UTC (`Z` or `+00:00`, up to six fractional digits).
- Sequence is an integer from 0 through 2^63−1. Booleans are not integers here.
- Context permits only optional template_id/reason_code/exit_code. Identifier
  values use 1–128 ASCII letters, digits, underscore, dot, colon or hyphen;
  exit_code is null or an integer from −2^31 through 2^32−1. No arbitrary prose.
- Each reference array has at most eight strings, each at most 1024 characters.
  References must be absolute local Windows paths, without UNC/device prefixes,
  parent traversal, control characters or alternate streams. They are **never
  resolved, statted or opened** and confer no access permission.

All producer fields are untrusted observations, not instructions or proof that a
job executed successfully. The consumer does not execute commands or inspect
logs, outputs, environment variables or referenced files. The envelope is carried
in MCP `observed.details.job_event`; existing user-selected watcher context stays
separate. A producer-reported completion is distinct from webhook HTTP receipt
and from any downstream conversation action.

## Durable behavior

The encrypted SQLite ledger retains source event IDs and canonical-JSON content
hashes independently of delivery retention. Identical ID/content is a duplicate,
including after restart or expiration of the transport's event row. Whitespace
and JSON object-key order do not change the fingerprint.

Same ID with different valid content flags the original ID as conflicted. The
original payload is never overwritten. If still pending intake, it cannot enter
the delivery queue; if already queued or received, that historical delivery is
not undone or replaced. A conflicting ID is not automatically cleared by putting
the old content back. A different ID reusing the same run/sequence, or switching
job identity within the same instance/run, is retained as a conflict and not sent.
Malformed files are rejected and counted separately.

Lower sequences with new IDs remain historical observations. `sequence_relation`
is first/advance/historical relative to accepted intake order, not a current-state
guarantee. Gaps are allowed. Consumers must compare `(instance_id, run_id,
sequence)` because callbacks and intake can arrive out of order. No state-machine
transition is invented and no observation is promoted to authority.

Valid events wait durably until the same watcher has an active subscription.
Transport queue insertion and ledger advancement share one SQLite transaction.
A crash commits both or neither. The existing signed delivery/retry/expiry rules
then apply; intake's `queued` does not mean received. Source stats are available
through authenticated `expergis_list`; transport receipts remain in
`expergis_check`. There is no producer acknowledgment protocol and **no producer
file is deleted, renamed or rewritten by this consumer**.

The ledger is capped at 10,000 rows and never silently evicts deduplication IDs.
The inbox is capped at 4096 flat entries. Reaching either limit stops intake for
operator review, preserving files and accepted data. Each two-second scan reads
at most 64 candidate files; round-robin batches prevent malformed early names
from starving later ones. At most 32 pending events enter the transport queue per
pass. Temporary publication files are ignored. Queue capacity/transient delivery
failures retain pending work. Invalid/transient read counters are capped.

Exactly one content consumer may be registered at a time. Intake rows remain
bound to their original watcher ID; recreate that same ID after expiry/removal
to continue pending handoff. Changing IDs does not replay or retarget previously
accepted events. Existing task TTL/revocation rules stop this watcher too.

## File safety

The directory must already exist and pass local/non-reparse containment checks.
Windows opens each candidate with OPEN_REPARSE_POINT and read-only sharing,
checks its final handle path against the selected inbox, refuses directories and
multiple hard links, checks size before reading, and reads no more than 16 KiB.
POSIX fixtures use descriptor-relative no-follow opens and regular-file checks.
Only immutable `event_id.json` files published by same-directory atomic rename
are supported. Partial writes are rejected/retried, not interpreted as events.
Logs contain no source bodies, callback credentials or reference contents.

## Later reviewable deployment step — not performed

1. Verify the canonical parser rules with the Arbitrium producer using shared
   synthetic fixtures. Agree on retention/acknowledgment separately; no automatic
   producer deletion is currently safe.
2. Prepare a new hash-pinned offline wheel and rollback wheel for the **currently
   installed dd483670bbf46761db4eaba7ec13a4848026d263** checkpoint. Do not rerun the
   older c90-to-dd48367 updater for this change. The new updater supports manifest
   profile `job_inbox_code_only`: it verifies the existing v2 scope and preserves
   it exactly, requiring structured-content permission to remain disabled. This
   profile neither creates an inbox nor enables content reads. Run without
   `--apply` to verify bundle hashes only. A later approved code-only install uses
   `--apply`; rollback uses `--rollback` while the original scope is unchanged.
3. With explicit deployment approval, create only the agreed flat directory
   `C:\Users\<user>\ExpergisSignals\job-events` using existing user permissions.
   Add the following reviewed settings to `mcp_events`, retaining every current
   root/process/service policy and keeping schedules disabled:

   ```json
   {
     "allow_job_event_contents": true,
     "job_event_inbox": "C:\\Users\\<user>\\ExpergisSignals\\job-events"
   }
   ```

4. Perform the package/config update and credential-bearing restart from the
   user's normal terminal. Verify READY and authenticated connector access.
5. Only then register one expiring `job_event_watcher` with the exact `inbox` and
   obtain the intended conversation subscription. Authorize one synthetic producer
   event separately; verify intake, signed HTTP receipt and actual conversation
   receipt independently. A locked-PC trial remains a separate authorized test.

Rollback of a deployed consumer requires stopping/removing its watcher before
returning to the prior package, which does not recognize this plugin. Keep the
encrypted ledger and source files intact; do not reinterpret them as acknowledged.

## Verification

Synthetic tests cover strict parsing, malformed/oversized input, never opening
references, hard links/junctions, atomic publication, bounded scanning, separate
permission, restart dedup after transport retention, ID/sequence/job conflicts,
out-of-order intake, authorization, queue rollback/capacity and signed mock
503→202 retry with stable transport ID. The test suite's HTTP guard blocks real
agents. No tests access the production inbox or SemSearch.
