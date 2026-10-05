# Opt-in Windows operation

Source milestone only: no task, service, persistent credential, production root,
or process allowlist is installed by this change. The bounded operator-run smoke
test has demonstrated authenticated tools, native file detection, a first-attempt
HTTP 200, and subsequent event delivery to the subscribed dot. Logon/reboot and
locked-screen operation of this supervisor remain untested.

## Runtime and privilege boundary

`expergis-runtime` supervises the authenticated MCP application and official
tunnel client. It listens only on an ephemeral IPv4 loopback port and gives the
tunnel the exact local and Auth0 discovery origins. It does not create services,
modify CC configuration, stop legacy stdio watchers, open public listeners, or
provision provider accounts. All four authenticated tools are available.

The optional scheduled task is **per user, at logon, Interactive, Limited**. It
uses the dedicated venv's `pythonw.exe` for hidden execution and the existing
signed-in token, no saved Windows password, and no elevation.
It can continue while that session is locked and the PC is awake/online; after
reboot it starts only when that user signs in. It does not run before login,
wake the PC, or promise observation while sleeping/offline. Persistent queued
events replay subject to retention and subscription expiry. Missed filesystem
activity while stopped is not reconstructed.

The task retries a failed process three times, one minute apart. An unavailable
network leaves the running client in its reconnect loop; status is degraded.
No automatic credential rotation, account grants, or privilege escalation occurs.
See [Microsoft principal settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal)
and [task settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset).

## Concrete activation review (do not execute before approval)

Proposed account: the existing signed-in Windows user. Suggested private install
directory: `C:\Users\YOU\AppData\Local\ExpergisRuntime`. Create only that new
directory with owner=user, protected DACL, and full access for user, SYSTEM and
Administrators; do not alter parent ACLs or grant sandbox access. Existing paths
require inspection, not ACL replacement. Run setup from the ordinary user
terminal: packaged Codex can redirect LocalAppData into its package cache. The
runtime refuses a resolved private path different from the requested path.

Within the approved private directory, create a separate `venv` using Python
3.11, then install this reviewed checkout with its `events` extra. Do not change
the live `.venv`. The checked-in `uv.lock` preserves the legacy SDK environment;
do not use it to provision the event runtime. Use the declared `events` extra
through pip as shown below. Prefer a non-editable installation so uncommitted source edits
cannot change an installed runtime. This does not install the official tunnel
client; supply the operator-verified binary path and SHA-256 checksum.

```powershell
# After approval, from an ordinary user terminal:
py -3.11 -m venv 'C:\Users\YOU\AppData\Local\ExpergisRuntime\venv'
& 'C:\Users\YOU\AppData\Local\ExpergisRuntime\venv\Scripts\python.exe' -m pip install 'F:\HexyLab\Expergis[events]'
```

Save the following as private `runtime.json`, replacing placeholders locally.
Do not add it, `policy.json`, encrypted key files, databases or event data to Git.
The runtime always pins its database and policy to this private directory.

```json
{
  "expergis": {
    "delivery_adapter": "mcp_events",
    "watchers": [],
    "mcp_events": {
      "owner": "VERIFIED_OWNER_SUBJECT",
      "allowed_roots": [],
      "allowed_process_names": [],
      "allow_schedules": false
    },
    "auth0": {
      "issuer": "https://YOUR_TENANT.auth0.com/",
      "resource": "EXACT_HTTPS_RESOURCE_OBSERVED_IN_CHATGPT",
      "client_ids": ["DEDICATED_OAUTH_CLIENT_ID"],
      "policy_file": "C:/Users/YOU/AppData/Local/ExpergisRuntime/policy.json"
    }
  },
  "tunnel": {
    "id": "tunnel_YOUR_EXISTING_ID",
    "client_path": "C:/Tools/approved-tunnel-client/tunnel-client.exe",
    "sha256": "VERIFIED_64_CHARACTER_LOWERCASE_SHA256"
  }
}
```

Private `policy.json` starts disabled:

```json
{
  "owner": "VERIFIED_OWNER_SUBJECT",
  "enabled": false,
  "watcher_ids": [],
  "managed_watcher_prefix": "job-",
  "tokens_valid_after": 0
}
```

The optional prefix permits dynamic IDs such as `job-build`, not wider monitoring.
Every file registration is independently confined to `allowed_roots`; process
names must be explicitly listed; schedules are disabled above. No roots/processes
are approved by these examples. First proposal: one newly created job-completion
signal directory, containing synthetic marker files only. Add particular project
folders or executable names only after the operator names and approves them.
Set `enabled` true only as part of the approved activation. Policy revocation is
read on every authenticated decision and delivery; changing roots or process
scope requires a stop/restart. Restore validates persisted registrations against
the new scope and refuses startup if any fall outside it.

File scope rejects traversal, UNC and reparse/symlink components. Event-mode
snapshots recheck paths and skip redirected file entries. A path changed into a
junction while running stops that watcher and marks health degraded; remove and
register it after correcting the path. This is defensive metadata monitoring,
not an OS sandbox against a hostile local account that can race directory edits.
No file contents are read or added to events. Context remains data, never authority.

## Preflight, key entry, first start

With `python` below meaning the dedicated venv executable:

```powershell
python -m expergis.windows_runtime preflight --directory 'C:\Users\YOU\AppData\Local\ExpergisRuntime'
python -m expergis.windows_runtime store-key --directory 'C:\Users\YOU\AppData\Local\ExpergisRuntime'
python -m expergis.windows_runtime run --directory 'C:\Users\YOU\AppData\Local\ExpergisRuntime'
```

`preflight` is offline: config, owner policy, private ACL, scope and binary hash.
`store-key` is a separate approved action with a hidden interactive prompt. It
saves a current-user DPAPI blob, never plaintext. Only the tunnel child receives
the decrypted key in its minimal process environment. There is no key command-line
argument, copied clipboard, environment discovery, or OAuth client-secret storage.
DPAPI is user-bound; it is not protection against another process already running
as that user. Rotation uses the same local prompt and then a restart.

Before first start, stop the temporary demo client and coordinate any overlapping
legacy stdio watchers; do not edit CC or siblings. Database locks prevent duplicate
owners of one database; a session mutex prevents these supervisors sharing a tunnel.
An unrelated old launcher cannot honor that mutex: stop it explicitly. A new private
database requires a new/renewed subscription; never copy callback secrets by hand.

`status` returns only fixed status, PID, timestamp and fixed reason code. `ready`
means ASGI started, tunnel health is ready and registered watcher tasks are alive;
it does not prove OAuth login, subscription, webhook acceptance or dot execution.
Treat an old timestamp as stale, especially after a forced termination. No raw
server/tunnel logs are retained. Failures exit nonzero for Task Scheduler recovery.

## Review and install the logon task

```powershell
# Review only; no registration or process launch:
.\scripts\manage-logon-task.ps1 -PythonExe 'C:\Users\YOU\AppData\Local\ExpergisRuntime\venv\Scripts\python.exe' -StateDirectory 'C:\Users\YOU\AppData\Local\ExpergisRuntime'
# Only after approving that exact plan, append -Apply.
```

Task name: `Expergis User Runtime`. The installer refuses to overwrite an existing
task. Installation does not start it immediately; manual first start and the next
sign-in are separate checks. No installer command has been applied by this milestone.

For a stop now: `python -m expergis.windows_runtime stop --directory ...` requests
graceful application shutdown and tunnel child cleanup. To prevent another logon
launch, use the script with `-Action Disable -Apply`. To uninstall the registration,
use `-Action Remove -Apply`; both verify the existing action identity, disable
future startup, request stop, and retain private credentials/state for recovery.
If configuration is invalid, disable/remove remains usable without full preflight.
If the interpreter is broken, disable the exact reviewed task in Task Scheduler;
do not kill unrelated Python or tunnel processes. Deleting retained private state
or revoking the remote key is a separate explicit operator action.

Rollback: disable and stop this task, confirm both owned processes exit, reinstall
the preceding reviewed package version into the dedicated venv, then preflight.
Do not downgrade live state without checking schema compatibility. Leave legacy
stdio configuration untouched and avoid overlapping scopes if reusing that runtime.

## Acceptance still required

| Stage | Current evidence |
|---|---|
| Native event → signed webhook → subscribed dot | Bounded manual smoke test passed; later dot wake was asynchronous |
| Supervisor stop/failure cleanup and duplicate protection | Isolated synthetic tests |
| Dynamic watcher IDs within approved scope | Policy and path regressions; production allowlists empty |
| Windows logon task | Script review/dry run only; installation and reboot test pending |
| User-bound persistent credential | DPAPI implementation; real storage/rotation not performed |
| Locked PC | Pending coordinated user lock while awake/online |

For the locked-screen test, approve one marker in the selected signal directory,
confirm the active subscription, have the user lock Windows, then create that one
marker. Compare observation, webhook receipt, and actual dot receipt separately.
MCP Events acknowledges delivery before asynchronous processing; batching can
delay the task. No fixed latency is promised. After receipt, retire the demo
subscription through the parent conversation and verify unsubscribe. Never infer
success from file creation or HTTP 200 alone.
