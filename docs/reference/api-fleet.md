# Fleet executor API

The fleet API is the authenticated, hub-authoritative boundary used by executor
daemons. It is separate from Coven's same-user local socket API. Tailscale,
HTTPS, SSH forwarding, or another private transport may carry requests, but
network reachability never replaces Coven enrollment.

## Identity lifecycle

An operator creates a short-lived, single-use enrollment code through the local
daemon socket:

```text
POST /api/v1/fleet/enrollments
```

The target exchanges that code once:

```text
POST /api/v1/fleet/enrollments/redeem
```

Redemption returns a node-scoped bearer secret. Coven persists SHA-256
verifiers for enrollment codes and node secrets, not usable credentials. Node
secrets must be stored with the same local protections as other daemon state.
An operator can revoke a node through the local socket:

```text
POST /api/v1/fleet/nodes/:nodeId/revoke
```

## Executor loop

An enrolled daemon repeatedly performs:

```text
POST /api/v1/fleet/nodes/:nodeId/heartbeat
POST /api/v1/fleet/nodes/:nodeId/jobs/claim?wait=25
POST /api/v1/fleet/jobs/:jobId/renew
POST /api/v1/fleet/jobs/:jobId/complete
POST /api/v1/fleet/jobs/:jobId/fail
```

Every request after redemption uses `Authorization: Bearer <node-secret>`.
Heartbeats carry a monotonically increasing connection epoch plus typed
capabilities. Observations expire, so an installed but disconnected node is not
eligible for placement.

Claim returns a bounded job, attempt id, short-lived lease token, and expiry.
Renewal and completion must match the authenticated node, job, attempt, and
lease token. Completion also requires a stable idempotency key. Replaying the
same completion is safe; changing its key or reporting from another node fails
closed.

Execution errors use the strict `coven.fleet-failure.v1` envelope. Executors
report redacted evidence but never choose retry policy. Reported failures are
terminal in the current delegation slice; lease expiry remains the hub-owned
reclaim path.

The current work payload remains compatible with `coven.executor.v1`. The
authenticated pull channel and hub-initiated SSH transport are edge adapters to
one hub-owned queue; they do not create separate scheduling authority.

## Capability observations

Capabilities are schema-validated facts covering protocol versions, platform,
resources, optional GPU information, runtimes, harnesses, workspace drivers,
and tools. Harness readiness must never include provider tokens or account
identifiers. The hub considers only fresh observations from a non-revoked node.

## Secrets boundary

Node credentials, job lease tokens, provider OAuth state, API keys, SSH keys,
and Tailscale state must not appear in workspace checkpoints, results, logs, or
capability observations. Provider authentication remains local to the executor.

Workspace jobs carry `coven.workspace-driver.v1` through the same leased queue
as bounded executor jobs. Placement requires both a canonical driver capability
such as `workspace:filesystem` or `workspace:s3-checkpoint` and
`protocol:workspace-driver:1`. Executors invoke the standalone `coven-roam`
process boundary and transactionally return its normalized response.

Only checkpoint, restore, release, and acquire operations may be leased. Scoped
transfer URLs may be present, but long-lived access keys, API keys, OAuth
tokens, and authorization headers are rejected before the job enters durable
state.

Managed actors use `coven.harness-host.v1`. A bounded `start` job chooses an
eligible executor and commits the actor-to-node binding. Later `send`, `status`,
and `stop` jobs are pinned to that owner; another capable executor cannot claim
them. Executor-local actor state survives daemon restart, and event evidence
stores only sizes and digests rather than prompt or output content.

An actor started for a roaming session is also immutably bound to its logical
session, placement, generation, harness, and executor-derived workspace path.
Replaying `start` is accepted only when that complete binding matches. Provider
authentication is resolved by the executor-local harness adapter and is never
part of this binding or a fleet payload.

## Delegation protocols

Remote child orchestration composes three versioned envelopes:

- `coven.delegation.v1` binds a task to its delegation, child, immutable parent
  base, workspace checkpoint, harness generation, and placement requirements.
- `coven.delegation-result.v1` is provisional evidence bound to the producing
  attempt and node. The hub validates its patch, artifacts, verification, and
  staged memory proposals before parent mutation.
- `coven.delegation-cleanup.v1` is submitted only after acceptance or
  cancellation and is pinned to the producing node and actor generation.

Finalization keys make accepted integration replay-safe. A changed key, result
digest, authority binding, or cleanup node fails closed. Cleanup completion—not
child execution completion—is the acknowledgment that executor-local resources
may be released. The public surface is currently the local
[`coven delegate`](cli-delegate.md) workflow; no HTTP delegation endpoint is
exposed.

## Session authority

Logical session, placement, run, queued-input, and finalization lifecycles are
stored separately. A transfer reserves a pending generation without declaring
it active. The source remains authoritative until checkpoint fencing; target
activation atomically promotes the pending placement and releases the exact
source placement. A transfer-fenced source is distinct from a run awaiting
finalization acknowledgment. Output must match the active session, placement,
generation, node, and run in the same transaction that appends its event.

Inputs are persisted with a monotonically increasing sequence before delivery.
The hub never assumes an active placement is local: managed input remains queued
for an authority-bound executor delivery. During cutover it cannot reach the
source runtime. An active placement claims inputs in order; an unacknowledged
oldest input replays before later sequences, and only delivery acknowledgment
creates the canonical input event. Process exit finalizes a run, not the logical session.
Result, revision, artifacts, and passing verification remain provisional until
a hub finalization acknowledgment releases the placement.

`POST /api/v1/sessions/:id/roam/progress` no longer mutates placement authority.
Remote transports are rejected, and local callers receive
`session_authority_required`. Normal advancement must arrive through a
validated, leased fleet completion.

## Local fleet control surface

Cave and other same-user clients consume one local, redacted projection rather
than the executor API or Coven's internal saga tables:

```text
GET /api/v1/fleet/ux?sessionId=:sessionId
```

The `coven.fleet-ux.v1` response contains bounded node availability, delegation,
matrix, and roam summaries plus a deterministic snapshot digest. It omits node
credentials, provider authentication, lease tokens, workspace locators, raw
payloads, prompts, outputs, and internal finalization keys. Unknown states and
actions fail closed. Remote and node-bearer transports cannot call this route.

The only local delegation decisions exposed to thin clients are:

```text
POST /api/v1/fleet/ux/delegations/:delegationId/integrate
POST /api/v1/fleet/ux/delegations/:delegationId/cancel
```

Both accept an empty body. Coven derives the stable integration idempotency key
inside the authority boundary and returns another redacted Fleet UX snapshot.
Clients cannot supply finalization keys or advance cleanup/saga phases.

## Automatic session roam

One local command creates a hub-owned, generation-fenced transfer:

```text
POST /api/v1/sessions/:id/roam/automatic
{}
```

The optional `targetNodeId` is the only accepted field. Coven derives the active
source placement, session harness, private workspace reference, and compatible
workspace driver from Session Authority. When no target is supplied, the Fleet
Registry scheduler deterministically selects a fresh compatible executor. A
live turn, unmanaged session, absent source, incompatible target, unknown field,
or remote transport is rejected before mutation.

The hub then submits a checkpoint job pinned to the source executor. Its
validated completion fences the source and submits a prepare job pinned to the
target. The target restores into an attempt-local staging placement, writes and
syncs its manifest there, atomically promotes the whole placement, and starts
the bound Harness Host actor. Only validated target readiness activates
generation N+1.

The transfer journal remains in `active` after cutover as the resident input
dispatcher for that placement. With no delivery in flight, its `input_job_id`
and `input_id` are null; repeated startup reconciliation is inert. Queued input
is dispatched through deterministic, target-pinned fleet jobs. A failed
delivery requeues the same input identity before a replacement fleet job is
created, preserving Harness Host idempotency.

Checkpoint or target-preparation failure compensates authority in the same hub
transaction: the pending target becomes terminal, the fenced source is restored
as the sole active placement, and pending/fenced lifecycle pointers are
cleared. Lease loss does not change session authority. A replacement attempt
may reclaim the same durable job, while completion from the abandoned attempt
is rejected.
