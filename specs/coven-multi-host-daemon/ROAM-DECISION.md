# Coven Fleet Roaming Decision

**Status:** Ratified architecture baseline - 2026-08-03
**Decision owner:** Lars van der Zande
**Companions:** [Product specification](./PRODUCT.md), [Technical specification](./TECH.md)

## Decision question

How can an always-on server, desktop, laptop, VM, or ephemeral worker become an
automatically discoverable Coven executor and receive a live session without a
human running a receive command, while preserving the hub as the sole authority?

## Decision

An enrolled Coven daemon may maintain an authenticated outbound job channel to
its hub. The channel carries capability and liveness observations from the node
and leased work from the hub. It does not transfer scheduling, session,
generation, memory, or queue authority to the executor.

The same executor contract applies to always-on and intermittent machines. A
laptop may be both a travel client and an executor, but those roles have
separate state and permissions. Losing hub connectivity disables its executor
role; it does not grant the travel client authority over hub state.

The foundational product invariant is:

> A Coven session belongs to Coven, not to a computer, executor process,
> harness, or provider. Execution placement may change or end without changing
> the session's identity or lifecycle.

Roaming is an automatic, hub-owned saga. There is no normal interactive
`receive` step:

1. The hub fences new turns on source generation `N` and leases a checkpoint
   job to executor A.
2. A writes an immutable, hash-verified checkpoint to the selected workspace
   store and reports its reference.
3. The hub leases restore and start-session work for generation `N+1` to B.
4. B restores the checkpoint and starts the selected harness with credentials
   already present on B.
5. B reports a harness readiness proof. Only then does the hub make `N+1` on B
   authoritative and route subsequent session input there.

## Binding invariants

1. **Hub authority:** the hub is the sole writer of node enrollment, queue
   assignments, leases, session generations, scheduler decisions, and canonical
   familiar memory.
2. **Outbound is not authority:** executor registration, heartbeat, claim,
   progress, and completion requests are observations or lease operations that
   the hub validates against enrolled node identity and current generation.
3. **Explicit enrollment:** tailnet membership or network reachability alone
   never authorizes work. Enrollment creates a revocable, node-scoped
   credential. The hub stores only a verifier, not the usable secret.
4. **Local provider identity:** Claude, Codex, and other harness credentials
   remain on the executor. They are neither checkpointed nor sent by the hub.
5. **Capability freshness:** scheduling uses capabilities from a live daemon
   lease, not installation claims or stale registry rows. Runtime capability
   means installed, compatible, and locally usable.
6. **Exactly one active generation:** output is accepted only for the active
   `(session_id, generation, node_id)` tuple. Retries use stable idempotency keys
   and cannot create a second active target.
7. **Immutable transfer baseline:** portable roam requires checkpoint and
   restore. Shared mounts and provider-specific remote execution are optional
   accelerators, never portability requirements.
8. **Managed sessions outlive jobs:** restore and start are leased jobs, but the
   resulting harness is a daemon-managed session actor. Starting returns a
   bounded readiness result instead of holding a generic job open indefinitely.
9. **No raw daemon exposure:** local daemon sockets stay local. Fleet endpoints
   are a separate authenticated protocol and may be carried over Tailscale,
   HTTPS, or another mutually authenticated private transport.
10. **Fail closed with recoverable work:** an expired lease never silently
    promotes a target. Once a checkpoint exists, the hub may retry B or select C
    from the same checkpoint. Before a checkpoint exists, the hub may safely
    cancel the fence and resume A if A is still the current source.
11. **Queued interaction during cutover:** user input arriving during a roam is
    hub-owned and queued. It is delivered only after a target generation becomes
    active.
12. **Protocol compatibility:** enrollment records protocol ranges. A node
    cannot claim work whose executor, workspace-driver, roam, or harness-adapter
    version it does not support.
13. **Independent lifecycles:** logical session, executor placement, and
    individual run are separate state machines. Finishing a run does not close
    the session; releasing a placement suspends or relocates the session.
14. **One canonical integration path:** remote child results, roam completions,
    artifacts, verification, and proposed memories return through hub-owned
    result integration. A child never writes directly into a parent's active
    workspace or canonical familiar memory.

## Deep module boundaries

The implementation is organized as a small set of deep modules. Each invariant
has one owner; workflows compose modules rather than duplicating their logic.

| Module | Owns | Narrow interface |
| --- | --- | --- |
| Session Authority | logical session lifecycle, canonical events, generation fencing, active placement, queued input, finalization | begin/finalize run, begin transfer, activate placement, suspend |
| Fleet Registry | enrollment, node identity, credential verification, connection epochs, fresh capabilities, availability | enroll, observe, list eligible, revoke |
| Placement Scheduler | constraint matching, preferences, policy, ranking, explanation | place work and return one decision |
| Durable Work Engine | queues, attempts, claims, leases, renewal, idempotency, retry, cancellation | submit, claim, renew, progress, complete, cancel |
| Workspace Mobility | portability checks, checkpoint, restore, diff, cache/release, storage adapters | probe, checkpoint, materialize, diff, release |
| Harness Host | installed/authenticated readiness, managed harness actors, normalized input/output, local continuation ids | probe, start, send, status, stop |
| Result Integration | parent/child linkage, base-revision validation, patches, artifacts, verification, conflicts, memory proposals | validate, preview, apply |
| Orchestration | sequencing and compensation for delegation and roaming | delegate/collect/integrate; roam/status/cancel |

Dependency direction is one-way:

```text
CLI / Cave / API
        -> Orchestration
             -> Session Authority
             -> Placement Scheduler
             -> Durable Work Engine
             -> Workspace Mobility
             -> Harness Host
             -> Result Integration
        -> Fleet Registry and edge adapters
```

The scheduler never executes work. The work engine never chooses nodes. Fleet
registration never changes session authority. Workspace mobility never knows
about a harness. Harness adapters never write hub state. Cave remains a thin
client. Tailscale, SSH, S3, Archil, Claude, Codex, OS-specific probes, and cloud
providers are edge adapters, not domain types.

These modules remain inside Coven unless they form a genuine protocol/package
boundary. Workspace Mobility uses the standalone `coven-roam` protocol; this is
not a reason to split every module into a service or repository.

## Fleet workflows

The fleet exposes three workflows over the same modules:

1. **Tool offload:** run one bounded command remotely and return evidence.
2. **Task delegation:** create a scoped child execution branch, possibly in
   parallel or across a platform matrix, then return a summary, changes,
   artifacts, verification, and memory proposals to the parent session.
3. **Session roam:** transfer the active placement of the logical parent session
   after a generation-fenced checkpoint and target readiness proof.

Delegation is the default for compute, RAM, GPU, OS/architecture testing, and
parallel code churn. The parent remains active. Roaming is reserved for moving
the whole interactive session. Both use the same registry, scheduler, leases,
workspace revisions, harness adapters, and result protocol.

For code-changing delegation, the child receives an immutable base revision and
an isolated workspace. It returns a patch, commit bundle, or content-addressed
change set tied to that base. Result Integration detects overlap and requires an
explicit integration decision when the parent has diverged. Concurrent agents
do not mutate one shared directory.

Platform matrix work fans out one child per normalized requirement set and
aggregates results into the parent. Source changes may integrate; binaries and
test artifacts remain tagged with their OS, architecture, runtime, and hardware
facts.

## MVP protocol

The hackathon proof uses authenticated long-polling because it works behind NAT,
on laptops, and in environments without inbound SSH. A future streaming
transport may replace the wait mechanics without changing lease semantics.

Conceptual fleet endpoints:

```text
POST /api/v1/fleet/enrollments/redeem
POST /api/v1/fleet/nodes/:nodeId/heartbeat
POST /api/v1/fleet/nodes/:nodeId/jobs/claim?wait=25
POST /api/v1/fleet/jobs/:jobId/progress
POST /api/v1/fleet/jobs/:jobId/complete
```

Every authenticated request includes the node identity. Every job mutation is
validated against its node, attempt, lease token, expiry, and session generation.
Job leases are bounded and renewable. Completion is idempotent.

The existing hub-initiated `coven.executor.v1` SSH transport remains supported
for operator-managed servers. Both transports deliver the same versioned job
envelope and produce the same normalized result; they do not create two queue or
authority models.

## Capability model

Capabilities are typed facts discovered by the daemon and normalized by the
hub, not an unbounded collection of scheduler-specific strings:

```json
{
  "protocols": {"executor": [1], "workspaceDriver": [1]},
  "platform": {"os": "macos", "architecture": "arm64", "version": "26.1"},
  "resources": {"cpuCores": 12, "memoryBytes": 34359738368},
  "gpu": {"vendor": "apple", "model": "M4 Pro", "memoryBytes": 17179869184},
  "runtimes": {"node": ["22", "24"], "rust": ["stable"]},
  "harnesses": ["claude", "codex"],
  "workspaceDrivers": ["filesystem", "s3-checkpoint"],
  "tools": ["xcode", "docker", "cargo"]
}
```

Placement requests distinguish hard requirements from ranking preferences.
Harness presence means its adapter passes a bounded local readiness probe; the
probe must not reveal tokens, account identifiers, or credential material.
Generated dependencies and build caches are reconstructed on the target rather
than transported across incompatible operating systems or architectures.

## Roam state and recovery

```text
preparing
  -> checkpointing
  -> checkpointed
  -> restoring
  -> starting
  -> active
```

`failed` and `cancelled` are terminal attempt outcomes, not permission to accept
stale output. Retrying creates a new attempt under the same target generation
when safe; starting a new roam increments the generation.

The source is turn-fenced while checkpointing but remains the rollback candidate
until an immutable checkpoint is committed. After checkpointing, recovery
prefers replaying that checkpoint on an eligible executor rather than allowing
divergent writes on the source workspace.

## Completion and release

Run completion is a hub-acknowledged finalization transaction:

```text
running
  -> finalizing
       -> flush normalized events and result
       -> commit a post-run workspace revision
       -> upload artifacts and verification
       -> report the current session, generation, node, and lease
  -> hub committed
  -> idle resident or released
```

Until hub acknowledgment, the executor retains its process, workspace, and
lease, and the result remains provisional/retryable. A serverless or ephemeral
environment must not terminate before this acknowledgment.

After a turn, placement policy chooses among `sticky`, `release-after-turn`, and
`until-session-close`. User-owned and always-on machines normally remain sticky;
metered or ephemeral workers normally checkpoint and release. The hub owns this
policy. Releasing an executor moves an open session to `suspended`; only an
explicit user action or completed workflow moves the logical session to
`completed`.

The three independent state machines are:

```text
session:   open -> suspended -> completed
placement: unassigned -> starting -> active -> finalizing -> released
run:       queued -> running -> succeeded | failed
```

If a node disappears during finalization, the last hub-committed workspace
revision remains authoritative. Partial output may be retained as uncommitted
evidence, but it cannot advance the session generation.

## Laptop role separation

One daemon process may host both roles, but their authority is distinct:

- **Executor mode** requires a live hub lease and performs only leased work.
- **Travel mode** uses a scoped read-only profile and append-only offline delta.

Offline travel work never masquerades as completion of a leased executor job.
Reconnect reconciliation happens before the laptop becomes eligible to receive
roaming work for the affected workspace.

## Workspace and secrets boundary

The workspace checkpoint contains only the configured workspace root after
policy exclusions. At minimum, the checkpoint implementation must reject or
exclude credential stores, sockets, device files, and paths outside that root.
Harness auth stores, OAuth tokens, SSH keys, Tailscale state, node credentials,
and the hub database never move with a session.

The hub stores the checkpoint driver, immutable locator, digest, size,
generation, and expiry metadata. Short-lived transfer URLs may be refreshed for
the same immutable object without changing checkpoint identity.

## Rejected alternatives

- **Manual receive command:** fails the automatic fleet product contract.
- **SSH-only dispatch:** useful fallback, but excludes sleeping laptops, NATed
  nodes, and many ephemeral runtimes from a uniform availability model.
- **Raw daemon socket over the tailnet:** exposes a local trust surface without
  fleet-scoped authentication or authorization.
- **Trust Tailscale membership alone:** network identity does not express Coven
  enrollment, revocation, job scope, or hub ownership.
- **Copy provider OAuth state:** expands credential exposure and breaks the
  executor-local identity boundary.
- **Make Archil mandatory:** excludes unsupported platforms and couples session
  mobility to one storage provider.
- **Treat a harness as a generic long-running job:** conflicts with bounded job
  leases, output limits, readiness reporting, and interactive input routing.
- **Peer-to-peer handoff:** bypasses hub fencing and creates ambiguous authority
  during partitions.

## Deferred without blocking the MVP

- WebSocket or HTTP/2 streaming in place of long-polling.
- Wake-on-LAN and provider-specific machine startup.
- Automatic cost-aware serverless provisioning.
- Live migration of an in-flight model request.
- Shared-mount optimizations and Archil-native checkpoints.
- Multi-hub federation.

## MVP proof gate

Using two daemon processes with separate `COVEN_HOME` directories, one command
must move an idle session from A to B. B must claim the job without an operator
command, restore a hash-verified checkpoint, start a fake deterministic harness,
report readiness, become the sole active generation, accept the next input, and
reject a late result from A. Restarting B during restore must resume or safely
retry without creating a second active generation.

A second proof delegates a platform-scoped child task while the parent remains
active. The child must run on a matching executor, return a base-bound change set
and verification evidence, and integrate through the parent without directly
mutating its workspace or memory.
