# Coven Fleet Migration Path

**Status:** Wayfinder review draft - 2026-08-03
**Baseline:** [Fleet roaming decision](./ROAM-DECISION.md)
**Scope:** Current Coven runtime, `coven-roam`, and the optional Coven Cave surface

## Outcome

Reach automatic tool offload, remote child delegation, and whole-session roaming
through one hub-authoritative fleet stack. Each implementation slice must exercise
the final module boundaries. Existing prototypes are inputs to the migration, not
independent authority models that must be preserved.

## Current inventory and disposition

| Current asset | Evidence today | Decision | Target owner |
| --- | --- | --- | --- |
| `executor_node.rs` and `coven.executor.v1` | Versioned bounded command/result envelopes, probes, timeouts, output limits, SSH and local transports | **Keep and adapt.** Retain the bounded payload/result semantics. Add lease identity and typed work kinds around it; do not fork the envelope for pull workers. | Durable Work Engine with SSH and outbound-poll edge adapters |
| Hub node registry, scheduler, queues, assignments, and dispatch in `hub.rs` | Durable nodes and jobs, capability filtering, queue pressure, SSH/local dispatch | **Split by authority.** Preserve schema/data where compatible, but move registry, placement, work lifecycle, and transport decisions behind separate deep interfaces. | Fleet Registry, Placement Scheduler, Durable Work Engine |
| Local daemon API and Unix socket | Mature same-user control plane | **Keep.** It remains the local operator/client boundary. Fleet HTTP endpoints are a distinct authenticated surface, never a remotely exposed local socket. | Local API edge; Fleet Registry/Work Engine fleet edge |
| Local session launch, PTY runner, harness adapters, event capture | Can launch and interact with local harness processes | **Wrap and deepen.** Introduce a managed actor interface with probe/start/readiness/send/status/stop. Do not run an interactive harness as one generic long job. | Harness Host |
| Session rows and event persistence | Existing logical sessions, local events, status | **Migrate.** Add explicit logical session, placement, generation, queued-input, run, and finalization records. Hub sequencing becomes canonical in fleet mode. | Session Authority |
| `roam.rs`, `session_roams`, and roam progress API | Generation counter, target filtering, transition checks, stale-node rejection | **Harvest then replace.** Reuse tests and fencing concepts. Remove direct client-driven progress and ad hoc target selection once Orchestration owns the saga. | Session Authority plus Orchestration |
| `handoff.rs` and `coven.handoff.v1` | Neutral session summary/continuation artifact | **Keep as optional context evidence.** It is not workspace state, session authority, or a transport protocol. | Orchestration input/output |
| `coven-roam` / `coven.workspace-driver.v1` | Filesystem and S3-compatible immutable checkpoints, SHA-256 verification, presigned transfer, optional Archil acceleration | **Keep as the standalone protocol boundary.** Harden policy/exclusions and call it through Workspace Mobility. Accept legacy driver aliases only at the edge. | Workspace Mobility; implementation remains in `lmvdz/coven-roam` |
| Archil adapter | Shared-mount and remote-exec capabilities on supported systems | **Keep optional.** Never require it for checkpoint/restore or macOS compatibility. | Workspace Mobility edge adapter |
| Cave roam modal and proxy route | Thin request/status UI prototype | **Defer and reshape.** Preserve useful UI work, but bind it to orchestration status and scheduler explanations only after daemon contracts stabilize. | `lmvdz/coven-cave` |
| Manual `roam progress` / receive-like workflow | Lets a caller advance internal states | **Remove from normal product flow.** Retain only guarded diagnostic/test hooks if needed. Executors claim work automatically; the hub advances sagas from validated work results. | Development edge only |

## Target ownership and dependency seams

The eight ratified modules stay inside `lmvdz/coven` initially. They should be
Rust modules with narrow traits and stores, not services or new repositories.
The dependency direction is:

```text
local CLI/API and Cave proxy
  -> Orchestration
       -> Session Authority
       -> Placement Scheduler -> Fleet Registry
       -> Durable Work Engine -> Fleet Registry
       -> Workspace Mobility -> coven.workspace-driver.v1 process adapter
       -> Harness Host -> local harness adapters
       -> Result Integration
```

Cross-cutting database transactions may be implemented in one SQLite store, but
domain mutations remain reachable only through their owning module. Transport
adapters translate requests; they do not contain scheduling or saga logic.

Repository boundaries are deliberately small:

| Repository | Responsibility |
| --- | --- |
| `lmvdz/coven` | All authority modules, executor daemon loop, fleet API, protocols, orchestration, persistence, CLI, deterministic multi-daemon proofs |
| `lmvdz/coven-roam` | `coven.workspace-driver.v1`, portable checkpoint implementations, storage adapters, archive safety |
| `lmvdz/coven-cave` | Thin status, selection, explanation, approval, and recovery UX after Coven APIs are stable |

No Coven upstream repository needs to be forked again, and no new
`coven-execute` repository is justified. The executable fleet runtime belongs in
Coven; only Workspace Mobility already has a real process/protocol boundary.

## Compatibility and migration rules

1. Define one versioned work envelope with a discriminated work kind. The
   existing bounded shell job is the first kind. SSH push and authenticated
   outbound claim both carry that envelope and complete through the same Work
   Engine transaction.
2. Read existing node/job rows through adapters while introducing normalized
   enrollment, capability observation, attempt, and lease records. Stop writing
   legacy assignment fields only after both transports use the new engine.
3. Keep current single-machine behavior as an implicit local node. It should use
   the same scheduler/work interfaces without requiring fleet enrollment.
4. Introduce authoritative session/placement/run records beside existing
   session rows, backfill lazily, and preserve session IDs. Do not infer logical
   completion from a process exit.
5. Convert roam endpoints from state mutation endpoints into orchestration
   commands and read-only status. Work completions are the only normal path that
   advances checkpoint, restore, readiness, and finalization states.
6. Keep `coven.handoff.v1` readable throughout migration, but never use it as a
   substitute for a content-addressed workspace revision or canonical events.
7. Cave remains compatible with the existing daemon until the new orchestration
   response is stable; then its prototype route/modal is rebased onto that
   response and the provisional assumptions are deleted.

## Vertical slices and gates

### Slice 1: fleet foundation and bounded tool offload

Implement explicit one-time enrollment, node-scoped revocable credentials,
fresh typed capability observations, authenticated long-poll claims, renewable
leases, and idempotent completion. Adapt `coven.executor.v1` bounded shell work
to this engine. Prove one command can select and execute on a second daemon
without SSH or a manual receive command, while SSH continues to pass the same
envelope through the same completion path.

This is the first shipping gate because it validates Fleet Registry, Placement
Scheduler, Durable Work Engine, executor identity, and the transport seam with
no dependency on session migration.

### Slice 2: workspace mobility contract in the work engine

Integrate `coven.workspace-driver.v1` as checkpoint/materialize/release work
kinds. Enforce root confinement, archive exclusions, digest/size/generation
metadata, immutable object identity, expiring URL refresh, and capability
version negotiation. Prove filesystem and self-hosted S3-compatible storage;
keep Archil optional.

### Slice 3: managed harness host

Place existing local harness launch and PTY behavior behind a daemon-owned
managed actor interface. Use a fake deterministic harness first. A start job
must return bounded readiness, while later input/output flows through the actor
identity. Provider credentials remain local and probes reveal only readiness.

### Slice 4: remote child delegation and result integration

Add base-revision-scoped delegation, isolated materialization, child execution,
post-run checkpoint, artifacts, verification, and a normalized result bundle.
Validate and preview a base-bound change set before applying it to the parent;
detect divergence and never write canonical memory directly. Prove the parent
stays active while the child runs and receives the result through one
hub-acknowledged finalization transaction.

### Slice 5: session authority and automatic roam

Introduce independent session, placement, and run lifecycles; generation
fencing; queued input; and retention policy. Orchestration then composes source
fence, checkpoint, target materialization, managed harness readiness, atomic
placement activation, and source release. Replace manual roam progress with
validated job completion. Run the two-daemon proof from the ratified decision,
including target restart and stale-source rejection.

### Slice 6: heterogeneous scheduling and platform matrices

Expand typed capabilities and hard-requirement/preference matching for OS,
architecture, resources, GPU, runtimes, tools, harnesses, and workspace driver
versions. Fan out delegation children by platform, tag evidence, and aggregate
results without transporting platform-specific caches.

### Slice 7: Cave product surface

Expose fleet availability, scheduler explanations, delegation/roam progress,
finalization, recovery, and explicit conflict decisions through thin Coven API
proxies and design-system-compliant UI. The UI never advances internal states or
stores node credentials.

## Security gates

Every slice fails closed unless its applicable gates pass:

- enrollment codes are single-use, short-lived, scoped to one hub, and exchanged
  for a rotatable node secret whose verifier—not usable secret—is stored;
- all fleet mutations bind node, attempt, lease token, expiry, protocol range,
  and when applicable `(session_id, generation, placement_id)`;
- replayed completion is idempotent, while wrong-node, expired-lease, and stale-
  generation mutations are rejected and audited;
- capability observations are bounded, schema-validated, non-secret, tied to a
  connection epoch, and expire when heartbeats stop;
- job input, environment, output, artifacts, and paths are bounded; secrets are
  explicit local references rather than serialized values;
- workspace archives reject traversal, links escaping the root, device files,
  sockets, credential paths, and digest/size mismatches;
- presigned URLs are short-lived and object-scoped; the hub stores immutable
  object identity separately from renewable transfer authorization;
- local daemon sockets remain local, and Tailscale reachability never substitutes
  for Coven enrollment or request authentication;
- harness OAuth/provider state, SSH keys, Tailscale state, and node credentials
  never enter checkpoints, work results, logs, or Beads.

## Proof suite

The release suite grows cumulatively:

1. Two isolated daemon homes: enroll, heartbeat, claim, renew, execute, complete,
   replay completion, revoke, and reject expired/wrong-node leases.
2. Run the same bounded shell envelope over local push, SSH push, and outbound
   pull adapters and compare normalized results.
3. Kill/restart hub and executor at each lease boundary and prove retry without
   duplicate execution authority.
4. Checkpoint and restore a hostile fixture plus a normal repository through
   filesystem and MinIO/S3-compatible storage; verify hashes and exclusions.
5. Start/restart/stop a deterministic managed harness and prove readiness and
   local credential isolation.
6. Delegate a child from an immutable base, advance the parent independently,
   and prove clean integration or explicit conflict without shared-directory
   mutation.
7. Roam A to B automatically, queue input during cutover, restart B during
   restore, accept only B generation `N+1`, and reject late A output.
8. Select and fan out against synthetic Windows, Linux, macOS Intel, macOS Apple
   Silicon, and GPU capability observations; never schedule on stale facts.

### Release gate ownership

The proof suite crosses the repository boundary by design; a Coven release must
not silently replace the workspace-driver implementation's tests with protocol
mocks. Groups 1-3 and 5-8 are exact-name gated by
`node scripts/fleet-release-proof.mjs` in the Coven CI and release workflows.
The Coven side of group 4 proves leased dispatch and strict protocol response
validation there as well. The implementation side of group 4 is owned and run
by `lmvdz/coven-roam` CI:

```text
pnpm typecheck
COVEN_ROAM_MINIO_TEST=1 pnpm test
```

That job starts a pinned, isolated MinIO server and proves filesystem and live
S3-compatible checkpoint/restore, independent archive hashes, exclusions,
generation/size/digest rejection, immutable object tamper rejection, expiring
presign refresh, traversal/link/device/socket hostility, and non-activation of a
failed destination. Unix socket and successful SSH-adapter fixtures are explicit
Ubuntu CI gates; portable archive and scheduler logic remains platform-neutral.

Every manifest proof is executed with libtest's `--exact` filter. Discovery is
only a fail-fast guard for deleted or renamed tests; it is not evidence that a
proof ran. Adding `#[ignore]` to a required proof therefore fails the release
because the exact invocation executes ignored tests as zero tests rather than
reporting a passing proof.

## Explicit deferrals

The migration does not block on WebSockets, wake-on-LAN, provider provisioning,
cost-aware autoscaling, in-flight model-request migration, Archil-native
checkpointing, shared-mount acceleration, multi-hub federation, production
Windows service packaging, or offline travel reconciliation. The interfaces
must leave room for these, but MVP code should not simulate them prematurely.

Serverless executors use the same outbound lease protocol and finalization ACK.
They become a deployment adapter only after the durable work and delegation
proofs pass. They must use executor-local provider authentication or separately
purchased API credentials; Coven will not proxy a consumer OAuth subscription
into an untrusted runtime.

## Review checkpoint

Implementation begins only after this ordering is accepted. Approval makes the
fleet foundation the first ready unit; later units remain dependency-blocked.
The current roam prototype stays uncommitted evidence until its reusable tests
and types are moved into the owning modules during the session-authority slice.
