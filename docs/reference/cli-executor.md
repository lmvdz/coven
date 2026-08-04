---
summary: "Automatic fleet executors and the coven.executor.v1 compatibility commands."
read_when:
  - Looking up executor
  - Wiring a machine into the hub as an executor node
title: "coven executor"
description: "Reference for enrolling an automatic executor, offloading bounded work, and using the stateless coven.executor.v1 SSH compatibility commands."
---

`coven executor` supports the authenticated daemon-originated fleet channel and
the hub-initiated `coven.executor.v1` compatibility transport. Once a machine is
enrolled, its normal `coven daemon` process advertises fresh capabilities,
long-polls for leased work, renews live leases, and completes jobs without a
manual receive command. SSH and local-process dispatch remain operator-managed
edge transports for the same bounded envelope; see the
[fleet roaming decision](../../specs/coven-multi-host-daemon/ROAM-DECISION.md).
Neither transport gives an executor scheduling or canonical-state authority.

```sh
coven executor probe     # print this node's availability envelope as JSON
coven executor run-job   # run one hub-dispatched job from a JSON spec on stdin
```

## Automatic fleet setup

On the hub, create a single-use code. The usable code is returned once and the
hub stores only its verifier:

```sh
coven executor enrollment-code --label "GPU workstation"
```

On the executor, send that code through stdin so it does not appear in process
arguments:

```sh
printf '%s' "$ONE_TIME_CODE" | coven executor enroll \
  --hub https://coven-hub.example.ts.net \
  --node-id gpu-workstation \
  --code-stdin
coven daemon restart
coven executor fleet-status
```

The executor profile is stored as `fleet-executor.json` under `COVEN_HOME` with
owner-only permissions. `fleet-status` reports whether a credential exists but
never prints it. Provider credentials remain in their normal executor-local
stores and never pass through the hub.

The hub URL may use HTTPS, including a `tailscale serve` endpoint with a
publicly trusted tailnet certificate. Plain HTTP is supported for loopback,
tests, and an already authenticated private tunnel; it should not cross an
untrusted network.

From the hub, offload one bounded command and wait for its normalized result:

```sh
coven executor offload -- cargo test -p my-crate
coven executor offload --cwd /srv/project --timeout-seconds 600 -- cargo test
```

The hub selects the freshest eligible node. If an executor disappears, its
lease expiry requeues the logical job as a new attempt; late results from the
old attempt are rejected.

## Portable workspace operations

Install `coven-roam` on executor machines, or set
`COVEN_WORKSPACE_DRIVER_BIN` to its executable. The daemon probes the adapter
and advertises only workspace drivers that successfully answer
`coven.workspace-driver.v1`.

Send checkpoint, restore, release, or acquire requests through stdin so scoped
S3 URLs do not enter shell history:

```sh
printf '%s\n' '{"protocolVersion":"coven.workspace-driver.v1","requestId":"checkpoint-1","driver":"filesystem","operation":"checkpoint","workspacePath":"/workspace/project","generation":1,"locator":{"archivePath":"/checkpoints/project-1.tar.gz"}}' \
  | coven executor workspace --request-stdin
```

The same command works with `s3-checkpoint` and short-lived presigned URLs from
MinIO or another S3-compatible store. Long-lived S3 credentials remain with the
signing service and are rejected from leased requests. Archil remains an
optional executor-local accelerator, never the portability baseline.

## Managed harness actors

`coven executor actor --request-stdin` leases `coven.harness-host.v1`
operations. `start` selects an eligible node and creates executor-local actor
state; subsequent `send`, `status`, and `stop` operations are pinned to that
same node. The initial deterministic `fake` harness provides the lifecycle
proof without provider credentials:

```sh
printf '%s\n' '{"protocolVersion":"coven.harness-host.v1","requestId":"start-1","operation":"start","actorId":"actor-1","harness":"fake","generation":1}' \
  | coven executor actor --request-stdin
```

Actor event logs retain only content size and SHA-256 evidence, not input or
output text. Credential fields are rejected before durable queueing. Real
harness adapters will resolve OAuth and other provider state locally on the
executor; the hub receives readiness and normalized actor output, never the
credential itself.

## Probe

`probe` prints a JSON availability envelope — `protocolVersion`, `role`
(`stationary_executor` or `compute_executor`), advertised `capabilities`,
`available`, `queuePressure` (always 0: stateless executors hold no durable
queue; the hub owns queues), `covenVersion`, and `probedAt`. The node's
advertised role and capabilities come from the optional
`<covenHome>/executor.json`; an absent config means a stationary executor
with base capabilities. The hub polls the probe via
`POST /api/v1/hub/nodes/:id/poll` and fails closed when the advertised role
does not match the registration.

## Run-job

`run-job` reads one job spec from stdin — argv, cwd, env, stdin payload, and
opaque hub context, everything the node needs with no local durable
authority — executes it, and replies on stdout with a normalized result
envelope (stdout/stderr/exit metadata). Transport failures are normalized
into the same envelope shape by the hub-side dispatcher, so
`coven hub dispatch <jobId>` always has a record to show.

## Operating executors

Registration, dispatch, and recovery run through the hub API and CLI:

- `coven hub nodes [<id>]`, `coven hub jobs [<id>]`, `coven hub dispatch
  <jobId>` — read-side inspection ([cli-observe](cli-observe.md)).
- `POST /api/v1/hub/nodes/:id/{poll,dispatch}` — hub-initiated transport.
- [HUB-OPERATIONS](../HUB-OPERATIONS.md) — supervisor setup and restart
  runbook; the multi-host spec lives in
  `specs/coven-multi-host-daemon/TECH.md`.

Managed actors and portable workspaces are composed into remote child work by
[`coven delegate`](cli-delegate.md). Delegation authority and result acceptance
remain hub-owned; the executor interface performs only leased operations.
