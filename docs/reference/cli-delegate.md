---
summary: "Queue, inspect, integrate, or cancel a remote child delegation."
title: "coven delegate"
---

`coven delegate` is the local, JSON-only interface to Coven's durable child
delegation saga. It is asynchronous: `start` returns after the hub has persisted
the child and fleet job, while an eligible outbound executor claims the work.

```sh
coven delegate start --request-stdin
coven delegate status <delegation-id>
coven delegate status <delegation-id> --collect
coven delegate integrate <delegation-id> --finalization-key <key>
coven delegate cancel <delegation-id>
```

Every command prints one `DelegationStatus` JSON object. Plain `status` is
read-only. `status --collect` imports a completed provisional result or records
a completed cleanup acknowledgment. There is no watch command yet; callers poll
with `status --collect`.

## Start request

`start` requires its JSON request on stdin so locators do not appear in process
arguments:

```json
{
  "protocolVersion": "coven.delegation.v1",
  "delegationId": "optional-stable-id",
  "parentSessionId": "optional-parent-id",
  "parentRepo": "/workspace/project",
  "baseRevision": "0123456789abcdef0123456789abcdef01234567",
  "task": "{\"writeFiles\":[{\"path\":\"result.txt\",\"content\":\"done\\n\"}]}",
  "workspaceDriver": "filesystem",
  "baseCheckpoint": {},
  "resultLocator": {},
  "requirements": [],
  "preferences": [],
  "harness": "fake"
}
```

The parent must be clean and `baseRevision` must be its full current commit ID.
The current proof supports only the credential-free `fake` harness and the
`filesystem` or `s3-checkpoint` workspace drivers. Provider-backed Codex or
Claude delegation is not enabled yet.

Requirements are translated into typed hard constraints. Supported forms are
`os:<windows|linux|macos>`, `arch:<x86_64|aarch64>`, `cpu-cores>=N`,
`memory-bytes>=N`, `gpu`, `gpu-vendor:<name>`, `gpu-model:<name>`,
`gpu-memory-bytes>=N`, `runtime:<name>=<exact-version>`, `tool:<name>`,
`harness:<name>`, `workspace:<driver>`, and the numeric protocol tags.
Preferences use the same leaf forms and contribute one bounded point each;
they never admit a node that fails a requirement. Ties are resolved by
hub-observed active work, bounded node pressure, then node id. A claim freezes
the selected capability observation and binds its digest to the child result.

## Platform matrices

A matrix fans out ordinary child delegations; it does not create another queue
or allow an aggregate to mutate the parent:

```sh
coven delegate matrix-start --request-stdin
coven delegate matrix-status <matrix-id>
coven delegate matrix-status <matrix-id> --collect
```

The `coven.delegation-matrix.v1` request carries the shared delegation fields
plus an `axes` array. Each axis has a unique `key`, its own `requirements`,
`preferences`, and `resultLocator`. Axes are canonicalized before stable lane
ids are derived. `allRequired` requires every lane; `allowPartial` also carries
`minSuccessful`. Aggregate results retain canonical per-lane node, placement,
platform, result, preview, and failure evidence while integration remains an
explicit per-child operation.

## States

| State | Meaning |
| --- | --- |
| `queued` | The child job exists; it may be waiting, leased, or executing. |
| `ready_to_integrate` | Collection validated a clean provisional result. |
| `conflicted` | Preview reported `diverged_parent`, `dirty_parent`, or `patch_conflict`; the result remains retained. |
| `applying` | Patch application began. Recovery requires the same finalization key. |
| `recovery_conflict` | Restart recovery found parent state that could not safely continue. |
| `cleanup_queued` | The parent accepted the patch; producer resources remain until cleanup acknowledgment. |
| `finalized` | Bound cleanup acknowledgment was collected. |
| `cancel_requested` | Leased work will be discarded and cleaned after it reports a result. |
| `cancel_cleanup_queued` | The result was rejected and producer cleanup is pending. |
| `cancelled` | Cancellation is terminal; queued work may reach it without allocating resources. |
| `failure_cleanup_queued` | The executor reported a typed terminal failure; producer cleanup is still pending. |
| `failed` | Failure evidence and the producer-bound cleanup acknowledgment are durable. |

A conflicted collection succeeds without mutating the parent. There is no
in-place conflict resolution or re-preview command yet; cancel it or start a new
delegation. `integrate` applies a patch to the parent working tree but does not
create a commit. Replaying the same finalization key is safe; a different key
fails closed.

## Retention and credentials

The producing executor retains
`COVEN_HOME/delegations/<delegationId>/<childId>/`, its actor, and the
attempt-bound `attempts/<attemptId>/result.json`
until integration or cancellation queues cleanup on that node. Cleanup stops
the matching actor generation and removes the allocation. Hub delegation rows
currently have no time-based pruning policy.

Execution failures use the strict `coven.fleet-failure.v1` envelope. Executors
report evidence; they do not choose retry policy. Reported failures are terminal
in this slice, while an expired lease remains eligible for hub-controlled
reclaim. Failed children follow the same producer-pinned cleanup handshake and
are not reported as `failed` until resources are acknowledged as released.

Coven queues orchestration data, never provider credentials. Harness Host
resolves authentication from executor-local state. Provider tokens must not be
placed in tasks, checkpoints, locators, results, capabilities, or logs.
