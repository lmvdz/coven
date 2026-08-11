# Coven Fleet trust and discovery

Coven Fleet is the authority for device identity, enrollment, durable trust,
reconnect, and revocation. Coven Discovery only finds possible service
addresses. Tailscale supplies encrypted reachability and a bounded peer
inventory; being in the same tailnet never grants Coven authority.

## Trust boundary

The Rust daemon owns all decisions and durable records. A Cave client may call
the versioned API to present setup and management, but it cannot create trust by
writing Cave configuration. Roam remains independent: portable workspace
checkpoints do not contain fleet credentials or define fleet membership.

Only the minimal advertisement is publishable to untrusted peers. Enrollment
creation, trust listing, and revocation are local/admin operations and must not
be routed through the discovery listener. Enrollment redemption and reconnect
are the only remote trust endpoints; their possession/proof checks are the
authorization boundary.

The hub persists only hashes of enrollment and node credentials. A node
credential is returned once, after credential enrollment or explicit approval,
then stored in the executor's local Coven store. Cave asks that local daemon to
derive reconnect proofs; routine management never reads the credential back.
Reconnect sends a proof derived from that credential and a short-lived
single-use challenge; it does not retransmit the credential. Revocation is
durable and idempotent.

## Discovery disclosure

`GET /api/v1/discovery/advertisement` is the only response intended for an
untrusted probe. It discloses:

- the constant service name;
- supported protocol versions; and
- configured local fleet roles (`hub`, `executor`, or `both`); and
- whether an administrator has opened a short enrollment window.

It never discloses hub or node identity, device names, users, paths, registry
membership, capabilities, queue state, jobs, or credential material. Discovery
clients must probe only addresses returned by a local Tailscale peer inventory,
with strict connection and response-size limits. They must not scan the tailnet
address range.

## Protocol flow

1. Cave asks the local Tailscale client for its peer inventory and probes only
   those peers for the minimal advertisement.
2. Cave negotiates `coven.fleet.v1`. No common version fails closed.
3. Enrollment follows either path:
   - A hub administrator creates a credential with a maximum ten-minute
     lifetime. The executor redeems it once with its node id.
   - The executor creates a five-minute pairing request and retains its private
     request secret. Cave lists the minimal pending request, and the user
     explicitly approves or denies it. The executor claims an approved request
     once using its secret. Denial creates no trust.
4. The hub atomically consumes the enrollment or approved request and returns a
   durable node credential exactly once. Cave immediately gives it to the
   executor's local daemon through `POST /fleet/local-credentials`; subsequent
   proof requests never return the credential.
5. On reconnect, the executor requests a 60-second challenge and sends
   `SHA-256("coven.fleet.v1" || NUL || SHA-256(node credential) || NUL || nonce)`.
   Challenges are single-use. A valid proof updates `lastSeenAt`.
6. Revocation marks the trust record durably. Further challenges and reconnects
   fail even after daemon or device restart.

Enrollment secrets and proofs require a confidential, authenticated transport.
On a tailnet, clients should use Tailscale identity-aware HTTPS or another
authenticated channel and still apply Coven authorization. Discovery metadata
alone is never evidence of trust.

## Threats and failure behavior

- An unrelated tailnet peer can learn only minimal advertisement fields and
  cannot enroll without a live credential.
- Captured enrollment credentials expire within ten minutes and cannot be
  replayed after first use.
- Pairing requests expire after five minutes. Approval alone is insufficient:
  only the requester holding the private request secret can claim the durable
  credential, and it can do so once.
- Captured reconnect proofs cannot be replayed because challenges expire and
  are consumed atomically.
- A copied durable credential remains dangerous until revoked; executor-local
  storage permissions and OS credential custody are therefore required.
- Version mismatch, unknown nodes, expired credentials, used challenges, and
  revoked nodes all fail closed with structured error codes.

This first protocol version uses a shared-secret challenge proof. A later
version may negotiate public-key device identity without changing the rule that
tailnet membership is transport context, never authorization.

## Local role, lifecycle, and sharing

The local daemon exposes a stable device id and persisted desired state at
`GET /api/v1/fleet/local-node`. Cave configures `hub`, `executor`, or `both`
through `PUT /fleet/local-node/role`. Fleet lifecycle actions are desired-state
operations: `start`, `stop`, `drain`, and `resume` are safe to repeat. `restart`
requires an `operationId`; replaying the same id returns the current state
without applying a second restart, while reusing it for another action fails.

Executor sharing is off by default and can be enabled only for `executor` or
`both`. The executor probe derives availability from the authoritative state:
it advertises available only while the fleet service is running, sharing is
enabled, and the local role includes executor. Draining immediately rejects new
dispatch while an already-running stateless job is allowed to finish.

## Desktop transport

Cave starts the local daemon with `COVEN_DAEMON_TCP=127.0.0.1:8787` and an
explicit `COVEN_DAEMON_ALLOW_HOST` containing only the machine's current
Tailscale IPv4 address. The background-daemon launcher carries those settings
into the hidden `daemon serve` process on macOS, Linux, and Windows. The daemon
still binds only to loopback; Cave publishes that one socket through a
tailnet-private Tailscale TCP Serve route.

Port 8787 is a restricted Fleet listener. It accepts only the minimal discovery,
enrollment redemption, pairing request/claim, challenge, and reconnect routes.
Local administration, health, memory, sessions, trust listing, approval,
revocation, and all other daemon APIs return `403` on that listener. The normal
Unix socket or Windows named pipe remains the local administration transport.

Cave inspects `tailscale serve status --json` before changing Serve state. It
claims port 8787 only when unused, treats the exact `127.0.0.1:8787` forward as
its own idempotent route, refuses to overwrite any other route, and removes only
that exact owned forward when Fleet stops.
