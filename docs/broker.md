# Credential-isolated reference inference broker (MVP.2d)

**Deferred legacy API transport.** Deploying this broker is not an approved next
step for the selected ChatGPT-subscription path. The checklist below is retained
as reference, not current deployment authorization.

`agent-platform-broker` (also `python -m agent_platform.broker`) is a separate,
foreground Linux process. Nothing in `prepare`, `doctor`, `run` or `resume` starts,
installs or configures it. The code is a reference implementation with offline
contract tests, **not an independently audited or production-ready deployment**.
No real credentials, hosted inference, privileged installation or live isolation
were used to build/test it. Real E2E remains BLOCKED until the operator completes
the external prerequisites and [live runbook](e2e.md).

## Interface and configuration

The existing [execution contract](execution.md) is unchanged:

- `GET /agent-platform/health` returns exactly protocol 1, configured broker ID,
  inference_only true, credentials_exposed false and network_tools false.
- `POST /v1/responses` accepts the explicit streaming inference subset below.
- Every other route/method, including CONNECT, auth, admin, models, query strings,
  absolute proxy URLs and alternate transports is denied with 403.

Linux SO_PEERCRED authenticates the exact **pair** of UID and primary GID on each
accepted AF_UNIX connection, before reading headers or a body. Socket permissions
and caller headers cannot replace that check. The PID is not an authority. Check
which host UID/GID the actual user-namespace relay presents; never assume its
namespace UID 0 is host root. An authorized host process under that same pair
shares the allowance: this is not per-process or per-task identity attestation.

Configuration is an explicitly selected owner/root-owned regular 0600 file, not
inside any task worktree, with no symlink ancestors, insecure writable ancestors
or external hardlinks. It is <=16 KiB; duplicate JSON keys, nonfinite numbers,
unknown fields and invalid policy values fail closed. Example **nonsecret schema**
(replace identity/model/peer values deliberately; this example grants nobody):

```json
{
  "version": 1,
  "endpoint": "https://api.openai.com/v1/responses",
  "broker_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "peers": [[12345, 12345]],
  "models": ["operator-approved-model"],
  "limits": {
    "concurrency": 1,
    "requests_per_peer": 16,
    "total_requests": 16,
    "lifetime_seconds": 300,
    "request_seconds": 120,
    "idle_seconds": 10,
    "max_output_tokens": 4096
  }
}
```

The endpoint must equal the literal value shown. The only TLS connection is to
`api.openai.com:443`, using that hostname for SNI/certificate verification and the
fixed `/v1/responses` path. System trust roots are used with TLS >=1.2, certificate
verification and hostname checking. There is no URL override, proxy environment
support, redirect following, alternate transport, connection pooling or retry.
The upstream host/model cannot be changed by a request. An operator chooses
1–16 explicitly allowed model identifiers; there is no live/default account.
The ID must be exactly 64 lowercase hex characters and match profile.json.

The credential is **not** a config field, environment lookup or CLI argument.
An operator-owned launcher passes an already opened descriptor >=3 to a private
0600, owner/root-owned regular secret file with one link. Only the descriptor
number is given through `--credential-fd`. The broker reads at most 513 bytes,
requires 16–512 ASCII letters/digits/underscore/hyphen (no newline), and closes
the descriptor immediately. Pipes/sockets/stdio and insecure files are rejected.
Provision/open that descriptor through separately reviewed secret management;
never paste the token into a command, prompt or repository. No credential path
is discovered automatically. The credential then exists in broker memory and its
fixed outbound Authorization header, never intentionally in requests to the model,
client responses, checkpoints or logs. Python cannot guarantee secure memory
zeroization; prevent memory/core/ptrace access through external confinement.

After external deployment approval, the launch interface is:

```text
agent-platform-broker --config <private-policy-file> --socket <trusted-socket-path> --credential-fd <preopened-descriptor>
```

This is an interface example, not an installation command. Tests use only private
temporary directories, fabricated tokens and injected fake upstreams. The test
injection is a Python API, not a CLI option for arbitrary HTTP endpoints.

## Strict inference subset

Request validation uses the [official Responses create schema](https://developers.openai.com/api/reference/python/resources/responses/methods/create)
as a reference, then deliberately accepts a smaller explicit subset:

- Required: configured `model`, `input` and `stream: true`. `store`/`background`
  must be false if present and are always explicitly sent false upstream. This
  rejects persistent/background requests; it does not promise provider-side zero
  retention or replace the operator's contractual provider retention controls.
- Optional: bounded `instructions`; `max_output_tokens` within policy;
  `parallel_tool_calls` boolean; `tool_choice` only auto/none; `reasoning` with
  enumerated effort/summary; `text` with plain-text format and enumerated verbosity;
  `include` only empty or `["reasoning.encrypted_content"]` for stateless history.
- Input: text, text-only system/developer/user/assistant messages, explicit
  function/custom calls and their string outputs, and reasoning summaries with
  optional opaque encrypted content. Image/file/audio/URL retrieval, item references,
  previous_response_id, conversations and other persistent references are refused.
- At most 64 function/custom declarations with distinct bounded names. Functions
  carry inert JSON Schema (external $ref/$dynamicRef prohibited; local references
  allowed); custom declarations permit text or explicit lark/regex grammar metadata.
  The broker never resolves schema references, compiles grammars, dispatches tool
  calls, launches code or executes their side effects. These describe model output
  for the already isolated caller; a function named shell grants no host authority.
  All hosted tools, MCP/network/computer/file-search tools and unknown tool types
  are rejected. Tool choice cannot select a hosted tool or alternate endpoint.

Unknown fields fail closed. In particular prompt cache keys, metadata, service
routing overrides, structured-output schemas and newer transports are not silently
forwarded. A pinned Codex build/model using unsupported fields will fail closed
and needs a separately reviewed compatibility extension and regression fixture.
Offline tests exercise text, local function/custom tool round trips and opaque
reasoning history through the existing relay. They **do not establish full real
Codex 0.164.0/provider compatibility**. Live compatibility remains unverified.

HTTP/1.1 requests have bounded ASCII headers and one unambiguous Content-Length.
Duplicate headers/JSON keys, folded/control-character headers, chunked requests,
Content-Encoding, Authorization/proxy/forwarded headers and upgrades are rejected.
Only the relay's Host, Content-Length/Type, Accept/Accept-Encoding (identity),
Connection and User-Agent headers are accepted. No incoming headers are forwarded.
There is one request per connection; extra/pipelined input terminates forwarding.

## Resource and stream enforcement

Policy limits can only **tighten** these defaults/hard maxima (positive integers):

| Limit | Default / hard maximum |
| --- | --- |
| Request bytes, including normalized JSON | 512 KiB |
| Response bytes per request (raw and canonical SSE) | 8 MiB |
| SSE event bytes (raw and canonical) | 64 KiB |
| SSE events | 10,000 |
| Decoded chunks | 32,768, each <=64 KiB (TLS reader uses 4 KiB) |
| Concurrent admitted connections | 2 |
| Requests per exact peer / all peers | 32 / 64 |
| Total canonical response bytes per broker lifetime | 32 MiB |
| Whole request / idle read or write | 120s / 10s |
| Broker lifetime | 300s |
| Output token request cap | 4,096 |
| HTTP headers | 8 KiB total, 32 fields, 2 KiB per line |

At most 16 exact peer pairs/models; input lists <=2,048 entries; schema traversal
is depth bounded. The admission cap covers slow incoming headers/bodies as well
as inference. Invalid inference attempts reserve and consume the request allowance
before body parsing; disconnects/errors do not refund it. Denials return generic
403; concurrency/request/lease exhaustion returns generic 429. Before any valid
SSE event, inference failure returns generic 502. Raw upstream status/error bodies,
headers, Location, stack traces and credential-bearing diagnostics are discarded.

The legacy protocol has no authenticated turn ID. Therefore **per-turn isolation
of accounting cannot be inferred** from request text, PID or session UUID. This
reference enforces stricter process-lifetime budgets and a finite lease; the
operator must reserve the instance for the approved task/turn(s), with no automatic
restart/reset. Separate per-turn reservation across broker restarts would need a
future trusted control-plane protocol. Restarting refreshes counters and is a new
manual authorization decision. Health checks do not consume inference counts and
can still succeed when inference budget is exhausted; health is not a quota or
security attestation. Resource/usage quotas are not a monetary spend guarantee.

Upstream HTTP accepts only status 200 with SSE, bounded identity body or strictly
parsed chunked framing (no extensions/trailers, compression or mixed length/TE).
SSE requires one event and one JSON data line per frame, valid UTF-8, duplicate-free
JSON, allowlisted successful Responses event types and first response.created.
Unknown/error/failed/incomplete events fail closed. Diagnostics in error fields
or literal credential echoes (including JSON escapes) are rejected. Completed is
held until clean stream termination; malformed/trailing/oversize data never gains
a successful terminal event. After SSE begins, failure closes the connection
without a completed event; it never inserts HTTP/error diagnostics into the stream.
Arbitrary re-encoding of a secret by a malicious upstream cannot be ruled out by
string filtering; the fixed TLS provider remains trusted with the credential.

One bounded frame is validated/canonicalized at a time; writer.drain provides
backpressure before reading more upstream. Deadlines cover stalled peers/streams
and partial headers/chunks. Client EOF or extra input races the forwarder, cancels
it and closes the upstream TLS transport. Lease expiry/shutdown cancels active
requests. No retry or provider cancellation endpoint is called. Tests demonstrate
local transport closure, **not that the provider immediately stops computation or
billing after disconnect**; that property needs live evidence/provider guarantees.
OS DNS resolver cancellation, kernel buffers, service-manager limits, trust-store
integrity and malicious local same-UID processes also require deployment review.

## Manual deployment and independent audit checklist

No deployment has been performed. A human operator and independent security
reviewer must separately complete all steps; the code never installs services,
users, policy, credentials, firewall rules or privileged filesystem state.

1. Review the exact HEAD, policy, parser, upstream, test evidence and dependencies.
   Run offline checks first. Inspect failure cases and residual limitations; do
   not equate CI_PASS with independent audit PASS, deployment readiness or E2E_PASS.
2. Decide the least-privilege service identity/confinement. Existing preflight
   requires socket ownership **and SO_PEERCRED UID 0**, so an ordinary non-root
   service alone does not satisfy the current profile. Do not relax that check.
   A separately audited root-identity deployment needs capability removal,
   constrained filesystem/network views, no repository/GitHub/SSH access, restricted
   process inspection and resource limits. This repository provides no root
   launcher, privilege drop, proxy shim or service unit. Root operation remains
   an explicit external security risk requiring review.
3. Provision a trusted root-owned directory and curated runtime separately. The
   broker requires non-writable, symlink-free ancestors and an absent leaf. It
   pins the parent directory descriptor, binds a fresh socket under umask 0177
   (0600), verifies owner/type/parent identity, and never unlinks a collision or
   repairs permissions. It leaves its socket path after shutdown for review.
   Production requires `/run/agent-platform/inference.sock`, root ownership and
   audited group access for the operator. Any group/mode setup on that new socket
   is a separate human deployment step; the broker does not chmod/chown privileged
   paths. Do not expose it world-wide or grant directory write permission.
4. Bind exact host UID/GID pairs, observed through the real sandbox relay, rather
   than broad groups or claimed headers. Test an unauthorized pair separately.
   Confirm client and server SO_PEERCRED semantics on the deployment kernel.
5. Provision policy and a least-privilege inference-only provider credential through
   human-managed secrets. Keep the token, policy, descriptors and broker memory
   outside every sandbox mount and task/transcript/checkpoint. Disable core dumps,
   protect proc/ptrace/memory and avoid logging inherited descriptors/environment.
   No debug wire dumps or packet captures with decrypted Authorization/body data.
6. Audit system TLS trust/DNS and egress rules allowing only the pinned provider
   origin; no redirects, proxies or hosted tools. Audit provider retention and
   billing controls, model allowlist, token caps and finite task lease. Network
   policy/TLS trust changes are operator work, not performed by this program.
7. Start explicitly in the foreground through an audited operator-owned launcher
   with a preopened secret FD. Do not use unattended restart loops: they replenish
   budgets. Verify disconnect, slow-reader backpressure, deadlines, shutdown and
   root-peer identity with nonsecret evidence, not just health booleans.
8. Match broker_id exactly to the separately curated profile. Run doctor and all
   [E2E controls](e2e.md) in an authorized disposable fixture, with explicit consent
   for each paid turn. Verify real minimal completion, session persistence and
   safe failure/resume without exporting model prompts/transcripts or tokens.
9. Keep audit logs to nonsecret lifecycle/outcome/count information; the reference
   emits no request/body logs and only a generic startup error. Retain operator
   evidence privately, with exact SHA/hash/ID and outcomes; redact access URLs,
   credential paths, prompts, raw SSE and upstream diagnostics.
10. Rotate tokens by stopping the instance, verifying children/connections are gone,
    revoking/replacing credentials through secret management and re-reviewing the
    lease/policy. Reconcile the owned stale socket manually before restart; do not
    remove an unknown socket or restart automatically after uncertain state.

The absence of the curated runtime, audited broker deployment or any negative
probe is still `isolation_unavailable`. This implementation does not change the
runner's namespace, lock, checkpoint, authorization or GitHub-write restrictions.

MVP.2e [read-only diagnostics](deployment.md) no longer propose broker deployment.
The [subscription-auth design gates](subscription-auth.md) prohibit OAuth token
forwarding through this API broker and require separate security review.
