# AP-AS/1 fixed signer and Unix IPC — Issue #80

Status: **NOT_DEPLOYED / LIVE_BLOCKED**. These are offline-testable libraries,
not a daemon, socket listener, key loader or enabled runtime. No real credentials,
App authentication, GitHub requests or deployment are part of this milestone.

## Trust and admission

`app_signer.SignerSession` accepts a pinned Policy, explicit approved run ID,
independently trusted Authority and in-memory CredentialProvider. Policy binds
App ID, target digest, public-key fingerprint, purpose and exact custody/signer
PID, UID and GID. Admission binds that policy, a run ID and nonce, a bounded
validity interval and exactly two ordered, distinct request/pass bindings.
An Authority must independently authenticate operator/controller admission;
Issue text, model output, a JSON digest or client-supplied fields cannot grant it.
There is deliberately no default Authority or admission producer.

The Authority must atomically persist UNKNOWN before signing, reject replay and
preserve the two-pass quota across processes, sessions, restarts and failures.
Its lookup must fail closed on missing, changed, uncertain or rolled-back evidence.
The test Authority is synthetic and in-memory: it proves call ordering and failure
behavior, **not durable admission or external anti-rollback protection**. A reviewed
controller, durable admission producer and independently trusted continuity
boundary are **NOT_IMPLEMENTED**. Local SQLite alone cannot prove protection from
external rollback, deletion or a compromised custody UID; AP-AJ/1's operator gates
remain required. No production operation is admitted without these prerequisites.

The existing AP-AL/1 Claims type is reused unchanged. The legacy
`sign(Claims, timeout)` entry point always blocks: it lacks the independently
approved run, nonce and pass context. There is no permissive Adapter fallback or
automatic bridge. A future custody integration must supply the complete trusted
admission chain; it cannot derive authority from the observation request itself.

## Fixed cryptography

Only RSA PKCS#1 v1.5 with SHA-256 (RS256) is supported, using cryptography's vetted
RSA implementation. The key provider supplies an RSA private-key object already
in trusted process memory, matching the pinned SHA-256 SPKI public-key fingerprint.
RSA modulus bounds are 2048–4096 bits and the exponent is 65537. No PEM/path,
environment, file descriptor, arbitrary payload, algorithm or generic signing
interface is exposed. Tests generate disposable keys and verify actual signatures
with the public key, including rejection under RSA-PSS.

Header is exactly `{"alg":"RS256","typ":"JWT"}`. Payload is the existing
Claims representation (`iss`, `iat`, `exp`), encoded as canonical bounded JSON and
unpadded base64url. App ID is policy-pinned. Claims must be current, issued no more
than 60 seconds ago, have at most a 600-second span, expire within 300 seconds of
now and not outlive the admission. Admission lifetime is at most 300 seconds.
No caller can sign arbitrary bytes. The client independently verifies the exact
claims, response binding and RSA signature with its pinned public key.

Dependency policy is `cryptography>=43.0.0,<51`; uv.lock pins 50.0.2 with public
PyPI artifact hashes, adding cffi and pycparser without changing existing tool
versions. Debian 13 uses its maintained python3-cryptography package (43.x), with
both version bounds declared and an exact reviewed builder mapping. This is
compatibility with Debian's security-maintenance channel, not a claim that 43.x
is the latest upstream release. Security advisories and installed package versions
must be reviewed again before live use. No runtime dependency installer exists.

## Bounded wire contract

`app_signer_ipc` handles one request on an explicitly supplied connected Linux
AF_UNIX SOCK_STREAM socket. It never binds, listens, chooses or opens a socket
path. Unnamed pairs and connected absolute nonabstract pathname sockets are
accepted; abstract addresses, other families/types and unavailable SO_PEERCRED
fail closed. Both sides verify kernel PID/UID/GID against policy. Socketpair
credentials identify the creator and are not proof of later descriptor ownership.
Tests using one UID are not evidence of process or credential isolation. A future
trusted launcher must establish distinct principals, authentic lifecycle pins,
secure socket ownership/path ancestry and descriptor custody. Path spelling
alone is never authentication.

Each frame is a four-byte big-endian payload length followed by canonical UTF-8
JSON and EOF (sender half-closes). Request limit is 2048 bytes and reply limit is
8192 bytes, including framing. Duplicate/unknown keys, nonfinite values,
noncanonical encodings, trailing data, partial frames, SCM_RIGHTS and ancillary
truncation are rejected. Received descriptors are closed. Total operation budget
is at most five seconds, including reads, writes and signing; deadlines are
rechecked around cryptographic/provider calls. Providers are trusted synchronous
code and must themselves be bounded: a Python deadline cannot preempt a hung
provider. One process-wide handler slot and one per-session lock permit no queued
work. Each admitted session has exactly two ordered, one-use signing passes.

Request keys are exactly `v`, `op`, `run_id`, `nonce`, `request_id`,
`pass_binding`, `policy_sha256`, `app_id`, `iat`, `exp`; `v` is integer 1 and
`op` is `SignAppJwtV1`. Successful reply keys are exactly `v`, `status`,
`request_sha256`, `jwt`, with version 1 and status `OK`. Failure reply is fixed
`{"code":"signer_blocked","status":"BLOCKED","v":1}`. Diagnostics never
reflect peer input, credentials, raw provider exceptions or JWTs. Client failures
poison that client; server failures close the session. Never automatically retry
an uncertain exchange or repeat a consumed intent.

UNKNOWN precedes cryptography. SIGNED means a token was generated, not that the
peer received it. Lost replies, late signing or failed completion retain consumed
or uncertain intent; reconstructing a session cannot reset durable authority.
Tokens have a private, redacted, non-pickleable one-shot custody wrapper. Python
introspection, memory copies, garbage collection and key-object release do not
provide guaranteed zeroization or protection from compromised same-process code.

## Future operator gates

Before any live capability, independently review and authorize all of:

- Controller-authenticated immutable admission and durable replay/continuity,
  including crash, deletion, rollback, rotation and reconciliation procedures.
- Separate signer, custody and metadata-output principals. Only custody receives
  JWTs/installation tokens; output receives redacted AP-AM/1 results. A compromised
  authorized custody process remains a threat; peer credentials do not eliminate it.
- Trusted fixed key provisioning, rotation and memory lifetime. systemd
  LoadCredential is delivery plumbing, not a process-isolation boundary.
- Secure socket provisioning, least privilege, denied credential access from
  coding/output processes, OS isolation and independent negative probes.
- Audited bounded provider behavior, resource limits, package/advisory review,
  host crash/power-loss testing and separately authorized deployment procedures.

There is no real signer service or production IPC orchestration in this Issue.
No GitHub writer, permission change, native activation or paid fallback is added.
AP-AM/1 remains metadata-only/non-authorizing; AP-CI/1, AP-CA/1, AP-AL/1, AP-AJ/1,
publication authorization and both exit-13 barriers remain unchanged.

| Event | Offline evidence | Future operator verification before live admission |
| --- | --- | --- |
| Credential handoff | In-memory provider type/fingerprint checks, no loader | Audited FD provenance, fixed identity, denied access from other principals |
| Reboot/restart | Synthetic authority rejects consumed or lost history | Durable admission lineage and independently attested continuity; no fresh allowance from restart |
| Rollback/deletion | Missing authority blocks; no repair/default | External anti-rollback witness and explicit reconciliation; local DB is insufficient |
| Partial/late signing or lost reply | UNKNOWN/consumed intent, poisoned session/client | Supervisor termination and human reconciliation without blind retry |
| Host isolation | Kernel peer checks and disposable process test | Distinct UIDs, trusted launch image, negative access probes, dump/swap policy |
