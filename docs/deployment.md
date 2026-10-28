# Read-only Linux diagnostics (revised MVP.2e scope)

PR #16 is limited to **backend-independent static manifest inspection and host
policy hints**. Product execution is intended to use Codex authenticated through
the maintainer's ChatGPT subscription. API-broker deployment, privileged socket
configuration and runtime promotion are deferred; they are not the next step.
See [subscription authentication gates](subscription-auth.md) before proposing any
execution change. No installation, credentials, login, inference or kernel
rehearsal is performed by these tools.

The existing `run`/`resume`/`doctor` and API broker are unchanged legacy code.
Their fail-closed checks, UID-0 peer requirement and binary-size cap remain intact.
This PR does not convert them into subscription authentication, forward OAuth
tokens through the API broker, grant root access or introduce a fallback backend.
PR #16 stays Draft and Issue #15 open pending independent review of the new SHA.

## Static manifest

```sh
python -m agent_platform.deployment manifest --source-sha "$SOURCE_SHA" --root "$CANDIDATE_TREE" --catalog "$REVIEWED_CATALOG"
```

The version-2 [catalog example](runtime-catalog.example.json) is an inert schema
example with **unapproved zero-hash placeholders**. An operator independently
reviews offline artifact provenance and supplies exact file hashes, kinds,
executable paths and ELF SONAME mappings. No Codex/provider/broker identity or
installed production path is required. Do not auto-generate an allowlist from
unknown files or include a home directory, authentication cache or secret files.

The scanner never executes candidates, invokes ldd, installs packages, downloads
artifacts or writes a tree. It verifies exact hashes, required executable modes
and static ELF64/little-endian x86-64 PT_INTERP/DT_NEEDED dependency closure. It
rejects unknown/missing files, unsupported binaries, symlinks/hardlinks, insecure
owners/modes, capabilities, special files, nested mounts and loader search hooks.
Catalog libraries must reside at explicit default loader paths. Approved scripts
can name only the cataloged /bin/sh or /usr/bin/python3 interpreter. It does not
prove safe program semantics, Python imports, dlopen behavior or authentication.

Bounds remain 256 KiB catalog, 2,048 files, 4,096 entries, depth 32, 512 MiB total
and **256 MiB per file**. No limit was increased to admit the oversized installed
Codex candidate. Traversal is descriptor-relative, uses O_NOFOLLOW and checks
file stability. Use a quiescent local tree. Numeric ownership is visible only in
the current user namespace; an unprivileged scan does not attest physical host
root ownership, approved runtime provenance or deployment safety.

## Read-only host hints

```sh
python -m agent_platform.deployment audit --source-sha "$SOURCE_SHA"
```

This inspects bounded namespace/Yama sysctls and a root-trusted, non-setuid
Bubblewrap executable/version. Only the fixed `bwrap --version` subprocess is
allowed, with a clean environment, five-second deadline and 128-byte output cap.
There are no socket connections, broker/profile reads, credential FDs, auth files,
GitHub calls, candidate execution, scratch creation, permission changes or root
services. `host_hints_pass` means those limited observations passed, **not** that
namespaces were exercised or that any authentication/execution path is ready.

The earlier API-coupled `rehearse` mode, production-profile/socket audit and
privileged deployment blueprint have been removed from this PR. A real-kernel
exercise must be designed against the independently reviewed subscription trust
boundary, rather than silently validating a deprecated API path. Existing runtime
preflight and doctor remain unchanged; their legacy API checks are not evidence
of subscription readiness.

## Evidence and handoff

The [report schema](deployment-report.schema.json) and
[example](deployment-report.example.json) label this scope static_diagnostics_only.
The supplied source SHA is an operator assertion to verify against the reviewed
installation. Output has aggregate hashes/counts and fixed reason codes, without
file paths, commands, credentials or raw tool errors. Reports remain E2E_BLOCKED.
Offline CI, real kernel, authenticated execution, credential isolation and live
inference have separate PASS/FAIL/BLOCKED/NOT_RUN outcomes. A static PASS cannot
promote any of the latter evidence levels. No token/login/session state is read.

Open gates:

- **AUTH-001:** the legacy runner selects a custom unauthenticated provider and
  empty sandbox home. It does not implement subscription-authenticated execution.
- **AUTH-002:** pinned help confirms login/exec/resume syntax only. Actual sign-in,
  JSONL/session behavior with subscription auth, refresh/re-auth and safe credential
  separation need a separately scoped design, tests and independent review.
- **ARTIFACT-001:** the observed installed Codex 0.164.0 candidate is 308,139,304
  bytes, above the unchanged 268,435,456-byte runtime/inspection limit. Its measured
  SHA-256 is b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306.
  A separate reviewed artifact/size-policy decision is required; do not strip,
  pack, raise caps or switch binaries to manufacture a PASS.
- **DEPLOYMENT-DEFERRED:** do not provision the root-owned API broker or adjust
  its socket as a proposed subscription solution. No privileged or live testing
  is authorized by this PR, and no production readiness is claimed.

No rollback script is needed: these tools only read and print JSON. Preserve
existing worktrees, sessions, checkpoints, guards and previously collected
forensic data. Do not delete sockets, reset work or edit state to bypass a gate.
A future credential/session design must provide its own reviewed recovery plan.
