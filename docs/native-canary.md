# Executable native Linux canary preflight (Issue #26)

Native Codex CLI remains the engine; this helper **never launches Codex**. It is
an opt-in, fabricated-only candidate-boundary experiment, separate from admission,
locks, checkpoints, native resume, GitHub permissions and the hard-disabled
subscription adapter. No broker, account, API key or model request is involved.

## Usage and evidence tags

```sh
agent-platform-native-canary
agent-platform-native-canary --run-synthetic
```

Default: exit 0, NOT_RUN / OFFLINE_SYNTHETIC, no dependency inspection, fixture
creation or subprocess. The sole opt-in flag authorizes fixed synthetic probes;
there are no path/command/rootfs/backend/privilege overrides, including through
environment variables. Invalid arguments exit 2 with a fixed nonsecret diagnostic.

| Outcome | Exit | Meaning |
| --- | --- | --- |
| NOT_RUN | 0 | No opt-in; not a readiness PASS |
| BLOCKED | 13 | Missing/untrusted prerequisites, unavailable namespaces, timeout/cancellation, unexpected report, or unresolved same-domain risk |
| FAIL | 14 | A valid probe report contradicts required confinement/allowed-write checks |

Reports separate host_containment, worker_codex_home, same_domain_codex_home,
finite check booleans, and UNKNOWN Codex internal routes. AUTH_E2E_NOT_RUN and
launch_allowed=false are unconditional. REAL_KERNEL_SYNTHETIC means actual
validated probe output, not authenticated or complete tool-mediation evidence.
Mocked subprocess/report tests are **OFFLINE_SYNTHETIC evidence only**, even when
they exercise how a real-kernel report would be classified. Neither result can
activate native_codex.execute or agent-platform subscription.

## Prerequisites: validated, never installed

An independently reviewed, credential-free immutable fixture must already exist:

- Linux, non-root caller with zero effective/permitted/inheritable/ambient caps;
  trusted `/usr/bin/bwrap` (UID 0, no group/world write, setuid/setgid or file
  capabilities; <=2 MiB). Its exact SHA-256 must match the manifest.
- `/opt/agent-platform/native-canary-v1/manifest.json`, root-owned, <=64 KiB,
  with exactly version=1, bwrap_sha256 and files (relative-name → SHA-256 map).
  This is an administrative audit input, not a self-attestation of safety.
- The adjacent rootfs: all regular files/directories root-owned and non-writable
  by group/world; no symlinks, special files, privilege bits/capabilities,
  external hardlinks or nested mounts. Exact manifest inventory, <=512 files,
  <=2,048 entries and <=64 MiB total. It contains a reviewed executable
  `usr/bin/python3` and only its required library/runtime files under the
  bin, usr, lib and lib64 top-level trees. No host home/root/run, Codex,
  credential-like names or populated proc/dev/workspace/codex-home directories.
- Empty proc, dev, workspace and codex-home mountpoint directories, and empty
  regular canary-probe.py / canary-policy.json placeholders in the manifest.
  Libraries/loader must work **inside** this image; host libraries are not bound
  as a fallback. Current supervisor Python and reviewed probe source are TCB too.

The [Issue #28 fixture specification](native-linux-fixture.md) supplies a guarded
build/audit plan and operator-reported sandbox01 evidence, not a verified installer
or permission to provision. No automatic dependency copying is supplied.
If any prerequisite cannot be proved, STOP/BLOCKED. Do not install services,
change sysctls/ownership/permissions, invoke sudo, relax checks or run probes on
the general host. These independent canary limits do not change production
runtime admission or admit the oversized Codex artifact.

## Fixed experiment

After validation only, the helper creates a fresh UUID directory under the
verified non-symlink, owner-only `/tmp/agent-platform-native-canary-<uid>`.
Existing runs/unknown files are never overwritten or deleted. New fixture data
is bounded: <=16 KiB reviewed probe source, <=4 KiB policy, six tiny fabricated
files, a symlink, two permitted edits and a fixture-owned socket. No real host
home, auth store, repository, Docker socket or credential service is mounted.

A sanitized, time-limited sentinel subprocess holds only a fabricated file/FD,
loopback listener and filesystem Unix socket in that new fixture. The positive
network control connects only to this listener. Probes target this synthetic
process's proc/fd/memory handles, **not** the authenticated developer process.
No process-memory or credential contents are read or printed; successful opening
of a fabricated credential is already exposure. Probe output is booleans only;
public reports add fixed categories, hashes and opaque fixture ID, never raw
commands, environment, paths, stderr or canary contents.

Bubblewrap uses explicit mandatory user, IPC, PID, network, UTS and cgroup
namespaces; mount isolation is additionally verified inside. No unshare-all,
optional -try, share-net, preserved sensitive fds or privileged fallback. The
curated rootfs is read-only, proc private, dev read-only, environment cleared,
capabilities dropped, worktree bound writable and fixed source/policy read-only.
Actual namespace IDs must differ and capability sets must be zero with
NoNewPrivs=1 **before** file/process/network probes begin.

1. **Worker view:** fake CODEX_HOME is absent. Require host-home/SSH/GitHub/
   control/session reads, traversal/symlink and hardlink escape attempts, writes
   outside worktree, sentinel proc/fds/memory access, inherited-canary descriptor,
   fixture TCP and Unix-socket access to be denied. Only the designated worktree
   edit/readback succeeds. A fixed fork/kill/wait checks controlled descendant
   reaping; this does not audit arbitrary daemon/parent-death escape behavior.
2. **Same-domain view:** the same confinement additionally exposes **only** the
   fabricated CODEX_HOME through a read-only bind. Its opening normally succeeds:
   host_containment=PASS can coexist with same_domain_codex_home=FAIL. Read-only
   mounting, a VM around the whole CLI and workspace-write do not prevent reads
   by tools in that credential domain. Overall status remains BLOCKED even after
   a successful demonstration; stronger unexpected denial is UNKNOWN, not proof
   of a general safe native design.

The source-controlled probe set is fixed. A 14-second work deadline plus a
one-second reaping budget bounds the outer run to 15 seconds, including validation; <=2 seconds per entire sandbox probe, 0.2-second connects, <=4 KiB
stdout/stderr per sandbox stream and <=1 KiB sentinel readiness (aggregate below
64 KiB). The sentinel has its own 12-second lifetime. SIGINT/SIGTERM/timeout stop
and reap the foreground children; there is no retry, persistence or daemon mode.
Fixtures are retained for explicit human inspection/reconciliation, not cleaned
up automatically. Repeated opt-ins create separate runs; no checkpoint recovery
or existing runtime directory is adopted.

The [vendor Bubblewrap option contract](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
was read at blob `b48cf5b448270f2234da911cf24ba8b47469ee26`: unshare-all includes
optional user/cgroup -try forms, so it is insufficient here. Supported flags in
a current document do not attest the installed binary; unsupported fixed options
fail closed. Online Codex sandbox docs are likewise not exact 0.164.0 evidence;
[Issue #24's bounded pinned help observations](native-codex.md) stay separate.
This experiment uses Python probes, no actual Codex sandbox or tools.

## Reproduce tests and current observations

```sh
uv run pytest tests/test_native_canary.py
# Separate operator opt-in; requires the reviewed immutable runtime above:
uv run pytest tests/test_native_canary.py::test_opt_in_real_linux_kernel --run-native-canary -rs
```

Normal CI never opts in. Offline tests simulate administrative metadata and a
fake Bubblewrap executable, exercise real synthetic sentinel/foreground process
I/O and cleanup, validate each fixed probe deterministically, and test report
sanitization, path/alias/privilege rejection, timeouts, cancellation and no
fallback. They do not establish kernel confinement.

Actual observations on 2026-10-28, inside the existing sandbox without elevated
probe execution:

- Default command: exit 0, NOT_RUN/OFFLINE_SYNTHETIC.
- Explicit --run-synthetic: **exit 13, BLOCKED/trusted_bwrap_unavailable**;
  /usr/bin/bwrap was UID 65534, mode 0755, not admissible UID 0. No fixture or
  sandbox subprocess was created. The fixed /opt runtime was also absent.
- Explicit kernel pytest selection: **SKIPPED**, BLOCKED for the same reason.
  Namespace capability availability remains untested; no kernel PASS is claimed.
- Host confinement, worker home protection and same-domain exposure: **NOT_RUN**.
  Codex internal routes UNKNOWN; real authentication/inference AUTH_E2E_NOT_RUN.

The report's recorded candidate size, **308,139,304 bytes**, comes from the prior
pinned artifact observation. It exceeds the unchanged **268,435,456-byte** cap;
this helper neither re-inspects Codex/auth nor admits the artifact. Next steps
remain independent packaging/admission review and an already safely available
Linux fixture. Even a future synthetic PASS cannot prove all native in-process,
shell, patch, MCP, plugin, subagent or resume routes use this worker boundary.
Native execution stays disabled pending separately reviewed deployment/security
and explicit operator account-use authorization. No custom agent/API alternative
or privileged workaround follows from BLOCKED.

## Validation and source preparation

PR #25 was genuinely merged; GitHub main, remote default HEAD and freshly fetched
origin/main matched `cf115550663c7a553a152ff77b1e405ff5017a7e`. Development used only
the dedicated issue-26 worktree/feature branch, preserving all previous checkouts.

- `uv run ruff check .`: PASS.
- `uv run pytest`: **702 passed, 1 skipped in 71.91s**: 621 baseline tests plus
  81 new passing offline cases; the one real-kernel test requires explicit opt-in.
- `git diff --check`: PASS.
- Explicit kernel test: SKIPPED/BLOCKED, not PASS, with trusted_bwrap_unavailable.
- `agent-platform subscription`: still **exit 13**, launch_allowed=false and
  authentication NOT_INSPECTED. Existing native adapter denial remains tested.

The SHA-pinned Draft PR records GitHub CI separately. CI_PASS is offline evidence,
not real Linux confinement, complete Codex tool isolation or authenticated E2E.

## Later operator-run sandbox01 observation (2026-11-02)

The [fixture evidence record](native-linux-fixture.md) preserves the full JSON
from the operator's Issue #28 comment: REAL_KERNEL_SYNTHETIC, host/worker PASS,
same-domain FAIL, overall BLOCKED/exit 13. This supersedes the historical absence
of a kernel result above only for that reported disposable fixture, not dev01.
No new run was performed here. Missing external build scripts/runtime manifest
prevent independent artifact audit and byte-identical reproduction; authentication
remains NOT_RUN, internal routes UNKNOWN and launch_allowed=false.
