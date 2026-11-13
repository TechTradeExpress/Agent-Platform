# CP-08 disposable local mechanics — AP-CL/1

**Source-only / unprivileged contributor tests / LIVE_NO_GO.** Issue #100 adds
`control_plane_local_runner`, separate from CP-06. It is not a host harness,
service, public CLI, entrypoint, runtime adapter or deployment artifact. No
production modules are invoked by its child. CP-06 `run`, `run_case`, fixed 30
cases, scratch contracts and policy candidates are unchanged.

The baseline contracts are [CP-01](control-plane-host-contract.md),
[CP-06 / AP-CF/1](control-plane-fixture.md),
[CP-07](https://github.com/TechTradeExpress/Agent-Platform/issues/99),
[AP-AJ/1](custody-journal-and-host-isolation.md) and
[AP-AS/1](app-signer-ipc.md). CP-07's public operator-reported inventory is
read-only testimony, not observed effective enforcement. Its account numbers,
host paths and reported facilities are never inputs to this runner.

## Explicit invocation and evidence

Only supervised contributor tests explicitly call `exercise(Config, Case)`.
There is no automatic suite, retry, queue or background activity. Import,
construction, configuration validation and report encoding do not start a child.
The caller uses a pytest-created private owned cwd; the API accepts no fixture
root, executable, command, adapter, callable or host operation. Tests invoke:

```text
uv run pytest -q tests/test_control_plane_local_runner.py tests/test_control_plane_fixture.py
```

A caller explicitly obtains `reviewed_bytes()` and separately reviews/retains
its source, helper, fixture, policy and active interpreter SHA-256 pins. These
are five separate fields, not invented hashes. Config additionally binds exact
budgets and AP-CL/1 in `configuration_sha256`. Fixed source artifact reads are
bounded, no-follow and checked for identity/metadata drift; policy JSON must
exactly describe the unchanged DESIGN_ONLY, installable=false CP-06 candidates.
Missing/malformed pins, unknown schema/case, changed candidate or mismatched
current bytes block before fixture/child creation. Bytes are rechecked after
execution; drift is UNKNOWN. No artifact is installed or executed for inspection.
No login store, host config, other user's process or real credential is read.

Digests correlate bytes; they do not authenticate human approval, trusted runtime
provenance, the interpreter/library closure, an independent witness or a host.
The reviewed closure here is the active contributor interpreter with `-I -S`,
the fixed inline helper, and its standard library in an already trusted developer
or CI environment. It is not suitable for hostile worktrees, arbitrary Python,
malicious same-UID concurrent changes, or production execution. There is no
promotion to CP-01's immutable installed runtime requirement. Set-ID, writable
by others and file-capability interpreter binaries are refused; root/changed
UID/GID execution is refused. Bounded own-process capability metadata must
also establish empty inheritable/permitted/effective/ambient sets; missing or
nonzero evidence refuses without launching. Missing Linux pidfd support is UNSUPPORTED with no
numeric-PID fallback. These are local safety prerequisites, not kernel isolation
assessment or host-admission probes.

The closed `Case` enum names hygiene, deadline, cancel, oversize and truncated
exercises. Each result records immutable case, expected code, observed code and
status, strict child accounting, budgets, pins and LOCAL_TEST_ONLY provenance.
`Report.encode()` revalidates types, closed codes, disposition consistency,
strict false authorization flags, counts and successful evidence completeness.
It emits deterministic sorted compact JSON <=64 KiB. There is no deserializer,
receipt conversion, admission token or authentication claim. Python objects and
structurally valid JSON are forgeable by their caller and authorize nothing.

| Evidence | Meaning |
| --- | --- |
| CP-06 VERIFIED_OFFLINE_FIXTURE | Synthetic reference-model match only, unchanged |
| LOCAL_MECHANICS_VERIFIED | The fixed hygiene child completed its local process checks and exact cleanup |
| FAIL | Output/protocol/child/accounting failure; STOP |
| UNKNOWN | Deadline, cancellation, ownership, cleanup or source uncertainty; STOP |
| BLOCKED | Invalid request, identity/pins, or occupied local slot; no launch |
| UNSUPPORTED | Required local pidfd/platform API unavailable; no fallback |
| HOST_NOT_RUN | Every real CP-01 boundary, always |

Negative exercises deliberately return FAIL or UNKNOWN, even when their
regression assertion succeeds. A test-suite pass never relabels them as host
PASS. Every result preserves `LIVE_NO_GO`, `gate_73=BLOCKED`,
`launch_allowed=false` and the complete CP-06 host matrix as HOST_NOT_RUN.

## Process and scratch ownership

At most one active case and one direct child exist per Python process. Contention
refuses immediately; no further child is created after any failure. The reviewed
helper never forks, execs, imports application/service code, opens sockets or
starts descendants. This is a fixed benign closure, not fork containment. Any
future descendant-capable or untrusted closure is BLOCKED pending separate
supervision/isolation design; process groups and cgroups are not implemented.

Fixed argv uses the active interpreter directly, `shell=False`, `close_fds=True`,
empty `pass_fds`, DEVNULL stdin, piped output, and exactly `LC_ALL=C`. Isolated
Python ignores user site/Python environment configuration. The child verifies
its own environment and open descriptors, including inherited high-numbered
FDs via bounded `/proc/self/fd` metadata enumeration. It reads no parent's or
other process's proc files. Fake parent env/pipe canaries remain in the parent;
markers, environment, stdout/stderr, paths, PIDs and raw errors never enter the
report. An injected environment/FD leak fails the helper. Core size is zero;
its own NOFILE limit is 64. There is no privileged helper or namespace setup.

The unchanged CP-06 scratch utility exclusively creates one unique private
fixture and fabricated marker in the test-created cwd. The runner uses that
fixture's open directory FD for child cwd through `/proc/self/fd`; it never
accepts a caller path or traverses a production tree. Only scratch FDs held by
the parent are used for identity checks and exact cleanup, never passed into
Python after exec. Extra files, symlink/hardlink/replacement/content/metadata
drift and partial creation retain uncertainty. Cleanup is explicit and limited
to the created marker/directory; no recursion, destructor, pre-existing content
inspection or cleanup retry. The same trusted single-process scratch assumptions
as CP-06 apply: private DAC is hygiene, not same-UID adversarial isolation.

Combined stdout/stderr is incrementally read in <=4096-byte chunks with a strict
<=64 KiB aggregate accepted/captured limit. One excess byte detects overflow;
it is discarded, never retained or reported. Raw stderr is discarded. Protocol
must be the exact fixed completion bytes, with no trailing or partial evidence.
The default probe deadline is 500 ms (maximum 5 s); case default is 5 s (maximum
60 s, with >=2.5 s termination reserve). Timeout, cancellation, overflow or
unexpected protocol ends capture and stops the child without retry. The helper
also arms its own two-second alarm, protecting against parent disappearance
after helper initialization. Before initialization, the trusted interpreter is
not an independently enforceable alarm boundary; supervisor/VM/cgroup failure
and uninterruptible kernel I/O remain BLOCKED host properties. Python elapsed
checks are not hard realtime guarantees for storage or a failed kernel.

The runner requires default SIGCHLD handling and a single main thread, and
checks the unreaped child relationship with WNOWAIT before/after opening its
pidfd. Unknown relationship or concurrent reaper configuration blocks safe
signalling. The parent opens a pidfd while its direct child remains unreaped; only that
handle can receive a termination signal. There is no numeric PID/PGID signal,
killall, wildcard or unrelated process access. `wait` reaps only that Popen child.
Termination/reaping is bounded to 2.1 s; pin/open/wait uncertainty cannot produce
verified mechanics. Without a pin, the benign child's self-alarm/exit is awaited,
no guessed signal is sent, and scratch is retained. Failed reaping retains
scratch and FAIL, with no next attempt. A process-local uncertainty latch also
refuses subsequent invocations after uncertain creation, ownership or cleanup;
there is no public reset/repair API. These abnormal paths use mocks when a
real failure would leave an unmanaged child. Actual KeyboardInterrupt and the
fixed cancel exercise stop/reap the known child; parent SIGKILL cannot record a
final result or clean scratch and is not claimed successful. Partial cleanup
is UNKNOWN and requires human reconciliation; no cleanup instruction is inferred
from the absence of a child or terminal output.

## CP-01 boundary mapping and remaining gates

All CP-06 entries below mean VERIFIED_OFFLINE_FIXTURE reference rules only,
never actual denial. No row authorizes a host command.

| CP-01 boundary | CP-06 | CP-08 local mechanics | True host test / prerequisite |
| --- | --- | --- | --- |
| Identity, NSS, groups, effective configuration | Fabricated peer/group/lifetime rules | Refuses privileged local identity; no host inventory | HOST_NOT_RUN: independently pin real identities/configuration |
| Cross-UID DAC/ACL, read/write/rename/link, inode/mode/metadata preservation | Synthetic ownership rules; scratch hygiene | Reuses exact owned scratch cleanup only | HOST_NOT_RUN: distinct principals, effective ACLs, denial/audit and unchanged protected metadata |
| Proc/environ/fd/mem, ptrace, process_vm, dumpability | Synthetic role and same-UID rules | Child inspects only its own FD metadata | HOST_NOT_RUN: cross-UID kernel/MAC denials and dumpability controls |
| FD/env handoff | Synthetic fixed plan and leak failures | Actual fixed benign child, fabricated inherited FD/env canaries | HOST_NOT_RUN: real credential/proc/memory and cross-principal isolation |
| Unix SO_PEERCRED, PID lifetime, framing, SCM_RIGHTS | Fabricated peer/lifetime/frame/ancillary cases | pidfd binds only owned local child; fixed stdout protocol | BLOCKED: no Unix listener/IPC or principal admission integration |
| IPv4/IPv6/DNS/loopback/inherited INET, L2/management | BLOCKED, no transport | None; no socket or packet operations | BLOCKED: effective guest/hypervisor network denial evidence |
| Fake-only credential loader/copy/key identity | BLOCKED, no loader | Random scratch canary only, never credential code | BLOCKED: safe loader and separately approved fake credential tests |
| Journal/anchor/storage/sidecars/locks | BLOCKED host proof | No journal, DB or external anchor touched | BLOCKED: independently protected continuity and storage evidence |
| Authenticated admission/replay/pass order/fencing | Synthetic library facts only | None | BLOCKED: actual authenticated producer and retained replay authority |
| Crash/full disk/fsync/lost reply | Synthetic uncertainty lifecycle only | Benign cancellation, not crash injection/durability | BLOCKED: separately authorized disposable fault tests and witness |
| Reboot/rollback/deletion | BLOCKED | None | BLOCKED: independent observer/storage assurance; no local-hash shortcut |
| systemd/AppArmor/namespace/seccomp/BPF attachment/audit | Inert candidate equality only | None; no services/profiles/namespaces | BLOCKED: reviewed artifacts, actual attachment and effective negative denials |
| cgroups/resources/dependency stop/recovery | Synthetic timeout/reap/stop rules | Bounded direct child, output, alarm, pidfd, exact cleanup | HOST_NOT_RUN: task/memory/cgroup/dependency-loss containment and reconciled stop |

## Future approval packet — non-executable and unapproved

No shell commands, loadable profiles, runnable units or deployment automation
are supplied. A future human must separately identify and review:

1. An explicitly disposable VM, physical/hypervisor ownership, allowed principals
   and narrowly enumerated privileges. No control01/Proxmox/other-host access is
   granted here. Pin exact full source/config/executable/library/unit/profile
   hashes from reviewed bytes; absent artifacts remain missing, never invented.
2. Fake assets and new disposable state only; deny production key/login stores
   and existing journals. Fixed command/case closure and expected positive and
   negative outcomes for every matrix row, independently reviewed before launch.
3. An independent observer and retained provenance chain: exact actual inputs,
   source/policy hashes, effective UID/groups, policy attachment after exec,
   independent kernel/audit and guest/hypervisor network evidence. Read-only
   inventory and syntax/security scores cannot substitute for actual denials.
4. Per-probe <=5 s, per-case <=60 s, combined capture/report <=64 KiB, bounded
   owned child/cgroup lifetime, redaction, lost-result/late/partial-write handling
   and STOP without retry. Retain unknown effects and external history; reconcile
   independently before approving a new attempt or recovery.
5. New narrow human approvals **for each** host installation, account/ACL change,
   profile load, service start, network probe, fault injection, reboot/rollback,
   cleanup and recovery. Approval to develop source or merge this PR supplies
   none of these. No automatic configuration, start, deployment or escalation.

Authenticated admission, external continuity, credential isolation, immutable
installed closure, distinct-principal IPC/MAC/network enforcement, crash/reboot
E2E and Gate #73 remain BLOCKED. All real host tests remain HOST_NOT_RUN. Native
subscription and public legacy run/resume/doctor retain exit 13. No API/App
writer, service packaging, CI privilege/secret, ruleset or production integration
changes are included. Delivery follows [AP-SM/2](solo-maintainer-policy.md):
Codex stops at Draft; separate ChatGPT technical review; human-only merge.
