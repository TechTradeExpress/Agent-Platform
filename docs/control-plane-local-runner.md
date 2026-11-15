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

## PR #103 local integration follow-up

The dedicated integration branch starts at the actual PR head
`8b2042a91fa4af8eeae5c0949c996a5fe6df0cd2` and merges verified main
`b63beefa487005ea3e0a29116987f4e93455224e` without rewriting either history.
The original contributor worktrees are retained. Delivery is LOCAL_ONLY; this
work performs no push, PR mutation, authenticated GitHub access or host activation.
That initial integration did not incorporate or predict the then-unmerged
Publisher work from PR #109; the subsequent merge is recorded below.

The closed Debian builder now classifies `control_plane_local_runner` explicitly
as **SOURCE_ONLY**. Neither Control nor Worker receives the module. Regression
tests inspect actual N/N+1 role archive inventories and reject imports of CP-08
from either installed role's module closure. Unknown modules still fail closed.
The CP-06 implementation, tests, 30 synthetic case semantics, configuration and
policy descriptors remain unchanged.

Additional local safety checks cover:

- Normalize `RLIM_INFINITY` before lowering the helper's NOFILE limit; infinity
  must not accidentally preserve an unbounded descriptor limit. Restore the
  helper's own SIGALRM default before arming its independent alarm.
- Reject an already exhausted case budget before fixture or process creation.
  Unsupported platforms refuse before accessing Unix-only identity APIs.
- Require an actual integer wait status for termination accounting. No new
  numeric PID/PGID signalling, descendant-capable helper or group API is added.
- Count overflow at the exact accepted-byte limit regardless of which output
  pipe becomes readable first. Retain at most twelve stdout protocol bytes and
  discard stderr; real repeated runs must have identical redacted reports.
- Preserve scratch and latch uncertainty on changed marker bytes, symlink or
  hardlink/extra-entry drift. No recursive deletion, repair or retry is added.

### CI diagnosis and evidence limits

The published historical CI run `43420493518` reported 84 setup errors in
`reviewed_bytes()`, before process assertions. This is distinct from the two
packaging failures reproduced immediately after merging current main: its
closed manifest correctly refused the previously unclassified CP-08 module.
The SOURCE_ONLY classification resolves those packaging regressions.

The historical pin failure was **not reproduced** on either the local Python
3.13.5 interpreter or a separately temporary Python 3.12.16 contributor test
interpreter. The latter is a different build from the historical Actions
interpreter; matching the minor version does not establish an exact CI-image
reproduction. An anonymous read of that historical job's log returned HTTP 403.
No credentials, alternative log-access route or weakened runtime admission was
used to fill this evidence gap. Its underlying stage remains **UNKNOWN**, not
claimed fixed, baseline or host failure.

New independent tests identify the failing stage using only fixed IDs: source,
fixture, policy, runtime_safety and runtime_bytes. They require no configuration
fixture and suppress raw exceptions/paths. Public library errors remain fixed
and redacted. The original regular-file/ownership/mode/capability checks, byte
pins and 64 MiB interpreter hashing ceiling remain enforced; the diagnostic
must never widen them or skip a safety failure. A new actual CI run is required
to identify or rule out the historical image-specific failure after publication
by the separately authorized reviewer. Local green checks cannot stand in for
that unavailable exact-image evidence.

Local full-suite results and any failures reproduced on unchanged main belong
in the exact-HEAD delivery record. No full-suite PASS, independent audit,
HOST_PASS, release authority or real host enforcement is inferred here. All
CP-01 host rows remain HOST_NOT_RUN/BLOCKED; LIVE_NO_GO, Gate #73 and subscription
and public legacy exit-13 barriers are unchanged.


### Integration after PR #109 merged

A subsequent local merge starts from CP-08 commit
`67851d843dfae751319bd37311bdd9273bdcd9e5` and incorporates actual main
`790dc17382689552bbf8f16823f7f16956ff37f5`, which contains PR #109. The
merge preserves both histories and all PUB-02 source modules, source-only
classifications, package exclusions and tests. No Publisher source, deployment
source, host configuration, role authority or runtime gate is changed relative
to that main. The CP-08 runner and stage diagnostics are unchanged from the
previous local integration; its classification remains SOURCE_ONLY beside the
Publisher's own source-only modules.

The historical run's 84 setup failures were confirmed as reviewed_bytes()
refusals; the specific pin stage remains UNKNOWN. This merge does not claim to
resolve that historical CI-image failure, widen pin/capability/ownership/hash
checks or create live evidence. Local tests and any reproduced main-baseline
failures are reported with the exact resulting commit/tree. LOCAL_ONLY,
HOST_NOT_RUN/BLOCKED, LIVE_NO_GO, Gate #73 and native/public exit 13 remain.

## Runtime refusal diagnostics after CI #214

The repair starts from the **published** PR #103 head
`79f40c879a91bca6e79be4d9d72f64228c922f25`, not from an unpublished local
merge. CI run `43638245600` reported 3340 passed, 2 failed, 95 fixture errors
and 1 skipped. The two failures were `pin_stage_runtime_safety` and
`pin_stage_runtime_bytes`. The latter evaluated `_runtime()` before calling
`_file_hash`; its failure is **not independent evidence of a binary read,
size or digest failure**. The 95 dependent errors occurred in `reviewed_bytes()`
before their local mechanics assertions could execute.

What the available evidence establishes: interpreter safety admission refused.
It does not identify which metadata/capability predicate refused. `_runtime()`
contains no Python-minor-version branch. A matching Python 3.12 version or a
successful local run cannot prove the metadata of an ephemeral Actions image.
Anonymous access to the actual CI job log returned HTTP 403; no credentials,
alternate route, remote probing or GitHub mutation was used to fill this gap.
The specific CI rejection remains **UNKNOWN / BLOCKED pending observation**.
Do not present an owner mismatch, mode bit or unsupported xattr as established
without its observed category.

A local restricted-sandbox reproduction on the unchanged published head produced
both coarse stage failures and the same 95 fixture errors. The new independent
categories in that same restricted view produced **six PASS and owner BLOCKED**:
regular file, allowed mode, absent capabilities and bounded readable bytes, but
owner neither root nor caller. Fixed boolean metadata independently confirmed
that ownership mismatch without publishing paths or numeric UIDs. The original
code and this patch both refuse that view. In the separately approved non-root
contributor test context, both versions accept the observed root-owned binary.
This establishes a local environment/ownership cause, **not an authenticated
observation of the GitHub runner's owner**. Do not infer the latter from matching
coarse symptoms or change sandbox settings as an automatic runtime fallback.

The production predicates are split into small private checks without relaxing
any accepted condition. The public error is still only `local_runner_blocked`.
Test-only, independently parametrized checks do not use the configuration fixture
and emit fixed nonsecret IDs, never the executable path, UID, environment,
capability bytes, binary bytes or raw OS exception:

| Diagnostic | Predicate / fixed refusal meaning |
| --- | --- |
| metadata | Resolve only the active interpreter and stat without following a final symlink; unavailable metadata blocks all dependent observations |
| file_type | Exactly a regular file |
| permission_bits | No set-ID or group/other-write bits: unchanged mask `0o6022` |
| owner | Owner exactly root or current caller; no image/user-name inference |
| capabilities | `security.capability` absent with ENODATA or empty bytes only; present, unsupported, denied and unknown errors are separate fixed refusals |
| binary_size | Strictly positive and at most the unchanged 64 MiB ceiling |
| binary_read | Independent bounded no-follow hash/read, preserving exact byte count and stable metadata checks; special/oversized files are explicitly blocked before diagnostic reading |

Binary diagnostic observations deliberately do not call `_runtime()`: that would
repeat the previous ambiguity. They inspect only the fixed active-interpreter
file, never launch it and never constitute admission. `reviewed_bytes()` and the
actual launch path **still require every original safety check** as well as exact
source/config/fixture/policy/runtime SHA-256 pins. Unsupported capabilities are
not equivalent to absent capabilities. The new status mapping also rejects
unexpected non-byte xattr results. No hash ceiling, deadline, FD/output limit,
process ownership, negative test or host gate is widened or skipped.

A compliant contributor/CI environment needs an independently trusted interpreter
and library closure whose actual file meets every row, a non-root test principal
and the existing local process/scratch prerequisites. A temporary independently
acquired caller-owned Python 3.12 contributor runtime can meet these checks; a
root-owned pre-existing reviewed interpreter is another possible candidate, only
after observation. Do not automatically copy/chmod/chown the rejected binary,
remove its capabilities, install packages, change the host, select a guessed
path or waive checks based on a tool-cache label. Selecting any different CI
runtime requires a separately reviewed workflow change and new actual CI results;
this patch does not change workflows or provision an image.

Until the actual failing image emits these categories, the specific CI cause
and remediation remain unresolved. Local results prove the diagnostic/refusal
logic only. CP-06, Publisher, closed Debian SOURCE_ONLY classification,
LIVE_NO_GO, Gate #73, native/public exit 13 and human-only merge remain unchanged.
Real host isolation remains HOST_NOT_RUN/BLOCKED.

### CI permission incompatibility follow-up

The next source-only CI change is documented in
[CI interpreter selection](ci-cp08-interpreter.md). It selects a pre-existing
OS interpreter explicitly instead of repairing the shared tool cache, and binds
the original validation to pytest in one process. The CP-08 runtime validator,
ownership/capability requirements, SHA-256 checks, limits and negative cases are
unchanged. Actual CI-image acceptance still requires a new observed run; no
local replay changes HOST_NOT_RUN/BLOCKED or supplies production authority.
