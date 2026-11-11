# CP-06 offline isolation fixture — AP-CF/1

Issue #97 implements a repeatable **OFFLINE_ONLY** reference-model harness.
All results retain **LIVE_NO_GO**, `gate_73=BLOCKED`, `launch_allowed=false` and
`HOST_NOT_RUN` for every host boundary. A model match is labelled
`VERIFIED_OFFLINE_FIXTURE`, never HOST_PASS. There is no real probe adapter,
public CLI, subprocess execution, socket/listener, network transport, service,
profile attachment, credential loader or privileged fallback. Import is inert.
No production publisher/admission/custody/signer or runtime gate is changed.

## Invocation and evidence contracts

The explicit library API is `run(Config, tuple[Step, ...]) -> Report` and
`run_case(Config, Step, FakeAdapter) -> CaseResult`. `scenarios(Config)` constructs
the fixed ordered suite of 30 deterministic positive/negative controls. Example
for an already running, supervised offline Python session:

```python
from agent_platform.control_plane_fixture import (
    Config, Fact, FACTS, Identity, Provenance, run, scenarios,
)
identity = Identity(
    "1" * 64, "2" * 64, "3" * 64, "4" * 64,
    tuple(Fact(name, Provenance.HOST_NOT_RUN) for name in FACTS),
)
config = Config(identity)
report = run(config, scenarios(config))
print(report.encode().decode())
```

Those four fabricated example digests identify fixture, source/config input,
policy candidate and collector. Real source-work callers should calculate hashes
of the exact reviewed source, configuration and candidate artifacts, and retain
that association separately. Digests and frozen Python objects are correlation,
not authenticated authority, anti-rollback witnesses or retained host evidence.
The model never discovers principals, reads NSS, mounts/proc, login stores or host
configuration. Its PID/UID/GID/lifetime values are fabricated and explicitly not
the operator-reported numbers on control01.

Versioned immutable Identity/Fact/Config/Step/Stimulus/Peer/Plan/CaseResult/Report
contracts distinguish expected and observed PASS/DENIED from FAIL, BLOCKED,
UNSUPPORTED, UNKNOWN and HOST_NOT_RUN. Every case has a separate HOST_NOT_RUN
field. Facts cover kernel, OS, user, groups, systemd, AppArmor, `mnt` and Yama,
with explicit SYNTHETIC, OPERATOR_REPORTED or HOST_NOT_RUN provenance; only bounded
nonsecret digests are retained, not arbitrary fact text. INDEPENDENT_RETAINED
claims are refused because this harness cannot authenticate them. Operator
reports never turn into independently verified host evidence. In particular the
historical `mount: ABSENT` typo is not missing `mnt` namespace evidence.

The suite requires exactly one of every enumerated case, in canonical order,
with each complete Stimulus exactly matching scenarios(config).
Missing, duplicated, unknown, reordered or substituted controls block before
simulated execution. A denial from a different stimulus cannot cover the named
case. Ad-hoc negative variants remain available through run_case, without a full
canonical-suite PASS claim. Input types, peer lifetime,
collector/fixture pins and SHA-256 of the complete immutable configuration,
completeness and bounds are checked before simulated
child creation. Malformed/partial evidence is BLOCKED. An observed violation is
FAIL, an unknown syscall is UNSUPPORTED, and cancellation/late completion or
incomplete cleanup is UNKNOWN. Any such case blocks the aggregate report.
After the first unexpected/uncertain result, later cases are retained as
HOST_NOT_RUN/after_stop without starting more simulated children.
Expected negative controls may observe DENIED and match the reference model;
this proves the model refused its fabricated input, not that an OS denied it.

`Report.encode()` validates the closed result schema and produces deterministic
sorted compact JSON, at most 64 KiB. It includes only fixed names/status/codes,
provenance, complete validated configuration and its SHA-256, identity digests
and expected/observed dispositions. Fake markers,
raw stdout/stderr, full environment, private paths, real PIDs and credentials
are never included. There is no report deserializer or conversion to an admission,
publication/test receipt, or launch authorization.

## Resource and lifecycle limits

A Plan has fixed symbolic argv `("CP06_MODEL_ONLY", case.value)`, shell=false,
empty environment/pass_fds, close_fds=true and **executable=None**. No strings
become commands, syscalls or paths. Default probe budget is 5,000 ms, case budget
60,000 ms, each may be reduced, never widened. Combined fake stdout+stderr is
at most 64 KiB, and one to four fabricated children are required per executed case. Zero children
or incomplete evidence cannot prove execution. Started/reaped deltas and the
recorded plan must account for the exact requested children before a model result
is accepted; a bare adapter return value is insufficient.
The deterministic adapter records exactly one attempt and reaps its complete
owned child/group model before returning, including timeout and cancellation.
Unreapable children FAIL without a second attempt. There is no generic injected
callable, host signal, actual child, queue, retry or privileged adapter.

Elapsed time and reaping here are simulated inputs. The harness cannot prove
real wall-clock preemption, kernel descriptor closure, process-group supervision
or cgroup containment. Those remain non-executable HOST_NOT_RUN requirements.
No OS child can escape this harness because it never creates one. A future real
runner needs separate approval, fixed trusted executable closure, sanitized
empty env/FD handoff, hard deadlines, bounded capture and independently verified
owned-group cancellation/reaping. No such runner is delivered by CP-06.

`DisposableFixture.create()` is a separately explicit **local scratch utility**.
It accepts no path argument and creates one unique private `.ap-cp06-*` directory
in the current contributor/test directory, after owner/no-extra-writers checks.
It uses exclusive creation, directory FDs and O_NOFOLLOW, a single 0600 random
fabricated marker, and immutable device/inode/owner/group/mode/link/size/time pins.
No marker is a key or token; marker bytes/digests/paths never enter a Report.
The utility is not automatically invoked by run/scenarios and is never handed
to a subprocess. Tests use only pytest-owned private temporary directories.

Explicit one-shot `cleanup()` checks the original root/child identity, at most
two directory entries, exact singly-linked marker identity and bounded content
hash, then unlinks only that marker and removes only its created directory.
Extra entries, symlink/hardlink, metadata/content/replacement drift or partial
creation retain evidence, return false/raise a fixed redacted error, close owned
FDs and never retry/reset/adopt/recurse into a caller-supplied or existing path.
There is no destructor or recursive delete. Partial creation and incomplete
cleanup require human inspection. Parent-directory FDs anchor operations without
walking caller paths. Private DAC is hygiene only: this utility assumes a trusted
single-process scratch area and cannot defeat a malicious same-UID concurrent
rename/unlink race or root/hypervisor. Actual adversarial principal/namespace/MAC
boundaries and safe host cleanup remain HOST_NOT_RUN.

## Inert systemd/AppArmor candidates

[control-plane-policy-candidates.json](control-plane-policy-candidates.json)
contains AP-CF/1 DESIGN_ONLY structured descriptors for Debian 13/systemd 257,
**not units or AppArmor profile source**. `policy_candidates()` supplies the
matching frozen requirements for each principal, based on CP-01. Static tests
check exact contents, empty supplementary groups/capabilities, UMask, read-only
system/home, proc/seccomp candidates, core-dump denial and cgroup budgets.

No ExecStart/ExecStartPre, [Install]/WantedBy, activation, real attachment, key
source, writable host path or managed-credential loader exists. Logical future
ledger/journal exceptions are explicit labels, not deployable ReadWritePaths;
signer has no persistent writable asset. Managed credentials remain signer-only
future requirements with the same-UID exposure caveat. Pathname IPC requires the
CP-01 named ACL/mode 0620, exact both-end PID/UID/GID/lifetime pins and rejection
of abstract/inherited/socketpair/SCM_RIGHTS traffic, never mode 0777.

Admission/signer families are AF_UNIX only. Custody lists possible future INET
families but has no egress allow pin: all candidates retain PrivateNetwork=yes
and IPAddressDeny=any, and custody requires separate fixed peer/TLS/route/firewall
review. These declarations do not establish effective network denial.
AppArmor requirements cover sibling state/credentials, ptrace/process_vm,
unsolicited execution, reviewed runtime/library closure, Unix peer/network
allowlists, enforce attachment and independent denial audit. They contain no
loadable profile attachment or policy loader.

`assess_policies` rejects changed, missing or unknown directives/requirements and
always returns BLOCKED/LIVE_NO_GO, including exact matching candidates. Kernel,
seccomp/BPF/cgroup/proc/namespace support, actual Debian patch level, effective
settings, dependency loss/fencing and AppArmor coverage remain unverified. No
systemd-analyze, parser, systemctl or apparmor_parser is invoked. Future syntax
checks are advisory only. The JSON is not an input to Debian package installation;
packaging, entrypoints, CI and governance remain unchanged. The inert Python
library is included by the existing module packaging rule, without activation.

## CP-01 matrix and future separately approved host work

| CP-01 boundary | Evidence implemented here | Required host work, all HOST_NOT_RUN |
| --- | --- | --- |
| Identity/effective config | OFFLINE_FIXTURE peer existence/groups/lifetime refusals and provenance validation | Independently pin UID/GID/NSS/process lifetime, immutable source/config/unit/profile hashes and effective settings |
| Cross-UID read/write/rename/link | OFFLINE_FIXTURE ownership reference rules; local scratch hygiene only | Actual distinct-principal denials, inode/mode/ACL preservation and audit |
| proc/environ/fd/mem, ptrace, process_vm_readv | OFFLINE_FIXTURE cross-role refusal model | Cross-UID kernel/proc denials with independently retained observer evidence |
| Same-UID dumpability | OFFLINE_FIXTURE accessible baseline and nondumpable denial model | Real PR_SET_DUMPABLE controls and same-UID positive/negative probes |
| FD/environment | OFFLINE_FIXTURE fixed empty handoff and leak FAIL cases | Actual FD/env/proc/memory inheritance and no surviving markers/handles |
| Unix peers/framing | OFFLINE_FIXTURE wrong PID/UID/GID/groups, stale/reused/unknown lifetime, spoof/inherited/socketpair/abstract/ancillary/frame faults | Both-end SO_PEERCRED/lifetime, real parser/SCM_RIGHTS FD closure, bounded frames/deadlines and secure socket ACLs |
| Network | BLOCKED; no transport | INET/IPv6/DNS/loopback/inherited FD/L2/bridge/management denial, fixed custody egress/TLS and independent guest/hypervisor captures |
| Credentials | BLOCKED; no loader/signer/real credentials | Separately approved fake-only loader failure and cross-principal credential/proc/dump denial |
| Journal/storage/anchor | BLOCKED; no production journal touched | Independent anchor, ownership/alias/sidecar/FS/lock checks and retained history under faults |
| Authenticated admission | BLOCKED; no authority implementation | Stale/expired/replay/pass-order/fence/refusal and restart continuity proof |
| Crash/fsync | BLOCKED; no real crash or disk-fault probe | UNKNOWN-before-effect, kill/lost response/full disk/fsync uncertainty and independent witness |
| Reboot/rollback/deletion | BLOCKED; no reboot/snapshot/restore | VM reboot, old ledger/local-anchor pair, deletion and independent external-witness detection |
| Startup/MAC/seccomp | OFFLINE_FIXTURE candidate static refusal only | Unknown settings/drop-ins, missing mechanisms, enforce attachment after exec, namespace bypass and denial audit |
| Resources/stop | OFFLINE_FIXTURE timeout/cancel/reap/leak/cleanup models | Actual bounded process groups/cgroups, dependency loss, hung provider, stop and no residual children |

All real host rows are deliberately non-executable under this Issue. A future
operator approval must identify exact disposable fixture/source/unit/profile
hashes, observer and negative-test scope before any host action. Installation,
loading, startup and enablement each need their own approved scope and effective
configuration/denial evidence, not an offline PASS. Do not SSH, provision users,
change permissions/sysctls/firewall, register Apps, load keys or probe secrets to
fill gaps. Authenticated admission, independent anti-rollback witness, safe signer
loading, writer, enforced policies, crash/reboot recovery, E2E and #73 decisions
remain deferred. Native SUBSCRIPTION_ISOLATION_BLOCKED and exit 13 remain unchanged.


## Review repair: execution and serialized evidence consistency

Serialization revalidates exact schema version, LIVE_NO_GO, gate_73=BLOCKED,
launch_allowed=false (strict bool) and every case's HOST_NOT_RUN field, including
otherwise empty refusal reports. Codes have closed disposition rules:
model_match requires the expected PASS/DENIED and model_matches=true;
model_mismatch requires an unequal model disposition and false; invalid_evidence
requires BLOCKED; owned_children_unreaped/execution_incomplete require FAIL;
cleanup_incomplete/cancelled/deadline require UNKNOWN; after_stop requires
HOST_NOT_RUN. After the first nonmatching result, every remaining case must be
after_stop; an uncaused stop, later execution or a resumed PASS refuses encoding.

Tests explicitly mutate frozen objects via object.__setattr__ and verify that
encoding rejects broken safety invariants. Frozen dataclasses are not an
integrity, cryptographic or authenticated evidence boundary. These checks prove
structural consistency of synthetic records only: a caller controlling Python
can still fabricate a structurally valid fixture report. No record authorizes
host activity or establishes production enforcement, execution or isolation.
