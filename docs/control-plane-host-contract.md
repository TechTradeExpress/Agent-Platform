# CP-01: Control Plane host isolation contract

Issue #87, 2026-11-10. **DESIGN_ONLY / NO-GO / HOST_NOT_RUN**.
Source base: `e19c0b3b124ac5689d0c31c60a5ea5e7330c11af`.
This is Agent Platform, separate from Diatonic Orchestrator. This document
specifies future requirements; it installs nothing and supplies no runnable unit,
listener, credential loader, admission authority or deployment authorization.

## Evidence and baseline

`VERIFIED_OFFLINE` means source inspection or a named synthetic test only;
`DESIGN_ONLY` means a proposed requirement; `HOST_NOT_RUN` means a future host
check has not run; `BLOCKED` means a prerequisite is absent. None implies live GO.
All permission/settings tables below are DESIGN_ONLY; all host probes below are
HOST_NOT_RUN. The authenticated admission/continuity producer is
**NOT_IMPLEMENTED / BLOCKED**.

The Issue's OPERATOR_REPORTED baseline for `control01` is Debian 13.7,
Python 3.13.5, systemd 257, OpenSSL 3.5.7, cryptography 43.0.0, SQLite 3.46.1,
ext4, AppArmor active and Yama ptrace_scope=0, on a 2 GiB-class VM. Separate
static locked no-login ap-admission, ap-custody and ap-signer accounts reportedly
exist, as do empty root:root 0755 /etc/agent-platform and /var/lib/agent-platform
parents. No service/package is reported installed. These are not independently
attested facts. Do not infer numeric IDs, effective confinement, durable storage
or absence of all legacy processes/state. Historical publisherapp and protected
legacy credential locations remain untouched; their paths/key identities are
not needed here. No host inventory or secret inspection was performed.

This refines [ADR 006](worker-pool-identity-architecture.md),
[AP-AJ/1](custody-journal-and-host-isolation.md) and
[AP-AS/1](app-signer-ipc.md). Older publisher01 naming is historical; control01 is
the proposed role here, without renaming or assuming a host migration.

## Principals, assets and flows

Resolve account names through trusted host configuration at future admission,
pin actual UID/GID and process lifetime, and reject duplicates, unexpected group
memberships or identity changes. No DynamicUser, shared secret-bearing UID,
supplementary groups, login shell, user service manager or unrelated jobs under
these UIDs. An empty SupplementaryGroups setting does not erase NSS memberships;
verify the effective groups. Root/operator remains trusted and separately scoped.

| Principal | Allowed assets and operations | Denied |
| --- | --- | --- |
| root/operator | Install reviewed immutable code/config; explicitly provision approved state; manage original PEM; authorize incidents | Automatic bootstrap, model-derived authority, incidental secret logging |
| ap-admission | Own private admission/replay ledger; authenticate exact human/controller approval; consult independently protected continuity; issue bounded run/session facts | PEM/JWT/token, custody DB, arbitrary signing/HTTP, deriving fresh authority from restart |
| ap-custody | Own AP-AJ journal; execute AP-AM observe with AP-AL injected clients; hold JWT and installation tokens in memory; call admitted signer; emit redacted Result | Original PEM, signer credential copy, admission ledger writes, arbitrary URLs, repository writers |
| ap-signer | Signer-only credential copy/memory; exact admitted AP-AS fixed RS256 sessions; authenticated authority lookup/consume/finish | Installation token, custody journal, Internet, arbitrary bytes/keys or Claims-only fallback |
| Future ingress/controller/output/publisher | Separate UIDs and separately reviewed fixed interfaces; output receives only redacted non-authorizing facts | Sharing these three UIDs, journal/credential FDs or direct worker-to-custody/signer routes |
| Workers/target code/model | No access to any protected local asset or private IPC | Every credential, DB, control-plane mount, peer route and authority operation |

| Direction | Allowed future payload / check | Denied reverse or alternate path |
| --- | --- | --- |
| Authenticated controller -> admission | Exact immutable scope, project/App/run/expiry and approval provenance | Ingress/Issue/model text as approval |
| Custody and signer -> admission | Separate fixed lookup/consume/finish or continuity protocols; exact peer and run pins | Caller-chosen policy, quota reset, generic ledger writes |
| Admission -> custody/signer | Independently authenticated admitted facts and continuity responses | Key/token/DB transfer; a digest as authentication |
| Custody -> signer | SignAppJwtV1 over pinned connected AF_UNIX; reply JWT only to custody | Signer-initiated custody operation, worker or output client |
| Custody -> GitHub | Future fixed AP-AL TLS routes/token lifecycle, metadata-only scope | Generic proxy, writer/review/publish API |
| Custody -> output | Validated redacted AP-AM Result only | Raw response, client, lease/token map, journal or signing handle |

The authority IPC schemas, authenticated ingress/controller and output transport
are not implemented. No socket endpoint in this design grants them authority.
Unique UIDs and DAC limit sibling access, but cannot protect against malicious
root/hypervisor or prove independent anti-rollback. Admission on the same VM is
not itself an independent continuity witness. Snapshotting DB and old anchor
together can defeat local history checks. External continuity/storage assurance
and crash-safe advancement remain separate BLOCKED gates.

## Filesystem and lifecycle contract

Except the explicit socket ACLs below, no default or extra access ACLs,
symlinks, writable ancestors, hardlink
aliases or unreviewed bind mounts. Trusted root-owned ancestors permit traversal
but no non-root writes. Validate with descriptor-based no-follow walks and pinned
inode/device identities; path spelling and a preflight stat alone do not prevent
replacement races. Code/config are never loaded from worktrees, homes or tmp.

| Proposed path class | Owner/group/mode and use |
| --- | --- |
| /usr/lib/agent-platform and installed modules | root:root dirs 0755/files 0644; reviewed executable wrappers 0755; read-only to all services |
| /etc/agent-platform | Preserve root:root 0755 parent; package.conf remains inert root:root 0644 conffile |
| /etc/agent-platform/control-plane | Future root:root 0755, nonsecret versioned contract/config only; files 0644; no authority from target JSON |
| /var/lib/agent-platform | Preserve root:root 0755 parent; never chown recursively |
| /var/lib/agent-platform/admission | ap-admission:ap-admission 0700, private future ledger files 0600; not a continuity witness |
| /var/lib/agent-platform/custody | ap-custody:ap-custody 0700; exact custody.sqlite3 0600, singly linked; no unrelated files |
| /var/lib/agent-platform/signer | No state directory approved; durable replay lives at independent authority, never ephemeral signer memory |
| Original PEM | Existing root custody unchanged, root-only traversal/read; no discovery, movement or new path assumed |
| Signer credential directory | Future systemd-managed per-unit credential mount; signer-only read, no sibling access; never under /etc public config or /var/lib journal |
| /run/agent-platform-{admission,custody,signer} | Separate ephemeral runtime dirs, owner corresponding principal, 0700; no continuity/approval state |
| /run/agent-platform-ipc/{admission,custody,signer}.sock | Future root-managed IPC parent root:root 0711; listener-owned pathname with exact access ACL below (mode 0620 after ACL mask); no group access; no secret files |

Proposed socket ACLs: signer endpoint owner ap-signer, connect permission only
ap-custody; admission endpoint owner ap-admission, connect only ap-custody and
ap-signer. A future custody endpoint requires a separately approved controller
identity, absent today: deny all other clients. ACL mask must allow only the
intended named users: owner::rw-, named client users:-w-, group::---,
mask::-w-, other::--- (stat mode 0620 reflects the ACL mask, not group access).
No default ACL. Do not grant
cross-principal directory write or shared supplementary groups. Root-controlled
provisioning of these endpoints is NOT_IMPLEMENTED; no unit is allowed to chmod,
unlink or replace an existing socket automatically. Private 0700 runtime dirs
cannot host a cross-UID pathname socket without a separately reviewed traversal
exception; use the distinct IPC parent above. Filesystem permissions supplement,
never replace, both-end kernel peer checks and independent admission.

Do not use StateDirectory= on the custody journal path: manager creation/chown
would undermine AP-AJ explicit empty-directory provisioning and identity pins.
Proposed units omit StateDirectory= and ConfigurationDirectory= entirely. Future
operator provisioning must be separate, approved, and refusal-only on existing
or uncertain data. RuntimeDirectory=agent-platform-<principal> with
RuntimeDirectoryMode=0700 is suitable only for ephemeral files; recreation on
boot is no authorization. IPC parent/ACL provisioning needs separate reviewed
packaging/administrative ownership, not implicit unit startup.

AP-AJ StoreIdentity pins namespace/source/App/installation, store ID, directory
and DB device/inode, filesystem class and independent storage evidence. Supply
Anchor independently on every reopen. Local ext-family magic does not attest
ext4 journaling, barriers, flush honesty or hypervisor persistence. No overlay,
tmpfs or network DB fallback. Hold nonblocking exclusive directory flock for the
entire owning process/thread session; no inherited SQLite session after fork.
Keep DELETE rollback journal, synchronous=EXTRA, busy timeout zero, exact schema,
256 KiB DB/128-event limits, full history and confirmed fsync/readback. Retained
sidecars, stale anchors, wrong identities and uncertain writes STOP without hot
recovery, repair, deletion, eviction or retry. A DB-derived anchor is not external.

Upgrade only reviewed immutable code/config after explicit quiescence and
reconciliation; retain all history/UNKNOWN records and external anchor. No
implicit data migration or downgrade. A changed inode/source/namespace requires
new reviewed identity/migration evidence, not replacement pins guessed from disk.

## Proposed systemd 257 requirements

Names: agent-platform-admission.service, agent-platform-signer.service and
agent-platform-custody.service. These are requirements tables, not installable
units. No ExecStart exists or is approved. No socket activation, timer, enablement,
WantedBy, automatic boot start or permissive placeholder. All start gates remain
BLOCKED until trusted executable/admission/continuity integration is reviewed.

| Common future setting | Required rationale / qualification |
| --- | --- |
| User=/Group= corresponding static principal; UMask=0077; SupplementaryGroups= empty | Verify effective NSS groups and unique IDs independently |
| Type=notify; NotifyAccess=main; TimeoutStartSec=15s | Future reviewed daemon must report ready only after all gates, never merely exec success |
| Restart=no; KillMode=control-group; TimeoutStopSec=10s; SendSIGKILL=yes | No unattended replay; forced stop preserves uncertainty and requires reconciliation |
| ProtectSystem=strict; ProtectHome=yes; PrivateTmp=yes; PrivateDevices=yes | Read-only mounts and private tmp/dev views; private tmp remains writable, never authority storage |
| NoNewPrivileges=yes; CapabilityBoundingSet= empty; AmbientCapabilities= empty | No privilege acquisition/capabilities; no privileged Exec prefixes/helpers |
| ProtectKernelTunables=yes; ProtectKernelModules=yes; ProtectKernelLogs=yes; ProtectControlGroups=yes; RestrictSUIDSGID=yes; LockPersonality=yes; RestrictRealtime=yes | Reduce kernel/control surface; no cgroup delegation |
| ProtectProc=invisible; ProcSubset=pid; LimitCORE=0; KeyringMode=private | Proc filtering and no core files; not isolation from root or same UID |
| SystemCallArchitectures=native; SystemCallFilter=@system-service; SystemCallFilter=~@privileged @resources @mount @debug | Candidate seccomp policy; must be profiled against actual reviewed Python/OpenSSL/SQLite closure, with no widening fallback |
| MemoryDenyWriteExecute=yes; RestrictNamespaces=yes | Must prove extension/runtime compatibility; failure blocks, never silently remove |
| LimitNOFILE=64; TasksMax=16; CPUQuota=25%; MemoryHigh=96M; MemoryMax=128M; MemorySwapMax=0 | Per-principal starting budgets, not measured capacity; <=384 MiB hard total leaves VM headroom; resource exhaustion STOP |
| StandardInput=null; StandardOutput=null; StandardError=null | No raw credential-bearing diagnostics; future fixed redacted status needs separate bounded audit design |

Only admission ledger and custody journal are future ReadWritePaths exceptions,
respectively; runtime dirs are separately writable via RuntimeDirectory. Signer
has no persistent write exception. ReadWritePaths does not grant DAC permission
or validate existing storage. Add InaccessiblePaths for sibling private state and
original credential storage once trusted paths are approved, without exposing
legacy secret paths in public artifacts. The signer receives only the managed
credential copy; custody/admission receive no credential mount. No ExecStartPre
provisioning or cleanup, recursive ownership fix, default environment credential,
PID file, shell or child tool execution.

Future dependency order: admission readiness before signer, then custody.
Signer Requires=/After=/BindsTo= admission; custody Requires=/After=/BindsTo=
admission and signer. Dependencies stop dependents on loss, but do not authenticate
approvals or detect a hung process. Normal stop is reverse order; suspend new
requests before draining. No OnFailure restart or reconnect/retry. Every restart
requires fresh process pins, durable history and independent continuity check;
a new PID never renews consumed passes. A future launcher must establish both
process identities while requests are disabled, distribute independently trusted
peer pins, then admit sessions; ordering alone cannot solve this startup
handshake. Reboot does not replay pending requests.

Compatibility reference: upstream
[systemd.exec 257](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html),
[service 257](https://www.freedesktop.org/software/systemd/man/257/systemd.service.html)
and [v257 resource-control source](https://github.com/systemd/systemd/blob/v257/man/systemd.resource-control.xml).
The proposed directives exist in that version; Debian patch level, kernel,
seccomp, cgroup v2/controllers, mount/proc namespace and BPF support still require
fixture verification. Unknown directives may be warnings rather than fatal;
future validation must reject warnings and compare effective settings, then test
actual denials. Declarative syntax is DESIGN_ONLY, not kernel evidence.

## Credentials, IPC and network

Future LoadCredential= uses one fixed reviewed root source and signer-only ID.
No key path is selected by a request. The current CredentialProvider accepts only
an in-memory RSA object: a safe loader and daemon remain NOT_IMPLEMENTED. Validate
RSA size/exponent/fingerprint and admitted App/purpose before use. Missing,
malformed or wrong key fails startup with fixed redacted status. No environment,
argv, log, core, inherited descriptor, subprocess or output transfer of PEM/JWTs.
LoadCredential copies are accessible to processes under the unit UID; hence no
untrusted code or unrelated process may share that UID. Deny ptrace/process_vm
and /proc/<pid>/{mem,environ,fd} cross-principal access; ptrace_scope=0 reported
baseline is not a protective Yama gate. Require tested DAC/non-dumpability, proc,
seccomp and MAC controls; no sysctl change is authorized. Assess swap/hibernation,
host dumps and residual memory independently; Python cannot guarantee zeroization.

Future launcher closes every non-allowlisted FD, uses CLOEXEC and never hands
credential/journal sockets to output/worker processes. AP-AS currently accepts
only injected connected AF_UNIX SOCK_STREAM sockets; it does not bind/listen or
load systemd sockets. Both ends pin exact SO_PEERCRED PID/UID/GID and trusted
lifetime. Socketpair credentials identify the creator, not later FD holders;
no inherited socketpair shortcut. Secure listeners and lifecycle pin distribution
are separately BLOCKED. Reject abstract sockets and SCM_RIGHTS/ancillary data;
close received descriptors. Keep 2048-byte request/8192-byte reply including
four-byte length, canonical JSON, EOF, <=5-second total operation, one process
handler/no queue, two ordered one-use passes. UNKNOWN precedes signing; lost
reply/late completion consumes authority and closes/poisons the session. A
synchronous provider cannot be preempted by Python deadlines; supervision must
bound it without retry. Claims-only sign() remains blocked; no AP-AL bridge.

Signer/admission: PrivateNetwork=yes, RestrictAddressFamilies=AF_UNIX,
IPAddressDeny=any. AF_UNIX pathname IPC can cross network namespaces, so DAC,
MAC and peer checks remain mandatory; inherited INET FDs must also be denied.
Custody: only future approved AF_UNIX plus AF_INET/AF_INET6 as needed for the
explicit numeric peer, IPAddressDeny=any with exact reviewed IPAddressAllow pins;
no current egress authorization. IP filters cannot pin TLS name, port or HTTP
route and may be ineffective without BPF support. Independent guest/hypervisor
firewall must constrain TCP 443 to approved peers, deny other egress/inbound,
L2/IPv6/bridge/management paths, and verify enforcement. AP-AL separately keeps
api.github.com Host/SNI/certificate validation, fixed CA, no DNS/proxy/redirect,
fixed routes/auth/deadlines; an IP change requires new approval, never wildcard
fallback. No network probe or firewall change is performed here.

Future AppArmor profiles must separately confine installed executables for each
principal: deny sibling secrets/state, ptrace, unsolicited execution, arbitrary
Unix peers and network; permit only reviewed libraries, authority IPC and the
listed assets. Active AppArmor alone proves no profile coverage. Enforce mode,
attachment after exec, denial logs and bypass/namespace paths need independent
negative tests. Missing enforcement is NO-GO, never a complain-mode fallback.

## Future disposable-fixture runbook and evidence matrix

Every row is HOST_NOT_RUN. A new specific human approval must identify the
fixture, exact source/unit/profile hashes and test scope before any host action.
Use only fabricated credentials and disposable accounts/storage, never production
paths. A reviewed harness must use fixed argv/no shell, 5-second individual
probes, 60-second case cap, <=64 KiB redacted evidence per case and bounded/reaped
children. Crash/reboot cases require separate operator control and 120-second
observation cap; timeout means STOP/unknown, not retry. No harness is supplied.

| Case / reproducible fixture stimulus | Expected DENY or STOP and independent evidence |
| --- | --- |
| Record identity/config | Trusted operator records version, effective UID/GID/groups, unit/drop-in/profile hashes, mount/cgroup/kernel features; mismatch STOP before readiness |
| Cross-UID access | Place unique fake markers in each private asset; attempt read/write/rename/link as every other principal and worker/output UID; DENY, unchanged bytes/inodes/modes/ACLs, kernel audit evidence |
| FD/env/proc | Inject fake secret FDs/env then launch through reviewed boundary; enumerate child FDs and probe proc/memory/ptrace from sibling UIDs at reported Yama=0; no marker or handle escapes; any leak STOP |
| Socket peers | Connect as wrong UID/GID, correct UID wrong PID, stale PID/lifetime, abstract socket, inherited socketpair, SCM_RIGHTS/truncated/oversized/trailing/slow frame; DENY, no signature, descriptors reaped, replay history retained |
| Network | Attempt IPv4/IPv6, DNS, loopback, inherited INET socket, same-L2 worker and management routes; signer/admission DENY all INET; custody only fake approved TLS peer; verify guest and hypervisor captures/counters, not unit score |
| Credentials | Absent/malformed/wrong fake PEM/fingerprint; negative startup, no ready socket/signature; sibling cannot read managed copy; inspect redacted result, not secret dump |
| Journal/anchor | Missing external anchor, wrong store inode/source/namespace, symlink/hardlink/ACL, sidecar, wrong FS or busy lock; STOP with no file repair/replacement; compare retained identity/history |
| Admission | Stale/expired/replayed/wrong-run/pass/order approval; restart and retry same request; DENY across sessions, independently retained UNKNOWN precedes signing |
| Crash and storage | Kill at UNKNOWN/sign/send/commit/anchor boundaries; simulate full disk/fsync failure; STOP, no replay; independent witness compares retained DB/sidecars and acknowledgement sequence |
| Reboot/rollback/deletion | Reboot disposable VM; restore old DB alone and DB+local anchor; remove ledger; readiness STOP on uncertainty, external witness detects rollback/deletion; local hashes alone cannot PASS |
| Startup confinement | Remove namespace/seccomp/BPF/MAC support, introduce unknown directive/drop-in, wrong groups or untrusted binary; readiness STOP, no permissive service or dependency restart |
| Resource/stop | Exhaust FD/task/memory/operation budgets, hang fake provider, stop admission; dependents stop, no signing after loss, unknown effects retained; cgroup/process observations and no surviving children |

Retain independent observer identity, exact test inputs/hashes, expected/actual
result, timestamps, effective configuration and redacted kernel/network evidence.
A missing observation remains HOST_NOT_RUN or BLOCKED. Synthetic library tests
are VERIFIED_OFFLINE only; systemd-analyze verify/security, package CI, declarative
settings and operator reports cannot establish live isolation.

Current reproducible offline checks: `uv run ruff check .`, `uv run pytest`,
`git diff --check`. Existing AP-AS/AP-AJ/AP-AL tests use disposable keys, synthetic
authority/transport and fabricated storage evidence; consult exact test output
in the delivery record. They do not exercise this proposed systemd composition.

## GO/NO-GO, packaging and recovery

CP-01 completion permits contract review only. Live remains **NO-GO / BLOCKED**
until separately implemented/reviewed authenticated authority and external
continuity, safe loader/IPC integration, immutable code provenance, effective
principal/MAC/network separation, durable storage/reboot evidence, bounded
supervision and every negative test pass under new human authorization. No
all-offline-PASS route to deployment exists.

On failure, stop new admissions and dependent operations; preserve journal,
sidecars, UNKNOWN/replay records, external anchors and redacted evidence. Never
restart blindly, restore an old DB/anchor pair, clear state, infer revocation
from token expiry or repeat an uncertain POST/sign. An authorized operator must
reconcile remote effects and continuity independently and approve any recovery.
Rollback of reviewed code can happen only after that reconciliation and schema
compatibility review; it never rolls back authority/history. No automatic
revocation, cleanup, account deletion or legacy credential migration is added.

The [Debian CLI package](debian-package.md) remains unchanged and inert: four
existing entrypoints, no units/sysusers/tmpfiles/service hooks or state creation.
Existing /etc/agent-platform/package.conf is nonsecret inventory, not service
policy. Future service packaging requires its own versioned reviewed artifact,
explicit install/start separation, no automatic enable/start/restart, ownership
and conffile migration plan, and disposable upgrade/remove/reboot tests. Reconcile
reported manually created accounts/parents without recreating accounts or
recursive chown. Preserve publisherapp, original protected credentials, unowned
state and all uncertain history on upgrade/remove/purge. No actual units,
sysusers/tmpfiles configuration or AppArmor profiles are delivered by CP-01.
Admission Authority, signer integration, independent continuity storage, ingress,
publisher and workers remain separate work. Native/subscription execution and
public legacy run/resume/doctor stay blocked at exit 13; no permissions, GitHub
App operations, host changes, paid inference or runtime activation follow.
