# PKG-05: read-only Worker observations

`agent-platform-worker doctor` is independent of the historical Control/legacy
`doctor.py`. Bare `doctor` dispatches through `/usr/bin/python3 -IB` to the
private P1 `provisioning/worker_doctor.py`. `doctor --issue N`, `run` and `resume`
retain their pre-I/O quarantine and public exit 13. Legacy-only options require
`--issue`; they cannot authorize the new diagnostic. P0 remains unchanged.
This diagnostic never calls provisioning, activation, login or Publisher APIs.
It requires no root escalation; inaccessible observations become NOT_RUN.
An operator may separately run it with existing read access, but it does not
request, acquire or change privileges. Import and construction perform no I/O.

## Observation contract and trust

The closed [AP-WORKER-DOCTOR/1 schema](worker-doctor.schema.json) defines fixed
check names, states and reason codes. JSON is sorted, compact and deterministic
for unchanged observations. Reports contain no timestamp, hostname, caller/home
path, exception text, tool stderr, environment values, journal contents, App key,
JWT/token, OpenAI sessions or private configuration. Only validated package and
Codex versions, pinned official URL/tag, public provenance hashes and the fixed managed effective path
are emitted. System tools use fixed absolute arguments, no shell, sanitized
environment, 5-second deadlines and a 64 KiB output cap. Candidate Codex is never
executed. No temporary files or repairs are needed.

Installation compares the root-owned local build/manifest metadata, dpkg state
and version, and every inventoried public payload hash/mode. No-follow ancestor
traversal, single-link files, ACL/capability exclusion and before/after metadata
checks fail closed. This is **local consistency**, not a signed release attestation
or independent protection against root replacing both code and manifest. External
artifact approval/provenance verification remains an operator prerequisite.
Only after this check may the doctor load the two fixed installed helpers.

Codex uses PKG-03R's unchanged `load_lock`, `inspect_store` and managed-link
validation. These bind AP-CODEX-INSTALL/1, exact reviewed release/provenance pin,
archive digest, actual installed binary SHA-256/size and static ELF ABI, all
retained versions and the active absolute path. Unknown or incomplete versions,
transaction journals, tampering, ownership, mode or xattr failures block. The
installer does not retain the downloaded archive: the archive digest is verified
against the trusted receipt and release pin, **not rehashed from an absent archive**.
An operator's acquisition evidence must retain that original archive digest.
The two path observations have separate, closed scopes:

- `caller_path` inspects names preceding the managed command in the current
  process PATH. It does not inspect HOME or confirm a coding session. A clean
  list yields **NOT_RUN / caller_path_only**, never CONFIGURED, even after Codex
  verification. A preceding candidate blocks with `path_shadowing`; denied
  metadata is NOT_RUN / observation_denied.
- `path` requires a successful `codex()` check and an unchanged in-process
  correlation of its effective path, binary SHA-256 and release pin SHA-256.
  Missing verification (including artifacts=None or an arbitrary artifact dict)
  blocks with `codex_verification_required`. Package/Codex rechecks invalidate the
  previous correlation before observing anything; failed checks cannot leave it
  usable. This correlation is not serialized authority or continuous attestation.
  It reads only public local `/etc/passwd` metadata for the fixed coding principal
  `agentdev`, rejecting missing/ambiguous/root/UID-alias identities or unsafe home
  names. It lstat-inspects only that candidate home's `.local/bin/codex` name.
  Existing personal Codex blocks with `home_codex_present`; denied metadata is
  NOT_RUN, not absence. No private home, shell, session, credential or binary
  contents are read, and neither caller HOME/PATH nor root's identity substitutes
  for coding-user scope.

A safe local account record and absence of that candidate still cannot establish
agentdev's effective NSS/session PATH, aliases or shell cache. There is no trusted
session-environment observation contract, and no su/sudo/login or shell inspection
is introduced. Therefore `path` returns **NOT_RUN /
coding_environment_scope_unverified**, never CONFIGURED. Global configuration
also remains BLOCKED when this required scope is unverified. Root's clean PATH
cannot hide a coding-home candidate or turn its own environment into Worker proof.
Trusted future callers must use the verified absolute binary path.
The updated closed AP-WORKER-DOCTOR/1 schema requires `caller_path`, and limits
both scope checks to BLOCKED/NOT_RUN with fixed reasons. Old consumers must reject
unknown/missing checks rather than silently ignoring this schema revision.

Python >=3.12 and a fixed Git version query are checked. Public local passwd/group
records are validated with PKG-04's identity policy, including UID/GID separation,
999/989 compatibility, no-login shells and no foreign group membership. No NSS
plugin or shadow/password store is queried; effective NSS and locked-password
verification remain NOT_RUN. State checks read only the fixed root provisioning
receipt (metadata only), inspect directory/journal ownership and modes without
reading journal bytes, bind device/inode metadata, reject pending/unknown ledger
entries, and compare the exact numeric configuration ACL. Permission denial is
NOT_RUN; it never causes chmod, chown, setfacl or a privileged retry. A matching
receipt proves local consistency, not history continuity or absence of UNKNOWN.

The diagnostic compares selected effective systemd hardening properties, identities,
limits, profile names and fixed fragment paths; unknown/missing values, enabled or
active units and unreviewed drop-ins block. It observes the kernel's AppArmor
profile list for both profiles in enforce mode. Neither an installed profile nor
this list proves attachment to a specific process. No process is started to obtain
attachment evidence. The BPF prerequisite check requires its kernel interface and a restrictive
effective publisher address/bind policy; missing or broad policy blocks. This
does not establish attachment. BPF attachment, process isolation, independent journal anchors,
authenticated per-worker App identity and current exact-payload operator approval
remain NOT_RUN. The current project has no trusted read-only evidence ingestion
contract for these facts: arbitrary JSON/receipts or a model assertion cannot fill
that gap. No `--ready`, `--root`, override, environment exception or skip exists.

## State and exit semantics

Per-check INSTALLED means the checked local artifact/dependency was observed.
CONFIGURED means only the named configuration/metadata check matched. Missing or
unsafe observations are BLOCKED; denied or unavailable required live evidence is
NOT_RUN. Overall status is BLOCKED / exit 13 even when all available local checks
succeed. READY_FOR_SUPERVISED_PUBLISHING is reserved in the state vocabulary but
**cannot be produced by this implementation**. A future independently reviewed
trusted live-evidence contract is required before adding that transition. Do not
reinterpret exit 13 as an installation failure or automatically repair it.

INSTALL_INERT, LIVE_NO_GO, Gate #73 BLOCKED, HOST_NOT_RUN,
SUBSCRIPTION_ISOLATION_BLOCKED, native/legacy exit 13 and human-only merge remain.
A doctor result grants no publication or runtime authority. There are exactly two
role .deb packages; there is no project Codex .deb or Codex APT dependency.

## Disposable validation

`tests/test_worker_doctor.py`, existing PKG-03R tests and PKG-04/archive tests use
fabricated data and ownership models; they are not live isolation evidence.
The Debian 13 amd64 CI image runs clean and existing 999/989 cases, co-install,
interruption/recovery, idempotence, upgrade, retained state, remove/purge/reinstall,
and installed doctor assertions. The offline synthetic upstream installer fixture
separately tests install, upgrade, rollback and recovery; no vendor executable or
credential is used. Container lifecycle does not prove boot-time systemd,
AppArmor attachment or BPF. Local delivery reports distinguish actual executed
checks from Docker/multi-UID tests unavailable on the development machine.
See [the future pilot checklist](worker-pilot-checklist.md); it authorizes nothing.

Effective-property renderers were checked against official
[systemd v257 systemctl-show.c](https://github.com/systemd/systemd/blob/v257/src/systemctl/systemctl-show.c)
and [bus-print-properties.c](https://github.com/systemd/systemd/blob/v257/src/shared/bus-print-properties.c).
Unsupported/missing renderings fail closed; no local booted-manager PASS is claimed.

## PKG-06: exact operator network configuration (Issue #122)

This is a read-only **local configuration consistency** contract, not publishing
admission or a trusted live-evidence channel. Source review does not authorize
installation on worker01. The only recognized exception to empty DropInPaths is
one exact publisher drop-in, backed by an explicit short-lived root-admin record.
Signer DropInPaths must remain empty. No packaged unit bytes are changed.

### Trust, scope and bytes: AP-WORKER-NETWORK/1

The trusted host administrator, after a separate host-specific human decision,
controls these fixed objects. There is no doctor option, environment variable,
worker-writable receipt or model boolean that selects another path/peer.

| Object | Required metadata / contents |
| --- | --- |
| `/etc/agent-platform-worker/publisher-network.json` | root:root 0600, regular single-link, no ACL/capability; canonical record below |
| `/etc/systemd/system/ap-worker-publisher.service.d` | root:root 0755, real directory, no ACL/capability; exactly the single filename below, no backup/extra files |
| `50-agent-platform-network.conf` in that directory | root:root 0644, regular single-link, no ACL/capability; exact generated bytes below |
| `/etc/machine-id` | safe root:root regular single-link, no symlink/ACL/capability; exactly 32 lowercase hex bytes and LF; only its hash is compared, never reported |
| `/etc/ap-publisher/job.json` | existing nonsecret AP-WP/1 job, root:root 0440, regular single-link; exact SHA-256 and network/expiry binding |

Every ancestor is opened with directory/no-follow flags and checked for ownership,
forbidden write/set-ID bits and ACL/capability metadata. All open ancestor/file
identities, namespace bindings and timestamps are rechecked after the bounded read.
Every input is limited to 64 KiB. These new checks do not loosen the ordinary
package/manpage metadata validator. Only the already documented `/etc/ap-publisher`
0750 directory and 0440 job may have their **exact** existing numeric read ACLs:
root owner, root group, named validated publisher/signer users and matching mask,
no other entries, no write grant, no default ACL or capabilities. Those accounts
must have passed the existing local identity check. No journal or secret is read.

The record is UTF-8 JSON: sorted keys, separators comma/colon without spaces,
exactly one terminal LF, no duplicate/unknown/missing keys. Its exact closed fields:

| Field | Constraint |
| --- | --- |
| `schema` | `AP-WORKER-NETWORK/1` |
| `authority` | `root_operator_network_only` |
| `machine_id_sha256` | SHA-256 of the exact machine-id bytes, including LF |
| `job_sha256` | SHA-256 of the exact installed AP-WP/1 job bytes, including its expiry and full publishing payload bindings |
| `dropin_sha256` | SHA-256 of the exact rendered drop-in bytes |
| `github_ipv4` | one canonical globally routable non-multicast IPv4 literal; no DNS name, list, private/loopback/link-local/documentation address, IPv6 or CIDR input |
| `peer_cert_sha256` | exact AP-WP/1 DER TLS certificate pin |
| `issued_at`, `expires_at` | integer UTC Unix seconds, not booleans; issued <= trusted current host time < expiry, lifetime 1..300 seconds; expiry must equal job.expires |

All digests are 64 lowercase hex characters. For approved literal P, the complete
permitted drop-in is exactly these three LF-terminated lines (P is a metasyntactic
placeholder, **not** a deployable value):

```ini
[Service]
IPAddressAllow=
IPAddressAllow=P/32
```

`network_dropin()` renders those bytes after `_network()` validates the literal.
One /32 is intentionally narrower than the previous 1..8 syntactic prefixes:
AP-WP/1 can connect to precisely one explicit IPv4 and certificate, so multiple
peers have no current job justification. There is no arbitrary config parser,
extra directive, broad prefix, recursive include, automatic refresh or generic
root-owned drop-in acceptance. A matching hash alone cannot admit other syntax.

Root ownership is the **local admin trust anchor**, not cryptographic proof that a
human approved a record. `authority` is a scope discriminator, not self-authenticating
consent. Operator approval must originate outside model/worker output, and root
must independently verify the complete actual job and endpoint evidence before
placing this record. Root replacing code/records, a cloned machine-id or an
untrustworthy host clock is outside this local consistency guarantee and requires
independent reconciliation. No key, token, PEM, receipts.json, session or home
content is consulted. The doctor does not validate the full Publisher job schema
or authenticate operator publication consent; Publisher's existing strict job,
receipt and journaling checks remain separate and unchanged.

### Effective properties, freshness and live evidence

`units()` invalidates any prior network correlation before checking. With no record
and no local drop-in, the original inert unit configuration can be CONFIGURED,
with empty IPAddressAllow; BPF remains BLOCKED / bpf_egress_policy_missing. An
unauthorized physical drop-in, even unloaded, is not silently ignored. An approved
record requires exactly that single DropInPaths entry for publisher, empty for
signer, the existing fixed fragments and every previously checked hardening
property. IPAddressDeny must render both default routes, SocketBindDeny=any,
RestrictAddressFamilies=AF_INET, IPAddressAllow exactly P/32. Both units must remain
inactive/static with NeedDaemonReload=no. Runtime, transient, inherited or foreign
effective drop-ins, duplicate/unknown/missing properties and stale manager cache
are rejected. No daemon reload or service start is performed by doctor.

After both effective unit checks, all record/file/ancestor observations are repeated
and correlated. `bpf()` requires that successful in-process units correlation,
checks the BPF interface, rechecks both complete unit/property sets and repeats
all configuration/expiry/job checks. Byte-identical inode replacement, changed job,
revoked/expired approval, modified file/ancestor or effective policy drift blocks.
There is no persisted PASS cache. This detects observed drift/TOCTOU; it is not an
atomic transaction with systemd or continuous protection against privileged
changes after observation. A later invocation must reobserve everything.

Even perfect prerequisites return **NOT_RUN / bpf_attachment_evidence_missing**.
A systemd property, mounted bpffs, local test or root config is not proof of an
attached/effective cgroup BPF filter. No bpftool, kernel probe, network test or
production process is run. READY_FOR_SUPERVISED_PUBLISHING stays unreachable;
LIVE_NO_GO, HOST_NOT_RUN, Gate #73 BLOCKED, SUBSCRIPTION_ISOLATION_BLOCKED and exit 13
are unchanged. The separate account-lock, profile attachment, process isolation,
continuity, App identity and operator-publication checks remain NOT_RUN.

Closed new report reasons are network_approval_invalid, network_approval_expired,
network_binding_mismatch, network_observation_changed and network_verification_required.
Existing metadata/unit/ACL and bounded observation failure categories still apply.
No address, host identity, approval/job hash, raw record, timestamp or exception
text is added to AP-WORKER-DOCTOR/1 reports. A report is deterministic for equal
observations **and the same validity interval**; expiry deliberately changes refusal.
The updated closed reason enum is in worker-doctor.schema.json.

### Endpoint selection and network reality

Current AP-WP/1 uses direct HTTPS to api.github.com, one literal IPv4 and a DER
certificate pin with TLS/SNI/hostname checks. It does not use DNS at publication
time, redirects, CDN discovery or HTTP(S) proxies; the packaged unit removes proxy
environment variables. This change does not add proxy support. A DNS lookup,
GitHub meta/IP range or general CDN list is not operator authorization and is not
an endpoint-verification method supplied by this code. There are no shipped peer
values. Synthetic test literals do not establish real GitHub ownership or reachability.

Before any separately authorized job, a trusted administrator must independently
verify the selected concrete endpoint and certificate for api.github.com, its
provenance/validity and suitability for the exact one-shot job, bind them into the
actual reviewed AP-WP/1 job, then approve that job's exact SHA, host and short time
window in the network record. If that evidence cannot be obtained reliably,
certificate/IP rotation occurs, or the network requires a proxy, **STOP**. Do not
expand to a CIDR/second IP, infer trust from DNS, refresh a pin automatically or
reuse a stale approval. A verified proxy design or a trusted live endpoint-evidence
mechanism is future separately reviewed scope. This diagnostic cannot supply it.

### Controlled migration, revocation and rollback (not executed)

1. Obtain independent source review and green exact-HEAD/current-base checks.
   Retain reviewed package/source SHA and all original security gates. Record that
   this procedure is documentation, not host authorization.
2. Obtain a separate human decision specifically for worker01's **inert** migration.
   Through the existing administrator channel, inspect package integrity,
   publisher/signer identities, inactive/static units, all current drop-ins and
   effective settings. Preserve state/journals and record hashes/uncertainties.
   Do not edit packaged fragments, enable/start services or use Publisher credentials.
3. In a separately approved disposable environment, run positive/negative metadata,
   single-peer, extra/runtime/inherited drop-in, drift and cache mismatch controls.
   Booted-systemd rendering and actual live cgroup-BPF evidence remain separate
   requirements, not synthetic PASS. A clean property comparison cannot satisfy them.
4. For a separately authorized exact prospective job, trusted admin verifies endpoint,
   complete job and trusted time, prepares exact root-controlled record/drop-in and
   existing job read ACLs. No automatic installation/repair is provided here. The
   administrator alone stages/applies the reviewed objects and, if authorized,
   reloads the manager without activation. Until all objects/cache agree, doctor
   must refuse. Never install a general allowlist merely to make doctor look green.
5. Run read-only doctor with existing access. Inaccessible root-only approval is
   NOT_RUN, not permission to escalate automatically. Independently retain hashes
   of input objects, local approval provenance, effective properties and outstanding
   NOT_RUN/BLOCKED reasons. Overall BLOCKED/exit 13 is expected; do not publish.
6. Any job/peer/certificate/host change requires fresh independent endpoint review,
   new job and new short-lived approval. No last-known-good or multi-peer fallback.
   For revocation, separately authorized admin withdraws approval and the exact
   drop-in, reloads and verifies inert default-deny/empty-allow state. Removing
   approval alone makes doctor fail closed even if manager still has an allow rule;
   it does **not** detach a filter, stop a process or revoke live networking.
   Expiry is diagnostic refusal, not automatic kernel-rule removal. Suspected live
   activity requires separately authorized incident handling, not a diagnostic fix.
7. Rollback restores the previously reviewed package/configuration and inert
   deny-all state through the operator change process. Preserve records/journals
   for reconciliation outside the single-entry drop-in directory; do not truncate
   state or automatically replay a job. Job one-shot/replay protection belongs to
   the unchanged Publisher journal protocol, not this read-only expiring record.
8. worker02 requires its own approval, distinct machine-id/job/endpoint/time evidence
   and complete host checks. No evidence or approval transfers from worker01.

All real-host changes/tests and service/BPF attachment evidence for this source
change are HOST_NOT_RUN. Tests in tests/test_worker_network_policy.py use explicit
temporary-root/current-owner and fabricated systemd/ACL/time observations. They
exercise real no-follow file reads and mutation detection but do not certify a
kernel, host, human approval, GitHub endpoint or operational publishing readiness.

References: systemd's [unit load and drop-in rules](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)
and [IP allow/deny resource controls](https://www.freedesktop.org/software/systemd/man/systemd.resource-control.html).
IP rules rely on cgroup BPF and can be ineffective when kernel support is unavailable;
configuration and live enforcement must remain separate evidence classes.
