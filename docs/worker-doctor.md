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
