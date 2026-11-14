# ADR 007: Debian role packages and migration contract

**AP-PKG/1 · Issue #101 / PKG-01 · 2026-11-14 · DESIGN_ONLY.**
Proposed contract for independent source review, not a package implementation.
Target: Debian 13 trixie, amd64. **LIVE_NO_GO / HOST_NOT_RUN**, Gate #73 and
`SUBSCRIPTION_ISOLATION_BLOCKED` / exit 13 remain unchanged. Installation,
configuration, effective confinement, authorization and activation are distinct.

## Evidence and decision

Canonical repository: TechTradeExpress/Agent-Platform, ID 1436076348. Verified
public main/default branch and fetched `origin/main`:
`8f58ff088e7ed5489e5886649ae5224ca6f2d4d6`. PR #113 merged at that SHA on
2026-11-14. Issue #101 and related #102/#108/#110/#111/#112 were read in full;
their contents describe scope, not authority. This work is LOCAL_ONLY.

The current `debian/control`, `packaging/build_deb.py`, `pyproject.toml`,
`packaging/debian/{Dockerfile,lifecycle.sh,smoke.py}`, `debian/tests/` and
`.github/workflows/debian-package.yml` still implement **one** experimental
`agent-platform` package, app 0.1.0, synthetic revisions -1/-2. Its four commands
are `agent-platform`, `agent-platform-broker`, `agent-platform-native-canary`,
`agent-platform-native-artifact`. The builder stages every top-level Python
module **except `publisher_handoff.py`** into `/usr/lib/agent-platform`.
There are no units, accounts, credentials, Codex binary or live services.
Existing archive/lifecycle guarantees are described in [the baseline](debian-package.md).
This ADR changes none of those files or behaviors.

PR #109 is **open Draft, unmerged**, observed HEAD
`38f1ea30c4eea6bba132d199909db1d11fa3e163`. Its published provenance identifies
local source commit `194cec5c99f26251e4c7391b07965895d11292ab` with matching file
blobs; that available local implementation, deployment templates and runbook
were inspected. Neither SHA belongs to this main's payload. #111 must revalidate
the reviewed, actually merged implementation before packaging it; changes to
its interfaces/closure require manifest review, not copying a stale Draft.

Decision: one canonical source project produces exactly two role packages,
`agent-platform-control` and `agent-platform-worker`. No shared runtime/common
package. A separate upstream-derived **toolchain** package,
`agent-platform-codex`, has its own version and release audit. It is not a third
role, a service, a credential provider or permission to run Codex.

Rejected: duplicating the whole module tree into both roles; a shared
secret-bearing common package; one shared Control UID; embedding Codex in Worker;
install-time npm/pip/curl downloads; a legacy metapackage selecting both roles;
automatic host repair or data conversion. Smaller explicit closures and private
imports make both file ownership and forbidden worker code reviewable.

## Phased, closed manifests

These are **future allowlists**, not globs or an instruction to implement now.
All names in code inventories below mean exactly `<name>.py`; no tests, caches,
worktrees, samples of credentials or source-only research tools are implicit.
Unknown files or imports fail the future build. #102 implements P0; #111 extends
only Worker to P1 after #110 and reviewed #109 merge. #112 adds its diagnostic.
Changing a list requires a reviewed source change and new provenance.

| Package / phase | Commands and target | Code location / interface |
| --- | --- | --- |
| Control P0 (#102) | `/usr/bin/agent-platform-control` delegates to `agent_platform.cli:main`; update help/program name only, preserve command syntax and pre-I/O exit-13 quarantine | `/usr/lib/agent-platform-control/agent_platform/`, exact C list below; no daemon entrypoint |
| Worker P0 (#102) | `/usr/bin/agent-platform-worker`: new inert role inventory CLI, only `--help`, `--version`; syntactically valid `run`, `resume`, `doctor` return fixed blocked/exit 13 before inspection; no fallback. `/usr/bin/agent-platform-worker-native-artifact` delegates to `agent_platform.native_artifact:main` | `/usr/lib/agent-platform-worker/agent_platform/`, exact W list below; inventory dispatcher is a reviewed standalone wrapper, not the Control CLI |
| Worker P1 (#111, conditional on #109) | `/usr/libexec/ap-worker-publisher`, `ap-worker-publisher-export`, `ap-worker-publisher-signer`, unchanged AP-WP/1 targets | `/usr/lib/ap-worker-publisher/agent_platform/`, exact P list below, empty `__init__.py`; preserve existing hard-coded root and isolated wrappers |
| Worker diagnostic (#112) | `agent-platform-worker doctor`, a separately implemented read-only diagnostic, replaces only that role CLI's doctor refusal | `/usr/lib/agent-platform-worker/agent_platform/worker_doctor.py`, exact dependency closure must be added at #112 review; must not import existing `doctor.py` or enable execution |
| Codex (#110) | `/usr/bin/codex`, original unmodified admitted upstream executable, no PATH shim or alternatives | Exact binary/license/provenance inventory below; no Python namespace or service |

P0 inventory wrapper and renamed manuals do not exist today. #102 supplies and
tests them; it does not implement a worker agent. No `/usr/bin/agent-platform`
compatibility alias, broker, native canary or unversioned common library is
shipped by either role. The developer wheel's existing entrypoints stay a
separate source interface, not a reason to include its entire contents in Debian.

**C — Control P0, 32 modules:**

```text
__init__ app_api_adapter app_api_wire app_metadata app_signer app_signer_ipc
chatgpt_handoff cli codex codex_assignment coding_app_identity custody_journal
draft_publisher execution github_evidence handoff_journal isolation issues
prepare process publisher publisher_candidate queue recovery review_comment
runtime_manifest state subscription subscription_hold supervisor task_status
worker_review_handoff
```

These are the current transitive application-import closure of the Control CLI,
metadata/custody/signer and trusted evidence/review/assignment APIs. Existing
`codex`, `execution`, `isolation`, `prepare` and `publisher` are needed by offline
imports, not activated services. Legacy helpers remain internal/quarantined;
Control never runs target code or Codex. No new CLI exposes these private APIs.
Private root-owned source readability does not grant admission or signing access.
Future services must use separate principals and fixed interfaces even though
their reviewed source resides in one Control package.

**W — Worker P0, four modules:**

```text
__init__ _native_elf native_artifact runtime_manifest
```

This is the read-only artifact inspector's complete application-import closure.
`runtime_manifest.py` is duplicated **bytes**, at different private package paths;
it holds validation, not authority or credentials. The inspector retains its
separate 384 MiB inspection ceiling and never changes the legacy 256 MiB runtime
gate. No native canary, paid probe, broker, credential loader, Control `cli`,
admission, custody, signer, GitHub writer or legacy executor enters W.

**P — Worker P1, five modules plus generated empty initializer:**

```text
worker_publisher worker_publish_artifact worker_publish_io
worker_publish_signer worker_publish_export
```

They import only each other and system libraries/cryptography; do not copy
Control `app_signer`, `app_signer_ipc`, `custody_journal`, `app_api_*`,
`publisher`, `review_comment` or `github_evidence` to satisfy dependencies.
AP-WP/1 is the explicit worker-local writer/signer exception, confined separately
from `agentdev`/Codex. It does not activate CP-02, AP-AS or AP-AL.

**Neither role P0 — remaining 16 current modules, kept in source only:**

```text
_native_canary_probe _sandbox broker broker_policy control_plane_fixture
deployment doctor native_canary native_codex native_security notification_outbox
notifications publisher_handoff telegram_console telegram_fake tool_dispatch_probe
```

Also exclude `_native_elf`/`native_artifact` from C and the C-only modules from W;
`__init__` and `runtime_manifest` are the sole C/W byte duplication. CP-08 is not
on this main; if merged later, `control_plane_local_runner.py` remains source-only
unless separately reviewed. No new top-level module is admitted by filename glob.

## File ownership, configuration and state

All packaged code/docs/config defaults are root:root; directories 0755, source
and metadata 0644, executable wrappers/helpers 0755. No set-ID/file capabilities,
world-writable dirs, symlinks to homes, bytecode generation or global
`dist-packages`. Python wrappers use `/usr/bin/python3 -I`, fixed private
`sys.path`, and disable bytecode writes. Cross-role imports/PYTHONPATH are denied.
The P wrappers retain `/usr/lib/ap-worker-publisher`, not a relocation that would
invalidate #109's code hashes, profile or startup admission.

| Dpkg owner | Exact path families / files |
| --- | --- |
| Control P0 | Commands above; `/usr/lib/agent-platform-control/agent_platform/{C}.py`; private `agent_platform-0.1.0.dist-info/{METADATA,INSTALLER,entry_points.txt}`; `/usr/lib/agent-platform-control/migrate-example` in synthetic N+1 only; `/etc/agent-platform-control/package.conf` sole conffile |
| Worker P0 | Commands above; `/usr/lib/agent-platform-worker/agent_platform/{W}.py`; corresponding private dist-info; `/usr/lib/agent-platform-worker/migrate-example` in synthetic N+1 only; `/etc/agent-platform-worker/package.conf` sole conffile |
| Each role P0 | `/usr/share/doc/<package>/{copyright,changelog.Debian.gz,README.Debian,build.json,manifest.json,examples/schema-v1.json}`; `/usr/share/man/man1/<owned-command>.1.gz`; no other files |
| Worker P1 additions | P code and three libexecs above; `/usr/lib/systemd/system/ap-worker-publisher{,-signer}.service`; `/etc/apparmor.d/ap-worker-publisher{,-signer}` (conffiles); `/usr/lib/sysusers.d/agent-platform-worker.conf`; `/usr/lib/tmpfiles.d/agent-platform-worker.conf`; reviewed nonsecret examples under its own doc directory |
| Codex | `/usr/bin/codex`; `/usr/share/doc/agent-platform-codex/{copyright,LICENSE,NOTICE,third-party-licenses.txt,provenance.json,manifest.json,changelog.Debian.gz,README.Debian}`; no conffile or writable directory. NOTICE records applicable upstream notices; absence upstream is explicitly recorded, never invented attribution |

Manifests enumerate every installed file, mode, owner and digest; generated
metadata is enumerated too. Brace notation in this ADR expands only the listed
names, not additional wildcard content. Standard shared ancestors (`/usr/bin`,
`/usr/lib`, `/etc`, `/usr/share/doc`) are traversal directories, never a shared
config file/code root. No leaf, private directory or conffile belongs to both
roles. P1 owns `/usr/lib/systemd/system`, not copies in `/etc/systemd/system`;
pre-existing manual overrides there require explicit reconciliation, never
overwriting or assuming the vendor unit is effective. #102 ships **none** of the
P1 units, profiles, sysusers/tmpfiles, service hooks or their active locations.

The two `package.conf` files contain inert version/schema/execution=blocked
inventory only. Administrator edits follow dpkg conffile handling; no secret,
enrollment, peer, key path or authorization defaults. P1 profiles are security
configuration; retaining an edited profile is not evidence of enforce attachment.
Any profile mismatch blocks readiness until separately reviewed, never installs
a permissive fallback. Inventory/provenance is correlation, not an approval.

Protected state is **not dpkg payload or conffiles**:

| Future owner | Path and preservation contract |
| --- | --- |
| Control root/operator | Existing `/etc/agent-platform` and `/var/lib/agent-platform` root:root 0755 preserved; `/etc/agent-platform/control-plane` root-owned nonsecret administrator policy, no package-generated authority |
| `ap-admission` | `/var/lib/agent-platform/admission` 0700, ledger 0600; separate admission authority, no credentials |
| `ap-custody` | `/var/lib/agent-platform/custody` 0700, `custody.sqlite3` 0600; AP-AJ store/anchor identity and full history preserved |
| `ap-signer` | **No `/var/lib/agent-platform/signer` or other persistent signer store**; durable replay remains at independent admission authority; separate signer-only managed credential copy |
| Control ephemeral principals | CP-01 `/run/agent-platform-{admission,custody,signer}` 0700 and separately root-managed `/run/agent-platform-ipc` 0711 with exact named socket ACLs; never a shared writable `control/` state root |
| Worker `ap-publisher` | `/var/lib/ap-publisher` 0700, `journal` 0600; no checkout access, no signer journal/PEM |
| Worker `ap-publisher-signer` | `/var/lib/ap-publisher-signer` 0700, distinct `journal` 0600; `/run/ap-publisher-signer` 0700 ephemeral job-bound JWT. This **worker** signer journal is AP-WP/1, not a change to stateless Control signer |
| Worker root/operator | `/etc/ap-publisher` 0750 with exact read-only named ACLs; `job.json`, `receipts.json`, `candidate.json` 0440 with allowed readers per #109; independently retained journal pins. Original `/etc/ap-publisher-keys/worker.pem` in root-only custody; never package-owned/read by Codex or Publisher |
| Untrusted coding principal | Its own homes/worktrees/CODEX_HOME stay outside package ownership; no scanner, migration, ACL broadening or copying from/to protected state |

CP-01 resolves static `ap-admission`, `ap-custody`, `ap-signer` UID/GIDs through
independently trusted host configuration. No single `agent-platform` account,
DynamicUser, shared secret-bearing UID/group, default ACL or recursive chown.
Ingress/controller/output need their own future reviewed accounts/interfaces.
Control provisioning is outside #111 and remains a separate future Issue.

Worker provisioner #111 must independently validate existing `ap-publisher`
(operator-reported UID 999/GID 989), provision a distinct locked no-login
`ap-publisher-signer`, and verify NSS memberships and negative access controls.
Never assign fixed IDs from this report, reuse `agentdev`, adopt an occupied ID,
or repair an existing directory's ownership. sysusers/tmpfiles are provisioning
mechanisms, not authority for blind adoption. No tmpfiles truncate/remove/age
rules over journals; no StateDirectory recursive ownership shortcut. New empty
journals require explicit exclusive, approved initialization with continuity
evidence; existing/uncertain state blocks adoption. Remove/purge retain accounts,
keys, journals, anchors and administrator data, not erase a security identity.

## Dependencies and APT availability

No `Pre-Depends`, role cross-dependency, `Provides: agent-platform`, common
package, recommends-based security or external-Codex alternative dependency.
Both role artifacts remain amd64, even though their P0 payload is Python;
architecture expansion needs explicit tests. Exact proposed direct dependencies:

| Artifact phase | Depends |
| --- | --- |
| Control P0 | `python3 (>= 3.12), python3-cryptography (>= 43.0.0), python3-cryptography (<< 51), git, gh` |
| Worker P0 | `python3 (>= 3.12), agent-platform-codex (= C)` |
| Worker P1 | P0 plus `python3-cryptography (>= 43.0.0), python3-cryptography (<< 51), git, ca-certificates, systemd (>= 257), apparmor (>= 4.1), apparmor-utils, acl` |
| Codex | Exact ELF-derived runtime closure from #110, expressed as versioned Debian dependencies; unresolved until audited; never empty by assumption |

`C` means the literal full reviewed Codex Debian version in the release lock,
substituted before building. An unresolved C or missing closure **blocks** a
Worker candidate build. #102 and #110 may develop independently, but an actual
install test needs a complete matching set. No fake Codex package or dropping
Depends to make #102 green. P0 doesn't need Git/cryptography on Worker: its
inspector uses stdlib. P1 uses Git only in the credential-free exporter; signer
and Publisher never spawn repository commands. Worker does not need `gh`, npm,
pip, Node, Docker or an API broker. Bubblewrap/native runtime prerequisites are
not inferred from this packaging dependency set.

Trixie publishes compatible [cryptography 43](https://packages.debian.org/trixie/python3-cryptography),
[systemd 257](https://packages.debian.org/trixie/systemd) and an
[AppArmor package including the parser](https://packages.debian.org/trixie/apparmor).
These are repository availability observations, not proof of installed versions,
kernel support or a frozen supply chain. Trixie's
[systemd file inventory](https://packages.debian.org/trixie/amd64/systemd/filelist)
supplies both `/usr/bin/systemd-sysusers` and `/usr/bin/systemd-tmpfiles`:
do not add a redundant virtual sysusers dependency or the conflicting standalone
non-systemd package. #111 must test the full signed APT closure and dependency
side effects.
Installing AppArmor dependencies may start/reload baseline framework profiles;
that is separate from authorizing either Publisher unit. Never suppress such
uncertainty with a silent security-policy change or a host workaround.

The three private Agent Platform packages are **not in Debian's archive** and
there is currently no project APT feed. Under future explicit install approval,
provide exact local Worker **and** Codex .debs to one APT transaction, with Debian
dependencies available from a verified cache/repository. A single local Worker
file cannot resolve an absent C from thin air. Offline fixtures pre-acquire the
whole closure then install with network disabled; `dpkg -i` alone is not a
dependency resolver. A future signed feed requires its own Release/InRelease,
key custody/rotation/revocation and scoped publication review. No maintainer
script downloads, `latest`, global npm/pip or credentials in CI.

## Versioning, protocol and upgrade boundaries

Roles share application/source version `0.1.0` initially, no epoch. First split
candidate profiles are `0.1.0-3` (N) and `0.1.0-4` (N+1), explicitly synthetic
profiles from one exact source, not historical releases. N+1 adds the existing
fake-only schema migration helper at each role's private path. No new application
feature is implied by the Debian revision. Subsequent reviewed source changes
increment application version when behavior requires; packaging-only fixes
increment revision. No version reuse for different bytes/source/toolchain.
Both packages from one build share source SHA, but administrators may install
and update either independently: no `Control (= Worker)` dependency.

Codex version is `<upstream-version>-<repack-revision>`, independent of role
versions. Example mapping `0.166.0-1` is **not a selected/admitted binary**:
ADR 005 inspected that release's source, not its executable or license closure.
#110 must select the exact official stable Linux amd64 asset and record URL,
release/tag/peeled source SHA, archive and extracted binary SHA-256, length,
ABI, notices and dependencies in a committed release lock. No release number
alone or a mutable tag supplies binary identity. Worker pins the **entire** C;
a security/repack update requires a reviewed Worker revision and joint APT
transaction. No automatic replacement with a newer upstream binary or fallback
to whatever `codex` is on PATH. Hold rollout on an incompatible dependency;
never discard newer journal history to fit older code.

| Pair / evidence | Compatibility result |
| --- | --- |
| P0 Control + P0 Worker, same or different versions | Co-installable files only; no authenticated product communication implemented |
| Any current Control/Worker pair | Enrollment, mTLS ingress, leases and versioned product protocol **NOT_IMPLEMENTED**; launch/dispatch denied |
| Future authenticated pair | Both must advertise exactly authenticated protocol major, schema/capability versions, peer/boot epoch, source/toolchain hashes and operator-approved compatibility matrix; unknown/required-unsupported capability or stale peer blocks before effects |
| Worker + exact approved C | Tool installation compatible only after #110/#112 ABI/hash checks; native execution still blocked |
| Worker + missing/different C, or arbitrary external Codex | APT dependency unsatisfied or readiness BLOCKED, never version negotiation by PATH |
| AP-WP/1 root job/artifact/receipt + matching P1 binary | Separate local one-shot protocol only, exact closed schema/identity/expiry; no bridge to Control admission or synthetic CP-03/CP-05 receipts |

This defines future compatibility **requirements**, no implemented wire format
or authenticated version handshake. New protocol majors need an independently
reviewed matrix and explicit migration plan; no implicit downgrade/strip-fields
behavior. Code, state schema, protocol and upstream tool versions are different
axes. Pre-upgrade operator quiescence, exact code/config checks and reconciliation
of any incomplete effects are mandatory before an activated service code change.
Packages never start/restart units to make an upgrade look complete.

## Codex binary, license and PATH contract

#110 repackages a pinned official standalone Linux x86_64 binary, unmodified:
no strip/patch/rebuild in the repack step. Audit ELF interpreter, dynamic NEEDED
and symbol version requirements against disposable Debian 13 amd64; map each
needed library to a real APT package and pin minimum supported ABI. A musl-named
asset is not automatically assumed fully static. If extra shipped helper assets
are required, STOP and review an expanded exact manifest; never silently copy
the entire release archive. Record upstream build reproducibility as UNKNOWN
unless separately demonstrated; deterministic repack from identical pinned
bytes/toolchain does not prove upstream source-to-binary equivalence.

The upstream [license](https://github.com/openai/codex/blob/rust-v0.166.0/LICENSE)
is Apache-2.0 and its [README](https://github.com/openai/codex/blob/rust-v0.166.0/README.md)
describes standalone release installation. #110 must audit exact-binary bundled
Rust/native dependencies, applicable licenses/NOTICE/copyright and source-offer
obligations, with a retained third-party report/SBOM tied to binary SHA. A source
LICENSE or Cargo.lock alone does not establish that report. Preserve attribution;
no OpenAI endorsement/trademark claim. If redistribution requirements cannot be
established, **block distribution and Worker package acceptance**. Separately
reviewed user-managed external installation with exact hash/version validation
is the documented alternative, not an OR dependency silently added to this
contract. It does not satisfy the chosen packaged-installer acceptance.

`/usr/bin/codex` is the only package-owned Codex executable. No shell startup,
PATH/profile, `~/.local/bin`, `/usr/local/bin`, symlink, alternatives or diversion
changes. Existing `~/.local/bin/codex` can precede it; shell aliases/functions
and cached command locations can also differ from the explicit system path.
Installation leaves them intact. #112 reports nonsecret resolution/version/hash
mismatch and BLOCKED for an intended packaged workflow; it must not execute an
arbitrary shadowing file to identify it or read private auth/session files.
Trusted future callers use absolute `/usr/bin/codex`, not a shell lookup. The
operator alone decides how to reconcile their interactive shell after review.

For Codex only, #110 implements a **refusal-only preinst collision guard**, not
a downloader or provisioner. Before unpack, the fixed `/usr/bin/codex` must be
absent, or an intact regular root-owned executable owned by the installed
`agent-platform-codex` package with matching previous installed manifest/hash.
Reject foreign/unowned files, links, unsafe parents or ambiguous dpkg ownership;
perform bounded no-follow metadata/hash checks without executing the file or
opening homes. A missing/corrupt prior manifest blocks upgrade, not permits
replacement. A foreign owning package needs an explicitly reviewed conflict
decision; no generic `Replaces`, virtual provider, diversion or overwrite.
This guard must cover direct dpkg and APT paths, including reinstall/downgrade
and interrupted unpack, in #110/#112 fixtures. Archive allowlists alone cannot
prevent dpkg replacing an unowned file. A privileged concurrent administrator
can still race package management and remains outside this guard's trust model.
No other custom Codex maintainer hook is approved here. No auth configuration,
home initialization or `codex --version` in maintainer scripts. Version execution
is confined to a disposable no-account fixture. Binary removal/purge never
touches `$HOME/.codex`, auth caches, sessions, subscription, worktrees or login.

## Legacy migration and lifecycle

**Retire the unreleased `agent-platform` candidate; no transitional package.**
Each role declares unversioned `Conflicts: agent-platform`. No `Breaks` (we need
to prevent simultaneous unpack, not merely configuration), no `Replaces` (no
files are taken over), no `Provides` (new names do not implement all old tools).
Control and Worker do **not** conflict with each other or with Codex. These
relations follow [Debian relationship semantics](https://www.debian.org/doc/debian-policy/ch-relationships.html).
An old residual-config state after **remove** is allowed; old configured/unpacked
code plus either role is not. Test both install directions with actual dpkg/APT.

This conservative mutual exclusion prevents the legacy full module payload on
a worker, despite new private paths being disjoint. APT may propose removing
the conflicting old package; that solver proposal is not approved migration.
An administrator must explicitly review and authorize the removal/installation
plan on the exact host. No package script removes, purges or renames old files.

| Transition | Required result / recovery boundary |
| --- | --- |
| Old -1/-2 installed -> split | Record inventory/config and quiescence; explicitly **remove, not purge**, old candidate; install selected new roles plus matching Codex set. Old four wrappers/lib files leave with their owner; new names are distinct, no compatibility symlink |
| Old config after remove | `/etc/agent-platform/package.conf` retained by dpkg, ignored by both new roles. Do not copy its contents into either new conffile or interpret it as policy. Admin review may create new nonsecret config separately |
| Fresh / role co-install | Independent private files and conffiles, no state/users at P0; either role may be removed without breaking the other's imports or commands |
| N -> N+1 | Normal dpkg conffile prompt semantics; CI deliberately preserves edits/modes with confold/confdef. Package schema inventory is not production state-schema authority |
| Synthetic migration | Explicit owner-run `migrate-example` in a NEW EXAMPLE_ONLY directory under each role's test scope, same AP-PKG-SYNTHETIC validation/backup/intent/no-unknown-retry rules as baseline; never run by package maintenance |
| Interrupted unpack/configure | Inspect dpkg status/audit, exact files and retained evidence; distinguish controlled staged interruption from power loss. No auto journal repair, code execution or state conversion; operator-authorized reconciliation before reconfigure |
| Remove / reinstall | Remove owned code, retain conffiles and all unowned state; reinstall restores code, respects config, never initializes existing journals or enables units |
| Purge | Remove only package conffiles/owned artifacts according to dpkg; retain unowned notes, identities, keys, journals/UNKNOWN/anchors/backups/worktrees. Nonempty admin/state directories stay; no account deletion or recursive cleanup |
| Rollback / downgrade | Explicitly reinstall reviewed compatible code only after quiescence/schema/continuity review. Never roll back journals/anchors/approval history with binaries. No synthetic v2 -> v1 conversion; interrupted/incompatible or UNKNOWN state means STOP |
| Return to legacy candidate | Explicitly remove both roles first, preserve their configs/data; old package remains a blocked experimental CLI, not an emergency privilege or authentication fallback |

No production migration of checkpoints, AP-AJ, signer/admission ledgers, key
custody, pins or user worktrees exists. Do not move them under new names or
retag source/namespace/store identities during upgrade. Hash/inode/source pins
can change only under a new reviewed migration and independent continuity plan.
The synthetic example tests bytes and recovery discipline, never proves a
production migration is safe. Standard dpkg config handling follows
[Debian file policy](https://www.debian.org/doc/debian-policy/ch-files.html).

## Provisioning, credentials and activation are separate gates

| Stage / owner | Allowed result | Does not grant |
| --- | --- | --- |
| #102 inert artifacts | Code/metadata/conffiles, no scripts/services/profiles/accounts/state or tool download | Host installation or runnable product services |
| #110 toolchain build | Audited deterministic Codex .deb, offline ABI/version tests | Login, session/tool invocation, redistribution before license audit |
| #111 Worker provisioning, disposable fixtures | Reviewed idempotent account/path/unit/policy packaging; disabled/inactive oneshots, no automatic restart/start/enable, no key or remote write | Host rollout or an operator approval receipt |
| #112 read-only readiness | Separate INSTALLED / CONFIGURED / READY_FOR_SUPERVISED_PUBLISHING / BLOCKED / NOT_RUN facts with actual provenance | Repair, authentication, activation, native GO or authorizing publication |
| #108 explicitly approved worker01, then worker02 pilots | Exact host/install/action consent, real independently retained evidence and App-authored disposable Draft PRs | Unattended runtime, merge, force, deletion, arbitrary API or other targets |

No P0 maintainer scripts/triggers, ExecStartPre provisioning or installable unit
templates. P1 may introduce narrowly reviewed Debian provisioning hooks, but
must suppress all unit autoactivation on install/upgrade/reinstall/remove and
test those paths. Installing profiles and loading effective policy are separately
observable actions: never claim an AppArmor dependency or syntax check proves
the two processes are confined. Installing software never creates/imports PEM,
discovers credentials, calls GitHub/OpenAI or supplies approval. Control service
units remain unimplemented CP-01 proposals, outside Worker provisioning.

Each VM uses **its own** App, subject to live revalidation: worker01 App 5748674 /
installation 181691110, worker02 App 5748675 / installation 181691061. These are
source/operator pins, not current authenticated identity proof. Only root owns
original keys; only distinct confined `ap-publisher-signer` receives a managed
copy. Publisher receives a job-bound short-lived JWT through a separate unit
credential mount and holds the scoped installation token in memory. Neither
`agentdev`/Codex nor its checkout gets keys, tokens, signer handles or journal
write access. No shared worker home/credentials or copied job approval.

Artifact export is credential-free and bounded; the operator transfers verified
content-addressed bytes into root-controlled intake. Publisher never opens the
Codex worktree or executes repository hooks/config. Preserve AP-WP/1 exact old
SHA/absence CAS, fixed routes, Draft-only operation, complete readbacks, token
revocation and UNKNOWN-before-effect durable journals. No network retry, reset
or auto cleanup after uncertain mint/sign/ref/PR/revocation. External journal-pin
continuity and independently tested worker isolation remain prerequisites.

This specializes older [ADR 006](worker-pool-identity-architecture.md) and
[CP-02](github-app-publisher-contract.md): their ban on untrusted worker/tools
receiving **Control** authority stays; the trusted, separately installed
worker-local P1 signer is the explicit PUB-02 exception. It is not a general
review publisher, Control custody bridge or broad worker token API. App grants
Contents write/PR write/Metadata read remain selected-repository and narrower
than arbitrary GitHub access; no Administration/Workflows/Issues write.
Repository-level Contents write is not feature-ref scoping. Server-enforced
main/App merge denial, operator-independent protection evidence and human-only
merge remain mandatory. Do not broaden grants because a minimal App cannot
read classic branch protection.

## Supply chain, tests and remaining gates

Future builder extends the current recipe, not an independent parallel installer.
Record committed source SHA, recipe/lock hashes, every payload digest/mode,
source epoch, exact build tools and full dependency inventory. Use the pinned
Debian image and action SHAs, no persisted Git credentials or CI writer. Pin
signed distribution snapshot inputs for stronger reproduction; current mutable
APT build inputs and same-toolchain byte repeatability are explicitly limited.
Checksums are not signatures or independent authenticity. SBOM, independent
rebuilds, .buildinfo/source release, signing and APT publication each need their
own reviewed release path; none occurs in PKG-01.

Required follow-up acceptance evidence, all **NOT_RUN for the future split**:

| Issue | Positive and negative checks |
| --- | --- |
| #102 | Real two-role N/N+1/rebuild archives, exact manifests and source hashes; verify all 50 current modules classified, no automatic inclusion of additions; parse transitive imports and exercise CLI paths from installed private roots with no source checkout/PYTHONPATH; no shared leaf ownership, forbidden authority in Worker, secrets/hooks/units absent |
| #102 | Actual isolated apt/dpkg install each and both, either removal order, both legacy conflict directions and residual config; corrupt archives, staged unpack/configure interruption, reinstall/purge, fake owned/unowned conffile/mode/history preservation, explicit synthetic migration and uncertain-state refusal; missing C blocks dependency installation |
| #110 | Exact original binary hashes/ABI/third-party report, deterministic repack, no auth/state paths; offline `--version`, missing ELF dependency, foreign/unowned `/usr/bin/codex` collisions, upgrade/downgrade/remove/purge and user shadowing preservation |
| #111 | Disposable Debian 13: full APT closure, new vs UID 999/GID 989 existing accounts, occupied IDs/symlink/hardlink/ACL/ancestor drift refused; no chown/reinitialization; no unit activation at every package phase, profiles not assumed effective, interrupted/repeated provision preserving UNKNOWN/anchors; manual unit override conflicts detected |
| #112 | Real read-only readiness vs fabricated facts; tampered code/wrong C/shadow binary, shared UIDs, missing parser/BPF, unconfined/incorrect attachment, stale approvals/unknown history/missing units report BLOCKED without repair or reading private auth; actual disposable boot/lifecycle evidence separately from container syntax |
| #108 | Both distinct Apps' real operator-approved disposable Draft publications, actual exact SHA/attribution, revocation, negative isolation and post-restart proof; no source-main destructive probe, merge or autonomous runtime |

Retain current Ruff/full pytest/diff checks, lintian/autopkgtest, conffile and
actual fake schema migration guarantees. Isolate package install tests from
developer/production hosts, pre-cache dependencies and disable lifecycle network;
no privileged fallback or Docker socket. Preserve direct HEAD package provenance
versus Python merge-result checkout evidence. Real apt/dpkg is not piuparts;
container lifecycle is not systemd boot or power-loss durability. CI/source PASS
cannot substitute for host negative probes, independent continuity or live pilots.

Root/hypervisor compromise, shared-host rollback, incomplete credential/tool
mediation, authenticated Control/Worker ingress, safe Control admission/signer
integration, MAC/proc/FD/env/memory denial, BPF/fixed TLS egress, swap/dumps,
effective App permissions and protected main remain open assurance boundaries.
LoadCredential copies are readable by the unit UID; DAC/0700/env filtering alone
does not isolate same-UID code. Preserve [CP-01](control-plane-host-contract.md),
[CP-06](control-plane-fixture.md), AP-AJ/AP-AS/AP-AL and native gates.
Missing evidence is BLOCKED/HOST_NOT_RUN, never configuration-driven GO.
No package version, receipt digest, doctor's READY or successful pilot can release
`LIVE_NO_GO`, Gate #73 or the public/native execution barriers.
