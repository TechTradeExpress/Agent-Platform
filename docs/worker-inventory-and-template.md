# Worker Pool B1: inventory and reproducible template contract

**AP-WB/0.1 — B1 / DESIGN_ONLY / NO_HOST_ACCESS**, Issue #84, 2026-11-08.
Companion to [ADR 006 / AP-WP/0.1](worker-pool-identity-architecture.md), not a
replacement for it. Agent Platform is unrelated to Diatonic Orchestrator.
Verified source baseline: `5f96501bb522d467a0126beb45351cac25b09361`.

## Scope, authority and current evidence

This milestone supplies documents only: no live inventory snapshot, discovery
script, image, VM, daemon or host attestation. No commands below were executed on
pve01, dev01 outside the authorized source worktree, publisher01 or another
machine. Source validation is not a host resource/isolation probe. The reported
pve01 context is Ryzen 5 PRO 4650G, **16 GiB RAM / 1 TB NVMe**, not independently
measured hardware, free capacity or an assertion about current guest allocation.
Existing dev01 becomes logical `worker01` without renaming it; `worker02` remains
a future machine. Both have interchangeable implement/review capability sets.
Initially one active task per worker and at most one pool-wide; no static hostname
role or autonomous scheduler is introduced.

| Stage | Permitted only under its own human instruction | Exit boundary |
| --- | --- | --- |
| B1 — this document | Supervised source documentation, tests, feature commit/push, Draft PR | DESIGN_ONLY / NO_HOST_ACCESS; no infrastructure authority |
| B2 — future inventory | Operator-executed bounded read-only collection on explicitly named pve01 and existing dev01 | Reviewed redacted evidence and conditional capacity decision; no changes, benchmark, login or probe permission |
| B3 — future disposable pilot | Clean offline image construction/inspection, then separately authorized per-host worker02 creation and bounded fixture tests | Inert verified image/guest only; C/D/E gates still block production network, identities and native execution |

A merged B1, B2 report, checklist, Issue label or model PASS cannot authorize the
next stage. Human instructions must identify stage, targets, operator, allowed
reads/actions, time window, evidence handling and stop authority. The operator
can stop at any point; missing facts stay UNKNOWN/NOT_MEASURED, never guessed.
No authority comes from target files, model output or a locally computed hash.
Follow [development](development.md) and [AP-SM/2](solo-maintainer-policy.md):
implementer stops at Draft, independent exact-SHA technical review is separate,
and only the human merges Agent Platform main. Multiple AIs or bots are not
independent human reviewers.

## B2 authorization and collection procedure — NOT_RUN

The future operator should receive a separate instruction with this scope:

> Authorize B2 read-only inventory of the independently identified pve01 and
> existing dev01 for Agent Platform worker capacity/template planning. Approve
> the exact nonsecret field/command allowlist, bounded observation window and
> private evidence destination. No publisher01 access, credentials, writes,
> installation, benchmark, Codex auth/inference, network/security probes, reboot
> or provisioning. Stop on denied access, unexpected output or target mismatch;
> review and explicitly approve redacted evidence before sharing.

This is a **scope template, not a request granted by this document**. Do not
invent VM IDs, IPs, current versions or login details. Operator maps logical
names to authoritative local management inventory without placing addresses or
access credentials in source. Use only an already approved administrative access
path; do not establish SSH, VPN, API tokens or broader rights to obtain evidence.

1. Record the human instruction reference, exact target identity mapping, UTC
   start/end, boot correlation and collector/tool provenance. Confirm target and
   read-only privilege before each host group. A copied hostname is insufficient.
2. Approve exact tool paths/versions and fixed argv/GUI fields locally. Bound
   duration/output, disable paging/debug/verbose dumps and collect no environment.
   Do not install a missing tool or use a privileged fallback. Shell expansion,
   arbitrary scripts, target-controlled executables/config and command injection
   are outside the allowlist. Example reads below are candidates for review, not
   a copy-paste discovery script or assertion that a release supports them.
3. Collect only whitelisted scalar/counter fields in the table. Suggested bound:
   10 minutes total per host, 10 seconds / 16 KiB per static read, at most a
   separately approved 60-second low-impact sampler and 64 KiB redacted report.
   Existing trusted historical metrics are preferred for workload peaks. Stop
   rather than truncate a required field into apparent completeness.
4. Review locally before export. Remove secret-bearing/free-text fields, replace
   unnecessary machine/guest identifiers with approved stable aliases, and mark
   each field OBSERVED, OPERATOR_REPORTED, DERIVED, UNKNOWN or NOT_RUN. Preserve
   units, collection period, counter reset/boot context, exit/completeness status
   and redaction reason. A short idle sample does not establish sustained peaks.
5. Operator reviews the sanitized report and approves its sharing destination.
   Retain immutable versions and approved nonsecret evidence hashes; corrections
   supersede by reference, never silently overwrite old evidence. Do not upload
   raw output to Issues, chat, Git, CI artifacts or model context. On accidental
   secret exposure stop export and use a separately authorized incident procedure;
   do not echo the value or automatically copy/delete evidence.
6. Independently evaluate the capacity/parity/unknowns matrix below and request
   the next scoped handoff. No B2 collection result changes host state or grants
   B3, C, D, E or a native launch.

### Inventory allowlist and redaction/parity table

All entries are **required future evidence, NOT_COLLECTED in B1**. Read-only
means no edits, installs, login/status probes, stress/load tests, security scans,
mounts, reboot, VM start/stop, backup/snapshot creation or management mutations.

| Target / facts | Future approved read source or fixed candidate read | Retain / exclude and interpretation |
| --- | --- | --- |
| pve01 release and boot | Proxmox version view or reviewed `pveversion` without verbose config dump; OS/kernel release metadata | Release/build, kernel and boot correlation alias; no subscription keys, repository credentials or complete config export |
| Host RAM / swap / overcommit | Trusted monitoring counters; reviewed `free --bytes`, selected `/proc/meminfo` fields and `vmstat 1 10` | Total/available/committed bytes, balloon/reservation facts, swap-in/out and memory-pressure/OOM counts over a stated interval; no process environments or credential-bearing logs |
| Existing guests and host reserve | Approved management inventory **field view**, not raw guest configs | Stable guest aliases, running state, vCPU caps/weights, configured/balloon/min/max and observed peak RAM; include other workloads without revealing tenant names, command lines, cloud-init or secrets |
| CPU topology / load | Reviewed `lscpu` selected topology fields and existing utilization/pressure telemetry | Physical cores/threads, vCPU allocation/caps/overcommit, sustained utilization and runnable pressure; no assumption vCPU count equals physical capacity |
| Storage / pool | Whitelisted Proxmox storage view, capacity/latency/error telemetry; reviewed `df --block-size=1` for approved volumes | Storage class/pool alias, free/allocated/thin provisioned bytes, growth/snapshot reserve, latency and errors; no serials, mount credentials, raw storage.cfg or benchmark writes |
| Snapshots / backup / restore risk | Operator policy and sanitized inventory summaries | Coverage/date/retention/restore-test reference, space cost, encryption/access policy and external continuity gaps; no backup contents, keys, tokenized URLs or snapshot extraction |
| dev01 guest baseline | `/etc/os-release` approved fields, kernel release, approved package database fields | Debian release/architecture/kernel, init/guest-agent package version and support status; not a claim capabilities or guest tooling are active |
| Guest RAM / CPU / disk | Same bounded counters as above, approved cgroup/resource settings and filesystem metadata | Available capacity, CPU caps, disk free/growth, PIDs and limits, swap/OOM indicators; no arbitrary `/proc/PID` reads, usernames or process listings |
| Real suite resource peaks | Existing sanitized measurements of required offline suites from an authorized run | Exact source SHA, command/test set, duration, peak aggregate RSS/PIDs, disk high-water/I/O, CPU and failures with method/units. Per-process RSS alone may miss child peaks; label limitations. If absent, NOT_MEASURED; B2 does not authorize running the workload |
| Codex artifact and supported behavior | Trusted install/package provenance and pinned official release/schema/help evidence reviewed offline | Approved executable location alias, version, artifact/source hashes, supported model/effort/config and subscription login-route evidence; all currently UNKNOWN. No current version or model is assumed |
| Git / gh / Python / uv / Ruff / pytest | Approved package manifests or reviewed version-only fixed argv using trusted tools | Exact versions, runtime/venv and lockfile provenance, architecture/ABI; no `gh auth`, account queries, config dumps or credential-helper invocation |
| Hypervisor guest tooling | Installed package/version and approved status fields from existing inventory | Compatibility and needed update/reboot state; no install/restart or active capability probes |
| Sandbox/native prerequisites | Existing audited kernel/package/config metadata and previous approved probe references | Namespace/cgroup/seccomp/capability/UID/mount/proc prerequisites and evidence class; metadata is not enforced isolation proof, live negative tests NOT_RUN |
| Network/firewall/zones | Operator-maintained diagrams and whitelisted effective-policy fields | Role/zone aliases, IPv4/IPv6/L2/bridge/backend/precedence and DNS/egress policy references; redact IPs/MACs/private endpoints and credentials. No connectivity/port/DNS probe or firewall edits |

Unknown command semantics, output containing unexpected free text, permission
failure or evidence drift blocks that read. Avoid raw `qm config`, cluster/config
archives, `journalctl`/dmesg dumps, full process/cgroup environments and network
configuration dumps. OOM/failure evidence must be aggregate counters or separately
reviewed nonsecret monitoring, not a pretext to collect logs containing secrets.
Read-only management queries can still disclose secrets; review **fields**, not
merely HTTP method or an executable's name. No Proxmox API implementation is added.

Codex version/help invocation is not automatically harmless: startup can discover
config/auth/plugins. Prefer existing signed artifact/package/source evidence.
Any future version-only invocation requires separate explicit reviewed no-account
scope, clean noncredential environment and bounded trusted executable handling;
it must not inspect the actual login store or launch a turn. Record intended
ChatGPT-subscription login route from operator attestation and supported docs,
**not** `auth.json`, tokens, `codex login status`, refresh, or account entitlement
queries. Model/effort availability and quota remain unverified until their own
approved evidence; no paid API fallback or authentication sharing.

### Immutable redacted evidence contract

Proposed schema **AP-WI/0.1**, documentation only, no parser or trusted loader.
A complete future report must reject unknown fields/types, duplicate IDs, missing
units/provenance, ambiguous time/boot/target or invalid hashes. Store only approved
nonsecret evidence. No credential values **or hashes of credential files** belong
in it. Never use a low-entropy secret hash as a redaction mechanism.

| Field | Required meaning |
| --- | --- |
| schema / report_id / supersedes | Exact version, unique immutable collection ID, prior report reference if corrected |
| stage / status | B2 plus collection outcome, separate from provisioning/launch authorization |
| authorization_reference / collector | Independently authenticated human instruction and actual operator identity/reference, not model text |
| source_contract_sha256 | Hash of the reviewed nonsecret contract version; correlation only |
| target / boot_reference | Approved machine/logical-worker mapping and boot evidence alias/hash, independent of an asserted hostname; no auth material |
| collection_started_utc / ended_utc | UTC interval and trusted clock/source uncertainty; missing trusted time blocks freshness |
| observations | Per-field value/unit, evidence class, sampled interval, read/command provenance, tool path/version/hash, exit/completeness/redaction status, nonsecret evidence digest |
| review / limitations | Human redaction/sharing decision reference, denied/missing fields, known sampling gaps and capacity decision with reasons |
| report_sha256 | Canonical approved redacted payload hash excluding this field; never a signature, freshness proof or approval by itself |

Illustrative **not a live snapshot** (null means uncollected, never zero):

```json
{
  "schema": "AP-WI/0.1",
  "report_id": "EXAMPLE-NOT-COLLECTED",
  "supersedes": null,
  "stage": "B1",
  "status": "DESIGN_ONLY_NO_HOST_ACCESS",
  "authorization_reference": null,
  "collector": null,
  "source_contract_sha256": null,
  "target": {"logical_name": "worker01", "physical_name_reported": "dev01"},
  "boot_reference": null,
  "collection_started_utc": null,
  "collection_ended_utc": null,
  "observations": [
    {"field": "peak_suite_rss", "value": null, "unit": "bytes", "class": "NOT_MEASURED", "provenance": null}
  ],
  "review": {"sharing_authorized": false, "capacity": "UNKNOWN"},
  "limitations": ["Example only; no host collection or provisioning authorized"],
  "report_sha256": null
}
```

The example intentionally cannot qualify as a complete B2 report. A future schema
must specify bounded enums, sizes and exact nested fields before implementation;
this illustrative JSON is not an executable interface or alternative authorization
framework. No source tool imports it. Observed scalar facts, operator-reported
hardware and derived arithmetic must remain distinguishable through every handoff.

## Secret-free reproducible template specification — B3 design

Prefer clean Debian-based image construction from independently verified base
media. Do **not** clone logged-in dev01 and attempt to scrub it. This document
authorizes neither downloading/building an image nor mounting/inspecting a disk.
B3 must pin base release/architecture/media digest and signature verification,
package repository snapshot/security updates and exact package versions, kernel,
build recipe/tool versions, config/file manifest, source/lockfile and Codex
artifact/source provenance, build time inputs and output image hash/SBOM.
Use trusted reviewed tools/config, no target repository hooks or arbitrary scripts.

Rebuild twice in separately approved disposable environments and compare outputs.
Deterministic content and metadata policy must be specified before comparing;
undeclared differences fail reproducibility. Do not call an image reproducible
because only the recipe matches. Retain nonsecret build inputs/digests and review
signatures through an independent operator boundary. A release label or hash alone
is not supply-chain authenticity or admission to execute native Codex.

| Template contents | Rule / verification requirement |
| --- | --- |
| Debian system/software | Approved minimum OS, kernel and fixed package manifest; no arbitrary user homes or development-VM backup as a base |
| Toolchain | Pinned Git/gh/Python/uv/Ruff/pytest and dependencies, reviewed guest tooling and immutable trusted runtime; Codex artifact only if separately scoped, never authenticated or executed by image validation |
| CODEX_HOME and account state | Absent: auth/login, refresh stores, keyrings, sessions/transcripts, account/workspace caches and model-generated histories, including alternate/XDG paths |
| SSH / machine enrollment | Absent: all user `.ssh` keys/known_hosts, host SSH private/public key pairs, enrollment keys/certs, preseeded host identity and copied machine-id |
| GitHub / custody | Absent: App PEM/JWT/token caches, Git credential stores/helpers with credentials, systemd credential payloads/copies, signer state, journal/anchors and approval/replay records |
| User/task residue | Absent: shell history, repos/worktrees, task/checkpoint data, SSH agent sockets, temporary files, dumps/swap/hibernation state and credential-bearing logs/backups |
| Image layers and snapshots | Inspect all backing files/layers/snapshots and recovery surfaces, not only current mounted tree; reject remnants, unknown parents or unverifiable sanitation |
| Services/config | No Agent Platform/native worker/scheduler activation, embedded bootstrap token, account login or credential loader; base distro services require explicit reviewed inventory, not implied extra rights |

Offline artifact inspection under B3 must verify allowed file ownership/modes and
manifest, forbidden-path/credential-marker **absence**, unknown files, image
parents/layers, build caches and alternate auth locations. Use synthetic sentinels
and reject/control pairs to test the inspection procedure; never copy or scan real
host credentials to prove detection. Do not emit content or hashes of suspected
secrets into reports. Human reviews safe pass/fail/evidence references before
export. If absence cannot be independently established, reject/rebuild from the
clean base; never declare sanitation PASS from deletion commands or a file list.
B1 installs, deletes, sanitizes and copies nothing.

First boot, under explicit B3 per-host approval, must generate unique OS machine
identity, host SSH keys and approved enrollment identity rather than reuse image
values. Record public nonsecret fingerprints only when sharing is approved.
Verify copied known_hosts/account stores are absent. Provisioning may stop there:
no account login, GitHub App creation, network policy change or native launch is
implicitly included. New boot/enrollment epochs cannot renew old assignments or
erase UNKNOWN journal/approval history. Do not copy native sessions between VMs.

### Version and capability parity, identity separation

worker01/worker02 must be equivalent in supported capabilities but distinct in
identity. A future release manifest must fill the **unmeasured** columns with
operator evidence; no current installed version is asserted here.

| Dimension | Parity requirement | Identity / drift handling |
| --- | --- | --- |
| OS/kernel/architecture | Same reviewed Debian target (Debian 13 candidate compatibility), ABI and required kernel security features | Unique machine/boot identity; metadata equality alone does not prove kernel enforcement |
| Tools/dependencies | Compatible pinned Git/gh/Python/uv/Ruff/pytest, exact lock/provenance and test set; reproduce Debian lifecycle | Compare manifests before assignment; missing/changed version quarantines, no mid-job upgrades |
| Stock Codex | Same admitted artifact/source/config/tool-route inventory and separately verified supported model/effort | No installed version claimed; complete AP-NF/1 mediation and unchanged artifact caps required before any native GO |
| Account/authentication | Intended ChatGPT-subscription path; supported eligible account/workspace policy independently verified | Separate protected CODEX_HOME/auth/session domains; never cloned/shared. Separate sessions do not prove distinct quota or permit automatic account switching |
| GitHub posting | Same approved role capabilities through controller-mediated writers | Distinct per-worker Apps/bot principals, independently verified installation/repo/permissions/expiry; illustrative Apps remain unregistered; existing metadata-only App unchanged |
| Agent/task | Either worker implements or independently reviews different assignments | Unique agent/execution/task/role/nonce/epoch; retained contributor lineage and fresh independent context prohibit self-review even after swapping hosts/bots |
| Resource policy | Same reviewed job budgets or explicit measured capability class | Insufficient worker is ineligible, not a reason to widen caps or weaken tests |

A clean VM does not solve the inner Codex-auth/untrusted-tools boundary. Keep
protected account owner and tools in independently enforced OS domains, including
proc/memory/ptrace, mounts, FDs/IPC, hooks/plugins/nested dispatch and lifecycle.
Same UID plus 0700, environment filtering or systemd LoadCredential alone is not
isolation. No worker may read App keys, request arbitrary signatures, receive raw
installation tokens or access a generic GitHub writer bridge. Distinct bot identity
proves no independent human review; actual PR author and reviewer must remain
distinct under product collector rules. Current supervised source review remains
AP-SM/2, exact HEAD and human-only merge, with no synthetic #49 Receipt bypass.

## Isolation and negative verification prerequisites — NOT_RUN

B2 may record previously approved evidence; it must not run these probes. B3 may
perform only separately authorized disposable offline image/guest tests. Actual
network/kernel/credential boundary qualification belongs to C/E and the separate
publisher trusted-host track. Every denial test needs a positive control proving
the attempted path/test worked, exact principal/boot/image/policy/time provenance,
fixed bounds, redacted results and operator review. Missing control is UNKNOWN,
not PASS. Do not use real credentials, infrastructure targets or unrestricted scans.

| Boundary | Later required negative/control evidence | Gate |
| --- | --- | --- |
| Worker01 <-> worker02 | Both directions denied, IPv4/IPv6, routed and same L2/bridge/VLAN paths, link-local/multicast and alternate interfaces; approved ingress control succeeds | C, disposable target-specific network tests |
| Worker -> protected infrastructure | Deny Proxmox/management/private publisher01 signer/custody/journal/control ports and local credential sockets; task UID cannot reach privileged handles | C and separate MVP.8g; no pve01/publisher01 probes authorized by B1/B2 |
| Pull ingress | Unique enrolled peer/server identity, bounded role/task/expiry-bound requests; wrong cert/peer, swapped task, replay, stale boot/role token rejected | C/F; ingress separate UID/process from controller/signer/custody, no inherited FD/key |
| Egress | Deny direct task Internet/DNS, IPv4/IPv6 IP literal, DNS/DoH, redirect/proxy/tunnel and L2 bypass; only reviewed GitHub/OpenAI routes from protected trusted principal | C/E; inspect effective hypervisor/guest firewall backend/precedence and reboot persistence |
| Credentials / process | Synthetic auth/key/signer sentinels inaccessible through files, proc, memory/ptrace, env/FDs, keyrings, SSH/Docker/agent sockets; permitted worktree operation succeeds | C/E; actual compromised task-UID probes, not only admin shell |
| Runtime lifecycle | Cancellation/timeout/reboot leaves no surviving child or fresh allowance; unknown state blocks, exact UUID/checkpoint/guard lineage retained | E/F; native remains exit 13 until existing gates pass |
| Identity / review | Wrong repo/App/installation/permission, fake PASS, self-review with swapped worker, duplicate claim and lost replay history rejected | D/F offline contracts then separately authorized E2E |
| Sanitation / restore | Forbidden synthetic residue in any image layer fails; clean control succeeds; replay/anchor rollback is not accepted as new authority | B3 image tests; continuity/restore assurance separate from local SQLite |

A guest firewall is not independent protection against a compromised guest;
hypervisor policy, guest controls and bridges require combined effective evidence.
No unsolicited inbound to workers; authenticated bounded pull only to separate
noncredential ingress. C must review DNS/NTP, IPv6, control/management zones,
allowlist/proxy trade-offs and private-network exclusion without invented addresses.
Do not infer host isolation from green unit tests, VM separation or a diagram.

## Conditional capacity and GO/NO-GO

Resource evidence is **UNKNOWN** until B2. Candidate allocations from ADR 006 are
publisher ~2 GiB and each worker ~4 GiB, not a provisioning decision. Reserve at
least **4 GiB for host plus measured additional existing-workload peak needs**;
include guest overhead/ballooning and storage/network services. The nominal
16 - 4 - 2 - 4 - 4 = 2 GiB remainder is before those additional needs, not proof of
fit. No current guest count/allocations, free disk, swap or workload peak is known.

Use measured concurrent baseline + job high-water + agreed margin, not total
configured RAM alone. A future operator must set explicit CPU/memory/PID/output/
disk/time caps and abort thresholds **before** a disposable benchmark is authorized.
Suggested conservative review thresholds below are planning candidates, not active
controls; production host tests and changing allocations are outside B1/B2.

| Decision | Conditional GO evidence | NO-GO / stop condition |
| --- | --- | --- |
| 2 GiB worker | Only a measured light task profile fits aggregate RSS/children/page cache/OS with >=25% guest headroom and retained host reserve | Unmeasured/full-suite profile, OOM, swap dependence or <25% headroom: not qualified; never suppress tests to fit |
| 4 GiB worker | Required real suite peaks and normal background load fit with >=25% guest headroom and host reserve intact | Memory pressure, missing sustained peak, unexplained OOM or reserve breach; heavy tests may need more, not an automatic resize |
| Host fit | Existing peak workloads, publisher/worker overhead and margin independently accounted for; no sustained swap-in/out | Available reserve below approved floor (minimum 4 GiB plus additional existing peak allowance), any new OOM or sustained swap pressure: stop new work, no unattended recovery |
| CPU/fairness | Measured physical topology/load, caps/weights and bounded runnable pressure; initially one pool job | Saturation harming host/other guests or unknown caps; proposed job duty cap/timeout requires later explicit approval, not vCPU overcommit by assumption |
| Storage choice | Measured local pool class, capacity/thin allocation/snapshot growth, NVMe latency/error and backup policy; approved high-water plus >=20% pool free candidate reserve | Unknown backing chain/durability, errors, reserve below approved floor or excessive latency; never choose journal storage from free-space arithmetic alone |
| Disk/latency stop | Operator sets workload/pool-specific latency ceiling and disk/PID/output budgets before test; measured high-water within margin | Missing ceiling or breached latency/free-space/PID/output/time bound: halt admission; no deleting unrelated files, extending limits or blind retry |
| Concurrency | Initially one active task per worker, **at most one pool-wide** | Two simultaneous tasks stay NO-GO until measured combined peaks, independent isolation and separate authorization |
| Backup/restore | Explicit operator risk decision, verified retention/restore procedure and continuity gap tracked | A snapshot/backup alone cannot establish independent anti-rollback or no secret residue; unverified restore blocks live trust assertions |

Storage selection remains conditional: a directory-backed image or thin-provisioned
volume is eligible only with measured backing-pool capacity, growth/snapshot
accounting and reviewed durability/restore behavior; thin virtual size is not
physical free space. A filesystem/pool with extra RAM needs (for example a
cache-heavy storage stack) must include those needs in the host reserve. Do not
select or migrate storage, create a pool or assume local NVMe implies safe flush
semantics. Unknown latency, backing chain or snapshot reserve means NO-GO.

RSS measurements must identify method and include children/cgroup memory peak,
cache and OS overhead limitations; do not equate test success with capacity.
Actual workload/benchmark collection, even offline, consumes resources and is not
read-only inventory: B2 may use prior evidence only. If it is absent, propose a
separately budgeted disposable B3 run, not a test on the existing development VM.
If reserve/pressure breaches occur during later approved tests, stop admission,
preserve uncertain task state and invoke the approved supervisor/incident plan;
never change VM resources, kill unrelated processes, clean disks or resume jobs
automatically. Existing runtime budgets and exit-13 barriers cannot be widened by
this resource plan. Shared pve01 remains a single failure/compromise domain, no HA.

## Operator acceptance and next-stage checklist

All host/evidence boxes below are presently **NOT_RUN / UNKNOWN**, not completed
by merging this source document. A future operator records actual decisions and
unknowns in an immutable redacted report, never manufactures a measurement.

1. B2: obtain direct human read-only target/field/time/evidence scope; independently
   identify pve01/dev01 and approved access path; reject publisher01/other hosts.
2. B2: review read allowlist/provenance and output bounds, collect nonsecret facts,
   stop on ambiguity, and have the human inspect redaction before sharing.
3. B2: distinguish observed/reported/derived/missing values; capacity decision must
   account for other guests, margins, existing suite evidence and sampling limits.
   No image build, workload execution or provisioning follows from B2 PASS.
4. B3a: request separate authorization for exact clean media, disposable build
   environment, package/artifact inputs, storage/output and offline image tests;
   build twice, inspect all layers, independently review reproducibility/sanitation.
5. B3b: **after B2 capacity and B3a image review**, obtain explicit per-host VM
   creation scope, unique target mapping, resources/storage and inert network
   attachment policy, artifact hash, backup/rollback and stop plan. No unknown
   existing VM/path may be overwritten. This document provides no VM commands.
   If safe attachment needs firewall/network changes, stop for C authorization;
   do not boot a guest onto an unverified network to discover policy later.
6. B3: separately approve first boot/identity generation and any disposable
   resource tests. Native runtime, account login, App installation and production
   access remain blocked even after an inert worker02 exists. Do not rename dev01.
7. C: separately authorize effective network/process/credential isolation design
   and disposable negative/control tests, including reboot. Do not treat B3 boot
   success as a network/OS isolation PASS.
8. D: separately authorize distinct GitHub App actors, exact installation/repo/
   permissions, restricted controller writers and durable audit after governance
   review. Existing Metadata-read App stays unchanged; no credentials in workers.
9. E: separately resolve AP-NF/1 artifact, complete native tool/auth mediation,
   supported subscription/account and real kernel gates before any explicit live
   turn consent. Otherwise native/public legacy stay BLOCKED / exit 13; no paid
   API fallback, supported-tool assumption or bigger-VM exception.
10. F: separately design/implement authenticated project-aware assignments,
    role-neutral durable claims/fencing/checkpoints and independent review;
    reuse existing contracts without stripping pins or resetting UNKNOWN. No
    autonomous scheduler, source reviewer transition or GitHub writer is enabled.

MVP.8g publisher trusted-host metadata pilot, AP-AS/1 admission producer/key
provisioning and AP-AJ/1 external continuity/storage/backup/restore gates are a
**separate track**, not included in B2/B3 or satisfied by worker template evidence.
Local SQLite, signatures, hashes, fsync and VM snapshots do not independently
prove rollback/deletion protection or defend against a compromised custody UID.
No missing Authority may fall back to a permissive signer or legacy Adapter bridge.

Preserve [AP-CI/1](coding-app-gate-b.md), [AP-CA/1](codex-assignment.md),
[AP-AM/1](app-metadata-observer.md), [AP-AL/1](app-api-adapter.md),
[AP-AJ/1](custody-journal-and-host-isolation.md), [AP-AS/1](app-signer-ipc.md),
[AP-NF/1](native-runtime-feasibility.md), AP-SM/2, #49/#59/#62, exact-payload
product authorization and all Gate B/live/publication NO-GO. Template parity is
not execution admission, bot identity is not human approval, and B1 CI PASS is
not host/security assurance. B1 ends at one documentation Draft PR: no host
access, infrastructure operation, credential access, service activation, Ready,
Issue closure, approval, merge or deployment.
