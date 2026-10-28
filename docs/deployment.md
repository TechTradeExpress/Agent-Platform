# Linux runtime and broker deployment blueprint (MVP.2e)

This is an operator handoff, not an installer or deployment authorization. No
root services, permissions, identities, credentials, packages or infrastructure
are provisioned here. `run`, `resume`, `doctor`, broker authentication and all
existing isolation gates are unchanged. A scoped code-review PASS authorizes
neither privileged installation nor paid inference. **E2E_BLOCKED** remains the
result until a separately audited deployment and explicitly authorized live test.

## Identity decision and unresolved gates

The candidate design retains the existing root-identity broker contract and a
non-root host operator. It is **not approved for deployment** until an independent
security reviewer validates confinement and the observed mappings on the actual
host. Use U and G for that operator's actual host UID and primary GID; do not use
copy-pasted example IDs, supplementary groups or an arbitrary dedicated group.

| Component/view | UID/GID and permission expectation |
| --- | --- |
| Host control-plane operator | Non-root U:G; GitHub credential/checkpoint writer stay outside both sandbox and broker |
| Bubblewrap user namespace | Inside 0:0 maps to host U:G; capabilities must be dropped, not treated as host root |
| Relay connecting inside that namespace | Broker in the host namespace must observe exactly U:G through SO_PEERCRED; verify on the real kernel |
| Broker listener | Trusted host-root identity 0; preflight's host-side connection must observe peer UID 0, unchanged |
| New reference socket | root:root 0600 at creation; **cannot serve non-root U:G in this state** |
| Candidate audited socket grant | Root owner retained, primary group G with group write (e.g. 0660), never world access; parent root-owned and non-writable to operator |
| Broker policy | Exact pair [U,G], matching 64-hex broker_id; no asserted headers/PID/session text as authority |

The group grant is a separate human-controlled deployment action, not a tool
feature. Directory search permission must permit U:G without granting directory
write. The sandbox mounts only the socket leaf; it never receives the broker's
parent, process memory, config or credential file. Supplementary membership alone
is insufficient after namespace group dropping. An ordinary unprivileged broker
fails the unchanged peer-UID-0 gate even if a socket pathname is root-owned.

Linux [user namespace mappings](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
translate identities between namespaces. [AF_UNIX SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html)
reports connection/listen-time credentials; it is not a current-capability or
confinement attestation. Do not invent a root-created socket/privilege-drop shim,
forwarding header, permissive ACL or proxy to make that check pass. A reviewer
must separately evaluate the root-identity process's restricted mount/network
views, capabilities, inherited descriptors and memory/ptrace protections. Merely
calling a daemon root-owned is not a least-privilege argument. If that design
cannot be demonstrated safe, **stop at finding DEPLOY-001 and propose a separate
security-review Issue**; do not run an unrestricted root daemon or relax UID 0.

## Reproducible pinned runtime specification

An independent operator supplies an immutable bill of materials from reviewed,
authenticated **offline artifacts**. No auto-download, package installation,
post-install script, `ldd` or candidate-binary execution is performed by tooling.
Record the exact Agent Platform source SHA, Linux x86-64 ABI, Codex **0.164.0**
release artifact hash/provenance, Python **3.12+** exact artifact/version, POSIX
shell exact artifact/version, offline test toolchain and every required library,
stdlib/module/data file by SHA-256. Unfilled versions/hashes mean BLOCKED; do not
use floating package names/latest or claim a complete build from this example.
The file-level catalog pins exact bytes, independently of package naming.

Curate first into a user-owned, quiescent local staging directory. Copy only
reviewed regular files from those offline artifacts, normalizing library paths to
explicit SONAME filenames; never copy a host home, repo, credential, full `/usr`,
symlink forest, service socket or package-manager state. Resolve symlinks while
reviewing the source artifacts, then include the actual regular bytes at each
required destination. The inspector does not dereference them on your behalf.

Required layout:

- `usr/bin/codex`, `usr/bin/python3`, `bin/sh`: regular executable ELF64,
  little-endian x86-64, explicitly approved hashes; no setuid/setgid/capabilities.
- Exact PT_INTERP path and recursive DT_NEEDED ELF closure. Catalog each SONAME
  under a default `lib`, `lib64`, `usr/lib`, `usr/lib64`, or x86_64-linux-gnu
  multiarch directory. No RPATH/RUNPATH, loader audit/filter hooks, ld.so.cache
  or ld.so.preload. A library outside default search paths is not dependency proof.
- Python stdlib and extensions needed by `_sandbox.py`, the test runner and chosen
  offline toolchain; shell utilities and their closures. Catalog each file,
  including `.py` and data files; no generated bytecode/caches or hidden artifacts.
  Scripts may use only literal `#!/bin/sh` or `#!/usr/bin/python3` with an approved
  interpreter. This narrower policy intentionally rejects other formats/arches.
- No missing/unknown files, symlinks, special files, hardlinks or nested mounts.
  Directories/regular files must have trusted owner and no group/world write or
  setuid/setgid bits. No file capabilities. Root-owned production promotion and
  secure ancestors are separately audited; user-owned rehearsal is not promotion.

Create the catalog through independent review of the BOM, not by automatically
trusting hashes discovered from an arbitrary directory. The inert
[runtime catalog example](runtime-catalog.example.json) contains **zero hash
placeholders**, not approved artifacts; replace them and source SHA before use.
Each entry has path -> {sha256, kind: elf/script/data}; the libraries map binds
SONAME to its audited regular path. An approved data hash is not proof that the
content is nonsecret or safe code: all payloads need review. The inspector never
executes a candidate to discover dependencies. Static ELF closure cannot prove
Python imports, dlopen behavior, semantics, provenance, CPU compatibility or safe
code. The real isolated helper/version probes and independent audit remain gates.

Inspector hard bounds are 256 KiB catalog, 2,048 files, 4,096 tree entries,
depth 32, 512 MiB total and **256 MiB per file**. The Codex per-file cap matches
`isolation.Profile` exactly; this increment does not raise it. Traversal is
bounded and descriptor-relative, with O_NOFOLLOW, mode/owner/link/capability and
file-stability checks; mountinfo is bounded to 1 MiB. A quiescent local filesystem
is required. No scanner can attest physical host-root ownership from inside an
arbitrary user namespace; `visible_root_owned` means only current-namespace stat.

After review, run the manifest check from the installed project (substitute
operator-reviewed paths and exact source SHA):

```sh
python -m agent_platform.deployment manifest --source-sha "$SOURCE_SHA" --root "$STAGING_ROOTFS" --catalog "$CATALOG"
```

This command only reads; it emits aggregate hashes/counts, fixed reason codes and
no filenames, identifying host paths or file content. It writes no report unless
the operator explicitly redirects stdout. The supplied source SHA must match the
catalog; its provenance is labeled operator_assertion, not self-attestation.
A PASS means the static catalog checks passed, not that any binary was executed.

Only after separate approval may the operator promote **identical reviewed
bytes** to `/opt/agent-platform/codex-0.164.0/rootfs` as root-owned/non-writable,
then manually supply the existing exact profile.json with version 1, Codex
version/hash and matching broker_id. Re-run static inspection on the deployed
bytes, then doctor. This blueprint includes no root commands or install script.

## Inert broker deployment handoff

Review [broker.md](broker.md)'s exact private configuration schema and finite
lease limits. The operator must separately approve all of these steps:

1. A confined foreground root-identity process under an independently audited
   launcher: reduced capability/bounding sets, narrow read-only runtime view,
   no application repos/home/GitHub/SSH access, limited provider-only network,
   controlled proc/ptrace, disabled core dumps and explicit CPU/memory/FD limits.
   No systemd unit, root helper or automatic privileged launcher is supplied.
2. A trusted root-owned broker directory and absent socket leaf. Start with the
   reference's 0600 creation rule intact; separately audit and apply any primary-G
   group access on the newly verified socket. Never chmod/chown an unknown path
   or add world access. Audit both ends' SO_PEERCRED using fabricated data first.
3. A root-owned/private nonsecret policy with exact [U,G], broker_id, fixed HTTPS
   endpoint/model allowlist and finite counts/deadlines. The inert example in
   broker.md is schema guidance, not authorization or an installed config.
4. Separately audited secret management opens a private regular 0600 token FD
   >=3 and passes only that descriptor number. Keep it outside every sandbox,
   repo, manifest and report; never read it with readiness tooling. Audit all
   inherited FDs, system TLS trust, DNS/egress and provider retention/billing.
5. Explicit foreground start/stop for the approved finite task window. No automatic
   restart or refresh: process-lifetime request budgets reset on manual restart.
   The protocol has no cryptographic turn identity. Provider computation/billing
   cancellation and full real Codex 0.164.0 request compatibility remain unproven.

## Read-only host audit and opt-in rehearsal

```sh
python -m agent_platform.deployment audit --source-sha "$SOURCE_SHA" --catalog "$CATALOG" --broker-policy "$NONSECRET_BROKER_POLICY"
```

Catalog/policy may be omitted to get an explicit blocked overview. Audit only
reads metadata/catalogs, static runtime hashes, fixed namespace-policy sysctls,
and root-trusted Bubblewrap version. It checks root-owned socket/no world access,
primary-G group write, policy pair and identity, then the existing bounded
root-peer health and denied endpoints. No inference/credential FD/secret file,
checkpoint, GitHub, sudo, service changes, socket bind/unlink or permission changes.
`host_audit_pass` means static/read-only prerequisites appear available, not that
kernel isolation, confinement or a coding turn passed. Codex version execution
and launch-specific admission/checkpoint state stay NOT_RUN: **doctor remains the
authoritative launch gate** for an explicit prepared task and trusted actors.

Only with an already available reviewed runtime/catalog and trusted Bubblewrap,
opt into the separate no-credential rehearsal:

```sh
python -m agent_platform.deployment rehearse --source-sha "$SOURCE_SHA" --root "$STAGING_ROOTFS" --catalog "$CATALOG" --scratch "$NEW_DISPOSABLE_SCRATCH" --consent-kernel-probe
```

The scratch path must be absent, outside the inspected image, under a safe parent.
Only this explicit mode creates private synthetic canary/lock artifacts; never a
production socket or checkpoint. Existing paths are conflicts, never overwritten.
Each subprocess is bounded to 10 seconds/4 KiB with fixed clean environment and
no shell. The namespace profile matches `Profile.command(probe=True)` in regression
tests; it mounts only the curated read-only image and fixed helper, with tmpfs
workspace/home/tmp, private proc/dev, dropped capabilities and unshared network,
PID/user/mount/IPC/UTS/cgroup. No host repos, homes, credentials or broker are bound.
It executes the real `_sandbox.py` negative probes, the pinned native sandbox
command and `codex --version` only. No coding turn or inference occurs. Scratch
is retained on success/failure for explicit review; no reset/cleanup/retry occurs.
Unavailable prerequisites yield BLOCKED, not a mocked kernel PASS. A probe marker
mismatch yields FAIL; neither can authorize launch. Production profile/helper
changes still require the existing fail-closed checks, regardless of rehearsal.

## Gap report and recovery

Use [deployment-report.schema.json](deployment-report.schema.json) and the
[blocked example](deployment-report.example.json). Outcomes are strictly
PASS/FAIL/BLOCKED/NOT_RUN. The exact source SHA is an operator assertion to be
checked against the reviewed installation; aggregate hashes and broker/profile
IDs are nonsecret. No raw commands, paths, namespace inode IDs, tokens, prompts,
SSE or tool stderr are saved. Keep these evidence levels separate:

1. offline_ci: fake tools/synthetic files only; never promoted to real kernel.
2. real_kernel: only successful actual opted-in probes; no broker/inference proof.
3. audited_broker: independent deployment audit, never inferred from health.
4. live_inference: separately approved disposable paid E2E, never run here.

The tools always retain E2E_BLOCKED because they cannot attest the last two.
Current open findings / next approvals:

| Finding | Blocker and required separate human action |
| --- | --- |
| DEPLOY-001 | Root-peer contract plus 0600 creation cannot serve a non-root operator without separately audited confinement/socket group grant; request security-design review, not a privilege bypass |
| DEPLOY-002 | Installed Codex candidate measured 308,139,304 bytes, exceeding unchanged 268,435,456-byte cap; do not strip/pack it or raise the cap here; propose a separate reviewed artifact/size-policy decision |
| DEPLOY-003 | Curated runtime/catalog/profile and root-owned broker deployment absent; need independently approved offline artifacts and explicit privileged deployment approval after review |
| DEPLOY-004 | Actual namespace/native runtime rehearsal BLOCKED by missing admissible image; positive policy sysctls and Bubblewrap 0.9.0 are hints, not kernel proof |
| DEPLOY-005 | Live compatibility, inference, provider cancellation/billing and per-turn identity remain unverified; require reviewed deployment and separate explicit paid-test consent/future protocol review |

The measured candidate SHA-256 is
`b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`;
this is an observed installed file, **not an approved deployable runtime hash**.
No candidate version was executed outside the sandbox by the audit. No safe
root deployment or kernel PASS is claimed; follow-up findings remain open in
this handoff rather than changing the broker or runtime trust boundary.

For rollback/recovery: stop the explicit foreground rehearsal/broker and verify
children and sockets are quiescent. Preserve synthetic scratch, private native
sessions, checkpoints/guards and redacted reports. Do not reset/delete worktrees,
unlink unknown sockets, repair modes or edit checkpoints. A separately authorized
operator reviews/reconciles owned artifacts and previous reviewed hashes before
any retirement or rollback; token revocation/rotation is secret-management work,
not this tooling. No automatic destructive rollback is provided.
