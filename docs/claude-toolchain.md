# HAR-04: official Claude Code toolchain verification and harness-aware doctor

**AP-HAR/1 companion · SOURCE_ONLY / OFFLINE_ONLY / INSTALL_INERT / HOST_NOT_RUN.**
[Issue #134](https://github.com/TechTradeExpress/Agent-Platform/issues/134) within
[HAR-00 #130](https://github.com/TechTradeExpress/Agent-Platform/issues/130),
stacked on the published HAR-03 head `c9cbd524e2a90a37b0a92b908b8e6ec6be4704ad`
(tree `037e2283fa3d24ab93be2ece64d4cc562650bd3a`, PR #142). Delivery is local-only.
`SUBSCRIPTION_ISOLATION_BLOCKED` / exit 13, `LIVE_NO_GO`, `HOST_NOT_RUN`, Gate #73
BLOCKED and human-only merge are unchanged. Nothing here downloads, installs,
executes or authenticates Claude Code, selects a harness, or enables `run`/`resume`.

## Official distribution research (observed 2026-11-16)

Primary sources, read as data: the [setup documentation](https://code.claude.com/docs/en/setup),
the [memory documentation](https://code.claude.com/docs/en/memory) and the official
bootstrap script served at `https://claude.ai/install.sh` (redirecting to
`https://downloads.claude.ai/claude-code-releases/bootstrap.sh`). The script was
never executed; its digest is recorded in the provenance evidence.

| Channel documented for Linux amd64 | Decision |
| --- | --- |
| Native installer (`install.sh`, auto-updating, installs under `~/.local`) | Not used: `curl | sh`, user-home install and background updates are all excluded by the Issue. Its release bucket layout is used as *data*. |
| Signed apt/dnf/apk repositories | Not used: they install `/usr/bin/claude` and add host package sources. That is a third distribution path outside ADR 007's two-package model. The provisioner treats `/usr/bin/claude` as **foreign**. |
| `npm install -g @anthropic-ai/claude-code` | Not used: needs Node/npm and in-place self-update. |
| Direct release bucket `https://downloads.claude.ai/claude-code-releases/<version>/` with a **GPG-signed `manifest.json`** | **Selected.** The documentation states that signing the manifest transitively verifies every platform binary, and that Linux binaries carry no individual code signature. |

Facts taken from the official sources and enforced by tests:

- The release signing key fingerprint is `31DD DE24 DDFA B679 F42D 7BD2 BAA9 29FF 1A7E CACE`
  (published in the setup documentation). The key retrieved from
  `https://downloads.claude.ai/keys/claude-code.asc` is RSA-4096 and its locally computed
  fingerprint equals it.
- Manifest signatures exist for releases from 2.1.89. The manifest lists per-platform
  `checksum` (SHA-256) and `size`. Debian 13 is glibc, so the platform is **`linux-x64`**;
  `linux-x64-musl` is never accepted.
- The official bootstrap script only compares the manifest checksum; the manifest field
  `manifestSignatureEnforcement` is `flag`. **Agent Platform enforces the signature itself.**
- Native installs auto-update in the background. A managed, root-owned, read-only copy cannot
  be replaced by that mechanism; a future launch must additionally set the documented
  `DISABLE_UPDATES` variable (HAR-07, NOT_RUN here). Vendor terms for automated and
  multi-agent use were **not** evaluated (HAR-05).

## Selected pin

| Field | Value |
| --- | --- |
| Version | **2.1.295** (official release; manifest build `2026-10-08T17:09:12Z`, commit `07e8f67ea3282bf154a9e05673a0942b1b173cef`) |
| Why this version | At least 2.1.281, the first release without the documented AGENTS.md session gaps; equal to the HAR-03 offline adapter profile; signed manifest available |
| Platform | `linux-x64` (glibc), member `claude`, 256113848 bytes |
| Binary SHA-256 | `4503bfe11a6c7fcc1e0b39b5e0d347c04248f750b03b0977b3ad6b531fe6f358` |
| Manifest SHA-256 | `b36d7b376c95dd409212ecce0b700cd547266d9ea014ab1f81a1d5bc49cb3cbe` |
| Signature SHA-256 | `7cc44851b80b692481cf986699276c4c14b4301b61aabf46682ad9224ab24c32` |
| Key SHA-256 | `bd70a5e4a268002704024ceba7f8446024114e94f3f0bdd11c23a9e592be81c6` |
| Key fingerprint | `31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE` |
| Informational URLs | `…/claude-code-releases/2.1.295/{manifest.json,manifest.json.sig,linux-x64/claude}` (derived from the version, never fetched by this code) |

The vendor binary itself was **not downloaded**: its identity rests on the signed manifest
checksum. Its ELF type, dynamic-library/glibc closure, behavior and loading of AGENTS.md
are `UNKNOWN / NOT_RUN`. `gpg` is unavailable on worker02, so the signature was verified
only with the in-repository stdlib verifier (key expiry and revocation cannot be checked
offline).

## Pinning and provisioning mechanism

Files: `provisioning/claude_upstream.py` (operator tool),
`provisioning/claude-release-lock.json` (reviewed lock, digest compiled into the tool) and
`provisioning/evidence/claude-2.1.295-{manifest.json,manifest.json.sig,provenance.json}` plus
`claude-code-release-key.asc`. Chain checked by `load_lock()` before any action:

1. the lock bytes equal the compiled `LOCK_SHA256`; schema/fields are closed;
2. the provenance, manifest, signature and key bytes equal the lock's SHA-256 pins;
3. the key's fingerprint is exactly the documented one and its modulus is at least 3072 bits;
4. the detached OpenPGP signature verifies over the manifest bytes (RSA PKCS#1 v1.5 with
   SHA-256/512, stdlib only, issuer subpackets must match);
5. the manifest version, `linux-x64` entry, member name, checksum and size equal the pin.

Rewriting the lock and evidence hashes together cannot forge step 4, and a substituted
key fails step 3 (both are regression tests). Versions below 2.1.281, `latest`, `stable`,
other platforms and unreviewed keys are refused.

The tool is **operator-only, offline and non-executing**. It has no network, subprocess,
environment, home-directory or vendor-CLI code (an AST test enforces the import set). The
operator supplies a previously obtained artifact; the tool verifies a no-follow, single-link,
stable regular file of the exact size, SHA-256 and ELF64 x86-64 header, then stores the
unmodified bytes:

```text
python3 -IB /trusted/code/provisioning/claude_upstream.py verify  --operator-path /usr/local/bin:/usr/bin:/bin
python3 -IB /trusted/code/provisioning/claude_upstream.py install --version 2.1.295 \
  --artifact /operator/supplied/claude --approve --operator-path /usr/local/bin:/usr/bin:/bin
python3 -IB .../claude_upstream.py install --version <newer> --artifact <file> --upgrade --approve --operator-path …
python3 -IB .../claude_upstream.py rollback --version <retained older> --approve --operator-path …
python3 -IB .../claude_upstream.py recover --approve --operator-path …
```

It requires root, Debian 13 amd64 and root-owned non-writable code; it is deployed by the
operator from a reviewed tree (it is **not** shipped in either Debian package, see below).
Obtaining the bytes (outside this project, by the operator) can follow the official
bucket layout and then be checked independently with `sha256sum` and, where available,
`gpg --verify` as in the vendor documentation; nothing is trusted until the tool's checks pass.

### Managed namespace and collisions

`/opt/agent-platform-claude` (root:root 0755) holds exactly `store.json`, `versions/`,
`current` and, only during an operation, `transaction.json` and `.current.next`. Each
version is `versions/<version>-<binary-sha256>/{claude,record.json}` (0755/0644). It is
disjoint from `/opt/agent-platform-codex`, `~/.local/bin`, `~/.claude`, `~/.codex` and
every user home, none of which is read, written or removed. **No command link is created**
and no PATH or shell file is edited; trusted callers must use the recorded absolute path.

| Condition | Result |
| --- | --- |
| `claude` present in `/usr/bin` or `/usr/local/bin` (file or symlink) | install/doctor BLOCKED `foreign_claude_command` |
| `claude` in any operator PATH directory | install BLOCKED `path_collision` |
| Coding user's `~/.local/bin/claude` (lstat of the name only) | doctor `personal_claude_requires_exec_binding`, the user's copy is preserved |
| Bytes differ from the pin, wrong size, link, hard link, group/world-writable, non-ELF or wrong machine | BLOCKED before any write |
| Replaced `current`/version directory (symlink, foreign target), modified record or binary, unknown version or file | BLOCKED, nothing repaired |
| Interrupted operation | all bytes retained; only `recover --approve` of its own published transaction completes; otherwise BLOCKED |
| Unknown or lower version, same-version rebinding | refused; upgrade needs `--upgrade`, rollback only to an intact retained older version |

At most three reviewed versions exist; there is no pruning. Rollback never downloads.

## Harness selection and worker doctor

A worker has one scalar selected harness (ADR 008). Until the deferred durable AP-HSEL/1
store exists, the doctor observes an **operator-written, root-owned local record**, which is
diagnostic input and *never* authority or an admission selection:

```json
{"harness_id":"codex","schema":"AP-HARNESS-LOCAL/1","selection_epoch":1}
```

at `/etc/agent-platform-worker/harness.json` (mode 0644, root:root, canonical JSON). The
package never creates it. `harness_id` is exactly `codex` or `claude_code`; any alias, case
variant, list, `auto`, model name, extra field, non-canonical bytes or bad epoch is BLOCKED
`harness_selection_invalid`; a missing file is `NOT_RUN / harness_selection_missing`.
A second read at the end of a run must be byte-identical, otherwise the check becomes
BLOCKED `harness_selection_changed` and no harness is reported as configured.

`worker_doctor.py` adds the closed checks `harness_selection`, `claude` and `claude_path`
and a closed `harness` block (AP-WORKER-DOCTOR/1 revision, see the schema):

- `claude` verifies the whole managed store against the embedded pin (mirrored from the
  lock; a test enforces equality), streaming the 256 MiB binary hash with a deadline. It
  never executes the file. Absent store is `NOT_RUN / claude_not_installed`.
- `claude_path` observes caller-PATH names and the coding user's personal name only and can
  never return CONFIGURED (`coding_environment_scope_unverified`).
- `harness.harnesses.<id>` reports `selected` and the toolchain state. **Only the recorded
  harness is selected.** A second installed toolchain is reported as
  `alternate_toolchain_ignored` and is never promoted: a missing selected toolchain is not
  replaced by the other one, in either direction.
- Installation is inventory: status stays `BLOCKED`, `launch_allowed=false`,
  `execution_binding` stays `NOT_RUN / trusted_absolute_exec_unobserved`, and
  READY_FOR_SUPERVISED_PUBLISHING remains unreachable.

Existing Codex checks, reasons and verdicts are unchanged (the PKG-05/PKG-07 tests pass
unmodified apart from the extended closed key sets).

## One canonical AGENTS.md

The repository root keeps the single `AGENTS.md`. No `CLAUDE.md`, `CLAUDE.local.md`,
import file, symlink or copy is created, and tests assert that none is tracked.

Documented vendor behavior (memory documentation): Claude Code reads `AGENTS.md` only when
no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` exists in the working directory
**or any ancestor**; a competing file silently replaces it. Native reading needs 2.1.277;
before 2.1.281 some sessions (Bedrock, telemetry disabled) read only `CLAUDE.md`.
`~/.claude/CLAUDE.md` and managed CLAUDE.md do not count but still load alongside.

`agent_platform.instruction_sources` (SOURCE_ONLY, pure, metadata only) implements
`diagnose(root, pinned_version)`:

| Result | Meaning |
| --- | --- |
| `CONSISTENT_UNVERIFIED` | pinned version ≥ 2.1.281, exactly one regular single-link root `AGENTS.md`, no CLAUDE files in the worktree or ancestors, no nested/ancestor/`.claude` AGENTS files |
| `CONFLICT` | any competing or duplicate source (reason codes such as `claude_md_in_ancestor`, `agents_md_nested`); AGENTS.md is **not** silently assumed to win |
| `AGENTS_MD_MISSING`, `VERSION_BLOCKED`, `NOT_RUN` | missing file, version below the contract floor, or unreadable/over-limit scan |

`load_confirmed` is always `false`: a consistent scan is not proof of loading.

**Future confirmation protocol (NOT_RUN, needs separate authorization):** with the exact
managed binary in the exact worktree, an authorized interactive session records the startup
notice `no CLAUDE.md found; AGENTS.md loaded: …` and `/context all` listing exactly the root
`AGENTS.md`. The operator then supplies a closed record:

```json
{"schema":"AP-INSTRUCTION-LOAD-EVIDENCE/1","claude_version":"2.1.295","binary_sha256":"<pin>",
 "agents_md_sha256":"<sha256 of AGENTS.md>","observed_via":"context_all","startup_notice":true,
 "memory_files":["AGENTS.md"],"provenance":"operator_attested_unauthenticated"}
```

`validate_load_evidence` can only return `OPERATOR_ATTESTED_UNAUTHENTICATED` or `REJECTED`.
`InstructionsLoaded` hooks do not fire for natively read AGENTS.md, so they are not evidence.
Changed AGENTS.md bytes, binary or version invalidate the record.

## Packaging

Exactly two role packages remain. `claude_upstream.py`, the lock and all Claude evidence are
deliberately **not** copied by `packaging/build_deb.py`; `instruction_sources` is classified
`SOURCE_ONLY` and excluded from every role/phase archive (existing closure tests extended).
The only shipped change is `worker_doctor.py` (plus its closed schema/doc). No third package,
Debian dependency on Claude, maintainer-script download, unit, account or conffile is added.
Promotion of the provisioner into the Worker P1 private tool path would be a separate,
explicitly reviewed manifest change, as PKG-04 did for Codex.

**Overlap with PKG-09 #138 (not merged here):** both change Worker P1 provenance. This change
edits `packaging/worker-provisioning/worker_doctor.py`, `docs/worker-doctor.schema.json`,
`docs/worker-doctor.md`, one `SOURCE_ONLY` line in `packaging/build_deb.py` and
`tests/test_debian_package.py`. PKG-09's version/manifest work (`-7`) must be reconciled
with the doctor schema revision by the human integrator.

## Migration and rollback

- Existing Codex-only workers: nothing to migrate. With no `harness.json` the doctor reports
  `configured: null`; Codex checks behave as before. Adding Claude tooling never selects it.
- Introduce Claude (separate approvals, none performed here): (1) operator deploys the reviewed
  tree, (2) `install` the verified artifact, (3) separately review isolation/eligibility
  (HAR-05/07), (4) only then write `harness.json` with a **higher** epoch and quiesce per
  ADR 008 (drain, reconcile, re-attest). Session and checkpoint namespaces are not shared.
- Roll back a toolchain: `rollback --version <older retained>` (atomic pointer swap).
- Roll back selection: write a new record with a higher epoch; never restore an old epoch.
  Removing the Claude store is a manual, reviewed operator action; the tool never deletes.

## Validation and what is not proven

Offline tests: real official evidence and signature; tampered manifest/signature/key and a
rewritten hash chain; wrong-key and issuer forgery; manifest mismatch matrix (including musl);
artifact defects; PATH/symlink/hard-link/foreign-command collisions; install, idempotence,
upgrade, downgrade, rollback, retention; interruption at every checkpoint; store tampering;
no-network/no-exec guarantees; doctor store parity with the provisioner; per-harness
selection (dual presence, drift, forged internal state, invalid records); schema closure;
AGENTS.md/CLAUDE.md conflict matrix; two-package/archive closure.

`NOT_RUN / BLOCKED`: real download, installation, execution or `--version`; the vendor
binary's ELF/ABI closure; AGENTS.md loading by the exact binary; auto-update suppression;
authentication, quota and vendor eligibility (HAR-05); isolation and tool mediation
(HAR-07); the disposable Debian lifecycle (the existing hosted Debian workflow builds both roles
with the changed doctor; nothing privileged or Docker-based was run on worker02); any real
host evidence.
