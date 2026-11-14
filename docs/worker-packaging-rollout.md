# Agent Platform: package-first Control/Worker distribution and rollout roadmap

**Status:** MAINTAINER DECISION / PLANNED. **Date:** 2026-11-14. **Scope:** Debian 13 trixie amd64, `control01`, `worker01`, `worker02`. This is a tracked plan and reviewable source document, **not installation, live authentication, service activation, or a GitHub write permission grant**. [Canonical tracker #35](https://github.com/TechTradeExpress/Agent-Platform/issues/35).

## Why change the rollout?

The initial Debian candidate is one unreleased `agent-platform` package (v0.1.0, synthetic revisions -1/-2): `debian/control`, `packaging/build_deb.py` and `docs/debian-package.md` define its payload and offline, adversarial apt/dpkg lifecycle. It deliberately has no `postinst`, installed services, Codex CLI, users, credentials or live execution authority. Preserve all those test guarantees; do not pretend it is a released, running host installer.

The PUB-02 one-shot worker Publisher source is in [Draft PR #109](https://github.com/TechTradeExpress/Agent-Platform/pull/109), exact published HEAD `38f1ea30c4eea6bba132d199909db1d11fa3e163`, awaiting source gate / controlled rollout. Issue [#108](https://github.com/TechTradeExpress/Agent-Platform/issues/108) remains open until **both** separately authorized real worker Apps publish test Draft PRs. We will no longer manually copy services, create signer users or install AppArmor on the real VMs before the tested installer exists.

Read along with [PKG-01 #101](https://github.com/TechTradeExpress/Agent-Platform/issues/101), [PKG-02 #102](https://github.com/TechTradeExpress/Agent-Platform/issues/102), the worker identity ADR, the Control Plane host contract and existing Debian policy. This roadmap prioritizes but **does not silently change** their security gates.

The reviewable PKG-01 specification is [ADR 007 / AP-PKG/1](debian-role-package-architecture.md):
closed module/file inventories, dependencies, versions, explicit retirement of
the experimental package, state ownership and negative lifecycle matrix.
It proposes the contract for #102/#110/#111/#112; none is implemented by the ADR.

## Distribution decision

Exactly **two product/runtime role packages** built from the one Agent Platform source tree, plus a separately versioned **toolchain dependency** for upstream OpenAI Codex CLI. The latter is not a third Agent Platform runtime role or a shared Control/Worker authority package.

| Debian package | Intended host | Payload and ownership | Activation status |
| --- | --- | --- | --- |
| `agent-platform-control` | `control01` | Eventually trusted Control Plane components, with **separate** controllers, signers, admission/custody principals and protected filesystem roots. No collapsing security domains to one Unix UID. | First milestone: inert candidate only. Real services/protocol/keys are separately gated. |
| `agent-platform-worker` | `worker01`, `worker02` | Worker-only code, future agent tools, vetted PUB-02 one-shot Publisher/exporter, independently confined **worker-local** App signer, read-only doctor, systemd/AppArmor templates and safe provisioning; explicit APT dependency on matching Codex package. | Installable and provisioned does **not** imply enabled, authorized or autonomous. |
| `agent-platform-codex` | Worker hosts | **Exact pinned, unmodified** official Codex CLI Linux amd64 binary, license/NOTICE/third-party compliance, package metadata and provenance. `/usr/bin/codex` without modifying shell PATH. | Binary installed; no automatic Codex login/session/tool invocation. |

GitHub's `openai/codex` source is Apache-2.0 and publishes standalone Linux release binaries. That alone is **not** proof that all bundled binary notices/third-party license obligations are satisfied. Audit the **exact chosen release** before distributing a vendor-derived binary. Respect OpenAI trademarks and never imply official endorsement. No third-party secrets, ChatGPT subscriptions or API credits are included.

**APT reality:** `apt install ./agent-platform-worker_*.deb` alone succeeds only when the required `agent-platform-codex` version is reachable through APT. For the initial *offline local artifact* flow, install `./agent-platform-codex_*.deb` together with `./agent-platform-worker_*.deb` in **one APT transaction**, alongside distribution packages from an available Debian repository/cache. A future signed APT feed can provide one-package command UX; this is **not** a reason to fetch unverified code in `postinst`.

## Execution and security identities

| Principal | Authority |
| --- | --- |
| `agentdev` / interactive Codex | Untrusted code development and worker-side bounded artifact export. No GitHub write token, App PEM or signer journal. Existing subscription-auth data remains outside product control. |
| `ap-publisher` | Root-provisioned isolated one-shot worker publisher; may receive only an ephemeral **App JWT** and one-repository installation token after independent approval and confinement checks. No PEM, no checkout access. |
| `ap-publisher-signer` | Separate non-login principal; has constrained access to a copy of **that worker's own unique GitHub App private key** via systemd credential mount, not to the untrusted checkout or Publisher token. |
| `control01` principals | Separate Control Plane trust domains, none merged into worker publisher identities. No copying Control Plane keys into workers. |

This per-worker App design (PUB-02) is a **deliberate specialization** of the older ADR 006 (which rejected worker access to *Control* authority credentials). Each worker gets only **its own** App and only narrow feature-branch Draft PR authority. Classic protection on `main` must continue to prevent Apps from merging. Source `Contents:write` alone is not a substitute for protected-default-branch governance.

**No installer can manufacture its own approval.** Operator must independently verify the actual App installation/scope, main protection including denied App merge, live AppArmor + systemd/BPF isolation, journal continuity/pins, user identities and each exact disposable Issue/ref/commit before any live Publisher write. `LIVE_NO_GO`, Gate #73, native `SUBSCRIPTION_ISOLATION_BLOCKED` / exit 13 and human-only merge remain unchanged.

## Implementation phases and dependencies

1. **PKG-01 [#101](https://github.com/TechTradeExpress/Agent-Platform/issues/101), DESIGN_ONLY, next handoff.** Design/update ADR, exact module and ownership inventories, migration of the existing single unreleased Debian candidate, version constraints, Control/Worker split, worker-local App signer distinction and separate Codex tooling exception. Establish exact executable/packaged paths and how explicit future provisioning avoids ambiguous authority. One Draft PR, independent source review, human-only merge.
2. **PKG-02 [#102](https://github.com/TechTradeExpress/Agent-Platform/issues/102), OFFLINE_ONLY.** After #101 merge, build **inert** `agent-platform-control` and `agent-platform-worker` Debian 13 candidates, with no installed services, users or `postinst` provisioning. Preserve N/N+1 apt/dpkg lifecycle, conffile, migration, reproducibility, lintian/autopkgtest and negative package-content tests.
3. **PKG-03 [#110](https://github.com/TechTradeExpress/Agent-Platform/issues/110), OFFLINE_BUILD.** After #101 design, create the separately pinned `agent-platform-codex` package with original release SHA, license/NOTICE/SBOM, `/usr/bin/codex`, safe reinstall/upgrade and no credential state ownership. Independent from #102's role builds; execution can be scheduled separately, one supervised developer Issue at a time.
4. **PUB-02 [#108](https://github.com/TechTradeExpress/Agent-Platform/issues/108) / [Draft PR #109](https://github.com/TechTradeExpress/Agent-Platform/pull/109), SOURCE REVIEW.** Review/merge source code via human-only workflow; green CI and synthetic tests alone do not approve host deployment. Keep Issue #108 open for the actual controlled pilots.
5. **PKG-04 [#111](https://github.com/TechTradeExpress/Agent-Platform/issues/111), INSTALL_INERT.** After #102, #110 and reviewed #109 merge: extend worker packaging with vetted real Publisher/signer and worker-only files, Debian-managed idempotent sysusers/tmpfiles (or rigorously justified equivalent), existing UID collision safeguards, root-owned code, security profiles and **disabled/inactive oneshot** services. New installs, upgrades and purges must never start Codex or Publisher, log in, change main/rulesets, generate App keys or delete protected state. Package dependencies resolve via APT; no curl/npm/pip in maintainer scripts.
6. **PKG-05 [#112](https://github.com/TechTradeExpress/Agent-Platform/issues/112), READ_ONLY DOCTOR + TESTS.** After #111, `agent-platform-worker doctor` reports `INSTALLED`, `CONFIGURED`, `READY_FOR_SUPERVISED_PUBLISHING`, `BLOCKED`, `NOT_RUN` from real separately sourced evidence. Distinguish package/toolchain installed from Codex authenticated, and from autonomous execution authorization. Disposable Debian 13 lifecycle matrix includes fresh install, legacy candidate, version skew, invalid profiles, user collisions, interrupted updates, upgrade/remove/purge and preservation of unknown journals.
7. **PUB-02 [#108](https://github.com/TechTradeExpress/Agent-Platform/issues/108), operator-controlled host pilot.** Only after all dependencies merge and fresh separate operator approval: verify artifact hashes and isolated setup on `worker01`, configure **only its own** App key in signer custody, pin a disposable Issue/ref/exact SHA, publish a Draft PR with App attribution, independently verify GitHub and revocation/journal status; then repeat with `worker02` using its **different** App, identity and separate evidence. Do not close #108 before both succeed; unknown states stop and require operator reconciliation.

Dependency order: `#101 → (#102, #110) → #111 → #112 → #108 live pilots`; PR #109 source merge is an additional prerequisite of #111, not permission to install. Work is scheduled by explicit maintainer prompts, no background scheduler.

## Debian safety contract

- Exact-source, deterministic `.deb` outputs; immutable upstream vendor asset pinned by SHA; build-time provenance and package file allowlists, proper copyright/NOTICE and ownership; no private keys/tokens/sessions included or retrieved.
- Role-private `/usr` locations and separately protected `/etc`, `/var/lib`, `/run` trees; no overlapping dpkg ownership. Clarify which config is a `conffile` and how it survives upgrade.
- No uncontrolled Internet access during package maintenance; external dependencies pre-resolved using APT, package repository/cache configured separately. Avoid `postinst` auto-login, Codex execution, application writes or downloads.
- Provisioning must distinguish **new** accounts/journals from existing worker states; workers currently have `ap-publisher` UID 999/GID 989, no `ap-publisher-signer`; importing or reassigning existing UIDs, changing ownership recursively, truncating protected journals, or removing private keys on purge is forbidden.
- Installing profile files or AppArmor dependencies may affect baseline system profiles. Test actual Debian package behavior in disposable VMs and document precise effects; **never enable/restart privileged publisher units on installation**. Only independent operator acceptance can authorize service run.
- Codex CLI in `/usr/bin` uses existing PATH; no changes to shell startup files. Preexisting `~/.local/bin/codex` may shadow it: detect and report, never silently delete/overwrite. Codex authentication remains an explicit owner action.
- Protect upgrades, rollbacks and removal: preserve evidence/journals/conffiles and worktrees, fail closed on incompatible versions, symlinks, UID conflicts, uncertain or partially written security state.
- `doctor` may inspect only approved nonsecret metadata and effective host controls; it must not inspect/copy raw private authentication, PEM or tokens, and is **not** a substitute for separately signed operator receipts.
- Do not release/tag/sign/upload artifacts to a public registry and do not install on real `control01`/`worker01`/`worker02` as part of source coding tasks. Every host change is a distinct operator authorization.

## Verified baseline, decision not deployment

As reported by operator for both `worker01` and `worker02`: Debian 13, systemd 257, Python 3.13.5, cryptography 43.0.0, root-owned `/usr/bin/git`; AppArmor kernel reports enabled but `apparmor_parser` is absent from current command PATH; current shell is `unconfined`, which does not establish service profile state. Existing `ap-publisher` UID 999/GID 989; **no `ap-publisher-signer`**. `ptrace_scope=0`. These are operator-reported preflight observations, **not** live MAC/BPF or credential isolation PASS. Recheck on each host before controlled package installation.

**Current stop:** no package or service installation, App private key provisioning, session login, live write, autonomous Codex execution, protected-branch mutation or GitHub merge is authorized by this document.

## Workflow and exit criteria

Use the existing manual contributor path from `AGENTS.md`, `docs/development.md` and AP-SM/2: maintainer assigns one Issue; Codex works in a safe dedicated worktree and creates one local commit / Draft PR when transport is authorized; ChatGPT independently reviews exact HEAD and CI (same GitHub actor comments are labelled AI-assisted, not separate human APPROVE); maintainer alone merges. Never close an implementation issue without its own acceptance evidence, and keep #108 open until both real pilot publications are observed.

**First coding handoff:** [PKG-01 #101](https://github.com/TechTradeExpress/Agent-Platform/issues/101). Its merged ADR must resolve version/package/dependency/licensing and identity conflicts before PKG-02/03/04 implement the result.
