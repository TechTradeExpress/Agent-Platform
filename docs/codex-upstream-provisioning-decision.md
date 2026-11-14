# AP-PKG/2: verified upstream Codex CLI provisioning, no binary redistribution

**Decision:** 2026-11-14, maintainer-approved architecture amendment to [ADR 007](debian-role-package-architecture.md).
**Status:** DESIGN_ONLY / SOURCE_ONLY / HOST_NOT_RUN / LIVE_NO_GO.
**Implementation tracker:** [PKG-03R #116](https://github.com/TechTradeExpress/Agent-Platform/issues/116).
**Supersedes:** the `agent-platform-codex.deb`, exact Codex APT `Depends`, Cargo repacking and third-party binary redistribution portions of original PKG-03 [#110](https://github.com/TechTradeExpress/Agent-Platform/issues/110). Prior investigation [PR #115](https://github.com/TechTradeExpress/Agent-Platform/pull/115) closed unmerged and retained for audit. This is a product-scope decision, **not** a claim that redistributing Codex is prohibited by law.

## Product and execution boundaries

Exactly **two Debian role packages** are produced by Agent Platform:
- `agent-platform-control`: trusted Control Plane package with future separate authority principals; current #102 scope remains inert.
- `agent-platform-worker`: worker-only P0 source and CLI at #102; later idempotent root-owned provisioning and Publisher signer at #111.

Neither package includes the Codex binary, an `agent-platform-codex` package, a source distribution, a copy of OpenAI's install script, credentials, private keys, or a `Depends: agent-platform-codex` relation. Worker P0 works without Codex and never launches it; public native and legacy `run` remain **SUBSCRIPTION_ISOLATION_BLOCKED / exit 13**.

Codex is **acquired by the operator onto their own worker from the official upstream**, under the separate reviewed on-host provisioner #116. The project distributes only its own source tooling, a vetted **release pin** (metadata, URL(s), SHA-256, version, platform, size) and verification logic, not the upstream binary. Licensing and upstream service/authentication requirements still apply to use of Codex; this design avoids Agent Platform republishing the vendor's executable.

## Installer workflow

1. `apt install ./agent-platform-worker_<version>_amd64.deb` uses only standard Debian dependency resolution; P0 is inert. No network from `preinst/postinst/prerm/postrm`, no implicit Codex download, profile edit, sysusers provisioning, background service start, Codex login or GitHub App access.
2. An administrator explicitly runs a **one-shot automatic provisioner**, proposed UX `sudo agent-platform-worker codex install`. This command performs **all** fetch/verify/stage/activation steps without manual installation of Codex. A paired `--archive /path/to/pinned.tar.gz` mode permits verified offline installation. The exact interface is implemented/reviewed in #116; this ADR does not pretend that it works today.
3. Only an independently reviewed release-lock entry may be selected. Lock includes pinned official release/tag, immutable allowed asset URL, archive and extracted binary SHA-256, exact member basename, platform/architecture, bounded sizes, and build/release provenance. The earlier #110 `rust-v0.166.0` research can inform selection but does **not** automatically authorize it. No runtime `latest`, unreviewed upgrade or endpoint substitution.
4. Download strictly over TLS with bounded redirects, allowlisted official asset origins/CDN redirects, size/elapsed-time/response caps and no credentials. No executing an upstream shell script, npm script, `curl | sh`, untrusted extraction hook, `postinst` network, auto-login or model inference. A trusted pinned SHA-256 proves consistency with the reviewed expected bytes, **not** upstream authorship alone.
5. Validate archive and extracted bytes **before** any activation: checksum, exact one expected regular file and basename, no links/dirs/path traversal/devices, no extra members, bounded decompression, mode, ownership expectations, platform/ELF/ABI checks and meaningful error categories. Reject unknown/malformed inputs without modifying the current executable.
6. Stage under a **versioned, root-owned worker toolchain path** (final absolute path decided by #116 tests), with fsync/rename and durable install-record provenance. Provide a conventional `codex` name through a **strictly checked** root-owned link at `/usr/local/bin/codex` only if vacant/previously managed; never overwrite package-owned foreign `/usr/bin/codex`, symlinks, home bin or shell configs. If unsafe, fail closed with a clear reconciliation instruction rather than create a partial install.
7. Re-running for an identical admitted hash is idempotent. Update to a *different* verified version is a separately reviewed lock plus explicit operator action; rollback only to an intact already verified version and never overwrite/delete unknown state. Preserve `~/.local/bin/codex`, `~/.codex`, sessions, credentials, and worktrees. A user-installed Codex may be shadowed by `PATH`; the operator reconciles aliases/shell hash. Trusted product callers use the recorded **absolute verified path**, never untrusted PATH lookup.
8. `agent-platform-worker doctor` in #112 checks the trusted on-disk install record, version, hash, effective path, shadowing and ABI **read-only**. It reports `BLOCKED`/NOT_RUN rather than probing user tokens. Having Codex installed never grants subscription auth, sandbox integrity, GitHub write permission, or a production worker `run` GO.

## Isolation, upgrades and compliance

No remote code from a target Git worktree, Issue text, or Codex output can alter trusted release locks or invoke privileged provisioning. Only an approved operator can run the privileged tool. The execution environment is not assumed isolated merely because the binary is in a VM. The installer itself must avoid shell command injection and TOCTOU/path-race effects. Publishing remains a separate operator-gated one-shot action with each worker's own App signer; source repo merge is human-only.

Provisioning may need Internet access; it is **not part of the Debian package lifecycle**, so reproducible `.deb` installs remain offline and deterministic. A future APT feed is independent. For disconnected hosts, supply an operator-downloaded *official* archive as data and validate against the same pin without making it a project-distributed vendor binary.

Ubuntu/Debian distro packages and required runtime ABI are tested against an actual disposable Debian 13 amd64 fixture. Some upstream archives are built for musl; do not infer ABI and dynamic library closure solely from filename. No docker socket, credentials, production key or network service should be implicitly supplied to any fixture. `#111` cannot auto-enable a privileged service as a consequence of installing or upgrading either .deb.

## Acceptance and issue order

- [#102](https://github.com/TechTradeExpress/Agent-Platform/issues/102): two inert, non-overlapping Debian role packages with complete synthetic N/N+1 lifecycle, installable *without Codex*.
- [#116](https://github.com/TechTradeExpress/Agent-Platform/issues/116): fixed-source verified fetch and offline archive path, safe activation/collision/rollback, source-only negative tests, no vendor bytes in project artifacts.
- [#111](https://github.com/TechTradeExpress/Agent-Platform/issues/111): idempotent service/account security provision with explicit operator gate to invoke #116, vetted worker-local Publisher/signer source from PR #109 after review.
- [#112](https://github.com/TechTradeExpress/Agent-Platform/issues/112): read-only installed-provenance/PATH/ABI checks and disposable package/installer lifecycle.
- [#108](https://github.com/TechTradeExpress/Agent-Platform/issues/108): independently approved real worker01 then worker02 App-authored Draft PR pilots, no bypass of main protection, no autonomous Codex launch.

After this amendment is **human-merged**, #102 and #116 may be developed as separate supervised scopes. Green source CI is not host proof. No package distribution, host provisioning, credentials, App policy change, native runtime admission, Codex sign-in or live writer action is authorized by this design document.
