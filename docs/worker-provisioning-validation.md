# PKG-04 local validation record

Base: `790dc17382689552bbf8f16823f7f16956ff37f5` (merged PUB-02).
Source implementation only; LOCAL_ONLY. No real host provisioning, App key,
OpenAI/GitHub credential, authentication or remote publication was used.

- `uv sync --locked`: completed.
- `uv run ruff check .`: PASS.
- Targeted Worker provisioning, Debian packaging, PUB-02 and upstream Codex
  tests: 224 PASS. Ownership in provisioning unit tests is explicitly modeled,
  not multi-UID kernel proof.
- Full `uv run pytest`: executed; existing filesystem mutation-sensitive tests
  can fail in this environment. Both
  `test_native_artifact.py::test_file_mutation_after_digest_read_is_detected`
  and `test_telegram_console.py::test_changing_evidence_before_write_is_blocked[journal]`
  were independently reproduced as failures on the exact unchanged base above.
  No changes to those tests or components are included. The delivery report gives
  the final full-suite count; this record does not claim whole-suite PASS.
- `git diff --check`: PASS.
- Real archive tests: P0 remains closed, P1 exact payload/control metadata,
  no vendor binary/Codex APT dependency, no configure/remove/activation hooks,
  repeatability and synthetic N/N+1 differences: PASS.
- Real Debian 13 amd64, offline disposable bwrap fixture from pinned official
  OCI manifest `1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d`:
  existing full P0 lifecycle PASS (independent/co-install, upgrade/interruption,
  migrations, legacy conflicts, remove/reinstall/purge, foreign state retention).
- P1 Debian dependencies acquired through signed APT indexes in the disposable
  acquisition namespace. Offline dependency install followed by actual P1
  dpkg unpack/configure completed. These are sequential operations, not proof
  of the single-transaction Docker APT acceptance case. The single-UID namespace
  reported Debian framework chown/ACL warnings for unmapped service IDs.
- Actual installed P1 operator tool in a fresh single-UID fixture: expected
  failure when creating ownership for a different UID, retained intent, denied
  retry, and preserved intent through actual dpkg remove/purge: PASS as a
  **negative** lifecycle only. No privileged fallback or ownership substitution.
- Lintian on real P1 candidate archives using disposable Debian tool files:
  completed with `--fail-on error`, exit 0.

## Remaining NOT_RUN / BLOCKED evidence

Docker, Podman and subordinate-ID mapping helpers are unavailable locally.
The available bwrap namespace maps only the invoking UID/GID; actual fchown to
separate publisher/signer identities is unavailable. Therefore **positive P1
multi-UID provisioning, 999/989 existing-user upgrade and kernel DAC probes
are NOT_RUN locally**, not PASS. A new disposable Docker CI target implements
clean and existing-user cases, exact negative access probes, collision checks,
post-receipt interruption/recovery, upgrade/conffile conflict and remove/purge.
It requires a Docker-capable approved disposable executor; no CI run was started
under this LOCAL_ONLY task. P1 single-transaction APT acceptance and this new CI
must pass before claiming the package acceptance matrix is complete.

Effective AppArmor attachment, network BPF, reboot/persistence, independent
journal continuity, privileged host negative probes and worker01/worker02 App
pilots remain NOT_RUN / LIVE_PUBLICATION_BLOCKED. Syntax-only parser success
is not confinement. piuparts/autopkgtest execution for P1 is NOT_RUN. #112 owns
readiness, #108 the two separately approved pilots. LIVE_NO_GO, Gate #73,
SUBSCRIPTION_ISOLATION_BLOCKED and exit 13 remain unchanged.
