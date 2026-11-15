# PKG-05 local validation record

LOCAL_ONLY / SOURCE_ONLY / HOST_NOT_RUN. Base and freshly verified anonymous
remote main: `fb8821b90e393195201c05689f7aaa5d6154c95e`.
Task branch: `feature/issue-112-pkg05-worker-doctor`, in its own registered worktree.
Original checkout, main and existing CP-08/other worktrees were preserved.
Read full current #112 (including its authoritative AP-PKG/2 amendment), #116,
#111, merged PUB-02 #109, ADR 007, AGENTS and development/AP-SM/2 instructions.
#109's observed merge is `790dc17382689552bbf8f16823f7f16956ff37f5`.
No GitHub credentials, write API, push, PR creation or pilot was used.

## Executed checks

Local Python 3.13.5, uv 0.13.7, Ruff 0.17.3, pytest 9.1.1. Cached dependencies
only (`uv run --offline`); no host package installation or privilege substitution.

- `uv run --offline ruff check .`: PASS.
- Focused `pytest -q` for `test_worker_doctor.py`, `test_worker_provisioning.py`,
  `test_codex_upstream_provisioning.py`, `test_debian_package.py` and
  `test_control_plane_fixture.py`: **391 passed**.
- Complete `uv run --offline pytest -q`: **3467 passed, 3 failed, 1 skipped**.
- Exact unchanged base exported to a fresh private temporary directory, using the
  same interpreter with explicit baseline `PYTHONPATH`: full pytest
  **3362 passed, 3 failed, 1 skipped**. The same three failures occurred:
  - native artifact mutation: expected `file_changed`, observed `invalid_load`;
  - notification dataclass contract: Python 3.13 `dataclasses.replace()` raises
    `TypeError` for an init=False field where the test expects `ValueError`;
  - Telegram journal mutation: expected `NEEDS_HUMAN`, observed `READ_ONLY`.
    This last test passed in isolation but failed in both complete suites.
- All **105 added tests passed**; no new failing test compared with the exact base.
  Existing failing assertions/validators were not weakened, skipped or changed.
- `git diff --check`: PASS.
- Actual `.deb` archive construction, manifest/provenance/hash checks and
  byte-repeatability are exercised by focused tests without host installation.
  Low-level test builds use explicit fabricated commit metadata; the delivery
  report separately records clean committed-source candidate builds if executed.

The complete source `src/`, upstream installer/lock/proof tree `provisioning/`,
Publisher deployment templates and existing CP-06/#116 test files are unchanged
from the base. CP-08 is not imported or packaged. Both P0 closed role manifests
and P1 Publisher closure/classifications remain intact. The doctor is an explicit
Worker P1 standalone addition, not a Control/legacy readiness API.

## NOT_RUN / remaining blockers

Docker/Podman are unavailable here. The extended Debian 13 amd64 clean/existing
999/989 multi-UID P1 lifecycle, real single-transaction two-role APT installation,
reinstall-after-purge and separate synthetic Codex container lifecycle are provided
as CI source but **NOT_RUN locally**. No hosted CI was triggered or attributed to
this local commit. Existing synthetic pytest coverage is not a substitute for
these actual disposable container tests.

Booted systemd effective-property observations, AppArmor process attachment,
cgroup BPF attachment/fixed egress, actual cross-UID DAC/MAC/proc/FD/env/memory
negative isolation, independent journal continuity/rollback protection, reboot,
power loss and real worker01/worker02 pilots remain HOST_NOT_RUN / BLOCKED.
No actual upstream Codex executable was installed or executed. No GitHub/OpenAI
login, App/signer key, production credential, Publisher effect or other-host
access was used. Source-known App IDs are not authenticated identity evidence.

The doctor intentionally cannot produce READY_FOR_SUPERVISED_PUBLISHING until
a separately reviewed trusted live-evidence observation contract exists. Missing
proof is NOT_RUN, unsafe observed configuration is BLOCKED, never artificial PASS.
A root-owned local manifest/receipt is consistency evidence, not independent
release authenticity or journal continuity. Original archives are not retained
by PKG-03R; the doctor binds their recorded digest to the reviewed pin rather than
claiming a rehash of absent bytes. These limits remain explicit in the runbook.

INSTALL_INERT, LIVE_NO_GO, SUBSCRIPTION_ISOLATION_BLOCKED, Gate #73 BLOCKED,
HOST_NOT_RUN, legacy/native exit 13, fail-closed and human-only merge remain.
