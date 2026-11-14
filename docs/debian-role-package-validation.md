# PKG-02 local fixture and evidence limits

Base: `2f6e7729badc772d40900ae02e2cdc86dc9bb591`, canonical public main and
merged PR #117 verified. Dedicated branch: `feature/issue-102-debian-role-packages`.
Existing checkouts, branches, commits and ignored data were preserved. LOCAL_ONLY;
no push, PR, merge, credentials, production host connection or runtime activation.

The unit suite builds real archives and compares both roles' N+1 bytes, exact
leaf inventories, source hashes, metadata, modes, conffiles and no-hook controls.
It rejects unknown modules, cross-role authority imports, unreviewed dependencies,
unsupported identities and unsafe synthetic data. Worker tests poison PYTHONPATH
and reject unimplemented Codex/provisioning operations; syntax-valid execution
commands return fixed exit 13. Existing CLI syntax is also regression-tested.

## Actual disposable Debian tests

Docker and Podman are unavailable locally. An equivalent offline user-namespace
fixture was exercised, not a pretend Docker PASS. The official Debian 13 amd64
image manifest is pinned to
`sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d`.
Its public OCI manifest and layer hashes were verified before extraction into a
new owner-only directory on the larger project build filesystem. Absolute image
symlinks were normalized to equivalent root-relative targets inside that fixture;
no host filesystem content, login store, key or user home was copied.

Signed Debian APT indexes and 75.3 MB of dependency archives were acquired once
in a separate bounded namespace step. This is mutable signed APT input, not a
historical snapshot or new authority to change hosts. All package lifecycle
operations then ran with `bwrap --unshare-all`, private PID/mount/network/IPC/UTS
namespaces, empty environment, no credentials, mapped UID/GID 0, dedicated copied
rootfs, read-only package/test mounts and a fresh evidence mount. No host root,
home, Docker socket or system service was exposed. Limits: 2 GiB address space,
240 CPU seconds, 360 seconds wall time and 256 MiB per output file. No privileged
fallback or new host user mappings were provisioned.

The single mapped UID cannot become Debian's `_apt` user. Only the disposable
copy used `APT::Sandbox::User=root`; the outer enforced namespace and offline
network remained unchanged. Normal Docker CI needs no such override. The slim
image's doc-exclusion config was removed in the **testbed**, so installed
provenance/manuals can be checked; the Dockerfile applies the same fixture choice.
No package changes an administrator's dpkg policy.

Real apt/dpkg lifecycle was exercised on fresh copies, covering:

- Worker alone before Control dependencies, Control alone, both installed;
  installed wrappers and every private module import, without Codex or checkout.
- Fixed native/subscription/legacy gates, no bytecode, no service/account/tool
  activation; fake tripwires and unchanged passwd/group provide negative checks.
- Edited conffile bytes/modes, N to N+1 staged unpack then explicit configure,
  corrupt archive rejection, explicit schema migration/idempotency, unsupported
  schema and retained uncertain temporary-state refusal.
- Downgrade without data rollback, both peer removal orders, reinstall/purge,
  foreign notes, fake home-bin Codex, checkpoint/UNKNOWN/backup retention.
- Actual pinned pre-split -1/-2 artifacts, conflicts in both directions, explicit
  remove (not purge), residual legacy config ignored by new roles, and restoration
  only into a new synthetic directory.

Development fixtures use explicitly fabricated zero-SHA staging attestations and
are not delivery artifacts. Final candidates must be rebuilt with the clean-tree
CLI from the single local implementation commit; report their actual hashes,
sizes, source SHA and repeated offline lifecycle separately. No zero-SHA archive
is a committed-source candidate. Retained evidence lives outside Git; binaries,
rootfs and downloaded dependencies are not added to the patch.

## Honest remaining limitations

Local quality-tool installation stopped before lintian/autopkgtest execution:
`man-db 2.13.1-1` cannot set ownership of `/var/cache/man.dpkg-new` to an unmapped
UID/GID in the single-UID namespace (`Invalid argument`). **The normal local lintian/autopkgtest quality stage is NOT_RUN / fixture setup
BLOCKED**, not PASS. A separate attempt to invoke unpacked lintian files found
a same-date changelog error (corrected before delivery), but could not complete
manual-page checks because man-db/man was unavailable. That partial invocation
was BLOCKED, not PASS. A separate tool-data fixture can unpack the unchanged
Debian man executable/libraries without its unmapped-owner cache or maintainer
scripts. Its standalone lintian outcome must be reported separately; it does
not establish a fully configured quality image or autopkgtest PASS. No ownership shim,
rewritten dependency package, ignored error, extra privilege or host install was
used to hide this. Run the existing pinned Docker quality image/quality.sh in
an approved disposable full-UID testbed; its lintian error gate and required
explicit autopkgtest smoke PASS remain enforced in CI.

GitHub Actions is NOT_RUN for the local-only commit. CI Docker builds have not
been executed locally. Namespace tests are not non-root account isolation,
service boot, abrupt power loss, production-state migration, piuparts or host
readiness evidence. All those checks remain NOT_RUN/BLOCKED. No working controller
or worker agent, enrollment protocol, Codex installer or activated Publisher is
provided. LIVE_NO_GO, Gate #73 and public/native execution barriers are unchanged.

## Repository validation

- `uv sync --locked`: completed in the dedicated virtualenv; no host install.
- Ruff: PASS. Focused packaging and CLI tests: **74 passed**.
- Full pytest (repeated after final code changes): **3171 passed, 1 failed,
  1 skipped**. `test_file_mutation_after_digest_read_is_detected` expects
  `file_changed` but observes `invalid_load`; this exact failure reproduced on
  an isolated snapshot of unchanged parent
  `2f6e7729badc772d40900ae02e2cdc86dc9bb591`. Neither that module nor test was
  changed, skipped or weakened. Full pytest is therefore not claimed PASS.
- `git diff --check`: PASS. Exact final artifact and source-SHA evidence is
  reported with local delivery, outside self-referential committed metadata.
