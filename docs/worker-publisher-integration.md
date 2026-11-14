# PUB-02 integration with inert Debian role packages

LOCAL_ONLY integration of Issue #108 / Draft PR #109. Remote PR source HEAD:
`38f1ea30c4eea6bba132d199909db1d11fa3e163`; fetched/public main:
`b63beefa487005ea3e0a29116987f4e93455224e`. Both identities and open Draft state
were verified before a normal no-ff merge. The existing local Publisher commit
`194cec5c99f26251e4c7391b07965895d11292ab` has the same Git tree as the remote
PR source, but a different history. It and every existing worktree/commit were
preserved. The new integration branch starts at the remote PR HEAD, not a rewritten
local equivalent. No rebase, reset, force, remote write or host change.

## Conflicts and resolutions

Only two paths conflicted:

- `packaging/build_deb.py`: retain main's exact two-role builder and add the five
  named PUB-02 modules to **SOURCE_ONLY**. Remove the obsolete single-package
  loop/prefix exclusion as part of selecting main's implementation. No P0 module,
  dependency, command, path, lifecycle helper or build/provenance rule is widened.
- `tests/test_debian_package.py`: retain all main archive/security/lifecycle cases;
  move the PR's exclusion assertions into both roles and both -3/-4 profiles.
  Verify source-only code is absent from package payload and input provenance.
  Add an unknown `worker_publish_unreviewed.py` case, proving the old filename
  prefix cannot silently admit or skip new files.

Control P0 remains exactly 32 modules, Worker P0 exactly four. Explicit source-only
inventory grows from 16 to 21 (55 total application source modules). Documentation
records P1 as future reviewed #111 work and distinguishes inert source availability
from deployed publisher readiness. No old `agent-platform` package or custom Codex
package/dependency is reintroduced.

The five Publisher modules, all deployment wrappers/unit/AppArmor/example files,
and its complete test file are byte-for-byte identical to the old remote PR HEAD.
The #116 provisioner, release pin, proof files and tests are byte-for-byte identical
to main. Export/import validation, separate signer/key custody, App identity, CAS,
UNKNOWN-before-effect journaling, replay guards and main protection are unchanged.
All successful wire/authentication tests use fabricated credentials and transports.
No real PEM/token, paid Codex, actual App action or production state is involved.

The integration commit has two parents (PR first, main second). It is delivered as
two full binary diffs plus exact parent/tree identity, not as an AP-WP/1 artifact.
The Publisher's single-parent candidate restriction remains intact. A later pilot
must use its separately approved supported candidate, not widen the exporter to
publish this merge commit.

## Observed validation and available testbed

- Ruff: PASS. PUB-02 plus role packaging tests: **112 passed** (77 Publisher,
  35 packaging), including the added closed-prefix regression.
- Full pytest: **3318 passed, 2 failed, 1 skipped**. Both failures independently
  reproduced on **both exact unchanged parents**:
  `test_file_mutation_after_digest_read_is_detected` (`invalid_load` rather than
  `file_changed`) and
  `test_changing_evidence_before_write_is_blocked[journal]` (`read_only` rather
  than `needs_human`). No changed implementation or skip masks them.
- Trial role archives N/N+1 and N+1 rebuild: byte-identical rebuilds. Real offline
  apt/dpkg lifecycle passed in a new copy of pinned Debian 13 amd64 image
  `sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d`.
  Trial staging uses explicitly fabricated zero-SHA metadata, not delivery
  attestation. Final clean-merge source builds and their results are reported
  separately with local delivery, avoiding self-referential commit metadata.
- The fixture has private user/mount/PID/network namespaces, no host homes/socket
  or credentials, read-only package/test mounts, cached signed APT dependencies,
  bounded memory/CPU/time, and no lifecycle network. Existing conffile, corruption,
  staged unpack/configure, downgrade, synthetic migration, both legacy conflicts,
  both peer removal orders and retained UNKNOWN/foreign data checks are preserved.
- Local systemd verification initially hit sandbox SO_PASSCRED restrictions;
  the supported approval retry reached the real check and returned nonzero for
  absent `/usr/libexec/ap-worker-publisher{,-signer}`. They are deliberately not
  installed on this host. No unit check PASS, service start or host installation
  is claimed. AppArmor parser/kernel attachment and BPF/host controls are NOT_RUN.
- Docker/Podman are unavailable locally. Available namespace lifecycle and
  standalone quality-tool outcomes are explicitly distinguished from the complete
  Docker workflow, hosted CI, piuparts, reboot and power-loss evidence.
- `git diff --check`: PASS. Both delivery diffs must pass application checks on
  snapshots of their exact respective parents. No format-patch pretends a merge
  is a single-parent source change.

## Open gates and metadata blocker

| Gate | Status |
| --- | --- |
| Source integration and offline implementation | Implemented/tested locally; independent exact-HEAD source review still required |
| Worker P1 account/unit/profile packaging (#111) | Not enabled by this merge; PUB-02 remains source-only |
| Installed readiness and lifecycle/doctor (#112) | NOT_RUN on real workers; P0 doctor refusal preserved |
| Upstream Codex provisioning (#116) | Existing main implementation preserved; actual worker install/login/execution NOT_RUN |
| Effective separate identities, key custody, enforcing AppArmor/BPF/proc/FD/env denial and restart controls | HOST_NOT_RUN / BLOCKED pending independent operator evidence |
| App scope, main App exclusion, live CAS/revocation and externally anchored journal continuity | No new live evidence; existing receipts/UNKNOWN requirements unchanged |
| Real worker01 App-authored Draft pilot | NOT_RUN |
| Real worker02 independent App-authored Draft pilot | NOT_RUN |
| Issue #108 | Must remain open until both pilots succeed |
| Autonomous/native runtime | LIVE_NO_GO, Gate #73, SUBSCRIPTION_ISOLATION_BLOCKED / exit 13 unchanged |

**Observed remote metadata blocker:** PR #109 still contains `Closes #108` in
its body. A future source merge could therefore auto-close the Issue before the
pilots. This local-only task cannot modify GitHub. Before any future source merge,
the separately authorized operator must remove/change that closing directive and
verify the intended Issue remains open. No local source PASS can authorize closing
#108. The Draft PR and Issue were not mutated here; human alone decides GitHub merge.
