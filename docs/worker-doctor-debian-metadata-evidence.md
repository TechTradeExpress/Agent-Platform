# PKG-05 Debian metadata investigation — BLOCKED pending installed evidence

Source parent: exact published PR #121 HEAD
`3dfbbcb90637e552c08466d04abc80fe7a40fefc`.
This change collects missing disposable-fixture evidence. **It does not claim to
fix the underlying unsafe_metadata failure or establish lifecycle acceptance.**
No production validator or metadata policy has been relaxed.

## Observed evidence

GitHub Debian run 43693261609, job 132748161136, fails in clean Worker P1 after
installing both roles. The package check returns BLOCKED/unsafe_metadata and the
original INSTALLED assertion fails. The existing-999/989 iteration was not reached;
the separate synthetic Codex step was skipped after that failure. Successful
archive/quality/P0 steps are not P1 lifecycle PASS.

Anonymous log/artifact GETs were denied (403/401). The connected GitHub read-only
tools supplied the existing job log and artifact 14153396761, without exposing
GitHub credentials to the shell or changing GitHub. Artifact ZIP SHA-256:
`1234172a6a019324f2a164af3762e7d1bec6a3d8bedfdd5677d7b3e3df41ef41`.

The actual CI Control/Worker archives in p1 (-5), p1-next (-6) and p1-rebuilt (-6)
were inspected. All six build records bind the exact published source parent.
Declared UID/GID/mode and file hashes match the dpkg data tar and project manifest;
files are root:root, 0644/0755, with no tar symlink or hardlink entries. This
excludes an observed archive/manifest inconsistency, **not** an installed-inode
or pre-existing-ancestor inconsistency. The artifact has no failed-inode stat,
installed ancestor ownership/modes, link counts or ACL/xattr observation. The
specific rejected object and predicate remain **UNKNOWN**.

The current reason can originate from the metadata predicates for ownership,
type/single-link status, forbidden permission bits, exact mode, or fixed-path
syntax validation. Attribute rejection has its own unsafe_attributes reason;
the coarse unsafe_metadata code does not prove absence of ACLs. Do not guess
which Debian directory, group or inode was involved or add an exception for it.

Docker/Podman are unavailable in this development environment. No daemon was
installed, no host/service settings were changed, and no forbidden host was used.
A namespace/ownership model is not substituted for the requested Docker evidence.

## Source-only diagnostic and failure propagation

- In the existing disposable P1 main, only after the original CLI reports the
  target package failure, replay the installed Observer.package with a wrapper
  around its original meta function. The wrapper delegates every check unchanged,
  restores the original function in finally, and never repairs/adopts an object.
- Record the first stable rejected predicate, public object name, expected versus
  actual UID/GID/mode/type/nlink/device/inode, fixed ACL/capability-name presence,
  and already checked public ancestor metadata. Compare full stat fingerprints,
  including nanosecond change times; drift becomes UNCERTAIN, not proof.
- Only bounded public package paths/ancestors are named. Unknown/private names
  become UNRECOGNIZED. No file contents, xattr values, environment, arbitrary
  stderr, credential files or private state are emitted. No journal is read.
- Evidence is written to worker-p1-metadata-clean.json or
  worker-p1-metadata-existing.json under the existing disposable evidence mount,
  capped at 16 KiB. NOT_REPRODUCED and EVIDENCE_UNAVAILABLE remain explicit. This
  AP-PKG-METADATA-EVIDENCE/1 test artifact is not a readiness/authorization receipt.
- The original `assert diagnostic["installation"] == "INSTALLED"` remains intact.
  Neither BLOCKED nor unavailable evidence is accepted as installation success.
- The P1 shell attempts clean and existing cases, aggregates failures, and exits
  nonzero if either build/run/evidence check fails. Synthetic shell tests verify
  both attempts and failure propagation; these are not real Docker tests.
- The separate existing synthetic Codex step uses !cancelled(), so it can supply
  an independent outcome even when P1 fails. Its commands and security limits
  are unchanged; it does not make the failed P1 step/job successful.

The diagnostic helper is copied only into the disposable test image. It is not
included in either role package or exposed by a product command. Production
doctor, PKG-03R, PKG-04, Publisher, runtime/CP-08 and package builder are unchanged.

## Local validation and remaining gates

- Ruff: PASS. Focused metadata/doctor/PKG-03R/PKG-04/archive tests: **302 passed**.
- Full Python 3.13 pytest: **3681 passed, 1 failed, 1 skipped**. Notifications
  dataclasses TypeError vs expected ValueError reproduced on the exact unchanged
  published parent. Targeted parent also reproduced native artifact mutation;
  that test and Telegram passed in the final full candidate run. No full-suite
  PASS is claimed. Earlier new diagnostic-fixture failures were corrected, not
  skipped; the final focused/full runs include all new cases.
- git diff --check: PASS. Actual CI archive metadata/hash comparisons: PASS.
- Real Docker clean/existing multi-UID P1, full N/N+1 lifecycle and separate Codex
  lifecycle with this source: **NOT_RUN locally**. New hosted CI: NOT_RUN; no push.
- Reproduce the failing installed inode and its ancestors in disposable Docker
  before deciding whether package metadata or a Debian-object interpretation
  needs correction. The actual cause and security-policy fix are still BLOCKED.

INSTALL_INERT, LIVE_NO_GO, HOST_NOT_RUN, SUBSCRIPTION_ISOLATION_BLOCKED,
Gate #73 BLOCKED, native/legacy exit 13 and human-only merge remain. No real
worker01/worker02/control01 installation, probing, login, secret access or
Publisher activation occurred. Source-only evidence collection is not host PASS.
