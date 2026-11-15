# PKG-05: full Debian image instead of a metadata-policy exception

LOCAL_ONLY / CI_ONLY / HOST_NOT_RUN. Source parent is the exact published PR #121
HEAD ae83e1895b54001643cbf8cda5ffed2552aed73e. The rejected policy exception from
local review ffc7e746ab29e056abaeb86952055ffc814f6720 is **not implemented**.
Production worker_doctor.py, PKG-03R/PKG-04, SHA/ownership/no-follow/TOCTOU
validation, package closures and all runtime security gates are unchanged.

## Selection and source evidence

Official docker.io/library/debian, linux/amd64:

- Previous trixie-slim, amd64 manifest
  sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d:
  root:root man1 **0775**.
- Selected full trixie-20261027, index
  sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1;
  amd64 manifest
  sha256:e2914ec98e08b24b4cee3cefcb9f90dfb5519f8d215a2ccf0c9a49b10b6e43de:
  root:root man1 **0755**, already in the upstream layer.

Anonymous public registry reads resolved tag -> index -> one linux/amd64
manifest. Raw manifest, config and compressed layer SHA-256 values were checked;
layer tar metadata was inspected without extracting or executing images. No
Docker login, user credential, host image installation or chmod/chown was used.
The complete selected/previous metadata and seven distinct manifest comparisons
are in evidence/pkg05-debian-image-selection.json. The evidence archive retains
raw registry manifests/indexes and the offline inspection procedure/results;
large OS binary layers are not redistributed by this source change.

Current full trixie/13 and historical full 13.0/13.1 also have 0755. Their slim
counterparts have 0775 in the inspected layers. Tags are discovery labels, never
runtime latest selectors. The selected same-date full counterpart minimizes the
delta: **all 78 installed base package versions and APT source-file hashes are
identical to the prior approved slim image**. There is no package downgrade.
Both /etc/debian_version observations are 13.7; os-release identifies Debian 13
trixie; dpkg is 1.22.22, libc6 is 2.41-12+deb13u4, passwd is 1:4.17.4-2 and
base-files is 13.8+deb13u7. These are measured archive values, not inferred names.
The newer current full tag differs in apt/libapt-pkg7.0/tzdata; it was not selected
to avoid combining the variant migration with that separate version change.

Across the audited security-relevant base paths, the sole metadata difference is
/usr/share/man/man1 (0775 -> 0755). All selected declared paths are real root:root
directories without the forbidden bits or PAX extended metadata. Paths inspected
include /usr/bin, /usr/lib, /usr/libexec where declared, /usr/share/doc, /usr/share/man,
/etc, /var/lib, /opt and /usr/local/bin. Absent future private package paths and
the runtime-generated root inode are not assumed verified; the original doctor
still checks actual paths after installation. Archive metadata is not kernel MAC,
process isolation, runtime ACL/xattr or host admission proof.

## Dependencies and reproducibility limits

P1 Depends and APT setup commands are unchanged. The selected base contains the
same passwd/dpkg/libc and package set as before; Python, cryptography, Git, gh,
CA certificates, systemd, AppArmor and ACL tooling are still installed by the
existing signed trixie dependency step. They are not falsely reported installed
in the base. The actual post-APT closure has not been executed locally. The P1
fixture now writes its bounded per-case dependency version inventory after role
installation, before the doctor assertion, so fresh CI can compare actual values.

OCI digest pinning reproduces the base bytes. Signed APT indices remain mutable,
as already documented in debian-package-inputs.json. This is not a claim of a
hermetic dependency snapshot or a new security certification. Review fresh image
build logs/version inventories and original bounded/no-network lifecycle checks.

## CI-only change and retained negative case

All positive stages inherit the pinned full image. Read-only stat assertions
require root:root directory 0755 before setup and after P1 dependency install.
Unexpected metadata fails; nothing repairs it. The existing clean/existing
999/989 loop, signer separation, original expected INSTALLED, N/N+1 recovery,
remove/purge/reinstall, separate Codex and full CI checks remain enabled.

An independent manpage-negative stage retains the **old exact slim digest**.
It installs only a test interpreter through normal APT, never alters man1, and
checks the actual 0775 directory with the unchanged doctor's real parent/FD
validation. The expected unsafe_metadata refusal must be observed on stable
root:root 0775. A test success records BLOCKED/expected_rejection_observed, not
package installation, safe host status or product execution. Product exit 13 is
untouched. Both source-policy unit checks and this real-container target remain;
the latter is NOT_RUN locally until an approved Docker executor runs the workflow.

## Validation and rollout gate

Local checks and exact commit/tree IDs are in the delivery report. All production
policy is byte-identical to the published parent; no general group-write allowance,
CI-specific validator exception, manpage omission, automatic chmod/chown, App
permission change or service activation was introduced. The image migration does
not inherit the rejected policy proposal.

Docker/Podman are unavailable locally. Fresh real clean/existing P1 full lifecycle,
N/N+1/recovery/purge/reinstall, negative old-image and separate synthetic Codex
runs on this candidate are **NOT_RUN**, not PASS. Source evidence shows a suitable
base image and supplies the unchanged positive tests plus the independent
negative image; it does not prove complete PKG-05 acceptance. No hosted CI is
started because this delivery is local-only. Independently review/publish only
under separate authorization, then require all real workflow outcomes at the
exact commit before acceptance. Never treat archive inspection as host PASS.

INSTALL_INERT, LIVE_NO_GO, HOST_NOT_RUN, SUBSCRIPTION_ISOLATION_BLOCKED,
Gate #73 BLOCKED, native/legacy exit 13 and human-only merge remain. No real host,
credential, GitHub write, merge, Publisher or service operation was performed.
