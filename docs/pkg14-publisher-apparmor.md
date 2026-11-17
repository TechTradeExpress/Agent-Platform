# PKG-14: F-02 Publisher/Signer ancestor mediation (#159)

SOURCE_ONLY / OFFLINE_ONLY / HOST_NOT_RUN / LIVE_NO_GO. No deployment, profile
load, manager reload, service, credential or GitHub operation is authorized.
`SUBSCRIPTION_ISOLATION_BLOCKED` / exit 13, Gate #73 and Publisher #108 remain.
This fixes only packaging/profile F-02. The separate PUB-02 source-fix PR #160
must be reviewed independently; its branch, worktree and pilot document are not
inputs to this change. Neither worker is pilot-ready on this evidence.

## Exact policy widening matrix

`worker_publish_io.read_file` opens `/` and every parent using
`O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, then fstats descriptors. Journals use this same
intake before append/lock. `confinement` checks the five installed module files
through the same walk. Leaf-only file allowances do not suffice for those opens.
The added rules are literal directory paths with **r only**, not recursive globs.

| Directory read/listing addition | Publisher | Signer | Actual consumer |
| --- | --- | --- | --- |
| `/` | yes | yes | Every descriptor walk starts here |
| `/etc/`, `/etc/ap-publisher/` | yes | yes | job.json, receipts.json; Publisher also candidate.json |
| `/run/`, `/run/credentials/` | yes | yes | Exact systemd credential intake |
| `/run/credentials/ap-worker-publisher.service/` | yes | denied | Publisher's app-jwt only |
| `/run/credentials/ap-worker-publisher-signer.service/` | denied | yes | Signer's app-key only |
| `/usr/`, `/usr/lib/`, `/usr/lib/ap-worker-publisher/`, `/usr/lib/ap-worker-publisher/agent_platform/` | yes | yes | Five reviewed installed code files |
| `/var/`, `/var/lib/` | yes | yes | Journal preflight |
| `/var/lib/ap-publisher/` | yes | denied | Publisher's journal |
| `/var/lib/ap-publisher-signer/` | denied | yes | Signer's journal |

Each role has exactly 13 literal added directory read rules. Directory `r` also
permits listing names where DAC/ACL and the namespace permit it; it is not a
stat-only grant. Shared parent listings can reveal entry names, including names
of sibling credential units, but never grant opening those private directories
or reading their contents. DAC execute/search permission is still required;
AppArmor permission does not grant DAC/ACL access. Root-staged `/etc/ap-publisher`
retains the exact read/traverse ACL and separate leaf ACL contract in
[PKG-08](publisher-isolation-readiness.md). Signer may see candidate.json's name
there, but cannot read it. No new directory write, execute, create, link, lock,
recursive read, generic credential unit or local include/drop-in grant is added.
Existing Python/base abstractions and library rules are retained, not narrowed
or treated as evidence of independently proven effective kernel confinement.

Explicit denies cover opposite-role journal/credential directories and contents.
Publisher also cannot enter/read Signer's runtime output or original key custody;
Signer cannot read candidate.json or original key custody. Both retain home/root,
proc-sensitive, ptrace and signal restrictions; Signer retains deny network.
Signer writes its existing exclusive output leaf `/run/ap-publisher-signer/app-jwt`
without descriptor-reading the parent, so no directory listing grant is added
there. Root/systemd transfers it; Publisher never reads that original output.
No `/usr/libexec/` descriptor-read grant is needed by the present code checks.

## Historical packages and controlled conffile upgrade

The exact historical -7 source `0fbc940ae94144f8cc29c9a0fd98afc704f58168`,
original recipe, archive/manifest pins and reconstruction remain unchanged.
[PKG-11](worker-pkg11-upgrade.md) still distinguishes reconstruction from an
observed installed artifact. No current-source -7 is produced or re-pinned.

The disposable upgrade fixture now checks both archives **before installation**:
old profile bytes must match the immutable historical SHA-256s; -6 to -7 must
remain byte-identical; -7 to the new CI_ONLY -8 must be exactly the reviewed
PKG-14 insertion, including new explicit denies, with all other bytes unchanged.
Missing rules, extra rules/includes, altered historical bytes and changed denies
fail. This allowlist is source-review evidence, not an authorization service.
A subsequent intentional policy change requires a new independently reviewed
allowlist; a profile supplied by an administrator cannot redefine it.

Each -7 to -8 disposable case edits one old profile before real dpkg unpack
(Publisher in empty-journal case; Signer in UNKNOWN case). confdef/confold must
retain the edit across unpack/configure and doctor remains BLOCKED. Only the
fixture's known edit is subsequently reset to exact new archive bytes for
independent payload checks. This reset is never a host recovery procedure.
The unedited profile must receive exactly its new packaged bytes. Existing
package.conf conflict, reinstallation conflict, receipt/journal inode/bytes,
UID/GID/ACL continuity, partial-package BLOCKED, activation tripwires, UNKNOWN
retention, downgrade refusal and corrupt-receipt STOP remain mandatory.
Installation never provisions state, reloads profiles or starts services.

## Evidence and later operator handoff

Focused tests check exact full-profile history/delta, ancestor union and actual
read_file control flow under fabricated descriptor denials; they are **not** an
AppArmor policy interpreter or kernel-enforcement PASS. Existing symlink/hardlink,
credential namespace, journal, provisioning, doctor and unit/drop-in regressions
remain. Parser checks use only `apparmor_parser --skip-kernel-load --skip-cache`
when available; otherwise NOT_RUN. The existing Debian 13 empty/UNKNOWN upgrade,
lintian/autopkgtest and other lifecycle matrices remain required in disposable
CI. Missing local runtimes/tools mean NOT_RUN, never a host fallback.

After both independently reviewed source changes are merged, freshly pin exact
merged commit/tree, original/current recipes, full inputs/toolchain and both
candidate/package hashes. PKG-13 real final generation remains BLOCKED and
ordinary --final-version remains refused. CI_ONLY artifacts cannot be promoted.
If any actual final 0.1.0-8 has been frozen/released, STOP and choose a separately
reviewed new revision; never replace different bytes under that version.

Follow the [PKG-12 per-host runbook](pkg12-host-upgrade-runbook.md) under separate
exact-host approvals: verify backup/continuity, inactive units, dpkg conffile
state and no unexpected unit/profile/drop-in edits. Conflicting local edits,
partial install or unknown journals mean STOP and human reconciliation; do not
force defaults, reset history or infer safe replay. Package installation does
not authorize profile reload or manager operations; those need later explicit
approval. After separately authorized reboot/reload, prove effective enforcing
profile labels, exact namespaces/inodes, positive opens and cross-UID negative
controls in both directions, including private credential/key/journal domains,
plus effective BPF and governance G-01 **before any real App key or GitHub write**.
Each worker and each pilot requires its own authorization and retained evidence.
Effective kernel enforcement, restart/reboot, actual host state and pilots remain
NOT_RUN here. Static/source/parser/CI success cannot supply those observations.
