Current build/version/upgrade rules: [PKG-11](worker-pkg11-upgrade.md).
Default candidates are `0.1.0-8~git<FULL_SHA>`. Exact -8 fixtures require
`--ci-final-fixture` and remain CI_ONLY / NOT_RELEASED. `--final-version` is
blocked. Historical -7 is reconstructed only from its pinned original source
and recipe; older synthetic profiles are not historical installed artifacts.
Release engineering preparation and host runbook: [PKG-12](pkg12-release-readiness.md).
This is an offline contract, not final generation or distribution authority.
Separate final-profile source implementation and non-installable rehearsal:
[PKG-13](pkg13-final-build-preparation.md); real generation remains BLOCKED.

## PKG-19 frozen Worker P1 upgrade candidate

From the clean, reviewed source checkout, build both source-qualified archives:

```sh
python3 packaging/build_deb.py --revision 9 --source-commit "$(git rev-parse HEAD)" --output /tmp/pkg19-candidate
```

Revision 9 is candidate-only. Debian orders every `0.1.0-9~git<FULL_SHA>`
above the pinned installed `0.1.0-8~git73bb2d521347ec87fb2c584ada8ee86a0ab3eaba`
and exact `0.1.0-8`. Source SHA suffixes do not order subsequent builds
within revision 9. The default -8 build and exact -8 CI/rehearsal contracts
remain available for compatibility.

The preinst reads stable systemd properties twice. Loaded inactive one-shots
are quiescent only with zero process IDs, no queued job, no restart policy
and no populated service cgroup. A failed historical Publisher can satisfy
the same requirements. The guard leaves failed state and historical data
untouched. Uncertain manager results block unpack. This is a point-in-time
check and the separately authorized host upgrade must exclude concurrent
operator activation. Release authorization under PKG-18, host checks in
#183, and explicit permission to install are still required.

# Inert Debian role candidates (PKG-02)

**CANDIDATE / NOT_RELEASED / NO_SERVICE / NO_LIVE_AUTHORITY.** Debian 13 trixie,
amd64 only. [ADR 007](debian-role-package-architecture.md) and
[AP-PKG/2](codex-upstream-provisioning-decision.md) define two independent P0
packages: `agent-platform-control` and `agent-platform-worker`. Neither P0 package includes
Codex, has a Codex APT dependency, downloads code, creates users/groups/state,
installs services/profiles or activates anything. `LIVE_NO_GO`, Gate #73,
`SUBSCRIPTION_ISOLATION_BLOCKED` and public/native exit 13 remain unchanged.

## Build and inspect

For ordinary current -8 candidates use the command in [PKG-11](worker-pkg11-upgrade.md).
The explicit commands below retain synthetic P0 N/N+1 regression coverage.

Use a clean committed checkout. The existing recipe exports the specified Git
commit, validates version/dependencies and the closed module inventory, and
builds **both** role archives. No wildcard admits new modules. The exact CLI
source export, rather than mutable worktree bytes, supplies every packaged input.

```sh
python3 packaging/build_deb.py --source-commit "$SOURCE_SHA" --synthetic-fixture --revision 3 --output /tmp/ap-role-n
python3 packaging/build_deb.py --source-commit "$SOURCE_SHA" --synthetic-fixture --revision 4 --output /tmp/ap-role-next
```

Output contains `agent-platform-{control,worker}_0.1.0-{3,4}_amd64.deb`,
`SHA256SUMS`, and separate `<package>.provenance.json`. Source/app version stays
0.1.0. Revisions -3 (N) and -4 (N+1) are synthetic profiles of the same committed
source, not historical releases. N+1 adds only the existing explicit example
migration helper and schema-2 inert inventory. Roles may update independently.
No epoch, role cross-dependency, common library or third package is introduced.

Embedded `build.json` identifies source SHA, epoch, module manifest, dependencies,
recipe and every consumed source-input SHA-256. `manifest.json` enumerates every
payload file, root ownership, mode and digest. Its own digest is external in the
role provenance to avoid an impossible recursive hash. External provenance also
records archive size/hash and Python/dpkg-deb/xz versions. Debian control
md5sums include generated manifests; conffiles are separately declared. These
checksums correlate bytes; they are not signatures or independent authenticity.

Identical inputs/epoch/toolchain must produce identical archives. The CI image
and action SHAs remain pinned in [input provenance](debian-package-inputs.json).
Signed APT dependencies are acquired only while constructing the disposable
fixture; their indexes remain mutable, and installed versions are retained.
Cross-toolchain reproduction, signed snapshot dependencies, .buildinfo/source
uploads, release signing and an APT feed remain separate work.

## Exact P0 contents and interfaces

The builder retains closed Control, Worker and SOURCE_ONLY module inventories
under ADR 007 and its reviewed source amendments. HAR admission, Claude parser
and instruction-source modules remain excluded from every role/phase archive. Application imports are
parsed before staging; a cross-role import or unclassified top-level Python
module blocks the build. `runtime_manifest` and `__init__` are the only source
bytes duplicated, under different private roots. Worker has no Control CLI,
admission, custody, signer, credential loader or GitHub writer.

| Owner | Installed content |
| --- | --- |
| Control | `/usr/bin/agent-platform-control`; `/usr/lib/agent-platform-control/agent_platform/{C}.py`; three private dist-info files; `/etc/agent-platform-control/package.conf` |
| Worker | `/usr/bin/agent-platform-worker` standalone inert wrapper and `/usr/bin/agent-platform-worker-native-artifact`; `/usr/lib/agent-platform-worker/agent_platform/{W}.py`; three private dist-info files; `/etc/agent-platform-worker/package.conf` |
| Each role | Own copyright, changelog, README, build/manifest JSON, schema-v1 example under `/usr/share/doc/<package>` and manuals for its own commands; N+1 private `migrate-example` only |

All directories are 0755, code/docs/config 0644 and wrappers/helpers 0755,
root:root, without set-ID, capabilities or links. There are no shared leaf paths,
private directories or conffiles. No global dist-packages, bytecode, legacy
command aliases, broker/canary, production config, key or journal is installed.
Wrappers use `/usr/bin/python3 -I`, disable bytecode and select the fixed private
root; PYTHONPATH and the source checkout are not required.

Control retains its existing command syntax and offline security gates, with its
own help name. Worker P0 supports help/version and syntax-valid `run`, `resume`,
`doctor` refusals **before inspection**, exit 13. It has no real worker agent or
Codex installer. Its separate artifact inspector remains read-only with the
existing 384 MiB ceiling; that does not admit an executable or relax the legacy
256 MiB gate. Unknown Worker operations fail syntax validation, not a fallback.

Control Depends: `python3 (>= 3.12), python3-cryptography (>= 43.0.0),
python3-cryptography (<< 51), git, gh`. Worker Depends: `python3 (>= 3.12)` only.
Both work without Codex. P1 adds the separately reviewed explicit upstream
acquisition (#116), provisioning (#111) and read-only diagnostics (#112).
Installation alone grants none of their authority.

## Retiring the experimental package

Each role has unversioned `Conflicts: agent-platform`, with no Replaces, Breaks,
Provides or compatibility alias. They do not conflict with each other or Codex.
The legacy candidate was never a production release. The test-only helper
`packaging/debian/build_legacy_fixtures.py` exports pinned pre-split commit
`2f6e7729badc772d40900ae02e2cdc86dc9bb591` and invokes its original recipe for
synthetic -1/-2 artifacts. This is not a second current-package builder.

On a separately authorized host, the operator first inventories configuration,
quiesces activity and reviews the APT plan. Explicitly **remove, not purge** the
old candidate, then install the selected role(s). APT's suggested removal is not
permission for migration. New package scripts do not remove/rename/adopt old
files. Residual `/etc/agent-platform/package.conf` is retained and ignored;
new role configs are not copied or interpreted from it.

Package installation, configuration, confinement, credentials and activation
are separate. P0 has **no preinst/postinst/prerm/postrm/triggers**, sysusers,
tmpfiles, units or AppArmor files. No account, HOME, PATH, GitHub App, key,
UNKNOWN journal, checkpoint, anchor, worktree or backup is touched by P0 install.
P1 adds only its blocking pre-unpack collision guard and inert units/profiles;
no configure/remove hook provisions state or starts services.

## Synthetic migration and lifecycle

Only an explicit owner invocation of
`/usr/lib/agent-platform-{control,worker}/migrate-example --directory <new-example>`
can migrate the fake `AP-PKG-SYNTHETIC` example. It is never called by dpkg.
The directory must be owner-only 0700, without symlink ancestors, containing
0600 regular singly-linked bounded files: marker `EXAMPLE_ONLY` with
`AP-PKG-EXAMPLE-ONLY v1\n` and strict schema-1 `example.json`. Schema 2 renames
`label` to `display_name`; exact backup and fsynced intent precede replacement.
Unsupported/duplicate/extra keys, foreign files, aliases or uncertain temporary
state refuse with exit 13 without cleanup. Verified complete output is idempotent.
No production state migration or reverse schema conversion is implemented.

Upgrade uses normal dpkg conffile semantics. CI chooses confdef/confold to retain
administrator bytes and modes. Remove retains conffiles and unowned data; purge
removes package conffiles but leaves foreign notes, state and nonempty directories.
Reinstall restores code; downgrade changes code only, never history. Restore a
synthetic backup only into a new marked directory, never onto uncertain state.

The existing [Debian CI workflow](../.github/workflows/debian-package.yml) retains
read-only GitHub permissions. Its checkout identity, step gate and evidence layers
are defined in [CI-01](#ci-01-checkout-identity-gate-and-evidence-layers).
It builds N/N+1/rebuilt archives, compares both roles,
runs lintian with error failure, and autopkgtest in a separate disposable testbed.
Lifecycle has no network or host home/socket mounts and uses fake activation
tripwires. It checks each role alone, both roles, both peer removal orders,
conffile edits/modes, corrupt archive rejection, real staged unpack/configure,
explicit migration/idempotency/uncertainty, downgrade/reinstall/purge, both legacy
conflict directions and -1/-2 remove-to-split transitions. Fake UNKNOWN state,
legacy config, home-bin Codex and foreign notes must survive unchanged.

Local pytest only builds/inspects archives and fake directories; destructive
APT/dpkg tests require an explicitly disposable Debian 13 fixture. Container or
namespace lifecycle is not systemd boot, power-loss durability or piuparts.
Those remain NOT_RUN, as do real hosts, credentials, runtime and Publisher pilots.
No Docker installation, privileged fallback or host provisioning is authorized.

See [local fixture evidence and limitations](debian-role-package-validation.md).

## CI-01 checkout identity, gate and evidence layers

The Debian CI checkout uses no `ref` override (Issue #194): on `push` it checks
out the exact pushed HEAD, and on `pull_request` it checks out the synthetic
merge result (`refs/pull/N/merge`) for the actual PR base, including non-default
integration targets. The check name is the same for both, so evidence must cite
the checkout record, not the display name. The first step after checkout,
`verify_checkout`, runs `ci/verify_checkout_identity.py`: the commit equals the
event SHA, and for a pull request the ref is `refs/pull/N/merge` and its two
parents equal the event's base SHA (first) and head SHA (second). Missing,
mismatched, stale or ambiguous facts fail the step; tree equality, the event
name or a run `head_sha` never count.

Every later step requires `steps.verify_checkout.outcome == 'success'`, joined
with `&&` to its unchanged previous status check: builds, upgrades and lifecycle
keep `success()`, the separate Codex lifecycle and the prior-manpage negative
keep `!cancelled()`, and archive inspection and artifact upload keep `always()`. A
rejected, skipped or cancelled verification therefore builds, inspects, runs and
uploads nothing; its diagnostic is the failed step's
`CHECKOUT_EVIDENCE_REJECTED: <reason>` line. After a verified checkout, a later
failure or cancellation runs the same diagnostics and upload as before. The gate
reads `outcome`, not `conclusion`, so a future `continue-on-error` cannot open
it. Every package build also asserts that its `--source-commit` equals the
verified checkout.

| Layer | What it states | Classification |
| --- | --- | --- |
| `lifecycle` job conclusion | The validation result for the checkout in the record | Disposable CI result; never release, custody or installation authority |
| `ci-checkout-evidence.json` | Checkout identity only: `scope=checkout_identity_only` | `status=CI_ONLY`, `release=NOT_RELEASED` classify this workflow-level evidence, not package provenance |
| Uploaded Actions artifact | Packages, evidence and diagnostics, also after a later failure | Diagnostic CI evidence with 14-day retention; never proof of a successful validation by itself, never a release vault |
| Embedded `build.json` and external provenance | Package provenance, unchanged by CI-01 | Ordinary candidates `build_kind=candidate`, `ci_only=false`, `release_authorized=false`; exact -8 fixture `ci-final-fixture`, `ci_only=true`; N/N+1 profiles `synthetic-fixture` |

On `pull_request`, ordinary candidates are therefore `0.1.0-8~git<merge SHA>`
with `source_commit` and `source_tree` of the verified synthetic merge commit
and embedded `ci_only=false`. They are not embedded CI_ONLY packages; before
CI-01 the same class was bound to the PR head instead. Their class and source
identity, not a flag, keep them out of release and custody admission:
[PKG-12](pkg12-release-readiness.md) admits only a future final archive rebuilt
by a separately admitted recipe from a newly observed post-merge commit,
`release_readiness.assess` rejects `candidate` and `ci-final-fixture` kinds
(`artifact_not_future_final`), and relabelling or rewriting embedded fields is
forbidden. A synthetic merge commit exists only under `refs/pull/N/merge`, in no
branch history, and is not the commit that a GitHub merge, squash or rebase
creates, so it cannot satisfy that re-pin. [Host Gate 0](pkg12-host-upgrade-runbook.md)
requires a frozen release bundle and separate human decisions; green CI
authorizes nothing. Release custody (`ProtectedCustody`) is NOT_CONFIGURED, no
repository code consumes Actions artifacts, and the worker doctor only reads an
installed record. A merge-result candidate may become unrebuildable once GitHub
drops that commit; it is review evidence for its run only.

## P1 Worker candidates (PKG-04)

Revisions -5/-6 intentionally extend only Worker with the closed Publisher,
signer, exporter, vendor units/profiles and explicit root operator provisioning
and #116 Codex commands. Control stays P0. Build with the same recipe and exact
source SHA and `--synthetic-fixture --revision 5` or `--synthetic-fixture --revision 6`.
Current -8 retains P1 without changing state semantics; -5/-6 are historical test
profiles, not the default. These
synthetic candidates still do not authenticate, activate units, acquire Codex
during dpkg or include its binary/dependency. Accounts and state require a
separate approved command, never a maintainer script. See
[the P1 contract](worker-provisioning.md) and ADR 007's explicit manifest update.
