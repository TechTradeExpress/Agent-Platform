# PKG-12: offline Debian release preparation (#155)

SOURCE_ONLY / OFFLINE_ONLY / NO DEPLOY / HOST_NOT_RUN / LIVE_NO_GO.
Exactly two Debian roles: `agent-platform-control`, `agent-platform-worker`.
`SUBSCRIPTION_ISOLATION_BLOCKED` / public exit 13, Gate #73 and Publisher #108
remain BLOCKED. This document and the pure assessor grant no release, host,
credential, service, registry, signing or runtime authority. Human-only source
merge, human final-release decision and later human per-host installation are
three distinct gates. No final package generation is implemented here.

[PKG-11](worker-pkg11-upgrade.md) remains normative for current builds and the
historical -7 reconstruction. The [host runbook](pkg12-host-upgrade-runbook.md)
is a future operator procedure; none of its host steps is executed in this task.

## PKG-13 source implementation follow-up

[PKG-13](pkg13-final-build-preparation.md) supplies a separate final-profile staging
recipe and synthetic non-Debian evidence rehearsal. It does not supply real final
encoding, authenticated generation admission, durable freeze or publication.
The real entrypoint remains unconditionally BLOCKED. The future implementation
requirements below must be read with that source-only progress and its limits;
no PKG-12 plan or SYNTHETIC_PASS authorizes generation.

## Three artifact classes, with no promotion path

| Class | Version and provenance | Status / permitted use |
| --- | --- | --- |
| Source candidate | `0.1.0-8~git<FULL_SHA>`; `build_kind=candidate`, `ci_only=false`, `release_authorized=false` | Review/rebuild and disposable compatibility tests only; not final |
| Exact CI fixture | `0.1.0-8`; `build_kind=ci-final-fixture`, `ci_only=true`, `release_authorized=false` | CI_ONLY / NOT_RELEASED; no relabelling, promotion, distribution or host installation |
| Future final archive | Exact `0.1.0-8`, rebuilt by a separately admitted final recipe from separately approved merged source; proposed `build_kind=final-unreleased`, `ci_only=false`, `release_authorized=false` | UNADMITTED / real generation NOT_RUN; requires new post-merge generation decision, actual-bit review, external human authorization and immutable freeze before distribution |

The proposed final embedded fields are a **future contract**, not a change to the
normal builder. That builder's `--final-version` refusal is unchanged. There is
no release flag, CLI, workflow-dispatch, tag trigger or alternate writer in PKG-12.
A new recipe capable of final generation needs separate scoped implementation,
independent review and human merge before it can be admitted. Wrapping
`--ci-final-fixture`, editing build.json, renaming/copying a .deb or changing a
flag to true is forbidden. Different embedded provenance means different bytes;
package metadata must never be rewritten after hash review.

A future final archive carries no self-authorizing boolean. Its generation and
publication decisions must be separate, authenticated human acts recorded outside
the immutable .deb and bound to exact source/inputs first, then actual payload
hashes/destination. Even after release, embedded `release_authorized=false` does
not become an execution decision. Detached attestations describe who authorized
what; a parsed attestation file alone is not an authenticated human instruction.

## Re-pin after the eventual human merge

The starting main `f8b447a716a410b8ebf2bd5f50e88167dc64d4b5`, tree
`63f08ff3e6d57173a941ce245936c5e9bb4c0da9`, identifies PKG-11, not the eventual
release source. This Issue's pre-merge HEAD, source ZIP, a tag, green CI or model
output cannot be substituted for a new observed merged SHA. These source/docs
changes themselves change consumed inputs. A later final recipe change requires
another source review/merge and another full re-pin; never guess its future SHA.

After those separate source decisions, a human release operator must independently
verify canonical repository/default branch, complete immutable commit/tree,
merge ancestry, exact observed source-review/CI evidence and a clean dedicated
checkout, with no hidden tracked changes, replacement refs or lazy fetches.
Record full commit, tree and commit epoch; export that exact object rather than
attesting mutable working-tree bytes. Inspect all source inputs and closed role
inventories using the reviewed builder validation. Observe original builder,
final-recipe and preparation-script paths and SHA-256 from those Git blobs.
An unavailable Git object, changed HEAD/base/recipe, dirty checkout or missing
post-merge decision is STOP. No host or network workaround follows.

Record the exact Debian 13 amd64 image digest, installed dependency/tool inventory
and inventory SHA-256, Python/dpkg-deb/xz versions, locale, archive settings and
`SOURCE_DATE_EPOCH` equal to commit epoch. Existing image pins do not freeze signed
but mutable APT indexes; actual installed versions and image identity are required.
Different toolchains can produce different gzip/archive bytes. Do not re-pin
historical expected hashes to hide such drift or claim hermetic reproduction.
No credentials, coding homes, host sockets or service control enter the build.
Environment filtering and same-UID file modes alone are not OS isolation proof.

## Evidence contract and integrity checks

Retain a manifest of **all** consumed inputs, per role, not just a recipe hash.
It must exactly match a separately reviewed closed inventory from immutable source;
unknown extra/missing inputs block. Paths are canonical relative source paths;
no symlink aliases, absolute/private paths or parent traversal. No auth/session
stores, private configuration or secret logs are build evidence.

For each role retain and independently inspect:

- exact package name, version, architecture, dependency/Conflicts metadata and
  maintainer-script inventory; no new hooks, units, users or tool downloads;
- original and final recipe digests; source commit/tree/epoch and per-input hashes;
- embedded build.json bytes/hash and manifest.json bytes/hash, every payload
  file path/type/mode/UID/GID/hash, closure and exclusion of HAR SOURCE_ONLY code;
- .deb byte count/SHA-256 and external per-role provenance SHA-256; source and
  environment bindings must agree across both roles and every representation;
- a second independent build from identical admitted inputs, epoch and toolchain;
  require byte-for-byte archive equality, not just matching version or file lists;
- actual lintian/autopkgtest, disposable lifecycle and full test outputs, with
  observed checkout identity and each NOT_RUN/error retained honestly.

Package SHA-256, manifests and canonical digests are integrity/provenance
**correlation, not signature-based authenticity**, human authorization or safe
publication. The manifest self-entry cannot hash itself; bind its raw bytes in
external provenance. Avoid circular attestations: artifacts/build records remain
immutable; a detached evidence bundle binds their hashes, and external approval
binds that bundle. Optional .buildinfo, signatures, signing-key custody, reproducible
snapshot feeds and an APT trust root are not supplied here. Record them as NOT_RUN
or NOT_IMPLEMENTED until separately reviewed; no signing key is requested.

## Pure consistency API — not a release gate implementation

`packaging/release_readiness.py` is source-only and is neither installed nor wired
to the builder, runtime, CI publisher or an entrypoint. `assess(plan, *, source_pin,
environment_pin, history_pin)` has no I/O, builder, file reader, persistence,
credential client or publication function. Direct execution does nothing.
Its bounded AP-PKG12-PLAN/1 facts compare only to separately supplied caller pins;
there is no JSON-to-authority loader. Pins are caller assertions, not authenticated
observations, and must never be obtained from Issue/model/target/plan content.
The source pin requires a separate final-recipe identity; no real such admitted
recipe/pin is established by this Issue. Production readiness is therefore blocked.

| Plan field | Required facts |
| --- | --- |
| Root | Exact schema, canonical repository, `version=0.1.0-8`, `architecture=amd64`; no approval/publish/tag/reset flags |
| source | Full commit/tree, integer epoch, builder_sha256, final_recipe_path and final_recipe_sha256; exact SourcePin equality |
| environment | `platform=debian-13/amd64`, image_digest, python, dpkg_deb, xz, packages_sha256; exact EnvironmentPin equality |
| roles | Exactly control and worker, distinct package/archive identities |
| Each role | package, archive_sha256, archive_size, manifest_sha256, embedded_build_sha256, provenance_sha256, rebuild_sha256, kind, ci_only and full inputs map |
| Artifact class | `kind=future-final`, `ci_only=false`; current candidate/CI kinds are rejected, not transformed |
| Input set | 6..256 bounded canonical input paths/hashes, including original/final recipes and core package inputs; canonical digest equals separate role-specific SourcePin digest |
| HistoryPin | EMPTY or FROZEN plus external continuity digest; FROZEN also pins entire bundle digest. None, UNKNOWN, malformed or lost history is never EMPTY |

SourcePin also carries control_inputs_sha256 and worker_inputs_sha256. Input-map
canonicalization is UTF-8 JSON with sorted keys, ASCII escaping and separators
`,` and `:`; SHA-256 over exactly those bytes. Bundle fingerprint uses the same
encoding over the entire validated plan (including source, environment, both roles,
input sets and rebuild evidence), scoped by repository/version/architecture.
The implementation bounds JSON-shaped facts and returns closed, path-free reasons.
It does not read the files, reconstruct Git, authenticate CI, establish input-set
completeness independently, or prove a claimed rebuild actually happened.

Even internally consistent, fully forged metadata produces at most
CONSISTENT_UNVERIFIED / plan_only. All outcomes retain
observations_authenticated=false, final_generation_allowed=false,
release_authorized=false, publication_allowed=false and installation_allowed=false.
Passing synthetic tests is not a live receipt. All real observations still need
independent collection/review. A saved plan/digest is never a capability.

## Immutable version registry and future staging design — not implemented

The frozen key is `TechTradeExpress/Agent-Platform/0.1.0-8/amd64` for the complete
two-role release bundle. Changing either archive, size, source, recipe, manifest,
provenance, inputs or environment conflicts with an existing frozen bundle.
Identical existing evidence still gives no resend/rebuild/publication permission.
After a final release, changed source or bytes require a new reviewed revision;
never overwrite -8 or rebuild current source as historical -7. Debian ordering is
`0.1.0-7 < 0.1.0-8~git<SHA> < 0.1.0-8`; hash suffixes do not order candidates by time.

The pure assessor detects conflicts against a **caller-attested** HistoryPin only.
It does not reserve/freeze a version or enforce a durable history. There is no real
registry, publisher or final generator in this task. Future tooling must enforce:

1. Independently protected, complete continuity across moves, deletions, store or
   signer rotation; missing/rollback/UNKNOWN history blocks. A fresh local empty
   file, new path or version namespace must not reset the stable key.
2. Human-authorized generation intent tied to observed immutable source, recipes,
   environment and scope before any final-bit attempt; retain uncertainty and
   partial outputs. No implicit retry/adoption of an unknown earlier attempt.
3. Exclusive no-replace staging in a new private release directory, without
   symlinks/hardlinks, never overwriting an existing version. Record real metadata,
   rebuild twice, compare bytes and run the final-artifact lifecycle matrix.
4. Separate review of actual immutable bytes and retained evidence. Human release
   authorization must name the exact bundle/artifact hashes, scope and destination;
   source review, generation approval and CI success do not authorize publication.
5. Atomic no-replace freeze of the entire verified bundle with durable confirmation
   and independent continuity before distribution. fsync/hash/0700 alone do not
   prove rollback resistance or isolation from untrusted same-UID code.
6. Unknown freeze/publication outcomes stop for read-only reconciliation, never
   blind retry, replacement, cleanup, history reset or automatic recovery.

These requirements are not implemented by adding a boolean to a manifest. They
need separately reviewed tooling/custody and explicit operator scope. No file
storage, host setup, credentials or privileged fallback is provisioned here.

## Distribution and decisions

Proposed eventual offline vault namespace:
`releases/agent-platform/0.1.0-8/<bundle-sha256>/`, containing frozen role archives,
external provenance, input/tool inventory, rebuild/test evidence and SHA256SUMS.
This is a logical namespace, not a configured path, server or permission grant.
Independent human release custody must retain the stable version index and
continuity elsewhere. Proposed public distribution is a later maintainer choice
(GitHub Releases, registry or APT feed); no destination/client/credentials are
configured and no upload occurs here. Existing Actions uploads remain disposable
candidate/CI evidence, with their current retention limits, not a release vault.

Only a directly authorized human release operator may later publish independently
reviewed frozen bytes under the actual release decision. No repository file,
tag, green PR, source merge, this checker or automated Agent Platform Publisher
can grant that right. Protected main and AP-SM/2 source review remain unchanged;
#108 is a separate blocked product capability, not a release transport fallback.
A publication failure/ambiguity requires reconciliation before any new attempt.
Each installation is a still later host-specific decision and exact hash check.

## Test/evidence matrix

Reuse existing PKG-11 original-recipe -7 reconstruction and two-role candidate/
CI_ONLY repeat builds, source/tree/epoch binding, closure, ordering, ordinary
--final-version refusal, worker doctor and Debian CI infrastructure. Preserve both
empty/UNKNOWN upgrade cases, controlled mixed-role/unpacked/configure cuts,
UID/GID/ACL/journal/receipt retention, conffiles, units/profiles, activation tripwires,
downgrade refusal, lintian/autopkgtest. Do not replace these with a JSON PASS.

PKG-12 negatives exercise missing/stale pins, CI promotion/renaming, authority
flags, wrong/duplicate roles, nonidentical rebuilds, full-input drift, malformed
or oversized/private data, lost/UNKNOWN freeze history and same-version replacement
of archive/source/environment/provenance. Even exact frozen matches deny actions.
Synthetic future-plan metadata never creates final .deb files or attestations.
Existing test-built exact -8 archives remain CI_ONLY.

Actual future final-bit staging/installability, release signing, registry storage/
continuity, authenticated approval/publication, host backup/restore, power-loss,
effective systemd/AppArmor/BPF, native tool/auth isolation and deployment are
NOT_RUN / NOT_IMPLEMENTED. Container root is scoped to an existing disposable
fixture, never host root or permission to install tools. Missing Docker/lintian/
autopkgtest means NOT_RUN, not host fallback. Source/build PASS, disposable CI
PASS and live readiness are separate evidence levels.
