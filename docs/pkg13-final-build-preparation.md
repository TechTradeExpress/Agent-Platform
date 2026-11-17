# PKG-13: separate final-profile recipe and synthetic evidence rehearsal (#157)

SOURCE_ONLY / OFFLINE_ONLY / NO RELEASE / HOST_NOT_RUN / LIVE_NO_GO.
`SUBSCRIPTION_ISOLATION_BLOCKED` / public exit 13, Gate #73 and Publisher #108
remain BLOCKED. Exactly two roles: `agent-platform-control`, `agent-platform-worker`.
No host inventory, installation, services, AppArmor/BPF, credentials, signing,
publication, freeze or actual final .deb generation is authorized or performed.
[PKG-11](worker-pkg11-upgrade.md), [PKG-12](pkg12-release-readiness.md) and the
[unexecuted per-host runbook](pkg12-host-upgrade-runbook.md) remain normative.

## What is implemented, and what is blocked

`packaging/final_recipe.py` is the separate recipe/adapter. Its `generate()`
unconditionally raises `Blocked(trusted_generation_unavailable)` before looking
at any arguments, source, paths, tools, history or authorization claims. Direct
execution prints one fixed refusal and exits 13. There are no usable approval,
environment, CLI, tag, repository-config or model-driven activation switches.
The independently trusted authenticated generation-decision integration does
**not** exist. A future integration and real final archive backend require
separate review/authorization; this Issue is not that authorization.

The actual recipe is exercised only by `rehearse()` on a fabricated Git source
with an exact `PKG13_SYNTHETIC_SOURCE` marker. Tests manufacture inert Python
modules, documents, helpers, vendor evidence and unit/profile fixtures; they never
execute those payloads or import code from the Git export. The only nonfabricated
fixture inputs are the separately digest-checked local staging/recipe code and
structural dependency contracts, not real application payloads. Source/tool/history
observations are caller-provided synthetic facts, never human authority.

The recipe assembles both complete role staging trees with exact version
`0.1.0-8`, `build_kind=final-unreleased`, `ci_only=false`, `release_authorized=false`
**from the start**, before hashing build.json and manifest.json. The records also
carry `SYNTHETIC_ONLY_NONINSTALLABLE` and a rehearsal frame binding both recipes,
full source inputs, environment and fabricated historical baseline. No candidate
or CI archive is read, relabelled, edited or copied to become a final archive.

The ordinary builder still rejects --final-version and historical -7 under
current source. Its public argument/profile validation is unchanged. A small
shared `_stage_archives` primitive and `_write_deb` extraction avoid duplicating
the existing closed P0/P1 payload recipe. Ordinary candidate/CI calls select their
old profiles and real archive encoder. Final-profile staging rejects that encoder
and requires the non-Debian rehearsal path. The private staging primitive and
in-process callbacks are **not** an OS/authentication boundary or a supported
operator activation API; arbitrary Python code can already execute arbitrary
operations. No production authority can be supplied through those test seams.

Rehearsals emit `.pkg13-fixture`, never `.deb`, starting with
`AP-PKG13-SYNTHETIC-NOT-DEB/1` followed by a deterministic regular-file tar staging
image. It is not a Debian ar archive; renaming it cannot make it installable.
Conversely a renamed candidate/CI .deb lacks this marker and is rejected. Actual
Debian final-bit encoding/installability is NOT_RUN; no real final encoder is
provided. Existing PKG-11 .deb migration/lint tests continue using CI_ONLY files.

## Source, recipe and environment binding

`SourcePin` contains commit/tree (full 40 hex), commit epoch, normal builder
SHA-256, separate recipe SHA-256 and canonical full-source-input-map SHA-256.
`EnvironmentPin` contains Debian 13 amd64 platform, exact image digest,
Python/dpkg-deb/xz version strings and complete tool/package inventory digest.
Pins are assertions for a synthetic rehearsal; no deserializer authenticates them.
A matching injected tool observer is mandatory; absent/mismatched/failed tools
block. No tool download, real package encoder or vendor CLI is invoked by rehearsal.

Only bounded local read-only Git argv are used, with credentials/global config,
replace refs, lazy fetching, hooks and fsmonitor disabled. The existing bounded
foreground capture is reused; stderr is never exposed. Before export require
HEAD equals pin, clean tracked/untracked state, exact commit/tree and epoch.
`ls-tree` must contain only regular blobs; submodules/symlinks are refused. The
bounded tar export has no aliases, traversal, duplicates, hardlinks or special
files. Every exported byte string is checked against its Git blob object ID and
mode; missing/export-ignored/substituted data blocks. The complete file map is
hashed using sorted compact JSON plus one trailing newline, as implemented by
`encoded()`; this newline distinguishes it from PKG-12's plan canonicalization.

Both recipe digests must match the export **and** the controlled local tooling
bytes. The staging module compiles exactly the checked local builder buffer,
not an exported recipe or mutable .pyc. Full-source hashes are retained separately
from each role's actual consumed-input hashes. Both recipes are consumed inputs.
HEAD/clean status is re-read after snapshot and immediately before evidence output;
moving or dirty source blocks. None of this establishes trusted real post-merge
source admission: the repository is deliberately fabricated in these tests.

Historical evidence uses a separate `HistoricalPin` (version/source/tree/recipe,
both archive and manifest hashes) and matching observer. Missing, UNKNOWN or
changed prior bytes/recipe block rather than assuming a new baseline. In rehearsal
these observations are fabricated and marked unauthenticated. The actual pre-HAR
-7 source `0fbc940ae94144f8cc29c9a0fd98afc704f58168` remains reconstructible only
by PKG-11's pinned original recipe; current code never emits a replacement -7.
A matching reconstruction/report is not current host or original archive access.

## Evidence production and inspection

Two independent temporary staging passes use identical source/epoch/recipe and
injected environment. Require byte-identical staging images and external role
provenance; a digest alone does not excuse differing bytes. The inspector verifies:

- exact two role/package identities, final-profile fields and synthetic class;
- source/tree/epoch, both recipe digests, full-source and consumed-input maps,
  environment and historical frame, plus external size/hash/provenance agreement;
- complete closed payload paths, role/module and Publisher sub-inventories,
  no HAR SOURCE_ONLY modules, accidental Codex/Claude or ELF payloads;
- every payload manifest hash/mode/UID/GID, root tar metadata and source epoch,
  manifest self-reference exclusion and external manifest hash;
- control version/architecture/dependencies/Conflicts, forbidden relationship
  fields, exact conffiles, md5sums and only the existing worker preinst hook;
- static oneshot unit constraints, with no service or publisher execution.

These are real checks of **synthetic staging bytes**, not signed authentic .deb
observations, kernel enforcement or a final release gate. No payload is executed.
Package version order remains `-7 < -8~git<SHA> < -8`; hash suffixes are not dates.
The existing PKG-11 tests provide the actual Debian ordering/CI fixture evidence.

Caller output parents must already exist with safe metadata and canonical
non-symlink ancestors. Open directories with no-follow descriptors, create only
a fresh owner-only leaf and regular singly linked evidence files with O_EXCL /
O_NOFOLLOW. No overwrite/adoption, even for an empty existing output directory.
Rehearsal bytes are nonsecret, but 0700 is not independent same-UID isolation.
An UNKNOWN intent is durably written first; each file is fsynced, completion
manifest is last, directory identity and durability are checked. Any error retains
caller-visible partial state, with no cleanup, repair, resume or retry. A later
invocation refuses that path. Private scratch generated wholly by this test
process may be removed; caller-owned prior evidence and uncertain outputs may not.

`HistoryPin` models the stable key
`TechTradeExpress/Agent-Platform/0.1.0-8/amd64`. Missing/UNKNOWN/incomplete history
blocks. Any changed source, recipes, image/tool inputs, historical record,
archive or provenance conflicts with an asserted frozen bundle. Even an identical
frozen bundle refuses replay/output. No local registry is created/read/reset;
a new empty file/directory cannot establish real absence of a previous freeze.
`history_authenticated=false` remains explicit. Durable independent continuity,
a real vault, stable version index, signer and publisher are NOT_IMPLEMENTED.
All rehearsal results retain final_generation_allowed=false,
release_authorized=false, publication_allowed=false and installation_allowed=false.

## Negative gate matrix and evidence limits

| Condition | Exercised refusal / evidence |
| --- | --- |
| No trusted human generation decision; flags/env/config/Issue/PASS claims | Public function/CLI fixed BLOCKED / exit 13, before I/O |
| Missing/stale source/tree/epoch/recipe/full inputs; dirty/moving HEAD | Refuse export or output; no recipe from export is executed |
| Fabricated Git export/objects; recipe replacement | Blob and exact tooling digest mismatch |
| Unknown/changed historical archive or recipe; absent tool observation | Refuse before caller output |
| Candidate/CI rename, inconsistent manifests/roles/rebuilds/provenance | Reject class/format/integrity; all role pairs compared |
| Symlink/hardlink/traversal/special archive or output alias | No-follow/type checks and exclusive creation; prior data retained |
| Partial/ambiguous output | Retained UNKNOWN intent; no automatic adoption/retry |
| Missing/UNKNOWN freeze or changed same-version identity | Block; identical frozen evidence also gives no replay permission |
| ELF/vendor binary, extra maintainer hook, unit activation | Closed inventory/integrity checks; payload never executed |
| Ordinary --final-version | Existing parser refusal regression-tested |

Normal candidate and CI artifact byte/provenance parity is compared against the
pinned parent recipe on the same fabricated inputs; missing immutable parent
objects means this one comparison is NOT_RUN, with no fetch in tests. Existing
source regressions, historical reconstruction, two-role closure, blocked doctor,
PKG-11 empty/UNKNOWN -7 to CI_ONLY -8 migration, lintian/autopkgtest and negative
fixtures remain. Ordinary pytest CI discovers the new tests; no tag, release or
real generation workflow is added. Container privileges remain confined to
already authorized disposable fixtures; no local host fallback or tool install.

Actual final ar/.deb production, final-artifact lifecycle, authenticated human
admission, independently protected registry/continuity, signing, publication,
actual host/backup/restore, effective systemd/AppArmor/BPF, native auth/tool
isolation and runtime activation are NOT_RUN / BLOCKED / NOT_IMPLEMENTED.
The callbacks, pins, marker and SYNTHETIC_PASS cannot authenticate any of them.

## Required later operator handoff after PKG-13 human squash merge

1. Independently review/publish source under the separate supervised workflow;
   only the human merges. Then freshly observe the actual merged commit/tree,
   epoch, both recipe blobs/digests and full closed inputs. The starting main
   `c27d0ef9bb1a07f56bbaa1fce9811827636c054f`, this pre-merge HEAD or a ZIP/tag
   is not the final source identity. Further adapter/admission changes require
   another reviewed merge and full re-pin; never guess future hashes.
2. Admit an exact trusted Debian 13 amd64 toolchain/dependency snapshot, source
   collector and OS/credential separation. Signed but mutable APT indexes are not
   a hermetic snapshot. Reverify actual historical -7 evidence and independent
   retained freeze continuity; unknown observations block.
3. Separately design/review the missing authenticated pre-generation decision
   procedure and real final encoder integration. A flag, file, model output or
   passed metadata checker cannot implement this. Obtain a distinct direct human
   decision naming immutable source/recipes/environment/inputs and generation scope
   before any actual final-bit attempt. The real entrypoint remains blocked today.
4. Only in that later approved scope build both final archives from the outset,
   twice; verify all actual bytes/metadata, closed roles and inert scripts, then
   run final-artifact Debian lifecycle/quality checks independently. Do not reuse
   rehearsal images or CI_ONLY archives. Retain each missing check as NOT_RUN.
5. Independently review actual bits and bundle digest, protected durable freeze
   continuity and custody/destination. Require a later distinct authenticated
   human publication decision. Hashes are correlation, not signer identity or
   approval. UNKNOWN effects stop for reconciliation, never blind retry.
6. Still later, each host needs its own exact-file/hash, backup/continuity/restore
   and STOP approvals under the unchanged PKG-12 runbook. No old worker01 exception,
   source merge, release decision, package installability or synthetic PASS grants
   host access, daemon reload, service/native runtime or Publisher #108 authority.
