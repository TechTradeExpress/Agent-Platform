# PKG-03 third pass: real Cargo attempts and supplied MPL candidate sources

2026-11-14. Local parent: `3fe266fe59f1d3f47cc0463613dfa7afdcd1e789`.
The existing worktree, common Git directory, feature branch, exact HEAD and clean
tracked/untracked state were verified before changes. Public #115 was observed
open Draft at `3e06cfd9d544fc0ae9e5ae9179592d7b6c5777c7`. No history rewrite,
fetch/rebase, PR mutation, credentials, system installation or runtime activation.

**No working agent-platform-codex.deb was produced.** This iteration attempted
the missing Cargo resolution rather than repeating a static graph. It supplies
real, reproducible covered-source candidate archives, but cannot claim a complete
binary redistribution manifest without the unresolved target inventory.

| Gate | Exact current status |
| --- | --- |
| 1. Actual CLI target/features/native/resource inventory | **BLOCKED**: both real Cargo attempts produced zero metadata bytes; first failed on ICU submodule fetch with ENOSPC, second was stopped at the fixture storage budget after freeing duplicate staging |
| 2. Complete redistribution license/copyright/NOTICE manifest | **BLOCKED**: the selected component set is not resolved; earlier verified texts/examples remain evidence, not a complete notice inventory |
| 3. MPL exact sources, recipient information and delivery | **PARTIAL**: full source archives for 11 identified candidates were acquired and verified, with notice and reproducible companion source bundle; completeness against the actual binary remains unproven |

These are project acceptance states. They are not assertions that Apache/MPL
prohibit redistribution, that an SBOM is legally mandatory, or that the missing
evidence is impossible to obtain in a suitable environment. LIVE_NO_GO, ADR 007
and the preflight's unconditional binary-build refusal remain intact.

## What actually ran and why it could not finish

The complete official source archive at
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856` was acquired; **9732 file/link blobs,
97140378 regular-file bytes**, were checked against the pinned complete Git tree.
The only source symlink, bubblewrap LICENSE -> COPYING, was reviewed as an
internal link. Source was mounted read-only; Cargo.lock and manifests were not
changed to omit companion packages or fabricate a simpler target graph.

Official standalone **Rust/Cargo 1.95.0**, the upstream workflow toolchain,
was acquired using `channel-rust-1.95.0.toml`, not latest. Its manifest SHA-256
matched the separately fetched checksum. The fixed 2026-04-16 cargo, rustc and
host rust-std archive digests were checked before extraction. They were assembled
only under a new private `/tmp` fixture; no installer was executed, no PATH/profile
was modified and nothing was installed into system directories.

In bubblewrap, with private namespaces, an empty fixture HOME/CARGO_HOME, a
read-only toolchain/source and no host user homes or credentials, the command was:

```text
cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-musl
```

Network was available only for this supervised public-source acquisition task;
this is not a production egress-enforcement claim. Git global/system config and
interactive credential prompting were disabled; no auth variables were provided.
No build scripts, Codex, model, package installer or native library build ran.
Cargo's needed rustc metadata queries are distinct from compiling the project.

[resolution-attempts.json](../packaging/codex/resolution-attempts.json) records
the exact command, immutable toolchain origins/digests, source observations,
exit/status, output sizes and redacted diagnostic hashes:

- **Attempt 1:** Cargo exit **101**, stdout **0 bytes**. Its chained error reached
  rusty_v8's native **ICU submodule** acquisition and reported `No space left on
  device`. The fixture filesystem is **3109699584 bytes total**. Only this
  attempt's newly created private Cargo cache was discarded after process exit;
  source archives, toolchain, logs/status and all pre-existing worktrees/data
  were preserved.
- Duplicate component-extraction staging from this iteration was then removed;
  assembled verified tools were retained. This recovered roughly 0.6 GB, leaving
  about 1.08 GB available. The first failure was not simply declared permanent.
- **Attempt 2:** a fresh cache, same read-only source/lock and command, no automatic
  network retries. Supervision stopped the owned process via pidfd at the storage
  guard: **870178075 cache bytes**, **60 seconds**, stdout **0 bytes**, exit **-9**.
  The guard was 768 MiB cache or <256 MiB remaining free, checked once per second;
  the measured size can overshoot between checks. This was an explicit local
  resource stop, **not** a second Cargo resolution error or a successful graph.
  Only this new cache was discarded after confirmed exit; diagnostic evidence
  was retained. No unrelated data was deleted to make space.

Cargo is acquiring workspace Git sources/submodules, including the separate V8
host's sources, before it can emit the requested metadata. Fetching rusty_v8/ICU
does **not** establish that V8 is linked into CLI. `--filter-platform` is not
permission to treat all workspace downloads as target binary components.
The earlier [upper-bound source analysis](codex-license-investigation.md) remains
separate from a real resolved graph, and neither is a native link map of the
official executable. No valid JSON graph can be inferred from partial Git caches.
Cargo's distinction between metadata/target filtering and dependency resolution
is documented in the primary
[metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html) and
[resolver](https://doc.rust-lang.org/cargo/reference/resolver.html) references.

### Concrete unavailable evidence and ways to obtain it

The unavailable result **in this fixture** is successful canonical Cargo
resolution output at the pinned source/lock/toolchain, followed by CLI normal
dependency/feature selection and comparison with the multibinary release roots.
The observed source-fetch storage need exceeded the attempted budget before
resolution completed. No exact minimum disk requirement is guessed. No claim is
made that a larger system or a verified vendored source set could not resolve it.

Useful ways forward, requiring no license bypass or host configuration change:

1. Run the same pinned acquisition/resolution in an approved disposable fixture
   with materially more storage/headroom, retain target metadata and normal/
   feature trees, and record the release's actual selected roots/features/native
   inputs. Do not repeat this download unboundedly on the current small filesystem.
2. Supply a complete, hashed Cargo-vendored source snapshot prepared from that
   exact source/lock in a sufficiently sized credential-free fixture. Supported
   Cargo source replacement can avoid repeated full Git/submodule acquisition;
   it must preserve package source identities and be verified, not silently
   rewrite manifests/patches or omit an inconvenient workspace dependency.
3. Obtain the upstream release's resolved target/feature/native input report or
   sufficiently detailed provenance/SBOM/notice bundle. Match it to the existing
   official binary SHA. A signature of an asset alone cannot replace its component
   and notice inventory; independent source-to-binary reproducibility remains a
   separate assurance limit under ADR 007.

Until one path supplies the missing data, selecting every Cargo.lock record,
using the static upper bound as the binary inventory, or declaring all crate
licenses accepted from cargo-deny alone would manufacture the requested evidence.

## Concrete MPL source delivery prepared here

[mpl-source-candidates.json](../packaging/codex/mpl-source-candidates.json)
lists exact source artifacts, sizes/SHA-256, origins, versions, source revision
identifiers and license-file hashes for:

- **nucleo 0.5.0 / nucleo-matcher 0.3.1**, complete Git source at
  `4253de9faabb4e5c6d81d946a5e35a90f87347ee`. All **42** archive blobs were checked
  against the Git tree. The actual `matcher/LICENSE` is a symlink to `../LICENSE`;
  the manifest records the root MPL license content, correcting the earlier raw
  symlink-text observation's limitation.
- **symphonia, symphonia-bundle-mp3, symphonia-common, symphonia-core,
  symphonia-format-isomp4, symphonia-format-mkv, symphonia-format-ogg,
  symphonia-format-riff, symphonia-metadata — all 0.6.0**. Complete published source
  `.crate` archives match the pinned Cargo.lock checksums. Their manifests and
  LICENSE texts were checked. All record source revision
  `980bf5830a90e069fd64641d9c38f067ab772a24` in `.cargo_vcs_info.json`; this is
  publisher-reported VCS metadata, not an independently reconstructed Git tree.

These are **source candidates**, not a claim that every listed family member
and no additional MPL component is in the executable. The source archive bytes
are unchanged; original source copyright/license notices are retained, including
the internal nucleo license symlink. The bundle tool makes no source changes.

[MPL-SOURCE-NOTICE.txt](../packaging/codex/MPL-SOURCE-NOTICE.txt) provides exact
identifiers and recipient instructions. Source availability is concrete: provide
the complete matching source archives in the same companion bundle to each
recipient, with the manifest and notice. Recipients can obtain the supplied
source **offline**, without account, payment or compiler; upstream URLs are
supplementary provenance, not the sole availability promise. Before a future
binary release, reconcile the candidate list with the actual target, add any
other covered source and distribute the completed bundle alongside it. MPL's
file-level source obligations do not relicense all Agent Platform.

The implemented source-only builder is:

```sh
python3 -I packaging/codex/mpl_sources.py \
  --sources /absolute/path/to/ten-verified-input-archives \
  --output /absolute/path/to/new-source-candidate-bundle.tar.xz
```

It verifies pinned manifest/notice and all ten archive bytes before output,
rejects incomplete/extra/symlink/hardlink/corrupt inputs and existing outputs,
uses fixed archive ownership/modes/timestamps, and never extracts or executes
the source inputs. A partial write is retained on I/O uncertainty, never silently
repaired. Output always says `SOURCE_CANDIDATE_BUNDLE_ONLY`, with binary-set
verification, redistribution clearance and `package_built` all false. No flag
promotes a source-bundle success into a license gate PASS.

Two real builds were byte-identical and all nested source archive hashes were
rechecked. Local artifact: `pkg-03-issue-110-mpl-source-candidates.tar.xz`,
**568276 bytes**, SHA-256
`86e71f9effaab2b83921d59b7591ac3f276528e9526524e1c1ea469ca71ab4f1`.
Only the manifest, notice and builder/tests are committed; source/binary archives
remain outside Git. This is source-delivery evidence, **not .deb repeatability**.
The equality claim applies to these pinned inputs and the same Python/xz
toolchain; no cross-builder or upstream binary reproduction is claimed.

## Boundaries

No ADR 007 scope expansion, alternative Codex binary, dynamic latest, system
dependency installation, worker/control host configuration, GitHub/OpenAI
credentials, remote write, service start or runtime activation. The original
binary remains pinned, and the license preflight still returns BLOCKED/exit 13
even with valid artifact and source evidence. The new reports/recipient notice
are hash-pinned; editing their status cannot release the gate.

## Validation

- Ruff: PASS. Focused graph/input/source-bundle and existing Debian/deployment
  tests: **110 passed**, including 11 new regression cases in this iteration.
- Actual source-candidate bundles: byte-identical; all ten nested archive hashes
  verified. Corrupt/incomplete/extra/aliased inputs, altered notices/reports and
  existing output refuse without granting binary clearance.
- Actual official binary/archive preflight with the original six text inputs:
  verified inputs, BLOCKED, exit 13. The new source/report evidence does not
  release that gate. No binary or model was executed in this iteration.
- Full pytest: **3207 passed, 2 failed, 1 skipped**. Both failures reproduced on
  an isolated snapshot of exact unchanged parent
  `3fe266fe59f1d3f47cc0463613dfa7afdcd1e789`:
  `test_file_mutation_after_digest_read_is_detected` and
  `test_changing_evidence_before_write_is_blocked[journal]`. Their source/tests
  are unchanged; no skip or security weakening was added. This is not full PASS.
- Local documentation links and `git diff --check`: PASS. Debian package
  build/install/upgrade/remove/purge/repeatability: **NOT_RUN / no .deb**.
