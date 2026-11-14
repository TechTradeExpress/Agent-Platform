# PKG-03 second pass: target graph, cargo-deny and redistribution obligations

2026-11-14, continuation of local `3e082c846198ba78197b8260155e97056e3b28b9`.
Same worktree/common repository/feature branch and clean tracked/untracked state
were verified before editing. No history reset or replacement. Public #115 is
open Draft at `95e7b510b2ab3fb0a8e05187e17c622c6e1e174c`; this iteration is a
new local child, not a rewrite of that reconstructed GitHub commit.

**BLOCKED remains**, but its basis is narrowed. This is a partial technical
license investigation, not a conclusion that redistribution is legally banned.
No binary-specific SBOM is universally required by Apache-2.0. The remaining
project acceptance gaps are the target/feature/native inventory, complete
applicable notice payload and a covered-source/recipient-notice plan for MPL
components. None can be satisfied by a renamed status or synthetic package.

## Reproducible source evidence

All Codex source inspected here is at **exactly**
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856`, the source pin for official stable
0.166.0. Archive/binary hashes and the version-only observation remain as recorded
in [the initial audit](codex-toolchain-package.md). No replacement binary, newest
release, authenticated endpoint, Cargo build or package installation was used.

[license-investigation.json](../packaging/codex/license-investigation.json)
retains size/SHA-256/Git-blob pins for **189 source files**, including **all 171
Cargo manifests under codex-rs**, the release/CI workflows, deny.toml and V8 build
configuration. Those source bytes were checked against the complete upstream
Git tree. Eight additional text observations use explicit external repository
revisions and retained SHA-256. Eight selected crates.io source archives were
downloaded at exact Cargo.lock versions and checked against lockfile checksums,
then read as data without running their code/build scripts. They are inspected
examples, **not a complete or binary-specific component inventory**.

The ledger is itself pinned by `release-inputs.json`; the preflight verifies
that digest and still unconditionally refuses package creation. Edits cannot
provide clearance. The source files/archives are not silently admitted at build
time and no large binary/archive is committed to Git.

## Release inputs and feature selection

The Cargo release job's Linux primary row selects
`x86_64-unknown-linux-musl` and binaries `codex`, `codex-code-mode-host`,
`codex-exec-server`, `codex-responses-api-proxy`, `bwrap`. The bwrap binary is built
first; the later command is `cargo build --target "$target" --release --timings`
with explicit `--bin` arguments for the other row entries. It supplies no
`--features`, `--all-features` or `--no-default-features` flags. CLI package is
`codex-cli`, binary `codex`, resolver is **2**, and cli/Cargo.toml declares no
root `[features]` table. Default dependency features plus explicit per-dependency
features apply; runtime feature settings are not Cargo feature selection.

The release command does not explicitly include `--locked`; the inspected
checked-in Cargo.lock is therefore a source-resolution input, not independent
proof of the actual resolved release graph. Multiple selected packages can also
unify dependency features. A standalone `cargo tree -p codex-cli` is useful but
must not silently be labelled the exact multibinary release feature graph.
Actual release rustc/link inputs were not independently retained here.

The workflow builds sibling executables and then makes **per-binary** tar.gz
archives. It separately builds resource-bearing `codex-package-*` archives.
The selected `codex-x86_64-unknown-linux-musl.tar.gz` contains only the CLI
executable, not those companion archives. Do not attribute all release-job
dependencies, voice resources or every Cargo.lock record to that one member.

### First-party graph and V8 correction

[license_graph.py](../packaging/codex/license_graph.py) computes an intentionally
conservative **normal-workspace upper bound**: all target tables and optional
normal edges are included, build/dev edges excluded; it resolves workspace
aliases and path dependencies, including implicit workspace members. Missing
path manifests block rather than silently dropping an edge. Merely scanning the
165 explicit workspace members misses e.g. `codex-chatgpt`; the complete source
set is required. Four regression tests cover those pitfalls and incorrect V8
exclusion. This utility does **not** implement Cargo's registry/Git resolver,
target filtering, feature unification, build scripts or linker analysis.

The result has **148 CLI-reachable first-party packages in that upper bound**,
not 148 proven binary components. No normal workspace route from CLI reaches
`codex-code-mode-runtime`, `codex-code-mode-host`, or a direct external `v8` edge.
The observed separate route is:

```text
codex-cli -> codex-core -> codex-code-mode         (client/protocol)
codex-code-mode-host -> codex-code-mode-runtime -> v8
```

The client library exports process-owned/gRPC session providers. CLI's build.rs
only adds a macOS Objective-C linker flag; it does not embed the host binary.
This corrects the first pass's overly broad V8 concern. Full external transitive
resolution is still missing, so the bounded source observation is not a claim
that binary membership/non-membership has been independently proven. **A V8
notice gap for a separately distributed companion is not by itself a reason to
deny this CLI-only repack.** Expanding the package to include the host would
require a new ADR manifest review and its own complete native notices.

The ledger's `workspace_reachability` can be reproduced offline by loading the
hash-verified manifest bytes into `workspace_graph(mapping)`, where mapping keys
are repository-relative paths and values are bytes, and comparing its result
with the saved object. No upstream source is imported/executed. The returned
`target_resolved`, `external_transitives_resolved`, `binary_components_proven`
and `redistribution_allowed` fields always remain false.

## What cargo-deny establishes, and what it does not

At this source pin, `codex-rs/deny.toml` explicitly allows:

```text
Apache-2.0; Apache-2.0 WITH LLVM-exception; BSD-2-Clause; BSD-3-Clause;
BSL-1.0; CC0-1.0; CDLA-Permissive-2.0; ISC; MIT; MIT-0; MPL-2.0;
OpenSSL; Unicode-3.0; Unlicense; Zlib
```

License confidence threshold is 0.8, exceptions=[], private.ignore=false.
Graph targets=[], all-features=false, no-default-features=false in **the config**.
Those values do not prove the actual action's effective CLI arguments.
Source rules require revision-pinned Git dependencies and allowed sources;
advisory exceptions are security policy, not redistribution notices.

`blocking-ci.yml` calls `cargo-deny.yml` and includes it in the required aggregate.
The reusable job chooses Rust 1.95.0, workspace manifest `./codex-rs/Cargo.toml`
and `EmbarkStudios/cargo-deny-action@82eb9f621fbc699dd0918f3ea06864c14cc84246`.
It does not explicitly set a target/package filter or action arguments. The
pinned action's source could not be verified in this investigation: its raw
action.yml returned HTTP 404 and the corresponding Git tree request HTTP 422.
No moving v2/new SHA/default argument was substituted. Thus effective action
defaults/tool version and actual exact-release check result are **NOT_VERIFIED**,
not assumed PASS, and config defaults are not misreported as observed execution.
This retrieval limitation is an auditability gap, not a legal license condition.

Even a verified cargo-deny PASS is evidence of accepted crate license
expressions; it is neither a license grant of its own nor the package's required
copyright/notice bundle. The official
[cargo-deny limitations](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html)
describe reliance on crate metadata and incomplete coverage of native code or
nonstandard notice locations. The positive upstream policy evidence materially
narrows concern; it cannot replace satisfying the selected licenses' conditions.

## Selected target dependencies and actual obligations

The following selection is grounded in normal-path manifests and exact source
archives, **not the whole lockfile as a list of linked components**. Cargo's
effective target/features and emitted objects still need confirmation. Unused
platform, test and build-only materials must not become invented runtime duties.

| Selected path / source evidence | Finding and distribution work |
| --- | --- |
| CLI Linux musl target table -> tikv-jemallocator; `tikv-jemalloc-sys` 0.7.1+5.3.1-0-g81034ce1f1373e37dc865038e1bc8eeecf559ce8 | Rust wrapper says MIT/Apache-2.0; native `jemalloc/COPYING` separately requires binary attribution/conditions/disclaimer. Retain it for included native code, not just wrapper licenses. |
| CLI -> core, exact musl target -> openssl-sys `vendored` | `openssl-src` 300.6.1+3.6.3 has wrapper MIT/Apache-2.0 and separate `openssl/LICENSE.txt` Apache-2.0. Identify actual built native source and applicable notices; do not include unrelated Perl build-tool terms as if linked. |
| CLI -> api -> utils-rustls-provider -> rustls `aws_lc_rs,std` | `aws-lc-sys` 0.45.0 declares a compound ISC/Apache/MIT/BSD expression. Its native LICENSE and fiat-crypto MIT notice are available. The allowlist accepting those expressions does not deliver those texts to recipients. |
| CLI -> state; workspace SQLx features include `sqlite-bundled`; libsqlite3-sys 0.37.0 | Wrapper MIT and bundled SQLite source notices differ. Inspect actual included SQLite sources/flags; don't infer a system sqlite dependency from a statically bundled target. |
| CLI -> tui, syntect `parsing,plist-load,regex-onig`, two-face `syntect-onig` | onig_sys 69.9.1 has a separate oniguruma COPYING. two-face 0.5.1 has compressed embedded syntax/theme acknowledgements and a public listing API. Its crate MIT/Apache expression alone does not cover all embedded data. Ledger pins the binary acknowledgement data and its decoding source. |
| CLI -> app-server -> file-search -> nucleo -> nucleo-matcher | Both inspected pinned manifests declare MPL-2.0, at Git revision `4253de9faabb4e5c6d81d946a5e35a90f87347ee`. Source is publicly available and matcher LICENSE was verified. Need a concrete recipient notice and reliable exact covered-source access for distribution; no obligation to release unrelated proprietary source is inferred. |
| CLI -> core -> utils-audio -> Symphonia | Workspace selects `isomp4,mkv,mp3,ogg,wav` with default-features=false. symphonia/symphonia-core 0.6.0 are MPL-2.0. Resolve the actually selected codec/format crates, retain their terms and provide covered-source availability/notice. Do not turn unrelated voice-host libraries into CLI components. |

This pass located useful native/license texts, not a finding that their terms
are incompatible. Filename-scanned paths in the ledger are explicitly
**candidates**, can include unrelated code with "notice" in its name and miss
embedded acknowledgements. `complete_obligation_scan=false` prevents equating
that scan with a complete notice audit. Rust compiler/runtime libraries and
embedded resources also belong in the final inventory where distributed.

### V8/rusty_v8: separate native chain

The resolved binding crate is v8 152.2.0, fork revision
`350c5a859a9b3c84ab8701b3ad51e3b7699b30c0`; its root license is MIT. Runtime
requests `v8_enable_sandbox`, which enables pointer compression; default includes
`use_custom_libcxx`. `setup-rusty-v8` verifies the target's two-line checksum
manifest against committed `third_party/v8/*release_manifests.sha256`, then the
native archive and bindings. The downloaded musl checksum manifest matched
`12acf8747729db642a9d49d3448174471fb07cf47e01a6238222e2d9299de72f`.
It pins archive `2f2679…97d0e7` and bindings `3e4d5f…519d5` (full values in ledger).
No native archive was downloaded or executed in this pass.

The Codex-owned Bazel configuration selects V8 15.2.124.1 source archive with
an integrity digest and local patches. That tag was observed at
`d848a2b3d3aedda62fd825ce5326e5c9d32db96f`; its verified root LICENSE is BSD-3-Clause
and explicitly distinguishes externally maintained libraries/subdirectory terms.
Binding MIT alone does not cover that native engine. The configured graph also
has separately pinned ICU, Highway, fast_float, simdutf, dragonbox, FP16, Abseil
and custom libc++/libc++abi inputs. A host distribution would need their actual
compiled subset and applicable copyright/license/NOTICE collection, including
any LLVM-exception terms, rather than copying V8's root license alone.
These are source/config observations, not a reconstructed native link map or
proof that this separate V8 archive was linked into the selected CLI executable.

## License requirements versus project assurance

| Category | Required distinction |
| --- | --- |
| Apache-2.0 distribution | Provide license and retain applicable notices/attribution; comply with modification notice rules if modifying. Repacking here is intended to keep the binary unmodified. Section 4 does not mandate an SBOM or independently reproducible build. |
| MIT/BSD/ISC/other selected terms | Retain applicable copyright, permission/conditions and disclaimers in the required distribution form; verify native/data terms, not only Rust wrapper metadata. |
| MPL-2.0 covered code | Establish covered-source availability and recipient information under sections 3.1/3.2; verify exact component source/license. File-level requirements do not automatically extend to the whole program. |
| Project acceptance / ADR 007 | Audited component/notice coverage for this exact repack, immutable inputs, artifact hashes, provenance and tested package lifecycle. A binary-bound SBOM is one method; a reviewed target/native inventory plus complete notices is another. |
| Additional security evidence | Build attestation, actual CI checkout/result, source-to-binary correspondence, native isolation and reproducibility increase assurance; missing evidence must not be mislabelled a license clause or a universal legal ban. |

Primary terms: [Apache-2.0 section 4](https://www.apache.org/licenses/LICENSE-2.0),
[MPL-2.0 sections 3.1/3.2](https://www.mozilla.org/en-US/MPL/2.0/), and
[Mozilla's unchanged-binary/source availability guidance](https://www.mozilla.org/en-US/MPL/2.0/FAQ/).
No conclusion here overrides those licenses or turns policy into legal authority.

## Exact remaining work and ways to obtain it

1. **Target/feature/native inventory.** In a separately approved disposable,
   credential-free source-analysis fixture, resolve the pinned Cargo sources and
   Rust toolchain, capture target-filtered metadata and normal/feature trees for
   CLI, then compare with the multibinary release's actual selected roots/feature
   unification and native linker inputs. `cargo metadata --locked --format-version
   1 --filter-platform x86_64-unknown-linux-musl` and `cargo tree --locked --target
   x86_64-unknown-linux-musl -p codex-cli -e normal,features` are useful starting
   evidence, not sufficient alone. No Cargo/Rust toolchain is installed in this
   source session, and these operations were NOT_RUN. Alternatively obtain an
   upstream release graph/native inventory or artifact-bound SBOM with enough
   provenance to review. Do not use all 1478 lockfile records as the answer.
2. **Complete notice payload.** Collect exact selected Rust/native/resource
   copyright/license texts, chosen alternatives for OR expressions and all AND
   obligations. Reuse the verified source archives, inspect native subtrees,
   extract the two-face acknowledgement listing for the selected data and check
   rust runtime/toolchain terms. Record included versus excluded components and
   reasons. An upstream complete redistribution bundle can supply this evidence;
   an SPDX allowlist, filename scan or generic Apache NOTICE cannot.
3. **Covered-source and recipient notice.** Record exact nucleo/Symphonia and any
   other selected MPL source URLs/checksums, applicable modifications, license
   notices and the actual recipient-facing source-availability text. Verify the
   source remains accessible under the required terms or provide an appropriate
   retained source delivery. Public source already exists; lack of source access
   is not presumed. The packaging/delivery plan has not yet been completed.
4. **Review, then real packaging.** Independently review that combined evidence
   against ADR 007 and replace the hard refusal only in a reviewed implementation
   change. Then implement the real builder/preinst and disposable Debian 13
   install/upgrade/remove/purge/rebuild matrix. Source hashes alone, this report,
   an operator-edited JSON flag or an unreviewed external installation cannot
   satisfy the project gate.

No .deb or synthetic lifecycle PASS is produced. Existing runtime/source gates,
LIVE_NO_GO, accounts, permissions, host configuration and credentials remain
unchanged. No push, PR mutation, merge, OpenAI/GitHub authentication or host
installation was performed.

## Validation for this iteration

Ruff PASS; **99 focused tests passed** (35 graph/input tests, including five new
in this iteration, plus 64 existing Debian/deployment tests). The real official
archive and original six text inputs still return verified inputs and BLOCKED,
exit 13, after checking the pinned investigation report. All 189 new source
observations and the saved workspace graph were rechecked/recomputed. Local
documentation links and `git diff --check` passed.

Final full pytest: **3196 passed, 2 failed, 1 skipped**. Both failures reproduced
on an isolated snapshot of the exact unchanged parent
`3e082c846198ba78197b8260155e97056e3b28b9`:
`test_file_mutation_after_digest_read_is_detected` and
`test_changing_evidence_before_write_is_blocked[journal]`. They remain the
intermittent baseline diagnostic/drift failures described in the initial audit;
neither implementation was changed or test skipped. This is not full-suite PASS.
Builder, package install/upgrade/remove/purge and .deb repeatability remain
NOT_RUN because distribution acceptance is still BLOCKED, not synthetically
satisfied. No upstream cargo-deny or Cargo resolution execution PASS is claimed.
