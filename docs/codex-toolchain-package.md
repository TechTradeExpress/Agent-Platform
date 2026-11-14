# PKG-03: pinned Codex inputs — BLOCKED before Debian distribution

Issue #110, 2026-11-14. Source parent
`edf15ccb8ac197de7542ab4cad89800e50c83ff9`, verified against fresh public
`origin/main`. PR #114 / [ADR 007](debian-role-package-architecture.md) is merged.
Issue #102 remains the separate inert role-package task. This work is
LOCAL_ONLY; no installation, credentials, release, PR or remote write.

**Result: BLOCKED / binary_license_closure_unverified.** There is no approved
`agent-platform-codex.deb`, completed builder, Worker dependency version C or
license-compliance PASS. The implemented command is a real offline input
verifier and fail-closed preflight, not a synthetic package or a disabled gate
that an operator can turn on. #110 is not complete. No override/accept-license
flag, editable clearance JSON, environment setting or passing hash can build.

## Exact upstream subject and observations

Selected audit candidate: official stable **Codex CLI 0.166.0**, Linux x86_64
musl asset, not Bazel, alpha, nightly or `latest`. This is a fixed audit subject,
not a claim of upstream support duration or currently newest release.

| Fact | Verified value |
| --- | --- |
| Official release | [rust-v0.166.0](https://github.com/openai/codex/releases/tag/rust-v0.166.0), ID 428320524; draft=false, prerelease=false; published 2026-10-29T19:47:53Z |
| Annotated tag object | `593389380740f7b4762771573c447ccfdc59742f` |
| Peeled source commit | `6ff1e1ca3b30fc8b914720681fcf5fe62e95f856` |
| Asset | `codex-x86_64-unknown-linux-musl.tar.gz`, asset ID 689712643 |
| Origin | `https://github.com/openai/codex/releases/download/rust-v0.166.0/codex-x86_64-unknown-linux-musl.tar.gz` |
| Archive size / SHA-256 | 121764138 bytes / `a0bf572d2f93f056c6712a6da348e96078dc84f3885fd7be67807ef389cb3978` |
| Archive inventory | Exactly one regular 0755 file, `codex-x86_64-unknown-linux-musl`; no bundled license, NOTICE, SBOM or other payload member |
| Binary size / SHA-256 | 319346888 bytes / `b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8` |
| ELF | ELF64 little-endian, x86_64 (62), ET_DYN/PIE (3), no PT_INTERP, no DT_NEEDED entries |
| Isolated invocation | Actual `codex --version` output `codex-cli 0.166.0`, exit 0, in the minimal namespace fixture below |
| Debian 13 package ABI/lifecycle | NOT_RUN; no approved .deb exists |

Archive SHA was independently computed over downloaded bytes and matched the
public GitHub Release asset digest. Binary SHA was computed over the sole member
without modification. Public API tag/ref/complete source-tree data established
the source pin; each inspected source file was also checked against its Git blob
SHA-1. SHA-256/size/Git-blob/immutable URL pins for all six inspected text inputs
are retained in
[release-inputs.json](../packaging/codex/release-inputs.json).
These observations correlate content; they do not verify a Sigstore certificate,
independent build attestation or source-to-binary reproducibility. No such PASS
is claimed. No binary/archive is committed to Git.

The ELF observations establish no mandatory dynamic loader/library dependency
at startup for this member. They do **not** establish that every feature is
self-contained: dynamically opened resources, embedded third-party code, CPU
requirements, minimum kernel, optional helpers/voice runtime and the complete
supported Debian dependency set remain unverified. `debian_dependencies=null`
means UNKNOWN, not an empty Depends field. No libc/Node/npm dependency is guessed
from the asset name. The 319 MB member exceeds the separate legacy runtime's
256 MiB admission ceiling; this packaging inspection does not change that ceiling
or admit the binary to any Agent Platform execution path.

## License audit findings and exact blocker

This is a partial technical evidence audit, **not complete redistribution
clearance**. Root source
[LICENSE](https://github.com/openai/codex/blob/6ff1e1ca3b30fc8b914720681fcf5fe62e95f856/LICENSE)
identifies Apache-2.0. Its exact bytes and root NOTICE are retained as
[upstream-LICENSE](../packaging/codex/upstream-LICENSE) and
[upstream-NOTICE](../packaging/codex/upstream-NOTICE), with hashes in the lock.
Apache attribution/NOTICE retention must be addressed in a future package;
this root license does not replace licenses of bundled dependencies or grant
OpenAI endorsement/trademark rights.

The pinned
[root NOTICE](https://raw.githubusercontent.com/openai/codex/6ff1e1ca3b30fc8b914720681fcf5fe62e95f856/NOTICE)
identifies Ratatui-derived MIT code and its copyright holders. That 242-byte
notice is not a complete third-party license collection. Source
`docs/license.md` only points to the root license. No release asset named as a
license inventory/SBOM was present in the inspected release response; this is
not proof that no usable evidence exists elsewhere upstream.

The exact source `codex-rs/Cargo.lock` contains **1478 package records, including
12 Git-sourced records**. This is a workspace resolution inventory, not the
target/features actually linked into this executable. Examples needing closure
review include Ratatui 0.30.2, aws-lc-sys 0.45.0, libsqlite3-sys 0.37.0 and v8
152.2.0 from the pinned rusty_v8 fork revision. Their presence in Cargo.lock is
not proof that all are linked, nor a license classification for their binaries.

The pinned `.github/workflows/rust-release.yml` configures an independently
downloaded rusty_v8 artifact/checksum before Cargo build. A Rust-only license
list cannot simply cover embedded V8/native components or their transitive
notices. Source `third_party/voice/NOTICE.md` separately describes voice runtime
libraries and license files for packages that contain voice; the selected
single-member archive does not contain those separate runtime files. Do not
infer either that all voice obligations apply here or that no native license
obligations remain. Build graph, feature selection, native archives and exact
release inputs must resolve that question.

**Missing evidence:** a complete dependency/native-resource inventory bound to
binary SHA `b8a11f…156b8`, verified license/notice texts and attribution for that
inventory, and any corresponding-source/relinking obligations applicable to
the actually distributed components. The checked materials do not establish
that evidence. There is no claim that upstream redistribution is prohibited;
the required completeness has not been verified. Adding Apache LICENSE, copying
all Cargo package names or setting `redistribution_allowed=true` is insufficient.

Unblocking requires upstream artifact-bound SBOM/notices/build provenance, or
an independently reviewed reconstruction of the exact target/feature/native
input closure with all applicable texts and obligations, then a new reviewed
source change implementing packaging and its lifecycle tests. A new upstream
version may be selected under a new explicit immutable lock; no dynamic fallback.
The documented alternative remains a **user-managed external Codex install**
with explicit hash/version validation, under its own approval. It does not
satisfy Worker `Depends: agent-platform-codex (= C)` or authorize bypassing ADR 007.

## Implemented preflight and safe input handling

The source-only command is:

```sh
python3 -I packaging/build_codex_deb.py \
  --archive /absolute/path/codex-x86_64-unknown-linux-musl.tar.gz \
  --sources /absolute/path/exact-upstream-text-inputs
```

`--sources` contains exactly the six **explicitly read** relative paths recorded
in the lock: LICENSE, NOTICE, docs/license.md, codex-rs/Cargo.lock,
.github/workflows/rust-release.yml, third_party/voice/NOTICE.md. It is not a
discovered source tree or executable checkout. Acquire those immutable HTTPS
URLs and the fixed archive separately with bounded GETs/no retries; verify with
this command before use. Build/preflight itself has no network client/download,
shell command, Git operation, subprocess, package manager or Codex invocation.

The lock's exact digest is pinned in the verifier. It verifies bounded regular,
singly linked no-follow final input files and metadata stability; streams archive
and binary SHA-256; requires the one exact tar member/mode/length; inspects bounded
ELF program/dynamic tables and rejects unexpected interpreter/dependencies.
Nothing is extracted, executed or installed. Output is deterministic JSON with
fixed status/codes/hashes, no raw stderr, private paths or file contents.
Valid real inputs return `inputs_verified=true`, `package_built=false`,
`redistribution_allowed=false`, `status=BLOCKED`, exit **13**. `version_executed`
is false because this preflight never executes; the separate version observation
above does not change its result. Invalid inputs return a fixed refusal.

This is developer-side evidence processing, not trusted OS admission or
protection against a malicious same-UID/root writer. Descriptor metadata checks
cannot guarantee every concurrent same-size mutation is detectable on every
filesystem, or authenticate an operator. Retain inputs in reviewed immutable
storage for stronger acquisition/build assurance. The report and lock cannot
authorize publishing, release a runtime gate or substitute for independent
license review. There is no .deb output path or build override to circumvent
the unresolved audit.

## Isolated version observation

Initially namespace creation was denied in the execution sandbox. The **same**
fixed probe was retried through the supported approval mechanism and succeeded;
no namespace option was removed and no host-execution fallback was attempted.
Only the verified executable was exposed as `/codex` inside bubblewrap with
`--unshare-all --die-with-parent --new-session --clearenv`, private proc/dev/tmp,
an empty synthetic HOME and no host libraries, checkout, credentials or network.
The only executable argument was `--version`; no login, model, app-server, tools
or Agent Platform native runtime was started. This proves version-only execution
on the available Linux kernel, **not** package installation/activation on Debian
13, authenticated isolation or supported runtime completeness. No worker01,
worker02 or control01 system configuration was changed.

## Package implementation and lifecycle remain blocked

No fake .deb is emitted for the tests. Consequently deterministic .deb rebuild,
dpkg file ownership/content/dependency assertions, refusal-only preinst collision
guard, install/reinstall/update/downgrade/remove/purge and Debian 13 APT closure
tests are **NOT_RUN**, not passing synthetic substitutes. ADR 007 requires these
before a usable package. The existing legacy package builder/lifecycle remains
unchanged and its own archive tests still run.

Once the audit is complete, preserve the original binary at `/usr/bin/codex`,
the exact Codex-only document manifest and refusal-only preinst from ADR 007.
Test foreign/unowned executable collisions before unpack, no modified binaries,
deterministic repack, interrupted upgrades, exact dependencies and user-state
preservation in disposable Debian 13. Never modify global PATH, shell profiles,
`~/.local/bin/codex`, `$HOME/.codex`, tokens, sessions or worktrees. Detect
shadowing by nonsecret resolution metadata, never execute an arbitrary shadow.

No maintainer-script download or login; no accounts, keys, services or auto-start.
An offline install needs the exact Worker and approved Codex .debs in one APT
transaction plus the signed Debian dependency closure/cache; a local Worker
file alone cannot acquire an unavailable toolchain. There is no APT feed or
newly selected C yet. Keep #102 blocked on a genuine approved C for acceptance,
not a dummy provider. `LIVE_NO_GO`, Gate #73, native subscription isolation,
public exit 13 and human-only merge are unchanged.

## Local validation evidence

Python 3.12.16, locked offline uv environment. Ruff PASS; 30 new input/refusal
tests plus 64 existing Debian archive/deployment tests PASS (94 total).
The real pinned archive plus six text inputs returned the expected BLOCKED
report with `inputs_verified=true`, exit 13. Local documentation links and
`git diff --check` passed. No downloaded binary was executed by pytest.

Full pytest: **3191 passed, 2 failed, 1 skipped**. Both failures were reproduced
on an isolated source snapshot of the unchanged exact parent above:
`test_native_artifact.py::test_file_mutation_after_digest_read_is_detected`
(intermittent `invalid_load` instead of `file_changed`) and
`test_telegram_console.py::test_changing_evidence_before_write_is_blocked[journal]`
(intermittent `read_only` instead of `needs_human`). Those source/test files are
unchanged; no skip or security weakening was added. This is not a full-suite PASS.
Debian install/upgrade/reproducibility and distribution approval remain blocked
as described above, independent of those baseline failures.
