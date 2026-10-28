# Native Codex artifact inspection — Issue #29

Decision: retain the unmodified official x86-64 musl Codex **0.164.0** candidate,
with a **native-only 384 MiB ceiling and exact release digest/length binding**.
This is an offline candidate-inspection policy, not installation or runtime
admission. Both legacy 256 MiB gates in `runtime_manifest.py` and `isolation.py`
are unchanged. The legacy aggregate limit remains 512 MiB. No runtime calls this
helper. `native_codex.execute()` and `agent-platform subscription` stay blocked.

## Packaging and provenance evidence

On 2026-10-28 a fresh unauthenticated download from the
[official release](https://github.com/openai/codex/releases/tag/rust-v0.164.0)
was hashed while streaming, then its single tar member was hashed while
streaming into a private non-executable scratch file. No installer, candidate,
loader, `ldd`, login command or inference was run. No auth directory was read.
The visible local launcher points into `.codex`; inspection stopped at that
link and used the fresh public release instead. The archive independently
matches GitHub's release-asset digest. Exact observations and public URLs are in
[native-artifact-evidence.json](native-artifact-evidence.json).

| Format | Evidence / decision |
| --- | --- |
| Vendor musl tar.gz | 114,979,035 compressed bytes; one **308,139,304-byte** executable, SHA-256 `b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306`. Matches Issue #29's observed candidate. Selected unchanged. |
| npm top-level package | 4,902 compressed bytes; `bin/codex.js` wrapper with platform optional dependencies, including `npm:@openai/codex@0.164.0-linux-x64`. Not a smaller native engine. |
| npm Linux x64 package | Release metadata reports 165,142,849 compressed bytes. Not downloaded or established as a smaller equivalent executable. Adds wrapper/dependency resolution if installed. |
| Bazel musl tar.gz | Release metadata reports 114,024,552 compressed bytes. Executable size/equivalence not verified; cannot substitute it on compressed size alone. |
| musl zst / Bazel zst | 82,489,732 / 81,787,282 compressed bytes in release metadata. Compression does not prove a smaller installed executable. |
| Other architecture, locally stripped/rebuilt binary | Not equivalent to this pinned x86-64 vendor artifact. No supported reproducibly smaller equivalent demonstrated. |

[The exact tag object](https://api.github.com/repos/openai/codex/git/tags/fe3b29455488c2e189e43ad5526a107900c5e1b7)
resolves to source commit `6aaac694803004a63c6f393d153c96d22521a6b9`.
GitHub reports the tag **unsigned** and release **not immutable**.
The pinned [release workflow](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/.github/workflows/rust-release.yml)
and [CLI package](https://github.com/openai/codex/blob/6aaac694803004a63c6f393d153c96d22521a6b9/codex-cli/package.json)
explain vendor archives and npm platform packaging. These establish a public
release association, not source-to-binary equivalence or supply-chain trust.

The downloaded `.sigstore` bundle has an embedded Rekor body claiming the same
binary SHA-256. **Its signature, certificate identity/chain and transparency
inclusion were not cryptographically verified.** HTTPS metadata/hash agreement
is not independent signature verification. No reproducible-build proof was
verified. The version is bound through the exact pinned release bytes, never a
self-reported `--version`. Digest mismatch cannot be overridden through CLI,
environment, catalog version or target repository configuration. Any replacement
requires an independently reviewed code/policy change.

## Offline operator contract

The separately installed command is:

```sh
agent-platform-native-artifact /absolute/private/candidate-image /absolute/private/catalog.json
```

It reads only; it never downloads, extracts, installs, executes or promotes an
artifact. Use a separately reviewed, nonsecret staging tree and a private catalog
based on [the exact example](native-artifact.example.json). The helper does not
create fixtures, change permissions or repair an unsafe tree. Do not supply
`.codex`, credentials, session stores, repositories or host library trees.

Schema version 1 requires exactly `artifact`, `files`, `libraries` and
`schema_version`. `artifact` must equal the compiled-in version, source commit,
target, byte count and SHA-256 (with exact types). `files` contains relative
paths and exact byte count/SHA-256; only `usr/bin/codex` and explicit library
paths under `lib`, `lib64`, `usr/lib`, `usr/lib64` are accepted. `libraries` maps
SONAMEs to those files. All catalog files must be reachable from the executable's
ELF interpreter/DT_NEEDED closure; unknown or unused files/directories fail.

Root/catalog paths must be absolute, bounded, free of traversal and symlinks.
Each component is opened relative to a retained directory descriptor with
`O_NOFOLLOW`; files additionally use nonblocking read-only opens. The tree must
be same-device, ordinary local storage without bind/subtree aliases. Mount
snapshots must remain stable. NFS, unknown filesystems and inaccessible mount
metadata fail closed. Directories/regular single-link files require visible
root/operator ownership, no group/world write, set-ID or file capabilities.
Only ancestor `/tmp` or `/var/tmp` may use the sticky-directory exception; the
candidate root itself must be private/immutable to other users. Namespace root
ownership is only an ancestor traversal anchor, never production root attestation.

The native executable's exact 308,139,304 bytes must also fit 402,653,184 bytes
(384 MiB). Other files are at most 64 MiB; total closure at most 536,870,912 bytes
(512 MiB), at most 128 files, 512 directory entries and depth 32. Catalogs are at
most 256 KiB. Streaming SHA-256 and validated ELF reads use the **same retained
file descriptor**, at most **64 KiB/read**. Descriptor and pathname identities,
size, ownership, permissions, link count and timestamps are compared before and
after. Mutation/replacement is failure. No full binary buffer or mmap is used.

Only ELF64 little-endian x86-64 executable/shared-image metadata is supported.
Program headers (at most 128), file-backed PT_LOAD mappings, entrypoint,
interpreter, dynamic table (64 KiB), and referenced dependency strings (129 bytes)
are range checked. Writable/executable loads or executable stack, overlapping
loads, malformed strings, search paths/audit/filter tags, unknown dynamic tags,
more than 64 dependencies or unresolved libraries are rejected. The declared
string table is at most 1 MiB and is never read wholesale. This parser is a
restricted metadata check, **not a full ELF loader or malicious-code proof**;
constructor behavior, dlopen/resource paths and executable semantics are unproven.

I/O is capped at 528 MiB including catalog/ELF rereads; monotonic deadline is
60 seconds checked between operations. Kernel filesystem calls can themselves
block; this is not a hard wall-clock guarantee on a stalled device. Operators
must run on approved responsive local storage. No subprocess is launched.

Success returns `INSPECTED_NATIVE_CANDIDATE`, exact size/hash and budgets, always
`runtime_admitted=false`, `execution_enabled=false`. It is **not**
`RUNTIME_ADMITTED`, signature verification, authorization or source equivalence.
Validation failures return generic nonsecret `BLOCKED` JSON, exit 13; usage is 2.

## Actual evidence and next gates

The fresh vendor file's bounded static ELF metadata shows x86-64 PIE with
**no PT_INTERP and no DT_NEEDED**. Its static ELF closure is one file. Under a
512 MiB aggregate ceiling this leaves **228,731,608 bytes**. That does **not**
prove a complete usable native runtime fits: shell, Python/relay/tool helpers,
resource data and any runtime-loaded objects still need a separately reviewed
full native-runtime manifest. The strict helper intentionally cannot admit a
full arbitrary tool runtime from this one-file catalog.

The initial mounted fixture returned **`BLOCKED: mount_alias`**. A new private,
non-executable staging copy was then created with supported approval, exact
size/hash rechecked, and the unmodified helper returned
**`INSPECTED_NATIVE_CANDIDATE`**, `visible_root_owned=false`,
`runtime_admitted=false`, `execution_enabled=false`. No mount-policy exception,
permission repair or skipped validation was used; existing files were preserved.
This is actual static artifact evidence, not kernel confinement or production
admission. The published example is a candidate catalog, not a signature or
root-owned installation claim. Required next gates are:

1. Independently verify vendor signature identity/chain/transparency and decide
   the acceptable unsigned-tag/source-equivalence evidence gap.
2. Review the native-only policy and a complete immutable, genuinely root-owned
   image, any loader/library closure and full tool/resource budget. Do not reuse
   the legacy credential-free API-broker runtime for subscription auth.
3. Independently provide the reviewed unprivileged Linux fixture (Issue #28);
   prove host filesystem/process/descriptor/network confinement without weakening
   caps. A host/container boundary still does not protect same-domain CODEX_HOME.
4. Resolve trusted subscription credentials versus model-invoked native tools and
   session persistence. No real credentials, account eligibility, refresh,
   subscription execution or live inference were tested or authorized here.

The offline tests use synthetic ELF, private fixtures, fake mount metadata and
an ephemeral sparse **268,435,457-byte** file; no vendor binary enters CI. They
check bounded read/memory budgets, exact pins, cap/budget failures, drift/races,
permissions/aliases/special files and malformed ELF/dependency tables. Synthetic
PASS is separate from the real artifact's hash evidence, actual private-tree
inspection, real kernel confinement and authenticated E2E (the latter two remain
unproven).
