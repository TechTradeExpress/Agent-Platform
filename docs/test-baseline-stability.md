# TEST-01: deterministic baseline security tests (Issue #124)

Base: merged main `6669bfea985e004a2689515920604f99af892d8d`.
This change fixes test inputs and the exact stdlib compatibility expectation.
Production Native Artifact, TelegramRequest, replay/state code, integrity checks,
rejection reasons, resource limits, package manifests and CI interpreter policy
are unchanged. No live process, host configuration, credential or service is used.

## Reproduction before changes

Existing pinned tools: CPython 3.13.5, pytest 9.1.1, uv 0.13.7. Only Python 3.13
was installed locally (`uv python list --only-installed --offline`); local 3.12
is NOT_RUN, not emulated or downloaded. Hosted CI continues using the existing
fixed `/usr/bin/python3.12` and unchanged `ci/cp08_pytest.py` validation.

Before editing, the full suite yielded **3830 passed, 3 failed, 1 skipped**.
Ten bounded runs of the original native mutation and replay journal tests found:

- Native mutation: 5 failed / 5 passed; failure reason `invalid_load`, expected
  `file_changed`. Every failure still rejected the artifact.
- Replay journal: 8 failed / 2 passed; `read_only`, expected `needs_human`.
- The original notification test separately reproduced `TypeError` where it
  expected `ValueError`.

All individual logs, commands/versions, summary and the raw nonsecret metadata
probe are retained in the delivery archive. These repetitions are explicit
validation, not a retry-until-success mechanism added to tests or CI.

## Native Artifact: observable mutation versus error precedence

The old `os.pread` hook first captured the original 120-byte synthetic ELF, then
changed byte 119 **without changing file length**, then returned the old buffer.
`Reader.hash()` therefore hashed the captured original bytes. `Reader.stable()`
compares inode/ownership/mode/size/link/timestamp metadata, not a second complete
content hash. The next descriptor reads feed the ELF parser. Offset 119 is the
high byte of the first PT_LOAD alignment; changing it to `x` makes the load
invalid. If the write changed the observed timestamps, stability rejected with
`file_changed`; if not, the parser rejected with `invalid_load`.

A disposable-file probe measured identical mtime_ns/ctime_ns and identical full
fingerprints across a same-size write, despite different file bytes. This explains
why the old test could not demand one rejection category on every filesystem.
It does not establish a new production error priority or imply acceptance of the
observed malformed artifact. No error regex was broadened and no reason changed.

The original test now explicitly captures a whole hash-read buffer and then grows
or shrinks the physical file. It asserts the changed size and requires the exact
`InvalidRuntime.reason == file_changed`. This deterministically exercises the
existing post-hash descriptor stability gate, without sleeping or depending on
clock progress. A separate regression feeds the original malformed alignment to
the unchanged parser and requires exactly `invalid_load`.

The existing positive read-only, hash mismatch, same-content pathname replacement,
metadata/capability, range/ELF and budget tests remain. A metadata fingerprint is
not continuous content attestation against an actor capable of making
metadata-indistinguishable edits or changing a file after observation. These
fixtures do not add such a guarantee, rehash a 384 MiB binary multiple times,
change the 528 MiB I/O cap, buffer an entire binary or admit native execution.
Candidate inspection remains offline; runtime admission/launch remain false.

## Notifications: precise CPython 3.12 / 3.13 contract

The rejection of replacing an `init=False` field is provided by dataclasses,
not a project exception wrapper. The upstream implementation raises ValueError
in [CPython 3.12](https://github.com/python/cpython/blob/v3.12.0/Lib/dataclasses.py#L1430)
and TypeError in [CPython 3.13](https://github.com/python/cpython/blob/v3.13.0/Lib/dataclasses.py#L1479).
The installed 3.13.5 implementation and actual failure confirm the latter.
Both refuse the same forbidden operation. Production TelegramRequest needs no
change and must not accept a caller-selected transport policy.

The test selects **one exact expected exception class** by interpreter version
(ValueError before 3.13; TypeError from 3.13), asserts its exact type and the
field-specific diagnostic, and verifies the original policy remains unchanged.
There is no broad exception tuple, generic Exception or permissive regex. The
supported-version evidence is 3.12 hosted CI and 3.13 local runs; this is not a
claim that every future Python implementation has already been tested.

Separate version-independent regressions verify all four protected fields
(origin, method, timeout, redirects) are non-init, rejected as constructor
arguments and frozen against assignment. A legitimate copy changing only chat_id
must retain the fixed policy and token-free body. Existing exact body/acknowledgment
checks remain; no network transport or credential support is added.

## Telegram replay: inject an actual change, refuse before write

The old Path.touch() assumed that mtime/ctime must advance. The disposable-file
probe observed neither advancing, with unchanged inode, size, ownership and bytes.
There is no distinguishable journal change in that input, so it cannot reliably
exercise the gateway's evidence drift refusal.

The journal case now creates a new private file **before** replacing replay.json.
That guarantees a distinct inode while preserving the bytes. The staging file
is outside the observed bot directory and is consumed by the rename: no unexpected
extra file can accidentally cause the intended refusal. The test asserts the
inode changed and still requires exactly NEEDS_HUMAN.

An additional case changes only a valid generation value with the exact writer's
encoding and unchanged byte length. It explicitly models unchanged mtime/ctime
for this fixture inode alone, retaining the other fingerprint fields and all
other objects' metadata checks. The test asserts the modeled fingerprint is
unchanged, proving that reloaded **data correlation**, rather than timestamp or
size drift, blocks the write. The lock-replacement case remains in place.
All cases prohibit any write_checkpoint call, require no pending marker and
verify the injected evidence is preserved, without repair, advancement or replay.
This model is test-local; production fingerprint and journal validation are
unchanged. Existing normal handling/replay and persistence-failure controls run too.

## Validation and boundaries

The delivery report records before/after full and targeted counts, all ten
post-fix repetition results, exact HEAD/base/tree, Python availability and fresh
hosted CI results. No xfail/skip, sleeps, arbitrary retries, system Python install,
uv.lock update or CI pin change was introduced. Remaining limitations include the
local absence of 3.12 and the stated metadata/privileged rollback trust boundaries;
a bounded successful sample is not proof against all possible concurrent edits.

LIVE_NO_GO, Gate #73 BLOCKED, SUBSCRIPTION_ISOLATION_BLOCKED, HOST_NOT_RUN for real
Publisher runtime, native/legacy exit 13 and human-only merge remain. Actual host
isolation and service/publishing tests are NOT_RUN. Source and disposable test
success never supply operational admission. No worker01/worker02 provisioning or
real personal home, session, journal, key or token was accessed.
