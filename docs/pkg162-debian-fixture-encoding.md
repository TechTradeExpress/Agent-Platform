# Issue #162 — offline Debian byte rehearsal

The test entry point `final_recipe.rehearse_debian` accepts the same fabricated
source, history, environment and historical observations as PKG-13, plus a
SHA-256 pin of the local encoder. It runs the existing synthetic admission,
closed staging and inspection before encoding. The encoder works from staged
files and modes, without invoking a package builder or consuming any existing
candidate or CI_ONLY archive.

The fixture packages use the separate names `ap-pkg162-fixture-control` and
`ap-pkg162-fixture-worker` at `0.0.0-162`. The encoder binds the test identity
in control and embedded provenance, updates manifest hashes and Debian md5sums,
and emits a deterministic ar with gzip-compressed USTAR members. Provenance
records the fabricated source, tree, epoch, inputs and tool observations used
by staging. The encoder compares two byte passes, parses the result against
the expected file bytes, ownership, modes and timestamps, then records the
resulting archive hashes. Fixture tool observations are synthetic. A separate
test calls real dpkg-deb inspection commands.

Use fresh private temporary scratch only. Existing content blocks reuse.
The staged rehearsal remains on a failed encoding attempt. Evidence writing
uses exclusive paths and records UNKNOWN before writing archives. Failures
leave that evidence for reconciliation. Tests keep archives in their temporary
fixture directory and the review bundle includes source and logs only.

`generate()` and the production CLI still refuse unconditionally. The existing
candidate, CI_ONLY and historical recipes retain their separate paths.

Remaining work:

1. Implement an independently reviewed authenticated operator decision before
   generation, binding source, recipe, dependencies and environment.
2. Implement independent durable freeze history and recovery. Missing or
   uncertain continuity must block.
3. Design trusted custody and signing separately from generation.
4. Independently review actual final bytes and require separate publication
   approval for the exact reviewed result.
5. Require separately approved backup, reconciliation and installation per host.

These functions are NOT_IMPLEMENTED. HOST_NOT_RUN, LIVE_NO_GO, Gate #73 and
subscription exit 13 remain applicable.
