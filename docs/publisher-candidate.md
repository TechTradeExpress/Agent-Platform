# CP-03 offline canonical candidate verifier — AP-PC/1

`publisher_candidate.verify(Candidate, Policy)` is a pure Python API. It imports
only hashlib, json, re and dataclasses. It never invokes Git, shell, network,
credentials, hooks, filters, worktree reads or writes. No CLI/runtime integration
is provided. Native SUBSCRIPTION_ISOLATION_BLOCKED and exit 13 are unchanged.

Candidate, GitObject, Policy and Result are frozen slotted contracts containing
bytes, scalars and tuples. Policy comes separately from the trusted caller;
there is no policy loader. Frozen objects do not authenticate that caller.
Candidate data, commit identities, hashes, model assertions and checkpoints are
never operator authorization or trusted test receipts. No existing publisher,
collector, review policy or target-project API is modified or bridged.

The UTF-8 JSON descriptor has exactly these fields (unknown/duplicate keys at
any depth block): version=`AP-PC/1`, repo_id, repository, issue, issue_id,
scope (64 lowercase SHA-256 hex characters identifying caller scope), base_sha,
operation (`create` or `update`), feature_ref, expected_old (`ABSENT` or full SHA),
commit, tree, object_format=`sha1`, inventory. Each inventory element has exactly
path, mode, oid. Identity, scope, base, operation, expected_old and ref must match
Policy. Policy pins the complete resulting path set and explicitly allowed
executable paths. Inventory is the complete tree, not a delta or claimed diff.

GitObject supplies an oid and uncompressed canonical bytes:
`type SP decimal-payload-length NUL payload`. The API recomputes SHA-1 over all
these bytes, rejects noncanonical size headers and checks exact payload length.
Only blob/tree/commit and full lowercase 40-character IDs are supported. The
inventory must contain exactly the referenced blobs, one tree and one commit,
without duplicate or unreachable objects. Shared identical blobs are permitted.
Trees are independently reconstructed and compared byte for byte, including
Git mode/name/NUL/raw 20-byte SHA entries in byte-sorted order.

This deliberately limited profile supports only nonempty, flat ASCII trees:
1–128 filenames, each <=128 characters, starting alphanumeric, followed by
alphanumeric, dot, underscore or hyphen. Dot/traversal, separators, Unicode,
control characters, trailing dots/spaces, DOS device aliases, lock suffixes,
Git metadata and casefold collisions are rejected. Nested trees, empty trees,
symlinks, submodules and all modes except 100644 and explicitly pinned 100755
are unsupported. This is conservative rejection, not a general Git parser.

Commits have exactly ordered tree, one parent, author, committer headers and
one printable ASCII message line (1–200 characters plus LF). Identity fields
follow the module's restricted ASCII grammar; timestamps are unsigned decimal
with at most 12 digits, offsets use the restricted numeric grammar. No signature,
encoding, extra parent/header, continuation or arbitrary message format is
accepted. Author/committer text proves no human or App identity. Creation requires
expected_old=ABSENT and parent=approved base. This is a requested precondition,
not observation that a remote ref is absent. Updates require a caller-pinned old
SHA and exactly that parent, then always return BLOCKED/remote_update_unverified.
No local result proves current remote base ancestry, fast-forward or atomic CAS.
Even supplying candidate claims of remote verification is rejected as unknown
fields. A future remote protocol requires separate design and authorization.

Limits: descriptor <=16 KiB, each canonical object <=256 KiB, descriptor plus
all canonical object bytes <=1 MiB, <=130 objects and <=128 paths. Limits are
checked before JSON/object parsing; truncation blocks rather than partial success.
Caller policy is trusted bounded configuration, not part of candidate byte budget.

Results are immutable AP-PC/1 with status VERIFIED_OFFLINE_FIXTURE/code verified
or BLOCKED and a fixed code from module CODES. Diagnostics contain no supplied
paths, text or exceptions. Every result has init-disabled publish_authorized=false.
Success proves synthetic byte consistency only. It supplies no approval, admission,
remote reservation, independent review, test receipt, replay protection or writer.
No upload, ref write, Draft PR, retry, journal, credential or paid inference occurs.
CP-02, AP-TP/1, UNKNOWN-before-write and all live NO-GO gates remain independent.

Tests build objects deterministically in memory; no real GitHub or production
worktree is used. They cover malformed objects/descriptors, identity/scope/ref
mismatches, modes/paths, limits, merges and blocked updates. Offline PASS is not
live publication or production isolation evidence.
