# Offline release input observation and operator boundary prototype

Use reviewed observer code from a separate trusted checkout. Select the
canonical repository and clean isolated source checkout out of band. The
repository label in the report is a scope constant. Remote identity and
operator authority require independent provisioning.

The observer reads HEAD and the index and uses a scratch bare Git directory
with a fixed environment and the local object store. It hashes commit and
tree objects directly, checks exported blob IDs and modes, compares the index
and working files with the export, and rejects alternate stores, aliases,
submodules and drift. The complete regular-file inventory binds all consumed
inputs conservatively, including inputs unused by a particular role. The
builder, final recipe and encoder have separate digests. No inspected source
is executed.

Local Debian 13 amd64 observations record fixed tool versions and executable
hashes and a digest of the dpkg inventory. Image origin is UNKNOWN. The fixed
PKG-11 pin binds the historical commit, tree, epoch and recipe. The observer
hashes both existing historical archives and requires their entire byte hashes
to match that pin. This Issue performs no reconstruction or package build.
The collector repeats its observations before returning an immutable tuple of
canonical byte records.

A disposable supervisor selects the operator and observer UIDs, fixed
one-shot output slot, fresh challenge and expiry. It provides a connected Unix
SEQPACKET endpoint. The kernel peer credentials and message credentials must
match PID, UID and GID. The separate client choice is OBSERVE followed by the
digest of the complete observation, release key, both roles, challenge and
expiry. JSON and proposed approval flags cannot serve as that choice.
A completed fixture still reports BLOCKED and authority NOT_CONFIGURED.
The fixed slot uses exclusive creation and the existing UNKNOWN-before-write
protocol. A replay or an interrupted write requires reconciliation. The
fixture models the observer UID in tests. Two distinct real principals are
NOT_RUN in this environment.

The calling supervisor and its clock, challenge and observation routing are
fixture assumptions. Production custody host, authenticated human identity
mapping, authorization channel and protected durable freeze history remain
NOT_CONFIGURED. The next implementation should provision and independently
test that boundary and durable version continuity before considering an
encoder integration. Actual final-bit generation and lifecycle, independent
byte review, separate publication decision, immutable distribution and
per-host backup and installation are NOT_IMPLEMENTED in this path.
Production generate and exit 13 retain their unconditional denial.

The fixture records the bound tuple and choice as UNVERIFIED_CALLER_FIXTURE.
A Python Observation value has no attestation of its origin. The binding
includes the supervisor-selected slot path to reject a packet replayed into
another slot. This fixture does not maintain a global challenge registry.
Machine reports explicitly carry REPOSITORY_IDENTITY_NOT_ATTESTED and
IMAGE_PROVENANCE_UNKNOWN until separately established by a custodian.
