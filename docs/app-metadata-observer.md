# AP-AM/1 — metadata observer boundary (MVP.8c)

Issue #74 adds `app_metadata`, a live-response-capable **contract**, implemented
and tested offline only. It supplies neither a network client nor a credential
issuer, signing helper, CLI, service or enabled live entrypoint. No operator
probe is run by this Issue. AP-CI/1 remains synthetic-only, byte-for-byte unchanged;
AP-CA/1's future writer profile is not satisfied by Metadata read permission.

## Trust model and types

The operator independently chooses exact target/App pins. Trusted custody owns
keys, signing and token lifecycle. A trusted collector consumes authenticated
transport observations. Codex/worktrees are untrusted and receive neither
credentials nor privileged clients. A future branch/PR publisher remains a
separate, unimplemented authority boundary. A source AP-SM/2 review or Issue prose
cannot grant downstream authority or credential use. Independent operator inputs,
not repository JSON, model output or labels, construct these typed values.

`Pins` reuses #59 AppIdentity, #62 InstallationIdentity, Principal and existing
repository/digest validators. It pins registration organization separately from
installation account, repository ID/name/default branch, expected Bot profile
ID/login and exactly `(("metadata", "read"),)`. Write or extra permission profiles
are rejected, not automatically requested. Other operator-approved organizations
and repositories are possible; no organizational ID is hardcoded in the module.
A configured AppIdentity.bot is an expected profile, not proven attribution.
No CodexAssignment, reviewer receipt, TargetProject, queue claim or authorization
is synthesized from metadata.

`Observation` pins a challenge, custody-source correlation ID, explicit evidence
source (offline HTTP fixture or external trusted transport), <=300-second lifetime,
complete bounded retained challenge history, optional assignment digest reference
and optional public Bot lookup. An independently supplied expected assignment
reference must agree. Digests/source enums are correlation and classification,
not signatures, authenticated approval or trust establishment. Complete history
must come from the trusted controller, never from a caller-selected target subset.
This pure API neither consumes challenges durably nor evicts/reconstructs history.
Missing continuity blocks; two stable reads are not durable single-agent claims.

## Endpoint and evidence map

| Fixed GET | Credential domain | Evidence category / limit |
| --- | --- | --- |
| `/app` | App JWT, external custody | `authenticated_application_and_installation_metadata`: actual App ID/slug/registration org, exact grants/events |
| `/app/installations/{pinned id}` | App JWT, external custody | Same category: App association, installation/account/target IDs/types, selected mode, permissions/events, no suspension |
| `/installation/repositories?per_page=100` | Installation-wide installation token | `authenticated_installation_repository_scope`: one complete page, exactly one numeric repo ID/name/owner/default branch; total_count=1, no Link, duplicates or extra repos |
| `/users/{escaped pinned Bot login}` (optional) | Public, no authorization credential | `observed_public_bot_profile`: actual profile ID/login/type=Bot only |
| No action endpoint in this contract | None | `app_attributed_bot_action=NOT_OBSERVED` always |

The first two category names describe the **external adapter's authenticated
provenance obligation**. On offline fixtures they remain explicitly classified
`OFFLINE_HTTP_FIXTURE`, not live authenticated evidence. `EXTERNAL_TRUSTED_TRANSPORT`
is likewise not proof of authentication by itself. A later adapter must actually
verify TLS and credential provenance and be independently approved. HTTP 200 from
a public repository or Bot profile proves neither possession of App credentials
nor an App-associated action. No flag/hash can upgrade these facts to publication
authority. Even a stray performed_via_github_app field on a user profile is ignored:
this contract does not inspect an authenticated action resource.

The endpoint contracts are documented by GitHub's
[App API](https://docs.github.com/en/rest/apps/apps),
[installation API](https://docs.github.com/en/rest/apps/installations) and
[user API](https://docs.github.com/en/rest/users/users#get-a-user).
API fields establish only their documented facts. Token issuer, installation-wide
issuance, absence of narrowed repository/permission restrictions, JWT/token kind,
expiry and credential-source identity are **separate trusted custody assertions**.
These GETs cannot introspect a token or prove those assertions. Without independently
verified custody, installation enumeration could hide extra installed repositories
behind a narrowed token, and no live scope assurance may be claimed.

## Transport bounds and lifecycle

`Transport` is an injected Protocol with one GET method. Requests fix
`https://api.github.com`, HTTPS/TLS verification, no redirects/proxies/environment
proxy settings, exact paths/auth kinds/query and per-pass binding/source/lease
correlation. Responses separate raw GitHub-shaped JSON from adapter assertions
about TLS, origin, redirects/proxy use and the actual authenticated request.
There is no arbitrary URL, headers/token field, HTTP method or route option.
The optional repository-installation endpoint is deliberately not implemented.

Each of two sequential complete observations uses a distinct lease and distinct
pass-bound digest. Normalized facts must match exactly, with no split-read or
old-request substitution. Every request has <=5-second timeout, <=64 KiB decoded
body, UTF-8 strict JSON, duplicate/nonfinite-key rejection and fixed route count
(maximum eight GETs overall). No Link is followed, no retries occur, and unknown
status/route/auth/provenance/body/owner/scope/grant facts block. Unneeded API fields
are discarded; hashes cover only normalized nonsecret facts and custody metadata.
Wall/monotonic clocks must advance consistently; rollback, >2-second divergence,
expired evidence or >30-second collection budget blocks the artifact.

`Custody` is a **separate interface**, not a GET-only fiction about token lifecycle.
GitHub issuance requires `POST /app/installations/{id}/access_tokens`; revocation
uses `DELETE /installation/token`. Neither endpoint is implemented/executable here.
The future external custodian implements `acquire(pins, pass_binding, timeout)` and
`revoke(lease, timeout)`, retaining credential material entirely outside this API.
Lease contains only nonsecret correlation, issuer/install/source/binding, kind,
installation-wide/unrestricted-grant assertions and bounded JWT/token lifetimes.
No raw PEM path, JWT, bearer token or Authorization header enters these types.

Acquire is single-use per pass. It must own cleanup/reconciliation of partial or
uncertain issuance **even if it raises before returning a lease**; this library
cannot revoke an unknown credential. Once any lease is returned, finally always
attempts revocation, including on malformed lease, HTTP, clock or evidence failure.
Revocation must return confirmed true; exceptions/false/timeout produce BLOCKED
with cleanup UNKNOWN and no partial fact artifact. Failure after confirmed cleanup
still BLOCKS. Mandatory emergency revocation retains a separate <=5-second cleanup
budget even after the read budget fails; it is not a read retry. A future adapter
must enforce hard I/O deadlines/stream caps. Same-process callbacks and response
booleans cannot isolate malicious code or physically interrupt a noncooperating
implementation. This is a trusted-component contract, not a new sandbox or proof
of exactly-once issuance/revocation. Durable issuance uncertainty is its custodian's
duty, and must not be repaired by blind retries or rotation.

## Result and safety limits

Frozen versioned results contain exact Pins/Observation, observation time/expiry,
normalized Facts, two matching evidence digests and distinct custody digests only
on success. Facts retain registration/installation ownership separately, selected
mode, unsuspended status, grants and optional public profile. Success is exactly
`METADATA_ONLY_BOT_ATTRIBUTION_UNVERIFIED`, never AP-CI/1's
`VERIFIED_OFFLINE_FIXTURE`, live VERIFIED or a launch receipt. Failure is BLOCKED
with one fixed redacted diagnostic and cleanup state; no partial facts, raw error,
response/header or secret escapes. Expiry is bounded by the observation and both
leases' JWT/token expiry. Revocation does not make this a reusable credential.

Every outcome has reserved/prepare/launch/resume/publish false, App-attributed
action NOT_OBSERVED and runtime exit code 13. No result is accepted into AP-CA/1
advice, #49 collector, #59 COMMENT publisher, #62 review approval, AP-CH/1 or queue
as authority. All existing contracts and UNKNOWN-before-POST behavior remain.
No automatic permission upgrade, Ready, Issue closure, merge, paid API fallback,
worker, live publication or operational activity is introduced. Human alone merges.

## Operator handoff — subsequent approval and implementation required

Operator milestone facts and open risks are recorded in
[coding-app-gate-b.md](coding-app-gate-b.md#operator-reported-mvp8b-milestone-and-mvp8c).
They are reported observations, not independently repeated by Codex or a permanent
allowlist. The next human-controlled steps are:

1. Independently review and merge this offline contract, then separately authorize
   a trusted-host adapter design and scoped read-only run. Reconfirm exact target,
   App/installation pins, metadata-only grants, current selected membership and
   current effective governance before contemplating any future write scope.
2. Review fixed-name systemd `LoadCredential=` custody: root retains the PEM and
   passes only an approved named credential to a separately confined signing
   component. Do not grant publisherapp direct source-PEM access or accept arbitrary
   paths/credential names from requests. The collector/worker must not receive
   that credential directory, signing key, token or a generic signing interface.
   No unit file, raw-PEM loader, SSH command, provisioning or deployment is supplied.
3. Verify the physical host, confinement/IPC, exact JWT issuer/time claims,
   unrestricted installation-wide token issuance, no proxy/redirect paths, hard
   deadlines, partial-issuance reconciliation and confirmed finally-revocation.
   Verify post-reboot permissions, custody availability and no automatic worker
   launch. Backup of VM 102 was deferred; explicitly decide credential-loss
   recovery/rotation and retain that risk before activation. Do not assume
   publisher01's full production security from its successful manual probe.
4. Under separate explicit approval, execute only that reviewed read-only adapter
   on the trusted host and record sanitized source/times/pins/digests, actual
   custody assurance and revocation result. Stop on mismatch, expired evidence,
   missing history, cleanup uncertainty or insufficient trust; never retry blindly.
5. Keep metadata and public Bot profile distinct from App-attributed author proof.
   Metadata-only grants cannot create an App-authored Issue comment. Do not upgrade
   permissions or bootstrap an action to satisfy AP-CI/1. Future write/publisher
   scope, actual PR author evidence, native isolation, authenticated exact-payload
   approval and durable claims require separately reviewed human-authorized work.
