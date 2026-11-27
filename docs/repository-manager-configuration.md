# Repository Manager declarative configuration model (RM-02)

Status: **SOURCE_ONLY**, evidence ceiling **VERIFIED_OFFLINE** for the behavior covered by
`tests/test_repository_manager.py`. **NO_LIVE**, **HOST_NOT_RUN**. This document describes
source in `src/agent_platform/repository_manager.py`. It implements the first stage of
ADR 012 / AP-RM/0.1 ([repository-manager-architecture.md](repository-manager-architecture.md),
sections 5, 8, 9, 10, 11, 15, 17 and 18) and changes none of its decisions.

A record that validates here is **not authentication, not authorization**, not provider
support, not freshness, not deployment, not an approval, not enrollment approval and
**never admission**. Validation establishes structure and internal consistency only.

## What this is and is not

In scope: closed, versioned, offline records and validators for a profile, a repository
manifest, desired state, actual state, per-control results, owner/pre-creation pins,
existing-repository pins, post-creation binding, a compliance report and an enrollment
record, with fabricated fixtures. Manifest, desired state, snapshot, results and enrollment
are structurally bound to their target, to each other and to exact pins.

Not in scope (later stages or separate approval): provider or REST client, native REST
versus OpenTofu choice (RM-03), live inspection and result classification (RM-04), plan
and template rendering and leakage lint (RM-05), administrative writer, approval
authentication and intent journal (RM-06), apply (RM-07), the `agent-platform-control repo`
command and package integration (RM-08), disposable-repository validation (RM-09),
Control Plane admission evidence (RM-10) and drift handling (RM-11). The model has no
credential, token, App key or signer field of any kind.

## Records

All records are JSON objects with an exact `schema` discriminator. An unknown value is
`unsupported_schema`; the identifier of another record is `wrong_record`. (The schemas are
unreleased: the RP-01 repair changed their shape without a version bump.)

| Schema | Meaning |
| --- | --- |
| `AP-RM-PROFILE/1` | Profile: reusable, target-independent desired controls (policy baseline). |
| `AP-RM-MANIFEST/1` | Manifest: one repository's additional desired controls, bound to one target and one profile. |
| `AP-RM-DESIRED/1` | Desired state: explicit composition of one profile and one target-bound manifest; keeps the target. |
| `AP-RM-ACTUAL/1` | Actual state: one bounded snapshot bound to one desired state, with the full observed repository identity and an explicit scope. |
| `AP-RM-RESULT/1` | Per-control result bound by digest to one desired state and one snapshot, with structurally required evidence. |
| `AP-RM-PRECREATION/1` | Owner pins and creation intent before the repository exists (no repository ID). |
| `AP-RM-EXISTING/1` | Complete pins for an existing repository, optionally with the origin that links it to its creation intent. |
| `AP-RM-BINDING/1` | Post-creation binding linking one verified repository to one intent. |
| `AP-RM-COMPLIANCE/1` | Final structural compliance report that an enrollment references by digest. |
| `AP-RM-ENROLLMENT/1` | Private enrollment record (data only). |

Module API (all pure): `parse_profile`, `parse_manifest`, `parse_desired`, `parse_actual`,
`parse_result`, `parse_precreation`, `parse_existing`, `parse_binding`, `parse_compliance`,
`parse_enrollment` take `bytes` and return immutable dataclasses; `dumps` and `digest` give
deterministic canonical bytes and their SHA-256. Derivation and structural checks:
`creation_target`, `existing_target`, `verify_target`, `compose_desired`, `verify_desired`,
`verify_binding`, `verify_origin`, `verify_actual`, `verify_result`, `summarize`,
`build_compliance`, `verify_compliance`, `verify_enrollment` (full) and
`verify_enrollment_linkage_only` (partial, see Enrollment). Direct construction of any
record runs the same validators as parsing. There is no function that creates a binding,
adopts a repository, enrolls or admits.

## Control vocabulary (finite)

A control entry is `{"control", "blocking", "value"}`. `blocking` states whether a
non-compliant result of that control blocks the overall summary. The vocabulary is a
closed enumeration; there are no arbitrary settings, commands, hooks, provider routes
or interpolation. Arrays of controls are strictly ascending by control name.

| Control | Value | Notes |
| --- | --- | --- |
| `repo.allow_merge_commit` | boolean | Repository merge-method setting. |
| `repo.allow_squash_merge` | boolean | Repository merge-method setting. |
| `repo.allow_rebase_merge` | boolean | Repository merge-method setting. |
| `repo.allow_auto_merge` | boolean | Desired value `false` records the ADR baseline (auto-merge disabled). |
| `repo.delete_branch_on_merge` | boolean | Repository baseline setting. |
| `actions.allowed_actions` | one of `all`, `local_only`, `selected` | Actions permission policy. |
| `actions.default_token_permissions` | one of `read`, `write` | Default workflow token permission. |
| `actions.can_approve_pull_requests` | boolean | Whether workflows may approve pull requests. |
| `branch_protection.require_pull_request` | boolean | Protection of the default branch. |
| `branch_protection.required_approvals` | integer 0..6 | Required approving reviews (zero is allowed; see AP-SM/2). |
| `branch_protection.require_conversation_resolution` | boolean | Protection of the default branch. |
| `branch_protection.require_up_to_date_branch` | boolean | Protection of the default branch. |
| `branch_protection.require_linear_history` | boolean | Protection of the default branch. |
| `branch_protection.allow_force_pushes` | boolean | Protection of the default branch. |
| `branch_protection.allow_deletions` | boolean | Protection of the default branch. |
| `branch_protection.required_checks` | 1..8 pins `{name, app_id}`, strictly ascending by name; observed value may be empty | Required check name plus numeric App identity; a display name alone is never a pin. |
| `observe.collaborator_count` | integer 0..1000 | Expected count only; identity allow-lists are deferred (RM-04). |
| `observe.installed_app_count` | integer 0..1000 | Expected count only; identity allow-lists are deferred (RM-04). |
| `observe.deploy_key_count` | integer 0..1000 | Expected count only; identity allow-lists are deferred (RM-04). |

Intentionally deferred: required status check *strictness* details beyond name and App
ID, review dismissal and code-owner rules, ruleset-specific fields, per-collaborator or
per-App identity lists, secrets and variables. None is claimed as covered.

## Profile, manifest and desired state

- A profile is **target-independent** and holds at least one control. A manifest holds zero or
  more, names its profile (`profile_id`) and carries an explicit typed **target**.
- The target is one of two closed records:
  - `creation`: owner ID/login/type, intended name, visibility, default branch, the exact
    creation `intent_id` and the SHA-256 of the exact pre-creation record. It has no
    repository ID field, and the parser rejects any `id`, `repository_id` or `full_name`
    (`repository_id_in_precreation`).
  - `existing`: the complete repository pins (owner ID/login/type, repository ID, name, full
    name, visibility, default branch) and the SHA-256 of the exact existing-pins record.
- `creation_target(pre)` and `existing_target(pins)` derive a target from exact pins;
  `verify_target(target, pins)` requires the target to equal them. Mode confusion is
  `target_mismatch`; owner, name, visibility, branch, intent or digest differences have their
  own reasons (`owner_mismatch`, `repository_mismatch`, `intent_mismatch`, `digest_mismatch`, ...).
- Composition (`compose_desired(profile, manifest, pins)`) verifies the manifest target against
  the supplied pins (so the pins are required context), requires the manifest to name exactly
  the supplied profile (`unresolved_reference`) and the two control sets to be disjoint
  (`overlapping_control`), and **preserves the target** in the desired state. A manifest or
  desired state therefore cannot be moved to another repository, owner or creation intent
  without detection: the target participates in the desired-state digest that snapshots and
  results are bound to.
- Desired state must contain at least one blocking control (`no_blocking_control`) and must
  not be contradictory: all three merge methods disabled, or a positive required approval
  count with the pull-request requirement disabled, is `inconsistent_controls`.
- Desired state comes only from an explicit validated profile and manifest, never from an
  observation or the target repository. `verify_desired` recomputes the composition.

## Identity pins

All identities are checked on numeric ID **and** exact name; the provider is `github`.

- **Pre-creation** (`AP-RM-PRECREATION/1`): owner numeric ID, login and type
  (`Organization` or `User`), intended name, visibility, default branch, administrative
  scope (must include `create_repository`), an opaque authorization reference and a
  32-hex creation intent identifier. A repository ID is never accepted, not even as
  `null`: `repository_id_in_precreation`.
- **Existing** (`AP-RM-EXISTING/1`): the full pin set including the repository ID from the
  start; the administrative scope must not include `create_repository`. The required `origin`
  field is `null` for a repository that was merely designated, or an object holding the
  `intent_id`, the SHA-256 of the pre-creation record and the SHA-256 of the binding when the
  repository was created by Repository Manager.
- **Post-creation binding** (`AP-RM-BINDING/1`): positive repository ID, full name,
  visibility and default branch, the exact intent identifier and the SHA-256 of the
  pre-creation record. `verify_binding` rejects owner, name, visibility, branch, intent
  or digest substitution. The binding records an *independent read-back* reference
  (`observation.kind` is fixed to `independent_read`) that must differ from the creation
  effect reference, so a create-response echo does not satisfy the structure
  (`binding_provenance`). `verify_binding` checks consistency only: it does not show
  that creation or a read-back happened. A binding is never created or adopted by the
  model, and a rename or transfer requires fresh operator pins.
- **Reconciliation keeps the intent**: `verify_origin(pins, pre, binding)` requires the
  existing pins' `origin` to equal the exact intent, pre-creation digest and binding digest,
  the binding to verify against the pre-creation record, and the pins' repository to equal the
  bound repository (`origin_mismatch`, or the specific mismatch reason). Because a target's
  `pins_sha256` covers the pins including `origin`, a post-creation manifest and desired state
  keep this relationship.

## Actual state and per-control results

Actual state (`AP-RM-ACTUAL/1`) is one **snapshot**. It carries the **observed repository identity**
(owner ID/login/type, repository ID, name, full name, **visibility and default branch**), the
SHA-256 of the exact desired state it was gathered for, a provenance label (`provider_read`,
`operator_reported`, `synthetic_fixture`; a label, not authentication), a source reference and
an observation time, an explicit `scope` (the expected control set) and a `complete` flag. There
is no implicit time-to-live; transition-local freshness is a later concern (RM-04 and later).

**Observed identity.** Visibility and default branch are observed values, not copies of the
expected pins. Either may be unobserved (`null`) only together with one closed
`unavailable_reason`; an identity with a reason and nothing missing, or missing values without a
reason, is rejected. `verify_actual` compares every observed part with the exact desired target
(`owner_mismatch`, `repository_mismatch`, `visibility_mismatch`, `branch_mismatch`); an unobserved
part is accepted structurally but makes the snapshot incomplete.

**Observations** have exactly three states:

- `observed`: a typed value;
- `unavailable`: one closed reason (`conflicting_observations`, `http_403_ambiguous`, `http_404_ambiguous`, `incomplete_observation`, `incomplete_pagination`, `not_observed`, `permission_missing`, `rate_limited`, `server_error`, `transport_error`); there is no value, and an empty
  required-check list is a distinct, valid observed value;
- `unsupported`: no value and no reason, but the observation itself carries the **limitation
  evidence** (below). This is the only representation of an affirmatively established
  limitation. An ambiguous or failed read (ambiguous 403/404, missing permission, rate limit,
  incomplete pagination or observation, transport or server error) and a conflicting read
  stay `unavailable` and can never become `unsupported`.

Limitation evidence names its control and its repository ID, an endpoint, a pinned
documentation reference and version, separate visibility and plan reads, an observation time and
at least two further distinct corroboration references; all references are independent, and a
provider message alone has no field. It cannot be moved to another control (`evidence_mismatch`)
or repository (`snapshot_mismatch`), and a result must carry exactly the evidence of the
observation it classifies.

Completeness is explicit and exactly verifiable:

- there is exactly one observation per scoped control, in ascending order
  (`scope_mismatch`, `duplicate_control`);
- `complete` is true **if and only if** the identity was fully observed and every scoped
  observation is `observed` (`completeness_mismatch`); an `unsupported` observation is therefore
  never complete;
- `verify_actual(actual, desired)` requires the snapshot to carry the digest of that desired
  state (`snapshot_mismatch`), to describe exactly the repository of the desired state's
  `existing` target (a creation target has no repository to observe, `target_mismatch`) and to
  have a scope equal to the desired controls (`scope_mismatch`). A snapshot with one control is
  therefore never "complete" for a larger desired state.

The per-control result set is exactly `COMPLIANT`, `NONCOMPLIANT`, `UNSUPPORTED`,
`UNVERIFIED` and `CONTRADICTORY`. A result carries the SHA-256 of the desired state and of
the snapshot it belongs to, plus structurally required evidence:

| Result | Required evidence | Required observation |
| --- | --- | --- |
| `COMPLIANT` | `observed_match`: desired and observed values, equal | `observed`, same value |
| `NONCOMPLIANT` | `observed_difference`: desired and observed values, different | `observed`, same value |
| `UNVERIFIED` | `unavailable`: one closed reason | `unavailable`, same reason |
| `UNSUPPORTED` | `affirmative_limitation`: the limitation evidence above | `unsupported`, carrying exactly this evidence |
| `CONTRADICTORY` | `conflicting_observations`: at least two distinct references with different values | `unavailable` with `conflicting_observations` |

`verify_result(result, desired, actual)` additionally requires the result digests to equal
the supplied desired state and snapshot (`snapshot_mismatch`: no cross-repository,
cross-desired-state or cross-snapshot substitution), the control and its blocking flag to
exist in the desired state (`coverage_mismatch`), the desired value in the evidence to be the
desired state's value, and the evidence to agree with the corresponding observation
(`evidence_mismatch`). Attaching syntactically valid limitation evidence to an ambiguous,
failed, incomplete or conflicting observation is `evidence_mismatch`.

`summarize(desired, actual, results)` is a purely structural aggregate and takes the full
context; there is no results-only conclusion. It verifies the snapshot, requires exactly one
verified result for every blocking desired control (`coverage_mismatch`,
`duplicate_result`), and returns the most severe blocking result (`CONTRADICTORY`,
`UNVERIFIED`, `UNSUPPORTED`, `NONCOMPLIANT`, then `COMPLIANT`). A snapshot that is not complete
(an unavailable or unsupported observation, or an incompletely observed identity) is never
reported as `COMPLIANT` overall: the summary is then at best `UNVERIFIED`. It asserts neither
freshness nor authenticity, and the provider observation and classification engine is not part
of RM-02.

## Enrollment

`AP-RM-ENROLLMENT/1` is a separate private data record: the complete repository identity
including visibility and default branch, an evidence reference with its SHA-256, and a
separate operator decision reference and time. The decision reference must differ from the
evidence reference (`not_independent`). Authority-looking fields (admission, approval,
authorization, publication, merge, execution, permissions, credentials, token, secret) are
rejected as `authority_field`.

The evidence is a compliance report (`AP-RM-COMPLIANCE/1`): the full repository identity, the
digests of the desired state and the snapshot, the overall result, an evidence reference and the
sorted digests of the verified per-control results. `build_compliance` derives it only from a
fully verified desired-state, snapshot and results context; `verify_compliance` recomputes it
and rejects any report that is not exactly the derived one (`evidence_mismatch`).

`verify_enrollment(enrollment, report, pins, desired, actual, results)` is the full check; the
whole context is required and cannot be omitted (a missing argument is a `TypeError`, a wrong
type is `bad_type`). It runs, in this order:

1. the desired state's target equals the exact supplied `ExistingPins`, including the pins
   digest (`repository_mismatch`, `digest_mismatch` for any changed authorization reference,
   scope or origin, `target_mismatch` for a creation target);
2. the report is recomputed from desired state, snapshot and results, which verifies the
   snapshot (digest, repository, observed identity, scope, completeness) and every result;
   an arbitrary result digest, a forged overall result or a report for another desired state or
   snapshot is `evidence_mismatch` or `snapshot_mismatch`;
3. the linkage: the enrollment's evidence reference equals the report's (`evidence_mismatch`),
   its evidence digest equals the digest of that exact report (`digest_mismatch`), owner,
   repository ID, name, visibility and default branch agree across enrollment, report and pins
   (`owner_mismatch`, `repository_mismatch`, `visibility_mismatch`, `branch_mismatch`), the report
   is `COMPLIANT` (`evidence_not_compliant`), and the decision reference is distinct from the
   evidence reference and the plan authorization reference (`not_independent`).

`verify_enrollment_linkage_only(enrollment, report, pins)` is retained for unit-level coverage
of step 3 only. It is **not sufficient** and must not stand in for `verify_enrollment`: a forged
report whose fields are individually valid can pass it.

**It does not establish**: that the operator actually decided or consented (references and
digests are data), that the snapshot or the report is authentic or fresh, that the results are
true statements about the provider, or anything about admission. Offline structural
consistency is not authentication. Enrollment is not admission, compliance evidence is not
authorization, and nothing in the module creates an enrollment, approves one or admits a
project. The signed evidence envelope (RM-10) and persistence are out of scope.

## Parsing, limits and diagnostics

- Input is exact `bytes` (not text, `bytearray` or `memoryview`), at most 65536 bytes,
  strict UTF-8 without a byte-order mark, strict JSON, depth at most 8, arrays at most 64.
- Duplicate object members at any depth, `NaN`, `Infinity`, floats, integers longer than
  17 digits, booleans where integers are required, unknown or missing fields, wrong
  types, unsupported versions, unsorted or duplicated lists and invalid identifiers,
  digests and timestamps (`YYYY-MM-DDTHH:MM:SSZ`) fail closed. There is no coercion,
  normalization, permissive fallback or silent dropping of unknown fields.
- Identifiers use fixed ASCII patterns; strings that start with a well-known GitHub token
  prefix or an access-key prefix are rejected as a best-effort guard. This is not secret
  detection (U9 and RM-05).
- Errors are `RepositoryManagerError` with a stable `reason` and a schema-defined
  `where`. They never contain untrusted values, and internal parser errors are not
  chained to them.
- Canonical serialization (`dumps`) sorts keys, uses compact separators and ASCII, with no
  trailing newline. It is a deterministic encoding of one record, not a plan digest or an
  approval artifact.

## Reason codes

- `authority_field`
- `bad_digest`
- `bad_identifier`
- `bad_json`
- `bad_range`
- `bad_timestamp`
- `bad_type`
- `bad_utf8`
- `bad_value`
- `binding_provenance`
- `branch_mismatch`
- `completeness_mismatch`
- `coverage_mismatch`
- `desired_mismatch`
- `digest_mismatch`
- `duplicate_control`
- `duplicate_key`
- `duplicate_result`
- `evidence_mismatch`
- `evidence_not_compliant`
- `identity_inconsistent`
- `inconsistent_controls`
- `intent_mismatch`
- `invalid_evidence`
- `missing_field`
- `name_mismatch`
- `no_blocking_control`
- `nonfinite_number`
- `not_bytes`
- `not_independent`
- `not_object`
- `not_sorted`
- `origin_mismatch`
- `overlapping_control`
- `owner_mismatch`
- `repository_id_in_precreation`
- `repository_mismatch`
- `scope_mismatch`
- `snapshot_mismatch`
- `target_mismatch`
- `too_deep`
- `too_large`
- `too_many_items`
- `unknown_control`
- `unknown_field`
- `unresolved_reference`
- `unsupported_schema`
- `visibility_mismatch`
- `wrong_record`

## Public source and private configuration

The model reads only bytes supplied by the caller. It has no path, no environment or home
default, no auto-discovery and no loader for configuration stored in a target repository.
The private store (form, location, integrity and custody: U2) stays unresolved. Public
fixtures use fabricated values only (`fictional-` owners, `fixture-` references, fixed
numeric IDs). Leakage detection of real identities in templates is U9 and RM-05.

## Package and runtime boundary

The module is **SOURCE_ONLY**: it is listed in `SOURCE_ONLY` in `packaging/build_deb.py`
only, not in any role module allowlist, publisher module list, command, entry point or
dependency, and no runtime, worker, Publisher, admission, custody or signer module imports
it. It has no Debian presence before the reviewed RM-08 amendment, which will place the
command in `agent-platform-control` only, never in the worker package.

## Unresolved decisions (ADR 012 section 18) not settled here

U1 (command names), U1a (principals and state), U2 (private store), U3 (credential
delivery), U4 (native REST versus OpenTofu), U5 (creation credential and bootstrap
authorization), U6 (journal), U7 (provider plan constraints), U8 (evidence envelope),
U9 (leakage detection) and U10 (gate relationships) are untouched. Field names, the
control vocabulary and the administrative scope tokens are provisional source schema
decisions open to review, not a wire format commitment.

## Verification

Offline tests cover valid fabricated creation and existing-repository scenarios with
round trips, adversarial inputs for every record and nested field, identity substitution,
pre/post confusion, unavailable versus empty observations, unsupported results without
evidence, contradictory records, manifest and desired-state substitution between
repositories, owners and creation intents, results from another repository, desired state
or snapshot, compliant results against unavailable or incomplete observations, partial
snapshots declared complete, UNSUPPORTED against every ambiguous or failed observation,
limitation evidence moved between controls, repositories and snapshots, observed identity with
changed or missing visibility and default branch, forged compliance reports with arbitrary
result digests, changed exact pins, substituted enrollment evidence, enrollment and
admission separation, absence of file,
network, process and environment access in the model paths, and the package exclusions.
Hosted CI, host installation and any live GitHub operation are NOT_RUN.
