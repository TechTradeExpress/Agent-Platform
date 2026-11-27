"""RM-02: closed offline Repository Manager configuration model (source-only).

Pure data and validation: no I/O, no network, no subprocess, no credentials, no
discovery of configuration. A record that validates here is *not* authenticated,
fresh, authorized, enrolled or admitted evidence. See
docs/repository-manager-configuration.md.
"""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

PROFILE = "AP-RM-PROFILE/1"
MANIFEST = "AP-RM-MANIFEST/1"
DESIRED = "AP-RM-DESIRED/1"
ACTUAL = "AP-RM-ACTUAL/1"
RESULT = "AP-RM-RESULT/1"
PRECREATION = "AP-RM-PRECREATION/1"
EXISTING = "AP-RM-EXISTING/1"
BINDING = "AP-RM-BINDING/1"
ENROLLMENT = "AP-RM-ENROLLMENT/1"
COMPLIANCE = "AP-RM-COMPLIANCE/1"
SCHEMAS = frozenset(
    {
        PROFILE,
        MANIFEST,
        DESIRED,
        ACTUAL,
        RESULT,
        PRECREATION,
        EXISTING,
        BINDING,
        ENROLLMENT,
        COMPLIANCE,
    }
)

MAX_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_ITEMS = 64
MAX_ID = 2**53 - 1
MAX_CHECKS = 8

REASONS = frozenset(
    """not_bytes too_large bad_utf8 bad_json duplicate_key nonfinite_number too_deep
    too_many_items not_object unknown_field missing_field bad_type bad_value
    bad_range bad_identifier bad_digest bad_timestamp unsupported_schema
    wrong_record unknown_control duplicate_control not_sorted unresolved_reference
    overlapping_control inconsistent_controls no_blocking_control
    repository_id_in_precreation identity_inconsistent intent_mismatch
    owner_mismatch name_mismatch visibility_mismatch branch_mismatch
    digest_mismatch repository_mismatch binding_provenance invalid_evidence
    evidence_mismatch not_independent coverage_mismatch duplicate_result
    desired_mismatch authority_field target_mismatch origin_mismatch
    snapshot_mismatch scope_mismatch completeness_mismatch
    evidence_not_compliant""".split()
)


class RepositoryManagerError(Exception):
    """Stable reason code plus a schema-defined location; never untrusted input."""

    def __init__(self, reason, where=""):
        self.reason = reason
        self.where = where
        super().__init__(f"{reason}:{where}" if where else reason)


def _fail(reason, where=""):
    if reason not in REASONS:  # pragma: no cover - programming error
        raise AssertionError(reason)
    raise RepositoryManagerError(reason, where)


class Control(StrEnum):
    REPO_ALLOW_MERGE_COMMIT = "repo.allow_merge_commit"
    REPO_ALLOW_SQUASH_MERGE = "repo.allow_squash_merge"
    REPO_ALLOW_REBASE_MERGE = "repo.allow_rebase_merge"
    REPO_ALLOW_AUTO_MERGE = "repo.allow_auto_merge"
    REPO_DELETE_BRANCH_ON_MERGE = "repo.delete_branch_on_merge"
    ACTIONS_ALLOWED_ACTIONS = "actions.allowed_actions"
    ACTIONS_DEFAULT_TOKEN_PERMISSIONS = "actions.default_token_permissions"
    ACTIONS_CAN_APPROVE_PULL_REQUESTS = "actions.can_approve_pull_requests"
    BRANCH_REQUIRE_PULL_REQUEST = "branch_protection.require_pull_request"
    BRANCH_REQUIRED_APPROVALS = "branch_protection.required_approvals"
    BRANCH_REQUIRE_CONVERSATION_RESOLUTION = (
        "branch_protection.require_conversation_resolution"
    )
    BRANCH_REQUIRE_UP_TO_DATE = "branch_protection.require_up_to_date_branch"
    BRANCH_REQUIRE_LINEAR_HISTORY = "branch_protection.require_linear_history"
    BRANCH_ALLOW_FORCE_PUSHES = "branch_protection.allow_force_pushes"
    BRANCH_ALLOW_DELETIONS = "branch_protection.allow_deletions"
    BRANCH_REQUIRED_CHECKS = "branch_protection.required_checks"
    OBSERVE_COLLABORATOR_COUNT = "observe.collaborator_count"
    OBSERVE_INSTALLED_APP_COUNT = "observe.installed_app_count"
    OBSERVE_DEPLOY_KEY_COUNT = "observe.deploy_key_count"


_BOOL = ("bool",)
_SPECS = {
    Control.REPO_ALLOW_MERGE_COMMIT: _BOOL,
    Control.REPO_ALLOW_SQUASH_MERGE: _BOOL,
    Control.REPO_ALLOW_REBASE_MERGE: _BOOL,
    Control.REPO_ALLOW_AUTO_MERGE: _BOOL,
    Control.REPO_DELETE_BRANCH_ON_MERGE: _BOOL,
    Control.ACTIONS_ALLOWED_ACTIONS: ("enum", ("all", "local_only", "selected")),
    Control.ACTIONS_DEFAULT_TOKEN_PERMISSIONS: ("enum", ("read", "write")),
    Control.ACTIONS_CAN_APPROVE_PULL_REQUESTS: _BOOL,
    Control.BRANCH_REQUIRE_PULL_REQUEST: _BOOL,
    Control.BRANCH_REQUIRED_APPROVALS: ("int", 0, 6),
    Control.BRANCH_REQUIRE_CONVERSATION_RESOLUTION: _BOOL,
    Control.BRANCH_REQUIRE_UP_TO_DATE: _BOOL,
    Control.BRANCH_REQUIRE_LINEAR_HISTORY: _BOOL,
    Control.BRANCH_ALLOW_FORCE_PUSHES: _BOOL,
    Control.BRANCH_ALLOW_DELETIONS: _BOOL,
    Control.BRANCH_REQUIRED_CHECKS: ("checks",),
    Control.OBSERVE_COLLABORATOR_COUNT: ("int", 0, 1000),
    Control.OBSERVE_INSTALLED_APP_COUNT: ("int", 0, 1000),
    Control.OBSERVE_DEPLOY_KEY_COUNT: ("int", 0, 1000),
}
assert set(_SPECS) == set(Control)

OWNER_TYPES = frozenset({"Organization", "User"})
VISIBILITIES = frozenset({"public", "private", "internal"})
PROVENANCES = frozenset({"provider_read", "operator_reported", "synthetic_fixture"})
ADMIN_SCOPES = frozenset(
    """create_repository baseline_settings actions_permissions branch_protection
    required_checks audit_read""".split()
)
UNAVAILABLE_REASONS = frozenset(
    """http_403_ambiguous http_404_ambiguous permission_missing rate_limited
    transport_error server_error incomplete_pagination incomplete_observation
    not_observed conflicting_observations""".split()
)
_AUTHORITY_KEYS = frozenset(
    """admitted admission approved approval authorized authorization publish
    publication merge merged execute execution permission permissions
    credential credentials token secret""".split()
)

_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_INTENT = re.compile(r"[a-f0-9]{32}")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_CHECK = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._/:()-]{0,99}")
_ENDPOINT = re.compile(r"[A-Z]{3,6} /[A-Za-z0-9_./{}-]{1,120}")
_SECRET_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "akia")


def _int(value, lo, hi, where):
    if type(value) is not int:
        _fail("bad_type", where)
    if not lo <= value <= hi:
        _fail("bad_range", where)
    return value


def _bool(value, where):
    if type(value) is not bool:
        _fail("bad_type", where)
    return value


def _text(value, pattern, where, reason="bad_identifier"):
    if type(value) is not str:
        _fail("bad_type", where)
    if pattern.fullmatch(value) is None or value.lower().startswith(_SECRET_PREFIXES):
        _fail(reason, where)
    return value


def _choice(value, allowed, where):
    if type(value) is not str:
        _fail("bad_type", where)
    if value not in allowed:
        _fail("bad_value", where)
    return value


def _stamp(value, where):
    _text(value, _STAMP, where, "bad_timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        valid = True
    except ValueError:
        valid = False  # never chain the parser error: it embeds the input
    if not valid:
        _fail("bad_timestamp", where)
    return value


def _tuple(value, where, lo=0, hi=MAX_ITEMS):
    if type(value) is not tuple:
        _fail("bad_type", where)
    if len(value) > hi:
        _fail("too_many_items", where)
    if len(value) < lo:
        _fail("bad_range", where)
    return value


def _ascending(keys, where, duplicate="not_sorted"):
    for first, second in zip(keys, keys[1:], strict=False):
        if first == second:
            _fail(duplicate, where)
        if first > second:
            _fail("not_sorted", where)


def _repo_name(value, where):
    _text(value, _REPO, where)
    if value in (".", "..") or value.endswith(".git"):
        _fail("bad_identifier", where)
    return value


def _branch(value, where):
    _text(value, _BRANCH, where)
    if (
        ".." in value
        or "//" in value
        or value.endswith(("/", ".", ".lock"))
        or any(part.endswith(".lock") for part in value.split("/"))
    ):
        _fail("bad_identifier", where)
    return value


def _scopes(value, where, create):
    _tuple(value, where, 1, len(ADMIN_SCOPES))
    for item in value:
        _choice(item, ADMIN_SCOPES, where)
    _ascending(value, where, "bad_value")
    if ("create_repository" in value) != create:
        _fail("bad_value", where)


@dataclass(frozen=True, slots=True)
class Owner:
    id: int
    login: str
    kind: str

    def __post_init__(self):
        _int(self.id, 1, MAX_ID, "owner.id")
        _text(self.login, _LOGIN, "owner.login")
        _choice(self.kind, OWNER_TYPES, "owner.type")

    def wire(self):
        return {"id": self.id, "login": self.login, "type": self.kind}


@dataclass(frozen=True, slots=True)
class RepositoryRef:
    owner: Owner
    id: int
    name: str
    full_name: str

    def __post_init__(self):
        if type(self.owner) is not Owner:
            _fail("bad_type", "repository.owner")
        _int(self.id, 1, MAX_ID, "repository.id")
        _repo_name(self.name, "repository.name")
        _text(self.full_name, _REF, "repository.full_name", "identity_inconsistent")
        if self.full_name != f"{self.owner.login}/{self.name}":
            _fail("identity_inconsistent", "repository.full_name")

    def wire(self):
        return {
            "owner": self.owner.wire(),
            "id": self.id,
            "name": self.name,
            "full_name": self.full_name,
        }


@dataclass(frozen=True, slots=True)
class Repository:
    ref: RepositoryRef
    visibility: str
    default_branch: str

    def __post_init__(self):
        if type(self.ref) is not RepositoryRef:
            _fail("bad_type", "repository.ref")
        _choice(self.visibility, VISIBILITIES, "repository.visibility")
        _branch(self.default_branch, "repository.default_branch")

    def wire(self):
        return {
            **self.ref.wire(),
            "visibility": self.visibility,
            "default_branch": self.default_branch,
        }


@dataclass(frozen=True, slots=True)
class CheckPin:
    name: str
    app_id: int

    def __post_init__(self):
        _text(self.name, _CHECK, "check.name")
        if self.name != self.name.strip():
            _fail("bad_identifier", "check.name")
        _int(self.app_id, 1, MAX_ID, "check.app_id")


def _check_value(control, value, observed):
    where = f"value.{control.value}"
    spec = _SPECS[control]
    if spec[0] == "bool":
        _bool(value, where)
    elif spec[0] == "enum":
        _choice(value, spec[1], where)
    elif spec[0] == "int":
        _int(value, spec[1], spec[2], where)
    else:
        _tuple(value, where, 0 if observed else 1, MAX_CHECKS)
        for pin in value:
            if type(pin) is not CheckPin:
                _fail("bad_type", where)
        _ascending([pin.name for pin in value], where, "duplicate_control")


def _value_wire(control, value):
    if _SPECS[control][0] == "checks":
        return [{"name": p.name, "app_id": p.app_id} for p in value]
    return value


def _value_from_wire(control, value):
    if _SPECS[control][0] != "checks":
        return value
    where = f"value.{control.value}"
    items = _array(value, where)
    return tuple(
        CheckPin(**{k: v for k, v in _fields(i, where, ("name", "app_id")).items()})
        for i in items
    )


@dataclass(frozen=True, slots=True)
class ControlSetting:
    control: Control
    blocking: bool
    value: object

    def __post_init__(self):
        if type(self.control) is not Control:
            _fail("bad_type", "setting.control")
        _bool(self.blocking, "setting.blocking")
        _check_value(self.control, self.value, observed=False)

    def wire(self):
        return {
            "control": self.control.value,
            "blocking": self.blocking,
            "value": _value_wire(self.control, self.value),
        }


def _settings(value, where, lo):
    _tuple(value, where, lo, len(Control))
    for item in value:
        if type(item) is not ControlSetting:
            _fail("bad_type", where)
    _ascending([i.control.value for i in value], where, "duplicate_control")


@dataclass(frozen=True, slots=True)
class Profile:
    profile_id: str
    controls: tuple

    def __post_init__(self):
        _text(self.profile_id, _LABEL, "profile.profile_id")
        _settings(self.controls, "profile.controls", 1)

    def wire(self):
        return {
            "schema": PROFILE,
            "profile_id": self.profile_id,
            "controls": [c.wire() for c in self.controls],
        }


@dataclass(frozen=True, slots=True)
class PreCreation:
    owner: Owner
    name: str
    visibility: str
    default_branch: str
    admin_scope: tuple
    authorization_ref: str
    intent_id: str

    def __post_init__(self):
        if type(self.owner) is not Owner:
            _fail("bad_type", "precreation.owner")
        _repo_name(self.name, "precreation.name")
        _choice(self.visibility, VISIBILITIES, "precreation.visibility")
        _branch(self.default_branch, "precreation.default_branch")
        _scopes(self.admin_scope, "precreation.admin_scope", create=True)
        _text(self.authorization_ref, _REF, "precreation.authorization_ref")
        _text(self.intent_id, _INTENT, "precreation.intent_id")

    def wire(self):
        return {
            "schema": PRECREATION,
            "provider": "github",
            "owner": self.owner.wire(),
            "repository": {
                "name": self.name,
                "visibility": self.visibility,
                "default_branch": self.default_branch,
            },
            "admin_scope": list(self.admin_scope),
            "authorization_ref": self.authorization_ref,
            "intent_id": self.intent_id,
        }


@dataclass(frozen=True, slots=True)
class Origin:
    """Retains the exact relationship of an existing repository to its creation."""

    intent_id: str
    precreation_sha256: str
    binding_sha256: str

    def __post_init__(self):
        _text(self.intent_id, _INTENT, "origin.intent_id")
        _text(
            self.precreation_sha256, _SHA256, "origin.precreation_sha256", "bad_digest"
        )
        _text(self.binding_sha256, _SHA256, "origin.binding_sha256", "bad_digest")

    def wire(self):
        return {
            "intent_id": self.intent_id,
            "precreation_sha256": self.precreation_sha256,
            "binding_sha256": self.binding_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExistingPins:
    repository: Repository
    admin_scope: tuple
    authorization_ref: str
    origin: object = None

    def __post_init__(self):
        if type(self.repository) is not Repository:
            _fail("bad_type", "existing.repository")
        _scopes(self.admin_scope, "existing.admin_scope", create=False)
        _text(self.authorization_ref, _REF, "existing.authorization_ref")
        if self.origin is not None and type(self.origin) is not Origin:
            _fail("bad_type", "existing.origin")

    def wire(self):
        return {
            "schema": EXISTING,
            "provider": "github",
            "repository": self.repository.wire(),
            "admin_scope": list(self.admin_scope),
            "authorization_ref": self.authorization_ref,
            "origin": None if self.origin is None else self.origin.wire(),
        }


@dataclass(frozen=True, slots=True)
class Binding:
    intent_id: str
    precreation_sha256: str
    creation_effect_ref: str
    observation_ref: str
    observed_at: str
    repository: Repository

    def __post_init__(self):
        _text(self.intent_id, _INTENT, "binding.intent_id")
        _text(
            self.precreation_sha256, _SHA256, "binding.precreation_sha256", "bad_digest"
        )
        _text(self.creation_effect_ref, _REF, "binding.creation_effect_ref")
        _text(self.observation_ref, _REF, "binding.observation_ref")
        if self.observation_ref == self.creation_effect_ref:
            _fail("binding_provenance", "binding.observation_ref")
        _stamp(self.observed_at, "binding.observed_at")
        if type(self.repository) is not Repository:
            _fail("bad_type", "binding.repository")

    def wire(self):
        return {
            "schema": BINDING,
            "intent_id": self.intent_id,
            "precreation_sha256": self.precreation_sha256,
            "creation_effect_ref": self.creation_effect_ref,
            "observation": {
                "kind": "independent_read",
                "ref": self.observation_ref,
                "observed_at": self.observed_at,
            },
            "repository": self.repository.wire(),
        }


def _same_repository(first, second, where):
    """Exact identity, visibility and default-branch pins; specific reasons."""
    if first.ref.owner != second.ref.owner:
        _fail("owner_mismatch", where)
    if first.ref != second.ref:
        _fail("repository_mismatch", where)
    if first.visibility != second.visibility:
        _fail("visibility_mismatch", where)
    if first.default_branch != second.default_branch:
        _fail("branch_mismatch", where)


def verify_binding(pre, binding):
    """Consistency only: does not establish that creation or a read-back happened."""
    if type(pre) is not PreCreation or type(binding) is not Binding:
        _fail("bad_type", "binding")
    repo = binding.repository
    if binding.intent_id != pre.intent_id:
        _fail("intent_mismatch", "binding.intent_id")
    if binding.precreation_sha256 != digest(pre):
        _fail("digest_mismatch", "binding.precreation_sha256")
    if repo.ref.owner != pre.owner:
        _fail("owner_mismatch", "binding.repository.owner")
    if repo.ref.name != pre.name:
        _fail("name_mismatch", "binding.repository.name")
    if repo.visibility != pre.visibility:
        _fail("visibility_mismatch", "binding.repository.visibility")
    if repo.default_branch != pre.default_branch:
        _fail("branch_mismatch", "binding.repository.default_branch")


def verify_origin(pins, pre, binding):
    """Existing pins that follow a creation keep the exact original relationship.

    Consistency only: nothing is adopted and no creation or read-back is proven.
    """
    if type(pins) is not ExistingPins:
        _fail("bad_type", "origin.pins")
    verify_binding(pre, binding)
    origin = pins.origin
    if (
        origin is None
        or origin.intent_id != pre.intent_id
        or origin.precreation_sha256 != digest(pre)
        or origin.binding_sha256 != digest(binding)
    ):
        _fail("origin_mismatch", "existing.origin")
    _same_repository(pins.repository, binding.repository, "existing.repository")


@dataclass(frozen=True, slots=True)
class CreationTarget:
    """Target of a not-yet-created repository: the exact intent, never an ID."""

    owner: Owner
    name: str
    visibility: str
    default_branch: str
    intent_id: str
    precreation_sha256: str

    def __post_init__(self):
        if type(self.owner) is not Owner:
            _fail("bad_type", "target.owner")
        _repo_name(self.name, "target.name")
        _choice(self.visibility, VISIBILITIES, "target.visibility")
        _branch(self.default_branch, "target.default_branch")
        _text(self.intent_id, _INTENT, "target.intent_id")
        _text(
            self.precreation_sha256, _SHA256, "target.precreation_sha256", "bad_digest"
        )

    def wire(self):
        return {
            "mode": "creation",
            "owner": self.owner.wire(),
            "repository": {
                "name": self.name,
                "visibility": self.visibility,
                "default_branch": self.default_branch,
            },
            "intent_id": self.intent_id,
            "precreation_sha256": self.precreation_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExistingTarget:
    """Target of an existing repository: the complete pins and their digest."""

    repository: Repository
    pins_sha256: str

    def __post_init__(self):
        if type(self.repository) is not Repository:
            _fail("bad_type", "target.repository")
        _text(self.pins_sha256, _SHA256, "target.pins_sha256", "bad_digest")

    def wire(self):
        return {
            "mode": "existing",
            "repository": self.repository.wire(),
            "pins_sha256": self.pins_sha256,
        }


def _target(value, where):
    if type(value) not in (CreationTarget, ExistingTarget):
        _fail("bad_type", where)


def creation_target(pre):
    """Derive the target of a creation intent from its exact pre-creation record."""
    if type(pre) is not PreCreation:
        _fail("bad_type", "target")
    return CreationTarget(
        pre.owner,
        pre.name,
        pre.visibility,
        pre.default_branch,
        pre.intent_id,
        digest(pre),
    )


def existing_target(pins):
    """Derive the target of an existing repository from its complete pins."""
    if type(pins) is not ExistingPins:
        _fail("bad_type", "target")
    return ExistingTarget(pins.repository, digest(pins))


def verify_target(target, pins):
    """A target must equal the exact pins it names; mode confusion is rejected."""
    if type(pins) not in (PreCreation, ExistingPins):
        _fail("bad_type", "target.pins")
    _target(target, "target")
    if type(target) is CreationTarget and type(pins) is PreCreation:
        if target.intent_id != pins.intent_id:
            _fail("intent_mismatch", "target.intent_id")
        if target.owner != pins.owner:
            _fail("owner_mismatch", "target.owner")
        if target.name != pins.name:
            _fail("name_mismatch", "target.name")
        if target.visibility != pins.visibility:
            _fail("visibility_mismatch", "target.visibility")
        if target.default_branch != pins.default_branch:
            _fail("branch_mismatch", "target.default_branch")
        if target.precreation_sha256 != digest(pins):
            _fail("digest_mismatch", "target.precreation_sha256")
    elif type(target) is ExistingTarget and type(pins) is ExistingPins:
        _same_repository(target.repository, pins.repository, "target.repository")
        if target.pins_sha256 != digest(pins):
            _fail("digest_mismatch", "target.pins_sha256")
    else:
        _fail("target_mismatch", "target")


@dataclass(frozen=True, slots=True)
class Manifest:
    manifest_id: str
    profile_id: str
    target: object
    controls: tuple

    def __post_init__(self):
        _text(self.manifest_id, _LABEL, "manifest.manifest_id")
        _text(self.profile_id, _LABEL, "manifest.profile_id")
        _target(self.target, "manifest.target")
        _settings(self.controls, "manifest.controls", 0)

    def wire(self):
        return {
            "schema": MANIFEST,
            "manifest_id": self.manifest_id,
            "profile_id": self.profile_id,
            "target": self.target.wire(),
            "controls": [c.wire() for c in self.controls],
        }


@dataclass(frozen=True, slots=True)
class DesiredState:
    profile_id: str
    manifest_id: str
    target: object
    controls: tuple

    def __post_init__(self):
        _text(self.profile_id, _LABEL, "desired.profile_id")
        _text(self.manifest_id, _LABEL, "desired.manifest_id")
        _target(self.target, "desired.target")
        _settings(self.controls, "desired.controls", 1)
        if not any(c.blocking for c in self.controls):
            _fail("no_blocking_control", "desired.controls")
        values = {c.control: c.value for c in self.controls}
        merge = [
            values.get(c)
            for c in (
                Control.REPO_ALLOW_MERGE_COMMIT,
                Control.REPO_ALLOW_SQUASH_MERGE,
                Control.REPO_ALLOW_REBASE_MERGE,
            )
        ]
        if all(v is False for v in merge):
            _fail("inconsistent_controls", "desired.controls")
        approvals = values.get(Control.BRANCH_REQUIRED_APPROVALS, 0)
        if approvals > 0 and values.get(Control.BRANCH_REQUIRE_PULL_REQUEST) is False:
            _fail("inconsistent_controls", "desired.controls")

    def wire(self):
        return {
            "schema": DESIRED,
            "profile_id": self.profile_id,
            "manifest_id": self.manifest_id,
            "target": self.target.wire(),
            "controls": [c.wire() for c in self.controls],
        }

    def value_of(self, control):
        return next((c.value for c in self.controls if c.control == control), None)


def compose_desired(profile, manifest, pins):
    """Desired state is an explicit profile plus a target-bound manifest.

    The manifest target must equal the supplied exact pins; the binding is kept.
    """
    if type(profile) is not Profile or type(manifest) is not Manifest:
        _fail("bad_type", "compose")
    verify_target(manifest.target, pins)
    if manifest.profile_id != profile.profile_id:
        _fail("unresolved_reference", "manifest.profile_id")
    if {c.control for c in profile.controls} & {c.control for c in manifest.controls}:
        _fail("overlapping_control", "manifest.controls")
    merged = sorted(profile.controls + manifest.controls, key=lambda c: c.control.value)
    return DesiredState(
        profile.profile_id, manifest.manifest_id, manifest.target, tuple(merged)
    )


def verify_desired(desired, profile, manifest, pins):
    if (
        type(desired) is not DesiredState
        or compose_desired(profile, manifest, pins) != desired
    ):
        _fail("desired_mismatch", "desired")


@dataclass(frozen=True, slots=True)
class Limitation:
    """Affirmative limitation: authoritative reads plus pinned documentation.

    It is bound to one control and one repository, and it is carried by the
    snapshot's observation, so it cannot be moved between controls or snapshots.
    """

    control: Control
    repository_id: int
    endpoint: str
    documentation_ref: str
    documentation_version: str
    visibility_ref: str
    plan_ref: str
    observed_at: str
    corroboration_refs: tuple

    def __post_init__(self):
        if type(self.control) is not Control:
            _fail("bad_type", "evidence.control")
        _int(self.repository_id, 1, MAX_ID, "evidence.repository_id")
        _text(self.endpoint, _ENDPOINT, "evidence.endpoint")
        _text(self.documentation_ref, _REF, "evidence.documentation_ref")
        _text(self.documentation_version, _REF, "evidence.documentation_version")
        _text(self.visibility_ref, _REF, "evidence.visibility_ref")
        _text(self.plan_ref, _REF, "evidence.plan_ref")
        _stamp(self.observed_at, "evidence.observed_at")
        _tuple(self.corroboration_refs, "evidence.corroboration_refs", 2, 8)
        for ref in self.corroboration_refs:
            _text(ref, _REF, "evidence.corroboration_refs")
        _ascending(list(self.corroboration_refs), "evidence.corroboration_refs")
        refs = [
            self.documentation_ref,
            self.visibility_ref,
            self.plan_ref,
            *self.corroboration_refs,
        ]
        if len(set(refs)) != len(refs):
            _fail("not_independent", "evidence")

    def wire(self):
        return {
            "control": self.control.value,
            "repository_id": self.repository_id,
            "endpoint": self.endpoint,
            "documentation_ref": self.documentation_ref,
            "documentation_version": self.documentation_version,
            "visibility_ref": self.visibility_ref,
            "plan_ref": self.plan_ref,
            "observed_at": self.observed_at,
            "corroboration_refs": list(self.corroboration_refs),
        }


@dataclass(frozen=True, slots=True)
class Observation:
    """One control observation: observed, unavailable, or affirmatively unsupported.

    `unsupported` is the only state that can support an UNSUPPORTED result, and it
    carries its own limitation evidence; ambiguous or failed reads stay
    `unavailable` with a closed reason.
    """

    control: Control
    observed: bool
    value: object = None
    reason: str | None = None
    limitation: object = None

    def __post_init__(self):
        if type(self.control) is not Control:
            _fail("bad_type", "observation.control")
        _bool(self.observed, "observation.observed")
        if self.observed:
            _check_value(self.control, self.value, observed=True)
            if self.reason is not None or self.limitation is not None:
                _fail("bad_value", "observation.reason")
        elif self.limitation is not None:
            if self.reason is not None or self.value is not None:
                _fail("bad_value", "observation.limitation")
            if type(self.limitation) is not Limitation:
                _fail("bad_type", "observation.limitation")
            if self.limitation.control != self.control:
                _fail("evidence_mismatch", "observation.limitation")
        else:
            if self.value is not None:
                _fail("bad_value", "observation.value")
            _choice(self.reason, UNAVAILABLE_REASONS, "observation.reason")

    @property
    def status(self):
        if self.observed:
            return "observed"
        return "unavailable" if self.limitation is None else "unsupported"

    def wire(self):
        if self.observed:
            value = _value_wire(self.control, self.value)
            return {"control": self.control.value, "status": "observed", "value": value}
        if self.limitation is not None:
            return {
                "control": self.control.value,
                "status": "unsupported",
                "limitation": self.limitation.wire(),
            }
        return {
            "control": self.control.value,
            "status": "unavailable",
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ObservedIdentity:
    """Observed repository identity, including visibility and default branch.

    Visibility and default branch may be unobserved (None) only with a closed
    reason; such a snapshot is incomplete and can never support COMPLIANT.
    """

    ref: RepositoryRef
    visibility: str | None = None
    default_branch: str | None = None
    reason: str | None = None

    def __post_init__(self):
        if type(self.ref) is not RepositoryRef:
            _fail("bad_type", "identity.ref")
        if self.visibility is not None:
            _choice(self.visibility, VISIBILITIES, "identity.visibility")
        if self.default_branch is not None:
            _branch(self.default_branch, "identity.default_branch")
        if self.complete:
            if self.reason is not None:
                _fail("bad_value", "identity.reason")
        else:
            _choice(self.reason, UNAVAILABLE_REASONS, "identity.reason")

    @property
    def complete(self):
        return self.visibility is not None and self.default_branch is not None

    def wire(self):
        return {
            **self.ref.wire(),
            "visibility": self.visibility,
            "default_branch": self.default_branch,
            "unavailable_reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ActualState:
    """One bounded snapshot for one repository and one desired state.

    `scope` is the explicit expected control set; there is exactly one observation
    per scoped control, and `complete` is true if and only if every one was observed
    and the repository identity (visibility and default branch) was fully observed.
    """

    repository: ObservedIdentity
    desired_sha256: str
    provenance: str
    source_ref: str
    observed_at: str
    scope: tuple
    complete: bool
    observations: tuple

    def __post_init__(self):
        if type(self.repository) is not ObservedIdentity:
            _fail("bad_type", "actual.repository")
        _text(self.desired_sha256, _SHA256, "actual.desired_sha256", "bad_digest")
        _choice(self.provenance, PROVENANCES, "actual.provenance")
        _text(self.source_ref, _REF, "actual.source_ref")
        _stamp(self.observed_at, "actual.observed_at")
        _tuple(self.scope, "actual.scope", 1, len(Control))
        for item in self.scope:
            if type(item) is not Control:
                _fail("bad_type", "actual.scope")
        _ascending([c.value for c in self.scope], "actual.scope", "duplicate_control")
        _bool(self.complete, "actual.complete")
        _tuple(self.observations, "actual.observations", 1, len(Control))
        for item in self.observations:
            if type(item) is not Observation:
                _fail("bad_type", "actual.observations")
        _ascending(
            [o.control.value for o in self.observations],
            "actual.observations",
            "duplicate_control",
        )
        if tuple(o.control for o in self.observations) != self.scope:
            _fail("scope_mismatch", "actual.observations")
        for item in self.observations:
            if (
                item.limitation is not None
                and item.limitation.repository_id != self.repository.ref.id
            ):
                _fail("snapshot_mismatch", "actual.observations")
        if self.complete != (
            self.repository.complete and all(o.observed for o in self.observations)
        ):
            _fail("completeness_mismatch", "actual.complete")

    def wire(self):
        return {
            "schema": ACTUAL,
            "repository": self.repository.wire(),
            "desired_sha256": self.desired_sha256,
            "provenance": self.provenance,
            "source_ref": self.source_ref,
            "observed_at": self.observed_at,
            "scope": [c.value for c in self.scope],
            "complete": self.complete,
            "observations": [o.wire() for o in self.observations],
        }

    def observation_of(self, control):
        return next((o for o in self.observations if o.control == control), None)


def verify_actual(actual, desired):
    """Snapshot is for this desired state, this repository and exactly its scope."""
    if type(actual) is not ActualState or type(desired) is not DesiredState:
        _fail("bad_type", "actual")
    if type(desired.target) is not ExistingTarget:
        _fail("target_mismatch", "desired.target")
    if actual.desired_sha256 != digest(desired):
        _fail("snapshot_mismatch", "actual.desired_sha256")
    identity, expected = actual.repository, desired.target.repository
    if identity.ref.owner != expected.ref.owner:
        _fail("owner_mismatch", "actual.repository")
    if identity.ref != expected.ref:
        _fail("repository_mismatch", "actual.repository")
    if identity.visibility is not None and identity.visibility != expected.visibility:
        _fail("visibility_mismatch", "actual.repository")
    if (
        identity.default_branch is not None
        and identity.default_branch != expected.default_branch
    ):
        _fail("branch_mismatch", "actual.repository")
    if actual.scope != tuple(c.control for c in desired.controls):
        _fail("scope_mismatch", "actual.scope")


class Result(StrEnum):
    COMPLIANT = "COMPLIANT"
    NONCOMPLIANT = "NONCOMPLIANT"
    UNSUPPORTED = "UNSUPPORTED"
    UNVERIFIED = "UNVERIFIED"
    CONTRADICTORY = "CONTRADICTORY"


@dataclass(frozen=True, slots=True)
class Match:
    desired: object
    observed: object


@dataclass(frozen=True, slots=True)
class Difference:
    desired: object
    observed: object


@dataclass(frozen=True, slots=True)
class Unavailable:
    reason: str

    def __post_init__(self):
        _choice(self.reason, UNAVAILABLE_REASONS, "evidence.reason")


@dataclass(frozen=True, slots=True)
class ConflictingObservation:
    ref: str
    value: object

    def __post_init__(self):
        _text(self.ref, _REF, "evidence.ref")


@dataclass(frozen=True, slots=True)
class Conflict:
    observations: tuple

    def __post_init__(self):
        _tuple(self.observations, "evidence.observations", 2, 8)
        for item in self.observations:
            if type(item) is not ConflictingObservation:
                _fail("bad_type", "evidence.observations")
        _ascending([o.ref for o in self.observations], "evidence.observations")


_EVIDENCE = {
    Result.COMPLIANT: ("observed_match", Match),
    Result.NONCOMPLIANT: ("observed_difference", Difference),
    Result.UNVERIFIED: ("unavailable", Unavailable),
    Result.UNSUPPORTED: ("affirmative_limitation", Limitation),
    Result.CONTRADICTORY: ("conflicting_observations", Conflict),
}


@dataclass(frozen=True, slots=True)
class ControlResult:
    """A result bound to the exact desired state and actual snapshot by digest."""

    desired_sha256: str
    actual_sha256: str
    control: Control
    blocking: bool
    result: Result
    evidence: object

    def __post_init__(self):
        _text(self.desired_sha256, _SHA256, "result.desired_sha256", "bad_digest")
        _text(self.actual_sha256, _SHA256, "result.actual_sha256", "bad_digest")
        if type(self.control) is not Control:
            _fail("bad_type", "result.control")
        _bool(self.blocking, "result.blocking")
        if type(self.result) is not Result:
            _fail("bad_type", "result.result")
        if type(self.evidence) is not _EVIDENCE[self.result][1]:
            _fail("evidence_mismatch", "result.evidence")
        ev = self.evidence
        if self.result in (Result.COMPLIANT, Result.NONCOMPLIANT):
            _check_value(self.control, ev.desired, observed=False)
            _check_value(self.control, ev.observed, observed=True)
            if (ev.desired == ev.observed) != (self.result is Result.COMPLIANT):
                _fail("evidence_mismatch", "result.evidence")
        elif self.result is Result.CONTRADICTORY:
            for item in ev.observations:
                _check_value(self.control, item.value, observed=True)
            if len({o.value for o in ev.observations}) < 2:
                _fail("evidence_mismatch", "result.evidence")
        elif self.result is Result.UNSUPPORTED and ev.control != self.control:
            _fail("evidence_mismatch", "result.evidence")

    def wire(self):
        kind = _EVIDENCE[self.result][0]
        ev = self.evidence
        if self.result in (Result.COMPLIANT, Result.NONCOMPLIANT):
            body = {
                "desired": _value_wire(self.control, ev.desired),
                "observed": _value_wire(self.control, ev.observed),
            }
        elif self.result is Result.UNVERIFIED:
            body = {"reason": ev.reason}
        elif self.result is Result.UNSUPPORTED:
            body = ev.wire()
        else:
            body = {
                "observations": [
                    {"ref": o.ref, "value": _value_wire(self.control, o.value)}
                    for o in ev.observations
                ]
            }
        return {
            "schema": RESULT,
            "desired_sha256": self.desired_sha256,
            "actual_sha256": self.actual_sha256,
            "control": self.control.value,
            "blocking": self.blocking,
            "result": self.result.value,
            "evidence": {"kind": kind, **body},
        }


def verify_result(result, desired, actual):
    """A result must belong to this snapshot and agree with its observation.

    Structural consistency only: the observation is not authenticated or fresh.
    """
    if type(result) is not ControlResult:
        _fail("bad_type", "result")
    verify_actual(actual, desired)
    if result.desired_sha256 != digest(desired) or result.actual_sha256 != digest(
        actual
    ):
        _fail("snapshot_mismatch", "result")
    setting = next((c for c in desired.controls if c.control == result.control), None)
    if setting is None or setting.blocking != result.blocking:
        _fail("coverage_mismatch", "result.control")
    seen = actual.observation_of(result.control)
    ev = result.evidence
    if result.result in (Result.COMPLIANT, Result.NONCOMPLIANT):
        if ev.desired != setting.value:
            _fail("evidence_mismatch", "result.evidence.desired")
        if not seen.observed or seen.value != ev.observed:
            _fail("evidence_mismatch", "result.evidence.observed")
    elif result.result is Result.UNSUPPORTED:
        # only an observation that itself carries this exact limitation supports it
        if seen.limitation is None or seen.limitation != ev:
            _fail("evidence_mismatch", "result.evidence")
    elif seen.observed or seen.limitation is not None:
        _fail("evidence_mismatch", "result.evidence")
    elif result.result is Result.UNVERIFIED and seen.reason != ev.reason:
        _fail("evidence_mismatch", "result.evidence.reason")
    elif (
        result.result is Result.CONTRADICTORY
        and seen.reason != "conflicting_observations"
    ):
        _fail("evidence_mismatch", "result.evidence")


_SEVERITY = (
    Result.CONTRADICTORY,
    Result.UNVERIFIED,
    Result.UNSUPPORTED,
    Result.NONCOMPLIANT,
    Result.COMPLIANT,
)


def summarize(desired, actual, results):
    """Structural aggregate over one desired state, one snapshot and its results.

    No freshness, authenticity or provider claim. Requires the snapshot to match
    the desired state and repository, exactly one verified result for every
    blocking control, and never reports COMPLIANT for an incomplete snapshot.
    """
    verify_actual(actual, desired)
    _tuple(results, "summarize.results", 0, len(Control))
    seen = set()
    for item in results:
        if type(item) is not ControlResult:
            _fail("bad_type", "summarize.results")
        if item.control in seen:
            _fail("duplicate_result", "summarize.results")
        seen.add(item.control)
        verify_result(item, desired, actual)
    if {c.control for c in desired.controls if c.blocking} - seen:
        _fail("coverage_mismatch", "summarize.results")
    blocking = {r.result for r in results if r.blocking}
    worst = next(
        level for level in _SEVERITY if level in blocking or level is Result.COMPLIANT
    )
    if worst is Result.COMPLIANT and not actual.complete:
        return Result.UNVERIFIED
    return worst


@dataclass(frozen=True, slots=True)
class ComplianceReport:
    """Final structural compliance context that an enrollment references by digest."""

    repository: Repository
    desired_sha256: str
    actual_sha256: str
    overall: Result
    evidence_ref: str
    result_digests: tuple

    def __post_init__(self):
        if type(self.repository) is not Repository:
            _fail("bad_type", "compliance.repository")
        _text(self.desired_sha256, _SHA256, "compliance.desired_sha256", "bad_digest")
        _text(self.actual_sha256, _SHA256, "compliance.actual_sha256", "bad_digest")
        if type(self.overall) is not Result:
            _fail("bad_type", "compliance.overall")
        _text(self.evidence_ref, _REF, "compliance.evidence_ref")
        _tuple(self.result_digests, "compliance.result_digests", 1, len(Control))
        for item in self.result_digests:
            _text(item, _SHA256, "compliance.result_digests", "bad_digest")
        _ascending(list(self.result_digests), "compliance.result_digests")

    def wire(self):
        return {
            "schema": COMPLIANCE,
            "repository": self.repository.wire(),
            "desired_sha256": self.desired_sha256,
            "actual_sha256": self.actual_sha256,
            "overall": self.overall.value,
            "evidence_ref": self.evidence_ref,
            "result_digests": list(self.result_digests),
        }


def build_compliance(desired, actual, results, evidence_ref):
    """Derive the report only from a fully verified desired/actual/results context."""
    overall = summarize(desired, actual, results)
    return ComplianceReport(
        desired.target.repository,
        digest(desired),
        digest(actual),
        overall,
        evidence_ref,
        tuple(sorted(digest(r) for r in results)),
    )


def verify_compliance(report, desired, actual, results):
    if (
        type(report) is not ComplianceReport
        or build_compliance(desired, actual, results, report.evidence_ref) != report
    ):
        _fail("evidence_mismatch", "compliance")


@dataclass(frozen=True, slots=True)
class Enrollment:
    repository: Repository
    evidence_ref: str
    evidence_sha256: str
    decision_ref: str
    decided_at: str

    def __post_init__(self):
        if type(self.repository) is not Repository:
            _fail("bad_type", "enrollment.repository")
        _text(self.evidence_ref, _REF, "enrollment.evidence_ref")
        _text(self.evidence_sha256, _SHA256, "enrollment.evidence_sha256", "bad_digest")
        _text(self.decision_ref, _REF, "enrollment.decision_ref")
        if self.decision_ref == self.evidence_ref:
            _fail("not_independent", "enrollment.decision_ref")
        _stamp(self.decided_at, "enrollment.decided_at")

    def wire(self):
        return {
            "schema": ENROLLMENT,
            "repository": self.repository.wire(),
            "evidence": {"ref": self.evidence_ref, "sha256": self.evidence_sha256},
            "decision": {"ref": self.decision_ref, "decided_at": self.decided_at},
        }


def verify_enrollment_linkage_only(enrollment, report, pins):
    """LINKAGE ONLY: not sufficient for enrollment. Use `verify_enrollment`.

    Checks that the enrollment names this report (reference and digest), that the
    enrollment, report and pins agree on owner, repository ID, name, visibility and
    default branch, that the report says COMPLIANT and that the decision reference
    is distinct. It does not check that the report is consistent with any desired
    state, snapshot or result, nor that the pins are the ones the desired state
    was built from, so a forged report can pass it.
    """
    if (
        type(enrollment) is not Enrollment
        or type(report) is not ComplianceReport
        or type(pins) is not ExistingPins
    ):
        _fail("bad_type", "enrollment")
    if enrollment.evidence_ref != report.evidence_ref:
        _fail("evidence_mismatch", "enrollment.evidence_ref")
    if enrollment.evidence_sha256 != digest(report):
        _fail("digest_mismatch", "enrollment.evidence_sha256")
    _same_repository(enrollment.repository, report.repository, "enrollment.repository")
    _same_repository(enrollment.repository, pins.repository, "enrollment.pins")
    if report.overall is not Result.COMPLIANT:
        _fail("evidence_not_compliant", "compliance.overall")
    if enrollment.decision_ref == pins.authorization_ref:
        _fail("not_independent", "enrollment.decision_ref")


def verify_enrollment(enrollment, report, pins, desired, actual, results):
    """Full structural enrollment verification; the context cannot be omitted.

    Establishes, in order: the desired state's target equals the exact supplied
    pins, including their digest; the snapshot matches the desired state, the
    complete observed identity and its scope; every result is bound to that
    snapshot and agrees with its observation; the report is exactly the report
    derived from desired state, snapshot and results (so it is COMPLIANT only if
    they are); the enrollment names that report by reference and digest; owner,
    repository ID, name, visibility and default branch agree across enrollment,
    report and pins; and the operator decision reference is distinct from the
    evidence and the plan authorization.

    Offline structural consistency only. It is not authentication, freshness,
    operator consent, an approval, an evidence envelope or admission.
    """
    if (
        type(enrollment) is not Enrollment
        or type(report) is not ComplianceReport
        or type(pins) is not ExistingPins
        or type(desired) is not DesiredState
        or type(actual) is not ActualState
    ):
        _fail("bad_type", "enrollment")
    verify_target(desired.target, pins)
    if type(desired.target) is not ExistingTarget:
        _fail("target_mismatch", "desired.target")
    verify_compliance(report, desired, actual, results)
    verify_enrollment_linkage_only(enrollment, report, pins)


def dumps(record):
    """Deterministic canonical bytes: sorted keys, compact, ASCII, no newline."""
    text = json.dumps(
        record.wire(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return text.encode("ascii")


def digest(record):
    return hashlib.sha256(dumps(record)).hexdigest()


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _constant(_name):
    _fail("nonfinite_number")


def _float(text):
    _fail("nonfinite_number" if not math.isfinite(float(text)) else "bad_type")


def _integer(text):
    if len(text) > 17:
        _fail("bad_range")
    return int(text)


def _depth_ok(node):
    stack = [(node, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            return False
        if type(item) is dict:
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)
    return True


def _load(raw, schema):
    if type(raw) is not bytes:
        _fail("not_bytes")
    if len(raw) > MAX_BYTES:
        _fail("too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None  # the error object would retain the raw input
    if text is None:
        _fail("bad_utf8")
    failure = None
    try:
        data = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_constant=_constant,
            parse_float=_float,
            parse_int=_integer,
        )
    except RecursionError:
        failure = "too_deep"
    except ValueError:  # JSONDecodeError retains the document
        failure = "bad_json"
    if failure:
        _fail(failure)
    if not _depth_ok(data):
        _fail("too_deep")
    if type(data) is not dict:
        _fail("not_object")
    found = data.get("schema")
    if "schema" not in data:
        _fail("missing_field", "schema")
    if type(found) is not str:
        _fail("bad_type", "schema")
    if found != schema:
        _fail("wrong_record" if found in SCHEMAS else "unsupported_schema", "schema")
    return data


def _fields(obj, where, required, optional=(), special=None, authority=False):
    if type(obj) is not dict:
        _fail("not_object", where)
    for key in obj:
        if special and key in special:
            _fail(special[key], where)
        if authority and key in _AUTHORITY_KEYS:
            _fail("authority_field", where)
    if set(obj) - set(required) - set(optional):
        _fail("unknown_field", where)
    if set(required) - set(obj):
        _fail("missing_field", where)
    return obj


def _array(value, where):
    if type(value) is not list:
        _fail("bad_type", where)
    if len(value) > MAX_ITEMS:
        _fail("too_many_items", where)
    return value


def _member(enum, value, where, reason="bad_value"):
    if type(value) is not str:
        _fail("bad_type", where)
    try:
        return enum(value)
    except ValueError:
        pass
    _fail(reason, where)  # outside the handler: no chained input


def _owner(obj, where="owner", **flags):
    o = _fields(obj, where, ("id", "login", "type"), **flags)
    return Owner(o["id"], o["login"], o["type"])


def _repo_ref(obj, where="repository", **flags):
    r = _fields(obj, where, ("owner", "id", "name", "full_name"), **flags)
    return RepositoryRef(
        _owner(r["owner"], **flags), r["id"], r["name"], r["full_name"]
    )


def _repository(obj, where="repository", **flags):
    r = _fields(
        obj,
        where,
        ("owner", "id", "name", "full_name", "visibility", "default_branch"),
        **flags,
    )
    ref = RepositoryRef(_owner(r["owner"], **flags), r["id"], r["name"], r["full_name"])
    return Repository(ref, r["visibility"], r["default_branch"])


_NO_ID = {
    "id": "repository_id_in_precreation",
    "repository_id": "repository_id_in_precreation",
    "full_name": "repository_id_in_precreation",
}


def _target_from(obj, where):
    if type(obj) is not dict:
        _fail("not_object", where)
    if "mode" not in obj:
        _fail("missing_field", where)
    mode = _choice(obj["mode"], {"creation", "existing"}, where + ".mode")
    if mode == "existing":
        t = _fields(obj, where, ("mode", "repository", "pins_sha256"))
        return ExistingTarget(_repository(t["repository"]), t["pins_sha256"])
    t = _fields(
        obj,
        where,
        ("mode", "owner", "repository", "intent_id", "precreation_sha256"),
        special={"repository_id": "repository_id_in_precreation"},
    )
    r = _fields(
        t["repository"],
        where + ".repository",
        ("name", "visibility", "default_branch"),
        special=_NO_ID,
    )
    return CreationTarget(
        _owner(t["owner"]),
        r["name"],
        r["visibility"],
        r["default_branch"],
        t["intent_id"],
        t["precreation_sha256"],
    )


def _setting(obj):
    s = _fields(obj, "setting", ("control", "blocking", "value"))
    control = _member(Control, s["control"], "setting.control", "unknown_control")
    return ControlSetting(control, s["blocking"], _value_from_wire(control, s["value"]))


def _settings_from(value, where):
    return tuple(_setting(i) for i in _array(value, where))


def _provider(value):
    if value != "github" or type(value) is not str:
        _fail("bad_value", "provider")


def parse_profile(raw):
    d = _fields(_load(raw, PROFILE), "profile", ("schema", "profile_id", "controls"))
    return Profile(d["profile_id"], _settings_from(d["controls"], "profile.controls"))


def parse_manifest(raw):
    d = _fields(
        _load(raw, MANIFEST),
        "manifest",
        ("schema", "manifest_id", "profile_id", "target", "controls"),
    )
    return Manifest(
        d["manifest_id"],
        d["profile_id"],
        _target_from(d["target"], "manifest.target"),
        _settings_from(d["controls"], "manifest.controls"),
    )


def parse_desired(raw):
    d = _fields(
        _load(raw, DESIRED),
        "desired",
        ("schema", "profile_id", "manifest_id", "target", "controls"),
    )
    return DesiredState(
        d["profile_id"],
        d["manifest_id"],
        _target_from(d["target"], "desired.target"),
        _settings_from(d["controls"], "desired.controls"),
    )


_LIMITATION_KEYS = (
    "control",
    "repository_id",
    "endpoint",
    "documentation_ref",
    "documentation_version",
    "visibility_ref",
    "plan_ref",
    "observed_at",
    "corroboration_refs",
)


def _limitation(obj, where, extra=()):
    e = _fields(obj, where, extra + _LIMITATION_KEYS)
    return Limitation(
        _member(Control, e["control"], where + ".control", "unknown_control"),
        e["repository_id"],
        e["endpoint"],
        e["documentation_ref"],
        e["documentation_version"],
        e["visibility_ref"],
        e["plan_ref"],
        e["observed_at"],
        tuple(_array(e["corroboration_refs"], where + ".corroboration_refs")),
    )


def _identity(obj, where="actual.repository"):
    r = _fields(
        obj,
        where,
        (
            "owner",
            "id",
            "name",
            "full_name",
            "visibility",
            "default_branch",
            "unavailable_reason",
        ),
    )
    ref = RepositoryRef(_owner(r["owner"]), r["id"], r["name"], r["full_name"])
    return ObservedIdentity(
        ref, r["visibility"], r["default_branch"], r["unavailable_reason"]
    )


def _observation(obj):
    base = _fields(
        obj, "observation", ("control", "status"), ("value", "reason", "limitation")
    )
    control = _member(
        Control, base["control"], "observation.control", "unknown_control"
    )
    status = _choice(
        base["status"], {"observed", "unavailable", "unsupported"}, "observation.status"
    )
    if status == "observed":
        o = _fields(obj, "observation", ("control", "status", "value"))
        return Observation(control, True, _value_from_wire(control, o["value"]))
    if status == "unsupported":
        o = _fields(obj, "observation", ("control", "status", "limitation"))
        limitation = _limitation(o["limitation"], "observation.limitation")
        return Observation(control, False, None, None, limitation)
    o = _fields(obj, "observation", ("control", "status", "reason"))
    return Observation(control, False, None, o["reason"])


def parse_actual(raw):
    d = _fields(
        _load(raw, ACTUAL),
        "actual",
        (
            "schema",
            "repository",
            "desired_sha256",
            "provenance",
            "source_ref",
            "observed_at",
            "scope",
            "complete",
            "observations",
        ),
    )
    return ActualState(
        _identity(d["repository"]),
        d["desired_sha256"],
        d["provenance"],
        d["source_ref"],
        d["observed_at"],
        tuple(
            _member(Control, c, "actual.scope", "unknown_control")
            for c in _array(d["scope"], "actual.scope")
        ),
        d["complete"],
        tuple(
            _observation(i) for i in _array(d["observations"], "actual.observations")
        ),
    )


def parse_result(raw):
    d = _fields(
        _load(raw, RESULT),
        "result",
        (
            "schema",
            "desired_sha256",
            "actual_sha256",
            "control",
            "blocking",
            "result",
            "evidence",
        ),
    )
    control = _member(Control, d["control"], "result.control", "unknown_control")
    result = _member(Result, d["result"], "result.result")
    kind, _cls = _EVIDENCE[result]
    ev = d["evidence"]
    if type(ev) is dict and ev.get("kind") != kind:
        _fail("evidence_mismatch", "result.evidence")
    if type(ev) is not dict:
        _fail("not_object", "result.evidence")

    def value(item):
        return _value_from_wire(control, item)

    if result in (Result.COMPLIANT, Result.NONCOMPLIANT):
        e = _fields(ev, "evidence", ("kind", "desired", "observed"))
        evidence = (Match if result is Result.COMPLIANT else Difference)(
            value(e["desired"]), value(e["observed"])
        )
    elif result is Result.UNVERIFIED:
        evidence = Unavailable(_fields(ev, "evidence", ("kind", "reason"))["reason"])
    elif result is Result.UNSUPPORTED:
        evidence = _limitation(ev, "evidence", extra=("kind",))
    else:
        e = _fields(ev, "evidence", ("kind", "observations"))
        items = []
        for item in _array(e["observations"], "evidence.observations"):
            o = _fields(item, "evidence.observation", ("ref", "value"))
            items.append(ConflictingObservation(o["ref"], value(o["value"])))
        evidence = Conflict(tuple(items))
    return ControlResult(
        d["desired_sha256"],
        d["actual_sha256"],
        control,
        d["blocking"],
        result,
        evidence,
    )


def parse_precreation(raw):
    d = _fields(
        _load(raw, PRECREATION),
        "precreation",
        (
            "schema",
            "provider",
            "owner",
            "repository",
            "admin_scope",
            "authorization_ref",
            "intent_id",
        ),
        special={"repository_id": "repository_id_in_precreation"},
    )
    _provider(d["provider"])
    r = _fields(
        d["repository"],
        "precreation.repository",
        ("name", "visibility", "default_branch"),
        special=_NO_ID,
    )
    return PreCreation(
        _owner(d["owner"]),
        r["name"],
        r["visibility"],
        r["default_branch"],
        tuple(_array(d["admin_scope"], "precreation.admin_scope")),
        d["authorization_ref"],
        d["intent_id"],
    )


def parse_existing(raw):
    d = _fields(
        _load(raw, EXISTING),
        "existing",
        (
            "schema",
            "provider",
            "repository",
            "admin_scope",
            "authorization_ref",
            "origin",
        ),
    )
    _provider(d["provider"])
    origin = d["origin"]
    if origin is not None:
        o = _fields(
            origin,
            "existing.origin",
            ("intent_id", "precreation_sha256", "binding_sha256"),
        )
        origin = Origin(o["intent_id"], o["precreation_sha256"], o["binding_sha256"])
    return ExistingPins(
        _repository(d["repository"]),
        tuple(_array(d["admin_scope"], "existing.admin_scope")),
        d["authorization_ref"],
        origin,
    )


def parse_binding(raw):
    d = _fields(
        _load(raw, BINDING),
        "binding",
        (
            "schema",
            "intent_id",
            "precreation_sha256",
            "creation_effect_ref",
            "observation",
            "repository",
        ),
    )
    o = _fields(d["observation"], "binding.observation", ("kind", "ref", "observed_at"))
    if o["kind"] != "independent_read" or type(o["kind"]) is not str:
        _fail("binding_provenance", "binding.observation.kind")
    return Binding(
        d["intent_id"],
        d["precreation_sha256"],
        d["creation_effect_ref"],
        o["ref"],
        o["observed_at"],
        _repository(d["repository"]),
    )


def parse_compliance(raw):
    d = _fields(
        _load(raw, COMPLIANCE),
        "compliance",
        (
            "schema",
            "repository",
            "desired_sha256",
            "actual_sha256",
            "overall",
            "evidence_ref",
            "result_digests",
        ),
    )
    return ComplianceReport(
        _repository(d["repository"]),
        d["desired_sha256"],
        d["actual_sha256"],
        _member(Result, d["overall"], "compliance.overall"),
        d["evidence_ref"],
        tuple(_array(d["result_digests"], "compliance.result_digests")),
    )


def parse_enrollment(raw):
    d = _fields(
        _load(raw, ENROLLMENT),
        "enrollment",
        ("schema", "repository", "evidence", "decision"),
        authority=True,
    )
    e = _fields(d["evidence"], "enrollment.evidence", ("ref", "sha256"), authority=True)
    n = _fields(
        d["decision"], "enrollment.decision", ("ref", "decided_at"), authority=True
    )
    return Enrollment(
        _repository(d["repository"], authority=True),
        e["ref"],
        e["sha256"],
        n["ref"],
        n["decided_at"],
    )
