"""HAR-02 trusted-caller OFFLINE binding advice. No loader, store or launcher.

Inputs are immutable, explicitly synthetic controller snapshots, never Issue,
checkout, model or serialized-report authority. A matching snapshot grants no
lease/effect. Authentication, durable CAS/continuity and real capability evidence
are not implemented. AP-CA/1 and native run/resume gates remain untouched.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from enum import StrEnum

from . import codex_assignment as ca

MAX_AGE = ca.MAX_AGE
MAX_ENTRIES = 4096
MAX_EPOCH = 2**63 - 1
ZERO = "0" * 64
CAPABILITY_REVISION = "AP-HCAP/1"
CAPABILITY_NAMES = (
    "native_event_parser",
    "exact_managed_build_parser_compatibility",
    "native_session_resume",
    "root_agents_loading",
    "official_executable_provenance",
    "complete_tool_auth_isolation",
    "process_tree_death",
    "native_account_eligibility",
    "product_execution",
)


REASONS = frozenset(
    {
        "invalid_contract",
        "stale_snapshot",
        "selection_unavailable",
        "selection_unapproved",
        "wrong_worker",
        "legacy_codex_only",
        "legacy_mismatch",
        "continuity_mismatch",
        "inventory_incomplete",
        "binding_mismatch",
        "capability_mismatch",
        "authorization_mismatch",
        "capability_unverified",
        "inventory_inconsistent",
        "assignment_replayed",
        "worker_busy_or_unknown",
        "snapshot_drift",
    }
)


class HarnessId(StrEnum):
    CODEX = "codex"
    CLAUDE_CODE = "claude_code"


class Blocked(ValueError):
    """Only closed, nonsecret reason codes leave the advice boundary."""


def need(condition, reason="invalid_contract"):
    if not condition:
        raise Blocked(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def sha(value):
    need(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value))


def public_ref(value):
    need(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value))


def integer(value, minimum=0):
    need(type(value) is int and minimum <= value <= MAX_EPOCH)


def version(value, expected):
    need(type(value) is str and value == expected)


def fresh(issued_at, expires_at, now):
    integer(issued_at)
    integer(expires_at, 1)
    need(issued_at <= now < expires_at <= issued_at + MAX_AGE, "stale_snapshot")


def capability_row(harness_id):
    need(type(harness_id) is HarnessId)
    return tuple(
        (
            name,
            "BLOCKED"
            if name == "product_execution"
            else "OFFLINE_CONTRACT"
            if name == "native_event_parser" and harness_id is HarnessId.CODEX
            else "REQUIRED_UNVERIFIED",
        )
        for name in CAPABILITY_NAMES
    )


def capability_matrix():
    """Exact HAR-01 document revision, not a live discovery/feature assertion."""
    return {
        "schema": CAPABILITY_REVISION,
        "scope": "DESIGN_ONLY",
        **{h.value: dict(capability_row(h)) for h in HarnessId},
        "launch_allowed": False,
    }


MATRIX_SHA256 = digest(capability_matrix())


@dataclass(frozen=True, slots=True)
class Binding:
    worker_ref: str
    enrollment_ref: str
    harness_id: HarnessId
    selection_epoch: int
    capability_matrix_sha256: str
    configuration_sha256: str
    executable_manifest_sha256: str
    parser_sha256: str
    instructions_sha256: str
    isolation_profile_sha256: str
    capability_revision: str = CAPABILITY_REVISION

    def __post_init__(self):
        public_ref(self.worker_ref)
        public_ref(self.enrollment_ref)
        need(type(self.harness_id) is HarnessId)
        integer(self.selection_epoch, 1)
        version(self.capability_revision, CAPABILITY_REVISION)
        need(self.capability_matrix_sha256 == MATRIX_SHA256)
        for value in (
            self.capability_matrix_sha256,
            self.configuration_sha256,
            self.executable_manifest_sha256,
            self.parser_sha256,
            self.instructions_sha256,
            self.isolation_profile_sha256,
        ):
            sha(value)

    def record(self):
        return {**asdict(self), "harness_id": self.harness_id.value}


@dataclass(frozen=True, slots=True)
class WorkerSelection:
    binding: Binding
    issuer_ref: str
    approval_sha256: str
    previous_selection_sha256: str
    continuity_witness_sha256: str
    state: str = "SELECTED"
    schema: str = "AP-HSEL/1"

    def __post_init__(self):
        version(self.schema, "AP-HSEL/1")
        need(type(self.binding) is Binding)
        replace(self.binding)
        public_ref(self.issuer_ref)
        for value in (
            self.approval_sha256,
            self.previous_selection_sha256,
            self.continuity_witness_sha256,
        ):
            sha(value)
        need(
            (self.binding.selection_epoch == 1)
            == (self.previous_selection_sha256 == ZERO)
        )
        need(
            type(self.state) is str
            and self.state in {"SELECTED", "QUIESCING", "RECONCILING", "BLOCKED"}
        )

    def record(self):
        return {
            **asdict(self),
            "binding": self.binding.record(),
            "launch_allowed": False,
        }

    @property
    def digest(self):
        return digest(self.record())


@dataclass(frozen=True, slots=True)
class CapabilitySnapshot:
    """Verified document snapshot only; unknown runtime support stays unknown."""

    binding: Binding
    values: tuple[tuple[str, str], ...]
    schema: str = "AP-HCAP-SNAPSHOT/1"

    def __post_init__(self):
        version(self.schema, "AP-HCAP-SNAPSHOT/1")
        need(type(self.binding) is Binding)
        replace(self.binding)
        need(
            type(self.values) is tuple
            and len(self.values) == len(CAPABILITY_NAMES)
            and all(
                type(item) is tuple
                and len(item) == 2
                and all(type(value) is str for value in item)
                for item in self.values
            )
        )
        need(self.values == capability_row(self.binding.harness_id))

    @property
    def digest(self):
        return digest(asdict(self))


@dataclass(frozen=True, slots=True)
class SelectionApproval:
    """External trusted-caller pins, NOT an authenticated operator receipt."""

    selection_sha256: str
    capabilities_sha256: str
    issuer_ref: str
    approval_sha256: str
    continuity_witness_sha256: str
    issued_at: int
    expires_at: int
    schema: str = "AP-HSEL-APPROVAL/1"
    provenance: str = "synthetic_operator_snapshot"

    def __post_init__(self):
        version(self.schema, "AP-HSEL-APPROVAL/1")
        version(self.provenance, "synthetic_operator_snapshot")
        public_ref(self.issuer_ref)
        for value in (
            self.selection_sha256,
            self.capabilities_sha256,
            self.approval_sha256,
            self.continuity_witness_sha256,
        ):
            sha(value)
        integer(self.issued_at)
        integer(self.expires_at, 1)
        need(self.issued_at < self.expires_at <= self.issued_at + MAX_AGE)


@dataclass(frozen=True, slots=True)
class TaskAuthorization:
    """Opaque complete target/role/App/admission policy digest from trusted caller.

    No harness selector. No target authorization is derived from these pins.
    AP-CA/1 migration binds the exact original object digest and agent mapping.
    """

    assignment_ref: str
    task_authorization_sha256: str
    task_identity_sha256: str
    worker_ref: str
    enrollment_ref: str
    selection_sha256: str
    agent_id: str
    model_policy_sha256: str
    account_policy_ref: str
    required_capabilities: tuple[str, ...]
    issued_at: int
    expires_at: int
    origin_schema: str = "AP-HAR-TASK/1"
    schema: str = "AP-HAR-AUTHORIZATION/1"
    provenance: str = "synthetic_task_authorization"

    def __post_init__(self):
        version(self.schema, "AP-HAR-AUTHORIZATION/1")
        version(self.provenance, "synthetic_task_authorization")
        need(
            type(self.origin_schema) is str
            and self.origin_schema in {"AP-HAR-TASK/1", "AP-CA/1"}
        )
        for value in (
            self.assignment_ref,
            self.worker_ref,
            self.enrollment_ref,
            self.account_policy_ref,
        ):
            public_ref(value)
        ca.agent(self.agent_id)
        for value in (
            self.task_authorization_sha256,
            self.task_identity_sha256,
            self.selection_sha256,
            self.model_policy_sha256,
        ):
            sha(value)
        need(type(self.required_capabilities) is tuple)
        need(len(self.required_capabilities) <= len(CAPABILITY_NAMES))
        need(
            all(
                type(name) is str and name in CAPABILITY_NAMES
                for name in self.required_capabilities
            )
        )
        need(len(set(self.required_capabilities)) == len(self.required_capabilities))
        need(tuple(sorted(self.required_capabilities)) == self.required_capabilities)
        integer(self.issued_at)
        integer(self.expires_at, 1)
        need(self.issued_at < self.expires_at <= self.issued_at + MAX_AGE)


@dataclass(frozen=True, slots=True)
class HarnessAssignment:
    binding: Binding
    assignment_ref: str
    selection_sha256: str
    task_authorization_sha256: str
    model_policy_sha256: str
    account_policy_ref: str
    schema: str = "AP-HASSIGN/1"

    def __post_init__(self):
        version(self.schema, "AP-HASSIGN/1")
        need(type(self.binding) is Binding)
        replace(self.binding)
        public_ref(self.assignment_ref)
        public_ref(self.account_policy_ref)
        for value in (
            self.selection_sha256,
            self.task_authorization_sha256,
            self.model_policy_sha256,
        ):
            sha(value)

    def record(self):
        return {
            **asdict(self),
            "binding": self.binding.record(),
            "launch_allowed": False,
        }

    @property
    def digest(self):
        return digest(self.record())


def bind(selection, authorization):
    """Copy the worker choice; there is deliberately no per-task harness option."""
    need(
        type(selection) is WorkerSelection and type(authorization) is TaskAuthorization
    )
    replace(selection)
    replace(authorization)
    need(selection.state == "SELECTED", "selection_unavailable")
    need(selection.digest == authorization.selection_sha256, "selection_unapproved")
    need(
        (selection.binding.worker_ref, selection.binding.enrollment_ref)
        == (authorization.worker_ref, authorization.enrollment_ref),
        "wrong_worker",
    )
    if authorization.origin_schema == "AP-CA/1":
        need(selection.binding.harness_id is HarnessId.CODEX, "legacy_codex_only")
    return HarnessAssignment(
        selection.binding,
        authorization.assignment_ref,
        selection.digest,
        authorization.task_authorization_sha256,
        authorization.model_policy_sha256,
        authorization.account_policy_ref,
    )


def bind_codex(legacy, selection, authorization):
    """Explicit AP-CA/1 compatibility adapter; never calls advise/arguments/execute."""
    need(type(legacy) is ca.CodexAssignment, "legacy_codex_only")
    replace(legacy)
    need(type(authorization) is TaskAuthorization)
    replace(authorization)
    need(authorization.origin_schema == "AP-CA/1", "legacy_codex_only")
    need(authorization.task_authorization_sha256 == legacy.digest, "legacy_mismatch")
    need(authorization.agent_id == legacy.agent_id, "legacy_mismatch")
    need(
        authorization.task_identity_sha256
        == digest(
            {
                "repo_id": legacy.admission.repo_id,
                "issue_id": legacy.admission.issue_id,
            }
        ),
        "legacy_mismatch",
    )
    need(
        (authorization.issued_at, authorization.expires_at)
        == (legacy.issued_at, legacy.expires_at),
        "legacy_mismatch",
    )
    return bind(selection, authorization)


@dataclass(frozen=True, slots=True)
class RetainedAttempt:
    assignment_ref: str
    assignment_sha256: str
    task_authorization_sha256: str
    task_identity_sha256: str
    worker_ref: str
    enrollment_ref: str
    selection_sha256: str
    selection_epoch: int
    state: str
    recorded_at: int
    schema: str = "AP-HAR-INTENT/1"

    def __post_init__(self):
        version(self.schema, "AP-HAR-INTENT/1")
        for value in (self.assignment_ref, self.worker_ref, self.enrollment_ref):
            public_ref(value)
        for value in (
            self.assignment_sha256,
            self.task_authorization_sha256,
            self.task_identity_sha256,
            self.selection_sha256,
        ):
            sha(value)
        integer(self.selection_epoch, 1)
        integer(self.recorded_at)
        need(
            type(self.state) is str
            and self.state in {"RESERVED", "PREPARED", "RUNNING", "UNKNOWN", "FINISHED"}
        )


@dataclass(frozen=True, slots=True)
class Inventory:
    """Complete global intent snapshot, plus exactly one worker's current choice.

    Completeness/generation/approval are external trusted-caller assertions.
    No reserve, release, lease expiry, store reconstruction or retry is supplied.
    """

    worker_ref: str
    enrollment_ref: str
    selections: tuple[WorkerSelection, ...]
    capabilities: CapabilitySnapshot
    approval: SelectionApproval
    retained: tuple[RetainedAttempt, ...]
    generation_sha256: str
    observed_at: int
    complete: bool
    schema: str = "AP-HAR-INVENTORY/1"
    provenance: str = "synthetic_harness_inventory"

    def __post_init__(self):
        version(self.schema, "AP-HAR-INVENTORY/1")
        version(self.provenance, "synthetic_harness_inventory")
        public_ref(self.worker_ref)
        public_ref(self.enrollment_ref)
        need(type(self.selections) is tuple and len(self.selections) == 1)
        need(type(self.selections[0]) is WorkerSelection)
        replace(self.selections[0])
        need(type(self.capabilities) is CapabilitySnapshot)
        replace(self.capabilities)
        need(type(self.approval) is SelectionApproval)
        replace(self.approval)
        need(type(self.retained) is tuple and len(self.retained) <= MAX_ENTRIES)
        for item in self.retained:
            need(type(item) is RetainedAttempt)
            replace(item)
        # Conflicting duplicates never get collapsed or last-wins treatment.
        for field in (
            "assignment_ref",
            "assignment_sha256",
            "task_authorization_sha256",
        ):
            need(
                len({getattr(item, field) for item in self.retained})
                == len(self.retained)
            )
        sha(self.generation_sha256)
        integer(self.observed_at)
        need(type(self.complete) is bool)


def advise(
    assignment,
    authorization,
    inventory,
    *,
    expected_worker,
    expected_selection_sha256,
    expected_generation_sha256,
    now,
    legacy=None,
):
    """Pure offline snapshot check. Repeated advice cannot consume/reserve work."""
    result = {
        "schema": "AP-HAR-ADVICE/1",
        "status": "BLOCKED",
        "reason": "invalid_contract",
        "assignment_sha256": None,
        "selection_sha256": None,
        "capabilities_sha256": None,
        "inventory_sha256": None,
        "evidence": "VERIFIED_OFFLINE",
        "host_evidence": "HOST_NOT_RUN",
        "runtime": "LIVE_NO_GO",
        "subscription": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "gate_73": "BLOCKED",
        "runtime_exit_code": 13,
        "reserved": False,
        "prepare_authorized": False,
        "launch_allowed": False,
        "resume_authorized": False,
        "publish_authorized": False,
    }
    try:
        need(type(assignment) is HarnessAssignment)
        need(type(authorization) is TaskAuthorization and type(inventory) is Inventory)
        replace(assignment)
        replace(authorization)
        replace(inventory)
        public_ref(expected_worker)
        integer(now)
        sha(expected_selection_sha256)
        sha(expected_generation_sha256)
        need(
            inventory.generation_sha256 == expected_generation_sha256,
            "continuity_mismatch",
        )
        need(inventory.complete is True, "inventory_incomplete")
        need(inventory.worker_ref == expected_worker, "wrong_worker")
        need(0 <= now - inventory.observed_at <= MAX_AGE, "stale_snapshot")
        before = digest(asdict(inventory))
        assignment_before = assignment.digest
        authorization_before = digest(asdict(authorization))
        selection = inventory.selections[0]
        binding = selection.binding
        need(selection.digest == expected_selection_sha256, "selection_unapproved")
        need(
            (binding.worker_ref, binding.enrollment_ref)
            == (expected_worker, inventory.enrollment_ref),
            "wrong_worker",
        )
        need(selection.state == "SELECTED", "selection_unavailable")
        need(
            assignment.binding == binding
            and assignment.selection_sha256 == selection.digest,
            "binding_mismatch",
        )
        approval = inventory.approval
        fresh(approval.issued_at, approval.expires_at, now)
        need(
            (
                approval.selection_sha256,
                approval.issuer_ref,
                approval.approval_sha256,
                approval.continuity_witness_sha256,
            )
            == (
                selection.digest,
                selection.issuer_ref,
                selection.approval_sha256,
                selection.continuity_witness_sha256,
            ),
            "selection_unapproved",
        )
        caps = inventory.capabilities
        need(
            caps.binding == binding and caps.digest == approval.capabilities_sha256,
            "capability_mismatch",
        )
        fresh(authorization.issued_at, authorization.expires_at, now)
        if authorization.origin_schema == "AP-CA/1":
            need(
                assignment == bind_codex(legacy, selection, authorization),
                "legacy_mismatch",
            )
        else:
            need(legacy is None, "legacy_mismatch")
        need(assignment == bind(selection, authorization), "authorization_mismatch")
        available = dict(caps.values)
        need(
            all(
                available[name] == "OFFLINE_CONTRACT"
                for name in authorization.required_capabilities
            ),
            "capability_unverified",
        )
        for old in inventory.retained:
            need(old.recorded_at <= now, "inventory_inconsistent")
            need(
                old.assignment_ref != assignment.assignment_ref
                and old.assignment_sha256 != assignment.digest
                and old.task_authorization_sha256
                != assignment.task_authorization_sha256
                and old.task_identity_sha256 != authorization.task_identity_sha256,
                "assignment_replayed",
            )
            if old.worker_ref == expected_worker:
                need(old.state == "FINISHED", "worker_busy_or_unknown")
        need(
            before == digest(asdict(inventory))
            and assignment_before == assignment.digest
            and authorization_before == digest(asdict(authorization)),
            "snapshot_drift",
        )
        result.update(
            status="OFFLINE_BINDING_MATCH",
            reason="binding_snapshot_only",
            assignment_sha256=assignment.digest,
            selection_sha256=selection.digest,
            capabilities_sha256=caps.digest,
            inventory_sha256=before,
        )
    except Blocked as error:
        result["reason"] = str(error) if str(error) in REASONS else "invalid_contract"
    except Exception:
        # No exception, native payload, path or untrusted value escapes.
        pass
    return result
