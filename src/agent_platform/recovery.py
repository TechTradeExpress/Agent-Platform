"""Human investigation guidance only; never repair, resume or replay a task."""

from dataclasses import asdict, dataclass

from agent_platform import codex, issues, publisher, task_status


@dataclass(frozen=True, slots=True)
class RecoveryReference:
    """Optional exact snapshot pin from a separately trusted controller, not files."""

    admission: publisher.Admission
    generation: int
    execution_id: str | None
    session_id: str | None
    checkpoint_sha256: str

    def __post_init__(self):
        publisher.require(
            type(self.admission) is publisher.Admission
            and issues.positive_int(self.generation)
            and publisher.hex_digest(self.checkpoint_sha256),
            "invalid_recovery_reference",
        )
        for value in (self.execution_id, self.session_id):
            if value is not None:
                codex.session_id(value)


INVESTIGATE = (
    "Preserve worktree edits, checkpoints, guards and temporary recovery artifacts.",
    (
        "Independently establish process quiescence; recorded state and "
        "lock do not prove it."
    ),
    "Compare durable lineage with independently trusted redacted receipts.",
    "Reconcile possible external side effects with their authoritative owners.",
    "Request a separate human-approved intervention before changing state.",
)
PROHIBITED = (
    "automatic_retry_resume_replay_restart",
    "terminate_or_signal_processes",
    "adopt_unrelated_or_recent_session",
    "delete_guard_or_repair_checkpoint",
    "reset_stash_clean_checkout_or_discard_edits",
    "assume_missing_terminal_event_means_no_side_effects",
    "assume_completed_means_exactly_once",
    "github_writes_or_issue_transitions",
    "codex_authentication_inference_or_session_store_access",
    "telegram_sending_or_remote_commands",
    "enable_blocked_runtime_or_bypass_original_checks",
)
SUMMARIES = {
    "no_interruption_indicated": (
        "READY is recorded locally; this is not launch authorization."
    ),
    "interrupted_start": (
        "Start intent is recorded; whether a turn ran is unknown. Do not replay."
    ),
    "missing_terminal_or_late_failure": (
        "RUNNING lacks durable terminal evidence. Missing output, "
        "timeout, exit or persistence failure cannot be distinguished. "
        "Do not replay."
    ),
    "ambiguous_stop": (
        "The recorded outcome is uncertain; human reconciliation is required."
    ),
    "known_pause": (
        "A failed turn is recorded. Review side effects before "
        "separately authorizing any resume."
    ),
    "recorded_completion": (
        "Completion is recorded, but external side effects and "
        "exactly-once execution are unverified."
    ),
    "leftover_guard": (
        "A guard remains despite a ready/terminal record. Preserve it "
        "and reconcile provenance."
    ),
    "checkpoint_persistence_incomplete": (
        "An incomplete checkpoint transaction exists; do not promote "
        "temporary data or repeat the turn."
    ),
    "orphan_guard": (
        "A guard exists without a confirmed checkpoint. Preserve "
        "evidence and investigate."
    ),
    "identity_conflict": (
        "Repository, task, admission or ref identity is conflicting or unverifiable."
    ),
    "evidence_changed": (
        "Evidence changed during inspection; this snapshot cannot justify recovery."
    ),
    "session_reference_conflict": (
        "Recorded execution/session identity contradicts the "
        "independently supplied reference."
    ),
    "checkpoint_reference_conflict": (
        "Checkpoint scope, generation or digest contradicts the "
        "independently supplied reference."
    ),
    "reference_unverifiable": (
        "The supplied reference is unsupported; no independent "
        "comparison is established."
    ),
    "guard_conflict": (
        "Guard identity or safety is contradictory; preserve all artifacts."
    ),
    "checkpoint_invalid": (
        "Checkpoint data is invalid or contradictory; do not infer a recoverable turn."
    ),
    "checkpoint_missing": (
        "No confirmed checkpoint was found; no task is prepared or "
        "restarted by this plan."
    ),
    "lock_busy": (
        "The mutex is busy. No checkpoint snapshot was read; process "
        "activity remains unknown."
    ),
    "local_evidence_unavailable": (
        "Local evidence could not be established safely; preserve it "
        "for manual investigation."
    ),
}


def _classification(observation, details):
    failure = details.get("failure")
    if observation["host_lock"] == "busy":
        return "lock_busy"
    if failure == "interrupted_checkpoint":
        return "checkpoint_persistence_incomplete"
    if failure == "orphan_guard":
        return "orphan_guard"
    if failure in {
        "checkpoint_changed",
        "guard_changed",
        "lock_changed",
        "source_changed",
    }:
        return "evidence_changed"
    if (
        failure
        in {
            "identity_mismatch",
            "checkpoint_identity_mismatch",
            "unconfirmed_worktree",
            "unexpected_refs",
            "stale_or_diverged_refs",
            "ambiguous_store",
        }
        or observation["identity"] == "conflicting"
    ):
        return "identity_conflict"
    if observation["execution_guard"] == "invalid":
        return "guard_conflict"
    if observation["checkpoint_validity"] == "invalid" or failure in {
        "invalid_checkpoint",
        "invalid_lineage",
        "invalid_guard",
    }:
        return "checkpoint_invalid"
    if observation["checkpoint_validity"] == "missing":
        return "checkpoint_missing"
    if observation["identity"] != "verified":
        return "local_evidence_unavailable"
    phase = observation["recorded_state"]
    if observation["execution_guard"] == "present" and phase in {
        "READY",
        "PAUSED",
        "COMPLETED",
    }:
        return "leftover_guard"
    return {
        "READY": "no_interruption_indicated",
        "STARTING": "interrupted_start",
        "RUNNING": "missing_terminal_or_late_failure",
        "PAUSED": "known_pause",
        "NEEDS_HUMAN": "ambiguous_stop",
        "COMPLETED": "recorded_completion",
    }[phase]


def plan(cwd, number, *, reference=None):
    """Bounded JSON-ready plan from the shared status snapshot; no new I/O path."""
    observation, code, details = task_status.inspect_local(cwd, number)
    classification = _classification(observation, details)
    reference_status = "not_provided"
    reference_conflicts = []
    if reference is not None:
        if type(reference) is not RecoveryReference:
            reference_status = "unverified"
            classification = "reference_unverifiable"
        elif "admission" not in details:
            reference_status = "unverified"
        else:
            comparisons = {
                "admission": (asdict(reference.admission), details["admission"]),
                "generation": (reference.generation, observation["generation"]),
                "checkpoint_digest": (
                    reference.checkpoint_sha256,
                    details["checkpoint_sha256"],
                ),
                "execution_id": (reference.execution_id, details["execution_id"]),
                "session_id": (reference.session_id, observation["session_id"]),
            }
            reference_conflicts = [
                name
                for name, (expected, actual) in comparisons.items()
                if expected != actual
            ]
            reference_status = "conflicting" if reference_conflicts else "matched"
            if reference_conflicts:
                classification = (
                    "session_reference_conflict"
                    if {"execution_id", "session_id"} & set(reference_conflicts)
                    else "checkpoint_reference_conflict"
                )
    if reference_status == "conflicting":
        observation = {
            **observation,
            "session_id": None,
            "status": "ambiguous",
            "identity": "conflicting",
            "checkpoint_validity": "unverified",
        }
        details = {}
    fingerprints = {
        k: details.get(k) for k in ("refs_sha256", "isolation_sha256", "runtime_sha256")
    }
    missing = [
        "live_process_activity_unknown",
        "external_side_effects_unknown",
        "remote_admission_not_refreshed",
        "worktree_content_not_examined",
        "native_session_store_not_examined",
    ]
    if observation["identity"] != "verified":
        missing.append("local_identity_unverified")
    if reference_status != "matched":
        missing.append("independent_reference_not_matched")
    result = {
        "schema_version": 1,
        "issue": observation["issue"],
        "classification": classification,
        "summary": SUMMARIES[classification],
        "external_side_effects": "unknown_not_exactly_once",
        "human_reconciliation_required": classification != "no_interruption_indicated",
        "reconciliation_state": "NOT_INDICATED"
        if classification == "no_interruption_indicated"
        else "NEEDS_HUMAN",
        "local_evidence": observation,
        "trusted_reference": reference_status,
        "reference_conflicts": reference_conflicts,
        "checkpoint_version": details.get("checkpoint_version"),
        "checkpoint_sha256": details.get("checkpoint_sha256"),
        "execution_id": details.get("execution_id"),
        "recorded_fingerprints": fingerprints,
        "fingerprint_verification": "recorded_only_not_rehashed",
        "missing_or_unverified": missing,
        "safe_investigation": list(INVESTIGATE),
        "prohibited_without_separate_authorization": list(PROHIBITED),
        "safe_to_replay": False,
        "resume_authorized": False,
        "mutations_allowed": False,
    }
    result["plan_sha256"] = publisher.digest(result)
    return result, (
        2
        if code == 2
        else 10
        if code == 10
        else 0
        if classification == "no_interruption_indicated"
        else 12
    )
