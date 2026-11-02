"""Offline joined supervisory evidence; never a launcher or HOLD authority."""

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import NotRequired, TypedDict

from agent_platform import (
    cli,
    codex,
    issues,
    prepare,
    publisher,
    queue,
    recovery,
    state,
    task_status,
)
from agent_platform import (
    subscription_hold as hold,
)

MAX_AGE = 300
MAX_REPORT = 16 * 1024


class SupervisorError(Exception):
    """Fixed nonsecret refusal, never arbitrary input/provider text."""


def need(value, reason="invalid_supervisor_evidence"):
    if not value:
        raise SupervisorError(reason)


@dataclass(frozen=True, slots=True)
class Evidence:
    """Trusted controller inputs, NOT decoded from task files or model output.

    observed_at is the oldest remote observation time, not report creation time.
    The caller owns freshness and authenticated provenance; types/hashes do not.
    """

    admission: publisher.Admission
    queue_snapshot: queue.Snapshot
    observed_at: int
    reference: recovery.RecoveryReference | None = None

    def __post_init__(self):
        need(type(self.admission) is publisher.Admission)
        need(type(self.queue_snapshot) is queue.Snapshot)
        need(type(self.observed_at) is int and self.observed_at >= 0)
        need(
            self.reference is None or type(self.reference) is recovery.RecoveryReference
        )
        need(self.reference is None or self.reference.admission == self.admission)


def _validate(evidence, now):
    need(type(evidence) is Evidence and type(now) is int)
    need(0 <= now - evidence.observed_at <= MAX_AGE, "stale_remote_evidence")
    snapshot = evidence.queue_snapshot
    need(type(snapshot.policy) is queue.Policy)
    need(publisher.hex_digest(snapshot.digest))
    entries = snapshot.policy.entries
    need(type(entries) is tuple and 0 < len(entries) <= queue.MAX_ENTRIES)
    need(all(type(e) is queue.Entry for e in entries))
    need(len({e.admission.issue for e in entries}) == len(entries))
    pin = evidence.admission
    need(any(e.admission == pin for e in entries), "admission_conflict")
    need(
        all(
            (e.admission.repo_id, e.admission.repository, e.admission.base_sha)
            == (pin.repo_id, pin.repository, pin.base_sha)
            for e in entries
        )
    )
    observations = snapshot.observations
    need(type(observations) is tuple and len(observations) == len(entries))
    need(all(type(o) is queue.Observation for o in observations))
    need({o.issue for o in observations} == {e.admission.issue for e in entries})
    need(type(snapshot.pull_requests) is tuple)
    need(len(snapshot.pull_requests) <= queue.MAX_ENTRIES)
    need(all(type(p) is queue.PullRequest for p in snapshot.pull_requests))
    need(
        len({p.admission.issue for p in snapshot.pull_requests})
        == len(snapshot.pull_requests)
    )
    need(
        all(
            p.admission in tuple(e.admission for e in entries)
            for p in snapshot.pull_requests
        )
    )
    # Bound serialization even for accidentally malformed in-process values.
    need(len(publisher.encoded(asdict(evidence))) <= 64 * 1024)


def _read(root, evidence, fd):
    pin = evidence.admission
    local_state, local, source, inventory = queue._local(root, pin, fd)
    # Do not hide stale Issue/PR evidence behind the queue's local-task override.
    rows = queue._evaluate(root, evidence.queue_snapshot, ())
    # A PR must not mask a failed current admission (e.g. blocking labels).
    unadmitted = {
        o.issue
        for o in evidence.queue_snapshot.observations
        if o.state == "open" and not o.admitted
    }
    for row in rows:
        if row["issue"] in unadmitted:
            row.update(status="blocked", reason="admission_unverified")
    observed = task_status.empty_report(pin.issue)
    observed["host_lock"] = "free"
    details = {}
    observed, _ = task_status._observe(root, pin.issue, observed, fd, details)
    held_observed, binding = hold._snapshot(root, pin, fd)
    need(held_observed == observed, "evidence_changed")
    store, path = hold._path(pin)
    record, fingerprint = hold._load(path, store)
    if record is not None:
        hold._validate(record, pin, binding)
    return {
        "local_state": local_state,
        "local": local,
        "source": source,
        "inventory": inventory,
        "trees": prepare.worktrees(root),
        "rows": rows,
        "observed": observed,
        "details": details,
        "binding": binding,
        "hold": record,
        "hold_fingerprint": fingerprint,
    }


def _reference(evidence, reading):
    actual = reading["binding"]["checkpoint"]
    expected = evidence.reference
    if expected is None:
        return "not_provided" if actual is not None else "no_checkpoint"
    return "matched" if asdict(expected) == actual else "conflicting"


class DecisionReport(TypedDict):
    schema_version: int
    status: str
    display_status: str
    reason: str
    issue: int | None
    recorded_state: str | None
    recovery: str
    hold_state: str
    trusted_reference: str
    queue: list[queue.Evaluation]
    local_tasks: list[dict]
    snapshot_consistency: str
    remote_freshness: str
    live_activity: str
    external_side_effects: str
    manual_intervention_required: bool
    launch_allowed: bool
    resume_authorized: bool
    mutations_allowed: bool
    publish_authorized: bool
    safe_to_replay: bool
    runtime_status: str
    repository_id: int | None
    base_sha: str | None
    evidence_sha256: str | None
    queue_snapshot_sha256: str | None
    report_sha256: NotRequired[str]


def _empty() -> DecisionReport:
    return {
        "schema_version": 1,
        "status": "BLOCKED",
        "display_status": "NEEDS_HUMAN",
        "reason": "invalid_supervisor_evidence",
        "issue": None,
        "repository_id": None,
        "base_sha": None,
        "evidence_sha256": None,
        "queue_snapshot_sha256": None,
        "recorded_state": None,
        "recovery": "local_evidence_unavailable",
        "hold_state": "unknown",
        "trusted_reference": "unverified",
        "queue": [],
        "local_tasks": [],
        "snapshot_consistency": "unverified",
        "remote_freshness": "unverified",
        "live_activity": "unknown",
        "external_side_effects": "unknown_not_exactly_once",
        "manual_intervention_required": True,
        "launch_allowed": False,
        "resume_authorized": False,
        "mutations_allowed": False,
        "publish_authorized": False,
        "safe_to_replay": False,
        "runtime_status": "SUBSCRIPTION_ISOLATION_BLOCKED",
    }


def report(root: Path, evidence: Evidence, *, now: int) -> tuple[DecisionReport, int]:
    """Return (bounded JSON-ready report, exit code); perform no state mutation.

    One non-creating host lock covers two complete observations. Neither a stable
    snapshot nor a free mutex establishes liveness, release, or launch readiness.
    Explicit caller time permits deterministic offline tests without a scheduler.
    """
    result, code = _empty(), 12
    try:
        _validate(evidence, now)
        input_digest = publisher.digest(asdict(evidence))
        with state.host_lock(create=False) as fd:
            lock = state.LOCK_DIR / "prepare.lock"
            lock_info = task_status.fingerprint(os.fstat(fd))
            need(task_status.fingerprint(lock.lstat()) == lock_info, "evidence_changed")
            first = _read(root, evidence, fd)
            need(_read(root, evidence, fd) == first, "evidence_changed")
            need(task_status.fingerprint(lock.lstat()) == lock_info, "evidence_changed")
            need(publisher.digest(asdict(evidence)) == input_digest, "evidence_changed")
            reference = _reference(evidence, first)
            reason = "hold_active_activity_unknown"
            if any(r["status"] in {"unknown", "blocked"} for r in first["rows"]):
                reason = "queue_evidence_blocked"
            elif reference == "conflicting":
                reason = "checkpoint_reference_conflict"
            elif first["hold"] is None:
                reason = "hold_missing_not_release"
            elif first["observed"]["recorded_state"] == "COMPLETED":
                reason = "retained_completion_requires_reconciliation"
            elif reference == "not_provided":
                reason = "independent_reference_required"
            elif first["inventory"]:
                reason = "retained_task_requires_reconciliation"
            result.update(
                status="NEEDS_HUMAN",
                reason=reason,
                issue=evidence.admission.issue,
                repository_id=evidence.admission.repo_id,
                base_sha=evidence.admission.base_sha,
                evidence_sha256=input_digest,
                queue_snapshot_sha256=evidence.queue_snapshot.digest,
                recorded_state=first["observed"]["recorded_state"],
                recovery=recovery._classification(first["observed"], first["details"]),
                hold_state="active" if first["hold"] is not None else "missing_unknown",
                trusted_reference=reference,
                queue=first["rows"],
                local_tasks=list(first["local"]),
                snapshot_consistency="stable_observed_snapshot_not_atomic_world",
                remote_freshness="caller_attested_bounded_age_not_live",
            )
    except state.PrepareError as exc:
        result["reason"] = (
            "lock_busy" if exc.code == 10 else "local_evidence_unverifiable"
        )
        code = 10 if exc.code == 10 else 12
    except SupervisorError as exc:
        result["reason"] = str(exc)
    except hold.HoldError:
        result["reason"] = "hold_or_lineage_unverifiable"
    except (
        OSError,
        cli.InspectionError,
        issues.AdmissionError,
        publisher.PlanError,
        queue.QueueError,
        codex.ProtocolError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ):
        result["reason"] = "local_or_input_evidence_unverifiable"
    result["report_sha256"] = publisher.digest(result)
    need(len(publisher.encoded(result)) < MAX_REPORT)
    return result, code
