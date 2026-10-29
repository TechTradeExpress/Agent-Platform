"""Offline usage facts and explicit operator HOLD; never execution authority."""

import os
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agent_platform import cli, codex, issues, prepare, publisher, recovery, state
from agent_platform import task_status as status

MAX_LINES = 256
MAX_LINE_BYTES = 64 * 1024
MAX_STREAM_BYTES = 1024 * 1024


class HoldError(Exception):
    """Fixed refusal only, never input text or provider errors."""


def need(value, reason="unverified_evidence"):
    if not value:
        raise HoldError(reason)


class HoldReason(StrEnum):
    OPERATOR_PAUSE = "operator_pause"
    SUBSCRIPTION_UNCERTAINTY = "subscription_uncertainty"
    REVIEW_REQUIRED = "review_required"


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int

    def __post_init__(self):
        need(all(type(n) is int and 0 <= n < 2**63 for n in asdict(self).values()))
        need(self.cached_input_tokens <= self.input_tokens)


@dataclass(frozen=True, slots=True)
class LimitEvidence:
    classification: Literal["unknown", "turn_failed_unclassified"]
    provenance: Literal["none", "synthetic_jsonl", "persisted_checkpoint"]
    phase: str | None = None
    usage: Usage | None = None

    def __post_init__(self):
        need(
            type(self.classification) is str
            and self.classification in {"unknown", "turn_failed_unclassified"}
        )
        need(
            type(self.provenance) is str
            and self.provenance in {"none", "synthetic_jsonl", "persisted_checkpoint"}
        )
        need(self.phase is None or self.phase in status.PHASES)
        need(self.usage is None or type(self.usage) is Usage)
        need(
            self.classification != "turn_failed_unclassified" or self.phase == "PAUSED"
        )


def summarize(lines, returncode, *, expected_session):
    """Bounded synthetic JSONL only, through the existing exact-session parser.

    Neither structured turn.failed nor any error/prose/extra fields establish
    subscription limits. A malformed or interrupted stream discards all facts.
    """
    unknown = LimitEvidence("unknown", "none")
    try:
        need(type(lines) is tuple and len(lines) <= MAX_LINES)
        need(type(returncode) is int)
        codex.session_id(expected_session)
        parser = codex.Events(lambda _: None, expected=expected_session)
        total = 0
        for raw in lines:
            need(type(raw) is bytes and len(raw) <= MAX_LINE_BYTES)
            total += len(raw)
            need(total <= MAX_STREAM_BYTES)
            parser.accept(raw)
        phase = parser.finish(returncode)
        usage = None if parser.usage is None else Usage(**parser.usage)
        return LimitEvidence(
            "turn_failed_unclassified" if phase == "PAUSED" else "unknown",
            "synthetic_jsonl",
            phase,
            usage,
        )
    except (HoldError, codex.ProtocolError, TypeError, ValueError):
        return unknown


@dataclass(frozen=True, slots=True)
class HoldDecision:
    """Direct trusted operator input, never decoded from model or repository JSON."""

    admission: publisher.Admission
    reason: HoldReason
    checkpoint: recovery.RecoveryReference | None = None

    def __post_init__(self):
        need(type(self.admission) is publisher.Admission)
        need(type(self.reason) is HoldReason)
        if self.checkpoint is not None:
            need(type(self.checkpoint) is recovery.RecoveryReference)
            need(self.checkpoint.admission == self.admission)


def _snapshot(root, admission, fd):
    need(type(admission) is publisher.Admission and isinstance(root, Path))
    state.no_symlinks(root)
    state.no_symlinks(root / ".git")
    need(root.resolve() == root)
    source = prepare.source_snapshot(cli.inspect(root))
    need(source["repository"] == admission.repository)
    need(source["base_sha"] == admission.base_sha)
    report, details = status.empty_report(admission.issue), {}
    report["host_lock"] = "free"
    report, _ = status._observe(root, admission.issue, report, fd, details)
    reference = None
    if report["checkpoint_validity"] == "missing":
        need(
            prepare.worktrees(root)
            == {str(root): (admission.base_sha, "refs/heads/main")}
        )
    else:
        need(
            report["checkpoint_validity"] == "valid"
            and report["identity"] == "verified"
        )
        need(details["admission"] == asdict(admission))
        reference = recovery.RecoveryReference(
            admission,
            report["generation"],
            details["execution_id"],
            report["session_id"],
            details["checkpoint_sha256"],
        )
    need(prepare.source_snapshot(cli.inspect(root)) == source)
    if report["usage"] is not None:
        Usage(**report["usage"])
    return report, {
        "source_sha256": publisher.digest(source),
        "checkpoint": None if reference is None else asdict(reference),
    }


def _path(admission):
    store = prepare.HOME / ".local/state/agent-platform-holds"
    parent = store / str(admission.repo_id)
    return store, parent / f"issue-{admission.issue}.json"


def _file_fingerprint(path):
    try:
        return status.fingerprint(path.lstat())
    except FileNotFoundError:
        return None


def _load(path, store):
    if not state.private_directory(path.parent, store, create=False):
        return None, None
    # Bound discovery before the shared atomic-store reader checks orphan temps.
    with os.scandir(path.parent) as listing:
        for count, item in enumerate(listing, 1):
            need(count <= 128)
            need(
                re.fullmatch(
                    r"issue-[1-9][0-9]{0,18}\.json(?:\.tmp-[a-z0-9-]{1,64})?", item.name
                )
            )
    before = _file_fingerprint(path)
    value = state.load_checkpoint(path)
    after = _file_fingerprint(path)
    need(before == after)
    return value, after


def _record(admission, binding, reason):
    record = {
        "schema_version": 1,
        "kind": "OPERATOR_HOLD",
        "admission": asdict(admission),
        **binding,
        "reason": reason.value,
    }
    return {**record, "idempotency_key": publisher.digest(record)}


def _validate(record, admission, binding):
    need(type(record) is dict)
    reason = HoldReason(record["reason"])
    expected = _record(admission, binding, reason)
    # Canonical bytes distinguish booleans from numeric lineage/version fields.
    need(publisher.encoded(record) == publisher.encoded(expected), "hold_conflict")
    return reason


def _empty(number, operation):
    return {
        "schema_version": 1,
        "issue": number,
        "status": "blocked",
        "operation": operation,
        "reason": "unverified_evidence",
        "observed_phase": None,
        "live_activity": "unknown",
        "hold_state": "unknown",
        "hold_reason": None,
        "idempotency_key": None,
        "classification": "unknown",
        "limit_provenance": "none",
        "turn_classification": "unknown",
        "usage": None,
        "usage_provenance": "none",
        "remaining_subscription_quota": "unknown",
        "reset_at": None,
        "display_status": "NEEDS_HUMAN",
        "missing_evidence": [
            "subscription_quota",
            "account_identity",
            "live_activity",
            "hold_record",
        ],
        "manual_intervention_required": True,
        "resume_authorized": False,
        "launch_allowed": False,
        "runtime_status": "SUBSCRIPTION_ISOLATION_BLOCKED",
    }


def _present(result, observed, record):
    phase = observed["recorded_state"]
    failed = phase == "PAUSED" and observed["stop_reason"] == "turn_failed"
    result.update(
        observed_phase=phase,
        turn_classification="turn_failed_unclassified" if failed else "unknown",
        classification="turn_failed_unclassified" if failed else "unknown",
        limit_provenance="persisted_checkpoint" if failed else "none",
        usage=observed["usage"],
        usage_provenance="persisted_checkpoint"
        if observed["usage"] is not None
        else "none",
    )
    if record is None:
        result["reason"] = "hold_missing_not_release"
        return 12
    result.update(
        status="observed",
        reason="explicit_operator_hold",
        hold_state="active",
        hold_reason=record["reason"],
        idempotency_key=record["idempotency_key"],
        classification="operator_hold",
        limit_provenance="trusted_operator_decision",
        display_status="WAITING",
        missing_evidence=["subscription_quota", "account_identity", "live_activity"],
    )
    return 0


def _operate(root, admission, decision):
    operation = "inspect" if decision is None else "record"
    number = admission.issue if type(admission) is publisher.Admission else None
    result = _empty(number, operation)
    code = 12
    try:
        need(type(admission) is publisher.Admission)
        if decision is not None:
            need(type(decision) is HoldDecision and decision.admission == admission)
        with state.host_lock(create=False) as fd:
            lock = state.LOCK_DIR / "prepare.lock"
            lock_info = status.fingerprint(os.fstat(fd))
            need(status.fingerprint(lock.lstat()) == lock_info)
            observed, binding = _snapshot(root, admission, fd)
            store, path = _path(admission)
            record, before = _load(path, store)
            if record is not None:
                _validate(record, admission, binding)
            if decision is not None:
                expected_reference = (
                    None if decision.checkpoint is None else asdict(decision.checkpoint)
                )
                need(
                    binding["checkpoint"] == expected_reference,
                    "checkpoint_reference_conflict",
                )
                expected = _record(admission, binding, decision.reason)
                if record is not None:
                    need(record == expected, "hold_conflict")
                    result["operation"] = "already_recorded"
                else:
                    # All source/lineage/storage checks precede the only write.
                    need(_snapshot(root, admission, fd) == (observed, binding))
                    need(status.fingerprint(lock.lstat()) == lock_info)
                    need(state.private_directory(path.parent, store, create=True))
                    state.write_checkpoint(path, expected)
                    record, before = _load(path, store)
                    need(record == expected)
            need(_snapshot(root, admission, fd) == (observed, binding))
            need(_load(path, store) == (record, before))
            need(status.fingerprint(lock.lstat()) == lock_info)
            code = _present(result, observed, record)
    except state.PrepareError as exc:
        result = _empty(number, operation)
        result["reason"] = (
            "lock_busy"
            if exc.code == 10
            else (
                exc.reason
                if exc.reason in status.RECOVERY_FAILURES
                else "state_unverifiable"
            )
        )
        code = 10 if exc.code == 10 else 12
    except HoldError as exc:
        result = _empty(number, operation)
        if str(exc) in {"hold_conflict", "checkpoint_reference_conflict"}:
            result["reason"] = str(exc)
    except (
        OSError,
        cli.InspectionError,
        issues.AdmissionError,
        publisher.PlanError,
        codex.ProtocolError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ):
        result = _empty(number, operation)
    result["report_sha256"] = publisher.digest(result)
    need(len(publisher.encoded(result)) <= 4096)
    return result, code


def report(root: Path, admission: publisher.Admission):
    """Read-only offline inspection; absent state is unknown, never release."""
    return _operate(root, admission, None)


def set_hold(root: Path, decision: HoldDecision):
    """Explicit trusted operator call only; no release, signals or runner hooks."""
    admission = decision.admission if type(decision) is HoldDecision else None
    return _operate(root, admission, decision)
