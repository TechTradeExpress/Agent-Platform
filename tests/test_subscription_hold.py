"""Synthetic streams, Git and private operator records only; no live credentials."""

import json
import os
import socket
from dataclasses import replace
from pathlib import Path

import pytest
from test_native_codex import native as native
from test_prepare import git, snapshot
from test_prepare import task as task
from test_task_status import EXECUTION, SESSION, USAGE, set_phase
from test_task_status import ready as ready

from agent_platform import (
    execution,
    issues,
    native_codex,
    prepare,
    publisher,
    recovery,
    state,
    subscription,
)
from agent_platform import (
    subscription_hold as hold,
)


def stream(*, failed=False, usage=None, extra=None, session=SESSION):
    return tuple(
        json.dumps(item).encode()
        for item in (
            {"type": "thread.started", "thread_id": session},
            {"type": "turn.started"},
            {
                "type": "error",
                "message": "secret quota exhausted; reset tomorrow",
                "limit": {"verified": True, "remaining": 0},
            },
            {
                "type": "turn.failed" if failed else "turn.completed",
                "usage": USAGE if usage is None else usage,
                **(extra or {}),
            },
        )
    )


def reference(task):
    record = state.load_checkpoint(task["checkpoint"])
    admission = publisher.Admission(
        **{k: record[k] for k in publisher.Admission.__dataclass_fields__}
    )
    return recovery.RecoveryReference(
        admission,
        record["generation"],
        record.get("execution_id"),
        record["codex_thread_id"],
        publisher.digest(record),
    )


def decision(task, reason=hold.HoldReason.OPERATOR_PAUSE):
    ref = reference(task)
    return hold.HoldDecision(ref.admission, reason, ref)


def path(task):
    return task["home"] / ".local/state/agent-platform-holds/12/issue-1.json"


def checked(result):
    report, code = result
    raw = publisher.encoded(report)
    assert len(raw) < 4096 and b"secret" not in raw and b"auth.json" not in raw
    assert not report["resume_authorized"] and not report["launch_allowed"]
    assert report["runtime_status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert report["reset_at"] is None
    assert report["remaining_subscription_quota"] == "unknown"
    assert report["live_activity"] == "unknown"
    assert report["report_sha256"] == publisher.digest(
        {k: v for k, v in report.items() if k != "report_sha256"}
    )
    return report, code


def inspect(task, request):
    result = checked(hold.report(task["root"], request.admission))
    assert checked(hold.report(task["root"], request.admission)) == result
    assert str(task["home"]) not in json.dumps(result)
    return result


def test_success_counts_are_not_remaining_quota():
    evidence = hold.summarize(
        stream(extra={"remaining": 0, "reset_at": "tomorrow"}),
        0,
        expected_session=SESSION,
    )
    assert evidence == hold.LimitEvidence(
        "unknown", "synthetic_jsonl", "COMPLETED", hold.Usage(**USAGE)
    )
    assert "secret" not in repr(evidence)


def test_failed_turn_and_spoofed_structured_quota_are_unclassified():
    evidence = hold.summarize(
        stream(
            failed=True,
            extra={
                "error": {
                    "message": "secret quota limit",
                    "code": "usage_limit_reached",
                },
                "quota": {"verified": True, "remaining": 0, "reset_at": 123},
            },
        ),
        1,
        expected_session=SESSION,
    )
    assert evidence.classification == "turn_failed_unclassified"
    assert evidence.phase == "PAUSED" and evidence.usage is None
    assert "quota" not in repr(evidence) and "secret" not in repr(evidence)


@pytest.mark.parametrize(
    "raw",
    [
        b"{secret",
        b"\xff",
        b"[]",
        b'{"type":NaN}',
        b'{"type":"turn.failed","type":"turn.completed"}',
        b'{"type":"rate_limits.updated","remaining":0}',
    ],
)
def test_malformed_or_unrecognized_events_never_prove_limit(raw):
    evidence = hold.summarize(stream()[:-1] + (raw,), 0, expected_session=SESSION)
    assert evidence == hold.LimitEvidence("unknown", "none")


@pytest.mark.parametrize(
    "kind", ["interrupted", "exit", "session", "count", "line", "total", "container"]
)
def test_ambiguous_or_oversized_stream_discards_partial_facts(kind):
    lines, rc, session = stream(), 0, SESSION
    if kind == "interrupted":
        lines = lines[:-1]
    elif kind == "exit":
        rc = 1
    elif kind == "session":
        session = EXECUTION
    elif kind == "count":
        lines = (b"{}",) * (hold.MAX_LINES + 1)
    elif kind == "line":
        lines = (b"x" * (hold.MAX_LINE_BYTES + 1),)
    elif kind == "total":
        lines = stream()[:-1] + tuple(
            json.dumps({"type": "error", "message": "x" * 60000}).encode()
            for _ in range(20)
        )
    else:
        lines = list(lines)
    assert hold.summarize(lines, rc, expected_session=session) == hold.LimitEvidence(
        "unknown", "none"
    )


@pytest.mark.parametrize(
    "usage",
    [
        {},
        {"input_tokens": True, "cached_input_tokens": 0, "output_tokens": 1},
        {"input_tokens": 1, "cached_input_tokens": 2, "output_tokens": 1},
        {"input_tokens": -1, "cached_input_tokens": 0, "output_tokens": 1},
    ],
)
def test_inconsistent_usage_cannot_be_reported_as_verified(usage):
    assert (
        hold.summarize(stream(usage=usage), 0, expected_session=SESSION).provenance
        == "none"
    )


def test_verified_limit_classification_is_not_constructible():
    with pytest.raises(hold.HoldError):
        hold.LimitEvidence("verified_limit", "synthetic_jsonl")


@pytest.mark.parametrize(
    "phase", ["READY", "STARTING", "RUNNING", "PAUSED", "NEEDS_HUMAN", "COMPLETED"]
)
def test_hold_is_distinct_from_every_checkpoint_phase(ready, phase):
    set_phase(ready, phase)
    request = decision(ready)
    before = snapshot(ready["home"] / ".local/state/agent-platform")
    git_before = snapshot(ready["root"] / ".git")
    result, code = checked(hold.set_hold(ready["root"], request))
    assert code == 0 and result["hold_state"] == "active"
    assert result["classification"] == "operator_hold"
    assert result["display_status"] == "WAITING"
    assert result["limit_provenance"] == "trusted_operator_decision"
    assert result["observed_phase"] == phase
    assert result["manual_intervention_required"]
    assert result["turn_classification"] == (
        "turn_failed_unclassified" if phase == "PAUSED" else "unknown"
    )
    assert result["usage"] == (USAGE if phase == "COMPLETED" else None)
    assert inspect(ready, request)[1] == 0
    assert snapshot(ready["home"] / ".local/state/agent-platform") == before
    assert snapshot(ready["root"] / ".git") == git_before
    assert path(ready).stat().st_mode & 0o777 == 0o600
    assert path(ready).parent.stat().st_mode & 0o777 == 0o700


def test_missing_hold_is_unknown_not_a_release_or_quota_wait(ready):
    set_phase(ready, "PAUSED")
    request = decision(ready)
    before = snapshot(ready["home"])
    result, code = inspect(ready, request)
    assert code == 12 and result["hold_state"] == "unknown"
    assert result["classification"] == "turn_failed_unclassified"
    assert result["display_status"] == "NEEDS_HUMAN"
    assert "hold_record" in result["missing_evidence"]
    assert snapshot(ready["home"]) == before


def test_explicit_preparation_free_hold_with_trusted_admission(task):
    admission = publisher.Admission(
        **prepare.approved(
            issues.GitHub("example/target"), "example/target", 1, ["maintainer"]
        )
    )
    request = hold.HoldDecision(admission, hold.HoldReason.SUBSCRIPTION_UNCERTAINTY)
    with state.host_lock():
        pass  # Existing host mutex is a prerequisite, never created by HOLD.
    result, code = checked(hold.set_hold(task["root"], request))
    assert code == 0 and result["observed_phase"] is None
    assert not task["checkpoint"].exists()
    assert json.loads(path(task).read_bytes())["checkpoint"] is None
    assert inspect(task, request)[0]["hold_state"] == "active"


def test_duplicate_is_read_only_but_conflicting_reason_is_refused(ready, monkeypatch):
    request = decision(ready)
    first, code = checked(hold.set_hold(ready["root"], request))
    assert code == 0
    before = snapshot(ready["home"])

    def forbidden(*args, **kwargs):
        pytest.fail("duplicate/conflicting HOLD must not write")

    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    again, code = checked(hold.set_hold(ready["root"], request))
    assert code == 0 and again["operation"] == "already_recorded"
    assert again["idempotency_key"] == first["idempotency_key"]
    conflict, code = checked(
        hold.set_hold(
            ready["root"], replace(request, reason=hold.HoldReason.REVIEW_REQUIRED)
        )
    )
    assert code == 12 and conflict["reason"] == "hold_conflict"
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("issue", 2),
        ("repo_id", 13),
        ("repository", "other/repo"),
        ("scope_sha256", "b" * 64),
        ("scope_revision", "2026-10-28T12:00:00Z"),
        ("admission_sha256", "b" * 64),
        ("base_sha", "b" * 40),
        ("issue_id", 999),
    ],
)
def test_wrong_admission_cannot_read_or_create_valid_hold(ready, field, value):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    changed = replace(request.admission, **{field: value})
    before = snapshot(ready["home"])
    result, code = checked(hold.report(ready["root"], changed))
    assert code == 12 and result["hold_state"] == "unknown"
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", 20),
        ("session_id", SESSION),
        ("execution_id", EXECUTION),
        ("checkpoint_sha256", "b" * 64),
    ],
)
def test_exact_operator_reference_required_before_writing(ready, field, value):
    request = decision(ready)
    request = replace(request, checkpoint=replace(request.checkpoint, **{field: value}))
    result, code = checked(hold.set_hold(ready["root"], request))
    assert code == 12 and result["reason"] == "checkpoint_reference_conflict"
    assert not path(ready).exists()


def test_changed_generation_or_session_does_not_release_old_hold(ready):
    set_phase(ready, "PAUSED")
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    original = path(ready).read_bytes()
    set_phase(ready, "PAUSED", attempt=2)
    result, code = inspect(ready, request)
    assert code == 12 and result["hold_state"] == "unknown"
    assert result["reason"] == "hold_conflict"
    assert path(ready).read_bytes() == original
    assert checked(hold.set_hold(ready["root"], decision(ready)))[1] == 12


def test_interrupted_atomic_write_leaves_evidence_and_blocks_replay(ready, monkeypatch):
    request = decision(ready)
    cp_before = ready["checkpoint"].read_bytes()
    original = os.replace

    def interrupted(source, destination):
        if destination == path(ready):
            raise OSError("secret simulated crash")
        return original(source, destination)

    monkeypatch.setattr(os, "replace", interrupted)
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    artifacts = list(path(ready).parent.glob("*.tmp-*"))
    assert len(artifacts) == 1 and not path(ready).exists()
    before = snapshot(ready["home"])
    assert inspect(ready, request)[1] == 12
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert snapshot(ready["home"]) == before
    assert ready["checkpoint"].read_bytes() == cp_before


def test_failure_after_replace_is_uncertain_but_restart_retains_hold(
    ready, monkeypatch
):
    request = decision(ready)
    original = state.sync_directory

    def fail(directory):
        if directory == path(ready).parent:
            raise OSError("secret directory flush failure")
        return original(directory)

    monkeypatch.setattr(state, "sync_directory", fail)
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert path(ready).is_file()
    monkeypatch.setattr(state, "sync_directory", original)
    assert inspect(ready, request)[0]["hold_state"] == "active"
    assert (
        checked(hold.set_hold(ready["root"], request))[0]["operation"]
        == "already_recorded"
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{secret",
        b"[]",
        b'{"kind":NaN}',
        b'{"schema_version":1,"schema_version":2}',
        b"x" * (state.CHECKPOINT_LIMIT + 1),
    ],
)
def test_corrupt_hold_is_preserved_and_never_means_released(ready, raw):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    path(ready).write_bytes(raw)
    before = snapshot(ready["home"])
    assert inspect(ready, request)[1] == 12
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize(
    "kind",
    ["symlink", "hardlink", "mode", "parent_mode", "parent_alias", "extra", "tamper"],
)
def test_unsafe_storage_is_never_repaired(ready, kind):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    p = path(ready)
    if kind == "symlink":
        p.unlink()
        p.symlink_to(ready["checkpoint"])
    elif kind == "hardlink":
        os.link(p, ready["home"] / "preserved-alias")
    elif kind == "mode":
        p.chmod(0o644)
    elif kind == "parent_mode":
        p.parent.chmod(0o755)
    elif kind == "parent_alias":
        p.parent.rename(p.parent.with_name("preserved"))
        p.parent.symlink_to(p.parent.with_name("preserved"), target_is_directory=True)
    elif kind == "extra":
        data = json.loads(p.read_bytes())
        data["reset_at"] = 1
        p.write_text(json.dumps(data))
    else:
        data = json.loads(p.read_bytes())
        data["idempotency_key"] = "b" * 64
        p.write_text(json.dumps(data))
    before = snapshot(ready["home"])
    assert inspect(ready, request)[1] == 12
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert snapshot(ready["home"]) == before


def test_busy_and_missing_mutex_never_initialize_hold_storage(task, ready, monkeypatch):
    request = decision(ready)
    with state.host_lock():
        result, code = checked(hold.set_hold(ready["root"], request))
        assert code == 10 and result["reason"] == "lock_busy"
    monkeypatch.setattr(state, "LOCK_DIR", task["home"] / "absent-lock")
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert not state.LOCK_DIR.exists() and not path(ready).exists()


def test_changed_checkpoint_guard_refs_and_source_alias_fail_closed(ready):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    alias = ready["root"].parent / "alias"
    alias.symlink_to(ready["root"], target_is_directory=True)
    assert checked(hold.report(alias, request.admission))[1] == 12
    guard = ready["checkpoint"].with_suffix(".execution-guard")
    guard.write_text("secret stale guard")
    guard.chmod(0o600)
    assert inspect(ready, request)[1] == 12
    git(ready["root"], "update-ref", "refs/remotes/origin/main", "0" * 40)
    assert inspect(ready, request)[1] == 12


def test_no_network_models_or_auth_and_only_explicit_hold_writes(ready, monkeypatch):
    request = decision(ready)
    before = snapshot(ready["home"] / ".local/state/agent-platform")

    def forbidden(*args, **kwargs):
        pytest.fail("no network, model, auth, signal or native session access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(issues, "GitHub", forbidden)
    monkeypatch.setattr(execution, "execute", forbidden)
    monkeypatch.setattr(native_codex, "execute", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    writer = state.write_checkpoint
    writes = []

    def scoped_write(p, *args, **kwargs):
        assert p == path(ready)
        writes.append(p)
        return writer(p, *args, **kwargs)

    monkeypatch.setattr(state, "write_checkpoint", scoped_write)
    assert checked(hold.set_hold(ready["root"], request))[1] == 0
    assert writes == [path(ready)]
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    opener = os.open

    def readonly(p, flags, *args, **kwargs):
        if p != os.devnull:
            assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            assert not {"auth.json", "codex-sessions"} & set(Path(p).parts)
        return opener(p, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", readonly)
    assert inspect(ready, request)[1] == 0
    assert snapshot(ready["home"] / ".local/state/agent-platform") == before


def test_native_subscription_gate_still_exits_13_before_inspection(ready, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("blocked native entrypoint cannot inspect or lock")

    monkeypatch.setattr(state, "host_lock", forbidden)
    with pytest.raises(state.PrepareError) as exc:
        native_codex.execute(None, 1, ["maintainer"])
    assert exc.value.code == 13 and exc.value.reason == "subscription_isolation_blocked"
    assert subscription.readiness()["status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"


def test_missing_lineage_or_model_decision_cannot_create_hold(ready):
    request = decision(ready)
    result, code = checked(
        hold.set_hold(ready["root"], replace(request, checkpoint=None))
    )
    assert code == 12 and result["reason"] == "checkpoint_reference_conflict"
    assert checked(hold.set_hold(ready["root"], {"reason": "operator_pause"}))[1] == 12
    with pytest.raises(hold.HoldError):
        hold.HoldDecision(request.admission, "operator_pause", request.checkpoint)
    assert not path(ready).exists()


@pytest.mark.parametrize(
    "kind", ["session", "corrupt_checkpoint", "scope", "dirty_source", "origin"]
)
def test_changed_local_identity_is_not_adopted(ready, kind):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    saved = path(ready).read_bytes()
    if kind == "session":
        set_phase(ready, "PAUSED")
        data = state.load_checkpoint(ready["checkpoint"])
        data["codex_thread_id"] = EXECUTION
        ready["checkpoint"].write_text(json.dumps(data))
    elif kind == "corrupt_checkpoint":
        ready["checkpoint"].write_text("{secret")
    elif kind == "scope":
        data = state.load_checkpoint(ready["checkpoint"])
        data["scope_sha256"] = "b" * 64
        ready["checkpoint"].write_text(json.dumps(data))
    elif kind == "dirty_source":
        (ready["root"] / "tracked.txt").write_text("secret changed source")
    else:
        git(
            ready["root"],
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/repo.git",
        )
    assert inspect(ready, request)[1] == 12
    assert path(ready).read_bytes() == saved


@pytest.mark.parametrize("kind", ["checkpoint", "hold", "lock"])
def test_changing_evidence_discards_report_and_never_continues(
    ready, monkeypatch, kind
):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    original = hold._snapshot
    calls = []

    def changing(*args):
        result = original(*args)
        calls.append(1)
        if len(calls) == 1:
            if kind == "checkpoint":
                set_phase(ready, "PAUSED")
            elif kind == "hold":
                path(ready).write_text("{secret")
            else:
                lock = state.LOCK_DIR / "prepare.lock"
                lock.rename(lock.with_name("preserved-lock"))
                lock.write_text("")
                lock.chmod(0o600)
        return result

    monkeypatch.setattr(hold, "_snapshot", changing)
    result, code = checked(hold.report(ready["root"], request.admission))
    assert code == 12 and result["hold_state"] == "unknown"
    assert result["observed_phase"] is None


def test_inconsistent_persisted_counts_fail_before_any_write(ready):
    set_phase(ready, "COMPLETED")
    data = state.load_checkpoint(ready["checkpoint"])
    data["usage"]["cached_input_tokens"] = data["usage"]["input_tokens"] + 1
    ready["checkpoint"].write_text(json.dumps(data))
    request = decision(ready)
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert not path(ready).exists()


def test_untrusted_errors_are_redacted(ready, monkeypatch):
    request = decision(ready)

    def bad(*args):
        raise hold.HoldError("secret token stderr /auth.json")

    monkeypatch.setattr(hold, "_snapshot", bad)
    assert (
        checked(hold.report(ready["root"], request.admission))[0]["reason"]
        == "unverified_evidence"
    )


def test_foreign_hold_owner_is_rejected_without_chown(ready, monkeypatch):
    from types import SimpleNamespace

    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    original = Path.lstat

    def foreign(p, *args, **kwargs):
        info = original(p, *args, **kwargs)
        if p == path(ready):
            fields = {k: getattr(info, k) for k in dir(info) if k.startswith("st_")}
            fields["st_uid"] = os.getuid() + 1
            return SimpleNamespace(**fields)
        return info

    monkeypatch.setattr(Path, "lstat", foreign)
    assert inspect(ready, request)[1] == 12
    assert checked(hold.set_hold(ready["root"], request))[1] == 12


def test_fabricated_account_assertions_do_not_create_quota_provenance():
    result = hold.summarize(
        stream(
            extra={
                "account_id": "fabricated-secret-account",
                "plan": "subscription",
                "quota": {"remaining": 0, "verified": True},
            }
        ),
        0,
        expected_session=SESSION,
    )
    assert result.classification == "unknown"
    assert "account" not in repr(result) and "secret" not in repr(result)


def test_bounded_hold_directory_has_no_partial_success(ready):
    request = decision(ready)
    checked(hold.set_hold(ready["root"], request))
    for n in range(2, 130):
        path(ready).with_name(f"issue-{n}.json").write_text("{}")
    before = snapshot(ready["home"])
    assert inspect(ready, request)[1] == 12
    assert checked(hold.set_hold(ready["root"], request))[1] == 12
    assert snapshot(ready["home"]) == before


def test_interrupted_native_session_persistence_blocks_hold_without_repair(
    native, monkeypatch
):
    from test_execution import events
    from test_native_codex import run, set_fake

    request = decision(native)
    set_fake(native, events())
    original = os.replace

    def interrupted(source, destination):
        if (
            destination == native["checkpoint"]
            and json.loads(Path(source).read_bytes())["phase"] == "RUNNING"
        ):
            raise InterruptedError("synthetic interrupted session persistence")
        return original(source, destination)

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(state.PrepareError):
        run(native)
    assert len(list(native["checkpoint"].parent.glob("issue-1.json.tmp-*"))) == 1
    assert native["checkpoint"].with_suffix(".execution-guard").exists()
    before = snapshot(native["home"])
    result, code = inspect(native, request)
    assert code == 12 and result["reason"] == "interrupted_checkpoint"
    assert result["display_status"] == "NEEDS_HUMAN"
    assert checked(hold.set_hold(native["root"], request))[1] == 12
    assert not path(native).exists()
    assert snapshot(native["home"]) == before
    assert len(native["calls"]) == 1
