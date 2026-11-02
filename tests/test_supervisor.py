"""Synthetic Git, controller pins and private records; never live providers."""

import json
from dataclasses import replace

import pytest
from test_prepare import git, snapshot
from test_prepare import task as task
from test_queue import capture, idle, policy, pr
from test_subscription_hold import decision, path, reference
from test_task_status import EXECUTION, SESSION, set_phase
from test_task_status import ready as ready

from agent_platform import (
    execution,
    github_evidence,
    issues,
    native_codex,
    prepare,
    publisher,
    queue,
    state,
    supervisor,
)
from agent_platform import subscription_hold as hold

NOW = 1000


def evidence(task, *, ref=None, prs=()):
    pins = policy(task, count=1)
    return supervisor.Evidence(pins.entries[0].admission, capture(pins, prs), NOW, ref)


def checked(task, inputs, **kwargs):
    result, code = supervisor.report(task["root"], inputs, now=kwargs.get("now", NOW))
    raw = publisher.encoded(result)
    assert len(raw) < supervisor.MAX_REPORT
    assert str(task["home"]).encode() not in raw
    assert SESSION.encode() not in raw and EXECUTION.encode() not in raw
    assert b"secret" not in raw and b"auth.json" not in raw
    for key in (
        "launch_allowed",
        "resume_authorized",
        "mutations_allowed",
        "publish_authorized",
        "safe_to_replay",
    ):
        assert result[key] is False
    assert result["runtime_status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert result["live_activity"] == "unknown"
    assert result["display_status"] == "NEEDS_HUMAN"
    assert result["manual_intervention_required"]
    assert result["report_sha256"] == publisher.digest(
        {k: v for k, v in result.items() if k != "report_sha256"}
    )
    assert code in {10, 12}
    return result, code


def test_missing_hold_is_not_idle_or_release(task):
    idle()
    inputs = evidence(task)
    before = snapshot(task["home"])
    result, code = checked(task, inputs)
    assert code == 12
    assert result["reason"] == "hold_missing_not_release"
    assert result["recorded_state"] is None
    assert result["queue"][0]["status"] == "eligible_candidate"
    assert "next_candidate" not in result
    assert snapshot(task["home"]) == before


@pytest.mark.parametrize(
    "phase", ["READY", "PAUSED", "COMPLETED", "STARTING", "RUNNING", "NEEDS_HUMAN"]
)
def test_recorded_phase_never_authorizes_activity(ready, phase):
    set_phase(ready, phase)
    ref = reference(ready)
    assert hold.set_hold(ready["root"], decision(ready))[1] == 0
    inputs = evidence(ready, ref=ref)
    before = snapshot(ready["home"])
    result, code = checked(ready, inputs)
    assert code == 12 and result["recorded_state"] == phase
    assert result["hold_state"] == "active"
    assert result["trusted_reference"] == "matched"
    assert result["reason"] == (
        "retained_completion_requires_reconciliation"
        if phase == "COMPLETED"
        else "retained_task_requires_reconciliation"
    )
    assert snapshot(ready["home"]) == before


def test_active_preparation_hold_still_requires_human(task):
    idle()
    inputs = evidence(task)
    assert (
        hold.set_hold(
            task["root"],
            hold.HoldDecision(inputs.admission, hold.HoldReason.OPERATOR_PAUSE),
        )[1]
        == 0
    )
    result, _ = checked(task, inputs)
    assert result["reason"] == "hold_active_activity_unknown"
    assert result["hold_state"] == "active"


@pytest.mark.parametrize(
    "kind", ["missing", "corrupt", "conflict", "orphan", "session", "unsupported"]
)
def test_hold_and_checkpoint_uncertainty_preserves_everything(ready, kind):
    set_phase(ready, "PAUSED")
    ref = reference(ready)
    assert hold.set_hold(ready["root"], decision(ready))[1] == 0
    inputs = evidence(ready, ref=ref)
    if kind == "missing":
        path(ready).unlink()  # synthetic fixture only
    elif kind == "corrupt":
        path(ready).write_text('{"secret":')
    elif kind == "conflict":
        record = json.loads(path(ready).read_text())
        record["checkpoint"]["session_id"] = EXECUTION
        path(ready).write_text(json.dumps(record))
    elif kind == "orphan":
        ready["checkpoint"].with_suffix(".json.tmp-crash").write_text("secret")
    else:
        record = json.loads(ready["checkpoint"].read_text())
        record["codex_thread_id" if kind == "session" else "phase"] = (
            EXECUTION if kind == "session" else "UNSUPPORTED"
        )
        ready["checkpoint"].write_text(json.dumps(record))
    before = snapshot(ready["home"])
    result, _ = checked(ready, inputs)
    assert result["status"] in {"BLOCKED", "NEEDS_HUMAN"}
    assert result["reason"] != "hold_active_activity_unknown"
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize("kind", ["none", "session", "generation", "digest"])
def test_independent_reference_is_not_adopted(ready, kind):
    set_phase(ready, "PAUSED")
    ref = reference(ready)
    hold.set_hold(ready["root"], decision(ready))
    changed = (
        None
        if kind == "none"
        else replace(
            ref,
            **{
                "session": {"session_id": EXECUTION},
                "generation": {"generation": ref.generation + 1},
                "digest": {"checkpoint_sha256": "f" * 64},
            }[kind],
        )
    )
    result, _ = checked(ready, evidence(ready, ref=changed))
    assert result["reason"] == (
        "independent_reference_required"
        if kind == "none"
        else "checkpoint_reference_conflict"
    )


@pytest.mark.parametrize(
    "kind", ["scope", "closed", "admission", "pin", "head", "base"]
)
def test_stale_issue_pr_and_base_are_not_hidden_by_local_task(ready, kind):
    pins = policy(ready, count=1)
    receipt = pr(
        ready, pins, state="open", merged=False, merge_sha=None, merged_at=None
    )
    inputs = evidence(ready, prs=(receipt,) if kind in {"head", "base"} else ())
    captured = inputs.queue_snapshot
    if kind in {"head", "base"}:
        receipt = replace(
            receipt,
            **{
                "expected_head_sha" if kind == "head" else "default_branch_sha": "f"
                * 40
            },
        )
        captured = replace(captured, pull_requests=(receipt,))
    else:
        changes = {
            "scope": {"scope_matches": False},
            "closed": {"state": "closed"},
            "admission": {"admitted": False},
            "pin": {"pin": replace(inputs.admission, scope_sha256="f" * 64)},
        }[kind]
        captured = replace(
            captured, observations=(replace(captured.observations[0], **changes),)
        )
    result, _ = checked(ready, replace(inputs, queue_snapshot=captured))
    assert result["reason"] == "queue_evidence_blocked"


@pytest.mark.parametrize("age", [-1, 301])
def test_remote_age_fails_before_local_io(task, monkeypatch, age):
    inputs = evidence(task)
    monkeypatch.setattr(state, "host_lock", lambda **kw: pytest.fail("lock reached"))
    result, _ = checked(task, inputs, now=NOW + age)
    assert result["reason"] == "stale_remote_evidence"


@pytest.mark.parametrize(
    "kind", ["hold", "checkpoint", "guard", "lock", "refs", "trees", "inventory"]
)
def test_changes_between_complete_observations_are_rejected(ready, monkeypatch, kind):
    set_phase(ready, "PAUSED")
    hold.set_hold(ready["root"], decision(ready))
    inputs = evidence(ready, ref=reference(ready))
    original = supervisor._read
    calls = 0

    def changing(*args):
        nonlocal calls
        calls += 1
        result = original(*args)
        if calls == 1:
            if kind == "hold":
                path(ready).write_text('{"secret":')
            elif kind == "checkpoint":
                ready["checkpoint"].write_text('{"secret":')
            elif kind == "guard":
                marker = ready["checkpoint"].with_suffix(".execution-guard")
                marker.write_text(EXECUTION + "\n")
                marker.chmod(0o600)
            elif kind == "lock":
                lock = state.LOCK_DIR / "prepare.lock"
                lock.rename(state.LOCK_DIR / "old-lock")
                lock.write_text("")
                lock.chmod(0o600)
            elif kind == "refs":
                git(ready["root"], "branch", "unexpected")
            elif kind == "trees":
                git(
                    ready["root"],
                    "worktree",
                    "add",
                    "--detach",
                    str(ready["home"] / "extra"),
                )
            else:
                ready["checkpoint"].with_name("issue-2.json.tmp-crash").write_text(
                    "secret"
                )
        return result

    monkeypatch.setattr(supervisor, "_read", changing)
    result, _ = checked(ready, inputs)
    assert result["status"] == "BLOCKED"
    assert result["snapshot_consistency"] == "unverified"


def test_missing_and_busy_mutex_never_created(task):
    inputs = evidence(task)
    result, code = checked(task, inputs)
    assert code == 12 and not state.LOCK_DIR.exists()
    with state.host_lock():
        result, code = checked(task, inputs)
        assert code == 10 and result["reason"] == "lock_busy"


def test_no_writer_network_session_or_runtime_route(ready, monkeypatch):
    set_phase(ready, "PAUSED")
    hold.set_hold(ready["root"], decision(ready))
    inputs = evidence(ready, ref=reference(ready))
    (ready["worktree"] / "coding-edit.txt").write_text("secret legitimate edit")
    before = snapshot(ready["home"])

    def forbidden(*args, **kwargs):
        pytest.fail("forbidden side effect")

    for module, name in (
        (state, "write_checkpoint"),
        (hold, "set_hold"),
        (queue, "capture"),
        (issues, "read_command"),
        (github_evidence, "GitHub"),
        (execution, "execute"),
        (native_codex, "execute"),
        (prepare, "prepare"),
    ):
        monkeypatch.setattr(module, name, forbidden)
    original = state.host_lock

    def read_only_lock(*, create=True):
        assert create is False
        return original(create=False)

    monkeypatch.setattr(state, "host_lock", read_only_lock)
    first = checked(ready, inputs)
    assert checked(ready, inputs) == first
    assert snapshot(ready["home"]) == before


def test_foreign_retained_task_blocks(task):
    idle()
    inputs = evidence(task)
    parent = task["home"] / ".local/state/agent-platform/99"
    parent.mkdir(parents=True, mode=0o700)
    parent.parent.chmod(0o700)
    marker = parent / "issue-7.json"
    marker.write_text("{}")
    marker.chmod(0o600)
    result, _ = checked(task, inputs)
    assert result["status"] == "BLOCKED"
    assert result["reason"] == "local_evidence_unverifiable"


def test_changed_primary_base_blocks(task):
    idle()
    inputs = evidence(task)
    (task["root"] / "tracked.txt").write_text("changed\n")
    git(task["root"], "add", "tracked.txt")
    git(
        task["root"],
        "-c",
        "user.name=Test",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-m",
        "new base",
    )
    result, _ = checked(task, inputs)
    assert result["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "kind", ["input", "observations", "prs", "digest", "admission"]
)
def test_malformed_or_conflicting_trusted_inputs_fail_before_lock(
    task, monkeypatch, kind
):
    inputs = evidence(task)
    if kind == "input":
        inputs = {"secret": "fake approval"}
    elif kind == "admission":
        inputs = replace(inputs, admission=replace(inputs.admission, issue_id=999))
    else:
        field, value = {
            "observations": ("observations", ()),
            "prs": ("pull_requests", ("secret",)),
            "digest": ("digest", "secret"),
        }[kind]
        inputs = replace(
            inputs, queue_snapshot=replace(inputs.queue_snapshot, **{field: value})
        )
    monkeypatch.setattr(state, "host_lock", lambda **kw: pytest.fail("lock reached"))
    result, _ = checked(task, inputs)
    assert result["status"] == "BLOCKED"


def test_pr_does_not_override_failed_current_admission(ready):
    pins = policy(ready, count=1)
    receipt = pr(
        ready, pins, state="open", merged=False, merge_sha=None, merged_at=None
    )
    inputs = evidence(ready, prs=(receipt,))
    captured = inputs.queue_snapshot
    captured = replace(
        captured, observations=(replace(captured.observations[0], admitted=False),)
    )
    result, _ = checked(ready, replace(inputs, queue_snapshot=captured))
    assert result["reason"] == "queue_evidence_blocked"
    assert result["queue"][0]["reason"] == "admission_unverified"
