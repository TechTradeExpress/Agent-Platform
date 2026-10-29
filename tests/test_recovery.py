"""Offline recovery plans from synthetic checkpoints/Git and fake execution only."""

import json
import os
import socket
import sys
from dataclasses import replace

import pytest
from test_execution import events, set_worker
from test_execution import prepared as prepared
from test_execution import run as run_fake
from test_prepare import git, snapshot
from test_prepare import task as task
from test_task_status import EXECUTION, SESSION, set_phase
from test_task_status import ready as ready

from agent_platform import cli, execution, issues, prepare, publisher, recovery, state
from agent_platform import task_status as status


def plan(task, **kwargs):
    result, code = recovery.plan(task["root"], 1, **kwargs)
    raw = json.dumps(result)
    assert len(raw.encode()) < 4096
    assert "secret" not in raw and str(task["home"]) not in raw
    assert (
        result["safe_to_replay"]
        is result["resume_authorized"]
        is result["mutations_allowed"]
        is False
    )
    assert result["external_side_effects"] == "unknown_not_exactly_once"
    assert result["local_evidence"]["live_activity"] == "unknown"
    assert result["local_evidence"]["remote_admission"] == "not_checked"
    assert (
        "assume_completed_means_exactly_once"
        in result["prohibited_without_separate_authorization"]
    )
    assert (
        "reset_stash_clean_checkout_or_discard_edits"
        in result["prohibited_without_separate_authorization"]
    )
    without_key = {k: v for k, v in result.items() if k != "plan_sha256"}
    assert result["plan_sha256"] == publisher.digest(without_key)
    return result, code


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


@pytest.mark.parametrize(
    "phase,classification",
    [
        ("READY", "no_interruption_indicated"),
        ("STARTING", "interrupted_start"),
        ("RUNNING", "missing_terminal_or_late_failure"),
        ("PAUSED", "known_pause"),
        ("NEEDS_HUMAN", "ambiguous_stop"),
        ("COMPLETED", "recorded_completion"),
    ],
)
def test_every_phase_is_guidance_never_authority(ready, phase, classification):
    set_phase(ready, phase)
    a, code = plan(ready)
    assert a["classification"] == classification
    assert a["human_reconciliation_required"] == (phase != "READY")
    assert a["reconciliation_state"] == (
        "NOT_INDICATED" if phase == "READY" else "NEEDS_HUMAN"
    )
    assert code == (0 if phase == "READY" else 12)
    assert a["local_evidence"]["recorded_state"] == phase
    assert a["execution_id"] == (None if phase == "READY" else EXECUTION)
    assert a["checkpoint_version"] == (1 if phase == "READY" else 2)
    assert a["recorded_fingerprints"]["runtime_sha256"] == (
        "b" * 64 if phase in {"PAUSED", "COMPLETED"} else None
    )
    assert a["fingerprint_verification"] == "recorded_only_not_rehashed"
    assert a == plan(ready)[0]


@pytest.mark.parametrize("phase", ["READY", "PAUSED", "COMPLETED"])
def test_leftover_guard_never_removed(ready, phase):
    set_phase(ready, phase, guard=True)
    before = snapshot(ready["home"])
    result, code = plan(ready)
    assert result["classification"] == "leftover_guard" and code == 12
    assert result["human_reconciliation_required"]
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize("orphan", ["temporary", "guard"])
def test_orphan_persistence_is_not_promoted_or_cleaned(ready, orphan):
    cp = ready["checkpoint"]
    cp.unlink()
    marker = (
        cp.with_name(cp.name + ".tmp-interrupted")
        if orphan == "temporary"
        else cp.with_suffix(".execution-guard")
    )
    marker.write_text("secret fabricated recovery evidence")
    marker.chmod(0o600)
    before = snapshot(ready["home"])
    a, code = plan(ready)
    assert code == 12
    assert a["classification"] == (
        "checkpoint_persistence_incomplete" if orphan == "temporary" else "orphan_guard"
    )
    assert a["execution_id"] is None and a["local_evidence"]["session_id"] is None
    assert plan(ready)[0] == a and snapshot(ready["home"]) == before


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'{"phase":"READY","phase":"RUNNING"}',
        b'{"generation":NaN}',
        b"x" * (state.CHECKPOINT_LIMIT + 1),
    ],
)
def test_corruption_never_becomes_replay_advice(ready, raw):
    ready["checkpoint"].write_bytes(raw)
    result, code = plan(ready)
    assert code == 12 and result["human_reconciliation_required"]
    assert result["classification"] == "checkpoint_invalid"
    assert result["execution_id"] is None and result["checkpoint_sha256"] is None


def test_busy_lock_does_not_read_checkpoint_or_prove_activity(ready, monkeypatch):
    def forbidden(*args):
        pytest.fail("no checkpoint during concurrent transaction")

    with state.host_lock(create=False):
        monkeypatch.setattr(state, "load_checkpoint", forbidden)
        result, code = plan(ready)
    assert code == 10 and result["classification"] == "lock_busy"
    assert result["local_evidence"]["recorded_state"] is None


def test_missing_lock_and_missing_checkpoint_are_non_creating(task):
    assert plan(task)[0]["classification"] == "local_evidence_unavailable"
    assert not state.LOCK_DIR.exists()
    with state.host_lock():
        pass
    assert plan(task)[0]["classification"] == "checkpoint_missing"
    assert not task["checkpoint"].exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("codex_thread_id", "--last"),
        ("generation", True),
        ("generation", 6),
        ("runtime_sha256", "secret"),
        ("issue", 2),
        ("repository", "other/repo"),
        ("worktree", "/secret/other"),
    ],
)
def test_invalid_session_generation_and_identity_are_not_echoed(ready, field, value):
    data = set_phase(ready, "COMPLETED")
    data[field] = value
    ready["checkpoint"].write_text(json.dumps(data))
    result, code = plan(ready)
    assert code == 12 and result["execution_id"] is None
    assert result["local_evidence"]["session_id"] is None


@pytest.mark.parametrize(
    "pin", ["session", "execution", "scope", "generation", "digest"]
)
def test_independent_reference_detects_otherwise_valid_conflicting_data(ready, pin):
    set_phase(ready, "COMPLETED")
    expected = reference(ready)
    if pin == "session":
        expected = replace(expected, session_id="0199a213-81c0-7800-8aa1-bbab2a035a55")
    elif pin == "execution":
        expected = replace(
            expected, execution_id="0199a213-81c0-7800-8aa1-bbab2a035a55"
        )
    elif pin == "scope":
        expected = replace(
            expected, admission=replace(expected.admission, scope_sha256="f" * 64)
        )
    elif pin == "generation":
        expected = replace(expected, generation=8)
    else:
        expected = replace(expected, checkpoint_sha256="f" * 64)
    result, code = plan(ready, reference=expected)
    assert code == 12 and result["trusted_reference"] == "conflicting"
    assert result["classification"] == (
        "session_reference_conflict"
        if pin in {"session", "execution"}
        else "checkpoint_reference_conflict"
    )
    assert (
        result["execution_id"] is None
        and result["local_evidence"]["session_id"] is None
    )


def test_matching_reference_is_not_external_side_effect_proof(ready):
    set_phase(ready, "COMPLETED")
    result, code = plan(ready, reference=reference(ready))
    assert result["trusted_reference"] == "matched" and code == 12
    assert "remote_admission_not_refreshed" in result["missing_or_unverified"]
    assert result["human_reconciliation_required"]


def test_changed_remote_scope_can_be_compared_only_through_trusted_offline_reference(
    ready,
):
    original = reference(ready)
    ready["fake"].items[1]["body"] += (
        "\n- Implement newly approved scope changes with additional safety tests."
    )
    fresh = publisher.Admission(
        **prepare.approved(
            issues.GitHub("example/target"), "example/target", 1, ["maintainer"]
        )
    )
    result, code = plan(ready, reference=replace(original, admission=fresh))
    assert code == 12 and result["classification"] == "checkpoint_reference_conflict"
    assert plan(ready)[0]["trusted_reference"] == "not_provided"


@pytest.mark.parametrize(
    "change", ["new_ref", "branch", "source", "guard_uuid", "temporary", "symlink"]
)
def test_changed_refs_worktree_and_guard_block_recovery(ready, change, tmp_path):
    set_phase(ready, "RUNNING")
    if change == "new_ref":
        git(ready["root"], "branch", "unexpected")
    elif change == "branch":
        git(ready["worktree"], "checkout", "-b", "unexpected")
    elif change == "source":
        (ready["root"] / "dirty").write_text("preserve")
    elif change == "guard_uuid":
        ready["checkpoint"].with_suffix(".execution-guard").write_text(SESSION + "\n")
    elif change == "temporary":
        ready["checkpoint"].with_name("issue-1.json.tmp-unknown").write_text("secret")
    else:
        cp = ready["checkpoint"]
        cp.rename(tmp_path / "original")
        cp.symlink_to(tmp_path / "original")
    result, code = plan(ready)
    assert code == 12 and result["human_reconciliation_required"]
    assert result["trusted_reference"] == "not_provided"


def test_edits_are_preserved_not_treated_as_success_or_failure(ready):
    set_phase(ready, "RUNNING")
    (ready["worktree"] / "tracked.txt").write_text("uncertain code edits")
    (ready["worktree"] / "untracked").write_text("possibly side-effect related")
    git(ready["worktree"], "add", "tracked.txt")
    before = snapshot(ready["home"])
    result, _ = plan(ready)
    assert "worktree_content_not_examined" in result["missing_or_unverified"]
    assert snapshot(ready["home"]) == before


@pytest.mark.parametrize(
    "point",
    [
        "starting",
        "session",
        "terminal_before",
        "terminal_after",
        "malformed_stream",
        "missing_terminal",
        "timeout",
    ],
)
def test_real_lifecycle_fake_execution_crash_matrix(prepared, monkeypatch, point):
    class Crash(BaseException):
        pass

    original_stream = execution.process.stream_jsonl
    original_write = state.write_checkpoint
    if point in {"starting", "session"}:

        def stream(argv, cwd, env, text, accept, **kwargs):
            if point == "session":
                accept(
                    json.dumps(
                        {"type": "thread.started", "thread_id": SESSION}
                    ).encode()
                )
            raise Crash

        monkeypatch.setattr(execution.process, "stream_jsonl", stream)
    elif point.startswith("terminal"):

        def write(path, data, **kwargs):
            if data["phase"] == "COMPLETED":
                if point == "terminal_after":
                    original_write(path, data, **kwargs)
                raise OSError("secret persistence error")
            return original_write(path, data, **kwargs)

        monkeypatch.setattr(state, "write_checkpoint", write)
    elif point == "missing_terminal":
        set_worker(prepared, events()[:2])
    elif point == "malformed_stream":
        set_worker(prepared, events()[:2], suffix="print('secret malformed JSONL')")
    else:
        set_worker(prepared, events()[:2], suffix="time.sleep(2)")
        monkeypatch.setattr(
            execution.process,
            "stream_jsonl",
            lambda *a, **kw: original_stream(*a, **kw, timeout=0.1),
        )
    with pytest.raises((Crash, state.PrepareError)):
        run_fake(prepared)
    monkeypatch.setattr(execution.process, "stream_jsonl", original_stream)
    monkeypatch.setattr(state, "write_checkpoint", original_write)
    before = snapshot(prepared["home"])
    result, code = plan(prepared)
    expected = {
        "starting": "interrupted_start",
        "session": "missing_terminal_or_late_failure",
        "terminal_before": "ambiguous_stop",
        "terminal_after": "leftover_guard",
        "malformed_stream": "ambiguous_stop",
        "missing_terminal": "ambiguous_stop",
        "timeout": "ambiguous_stop",
    }[point]
    assert result["classification"] == expected and code == 12
    assert plan(prepared)[0] == result and snapshot(prepared["home"]) == before


def test_no_writes_network_models_native_store_or_publisher(ready, monkeypatch):
    set_phase(ready, "COMPLETED")
    before = snapshot(ready["home"])
    refs = execution.refs(ready["root"])
    original_open = os.open
    original_read = prepare.read_command

    def readonly(path, flags, *a, **kw):
        if str(path) != os.devnull:
            assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        assert "codex-sessions" not in str(path) and ".codex" not in str(path)
        return original_open(path, flags, *a, **kw)

    def read(argv, cwd, env, **limits):
        assert argv[0] == "git"
        assert not {
            "push",
            "commit",
            "fetch",
            "reset",
            "clean",
            "checkout",
            "add",
        } & set(argv)
        assert not {"GH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN"} & env.keys()
        assert limits["timeout"] <= 5 and limits["limit"] <= 256 * 1024
        return original_read(argv, cwd, env, **limits)

    def forbidden(*a, **kw):
        pytest.fail("recovery attempted mutation/network/model/session I/O")

    monkeypatch.setattr(os, "open", readonly)
    monkeypatch.setattr(prepare, "read_command", read)
    monkeypatch.setattr(cli, "read_command", read)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(issues, "GitHub", forbidden)
    monkeypatch.setattr(execution, "execute", forbidden)
    monkeypatch.setattr(execution, "runtime_digest", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    monkeypatch.setattr(publisher, "plan", forbidden)
    result, code = plan(ready)
    assert code == 12 and result["classification"] == "recorded_completion"
    assert snapshot(ready["home"]) == before and execution.refs(ready["root"]) == refs


def test_cli_and_existing_status_contract(ready, monkeypatch, capsys):
    monkeypatch.chdir(ready["root"])
    monkeypatch.setattr(
        sys, "argv", ["agent-platform", "recovery", "plan", "--issue", "1"]
    )
    assert cli.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["classification"] == "no_interruption_indicated"
    report, _ = status.diagnose(ready["root"], 1)
    assert report.keys() == status.empty_report(1).keys()
    assert result["local_evidence"] == report


@pytest.mark.parametrize("value", ["0", "-1", str(2**63)])
def test_invalid_issue_does_not_inspect(value, monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["agent-platform", "recovery", "plan", "--issue", value]
    )
    monkeypatch.setattr(recovery, "plan", lambda *a: pytest.fail("invalid input"))
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2 and capsys.readouterr().out == ""


def test_partial_checkpoint_replace_failure_uses_real_atomic_writer(
    prepared, monkeypatch
):
    original_write = state.write_checkpoint

    def write(path, data, **kwargs):
        if data["phase"] == "RUNNING":
            with monkeypatch.context() as patch:

                def fail(*args):
                    raise OSError("secret atomic replacement error")

                patch.setattr(os, "replace", fail)
                return original_write(path, data, **kwargs)
        return original_write(path, data, **kwargs)

    monkeypatch.setattr(state, "write_checkpoint", write)
    with pytest.raises(state.PrepareError):
        run_fake(prepared)
    monkeypatch.setattr(state, "write_checkpoint", original_write)
    assert list(prepared["checkpoint"].parent.glob("*.tmp-*"))
    before = snapshot(prepared["home"])
    original_open = os.open

    def no_temporary_reads(path, *args, **kwargs):
        assert ".tmp-" not in str(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_temporary_reads)
    result, code = plan(prepared)
    assert (
        code == 12 and result["classification"] == "checkpoint_persistence_incomplete"
    )
    assert result["execution_id"] is None
    assert snapshot(prepared["home"]) == before


@pytest.mark.parametrize("point", ["checkpoint", "guard", "lock"])
def test_changed_inspection_drops_partial_identity(ready, monkeypatch, point):
    set_phase(ready, "COMPLETED")
    original = prepare.confirm_identity

    def mutate(root, record):
        original(root, record)
        if point == "checkpoint":
            ready["checkpoint"].write_text("{}")
        elif point == "guard":
            marker = ready["checkpoint"].with_suffix(".execution-guard")
            marker.write_text(EXECUTION + "\n")
            marker.chmod(0o600)
        else:
            lock = state.LOCK_DIR / "prepare.lock"
            lock.rename(state.LOCK_DIR / "preserved-lock")
            lock.touch(mode=0o600)

    monkeypatch.setattr(prepare, "confirm_identity", mutate)
    result, code = plan(ready)
    assert code == 12 and result["classification"] == "evidence_changed"
    assert result["execution_id"] is None and result["checkpoint_sha256"] is None


def test_reference_does_not_mask_busy_or_incomplete_evidence(ready):
    pin = reference(ready)
    with state.host_lock(create=False):
        result, code = plan(ready, reference=pin)
    assert code == 10 and result["classification"] == "lock_busy"
    assert result["trusted_reference"] == "unverified"
    assert result["reference_conflicts"] == []


def test_invalid_reference_and_invalid_api_issue_are_redacted(ready):
    result, code = plan(ready, reference="secret untrusted input")
    assert code == 12 and result["classification"] == "reference_unverifiable"
    result, code = recovery.plan(ready["root"], "secret input")
    assert code == 2 and result["issue"] is None
    assert "secret input" not in json.dumps(result)


def test_completed_snapshot_cannot_be_used_as_publisher_or_resume_authority(ready):
    set_phase(ready, "COMPLETED")
    result, _ = plan(ready, reference=reference(ready))
    assert result["human_reconciliation_required"]
    assert "exactly-once" in result["summary"]
    assert (
        "assume_completed_means_exactly_once"
        in result["prohibited_without_separate_authorization"]
    )
