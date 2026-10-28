"""Offline readiness uses real validation and synthetic Git; no inference."""

import json
import sys

import pytest
from test_execution import events, run, set_worker
from test_execution import prepared as prepared
from test_isolation import profile as profile
from test_prepare import git, snapshot
from test_prepare import task as task

from agent_platform import cli, doctor, isolation, process, state


@pytest.fixture
def no_turn(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("doctor must never launch a coding turn or write a checkpoint")

    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    monkeypatch.setattr(process, "stream_jsonl", forbidden)


def diagnose(task, **kwargs):
    return doctor.diagnose(task["root"], 1, ["maintainer"], **kwargs)


@pytest.fixture
def ready(task, monkeypatch):
    # Prepare before installing the mutation tripwire.
    from test_prepare import run as prepare_task

    with monkeypatch.context() as patch:
        patch.setattr(state, "write_checkpoint", ORIGINAL_WRITE)
        prepare_task(task)
    return task


ORIGINAL_WRITE = state.write_checkpoint


def test_real_preflight_shared_and_nonmutating(ready, profile, monkeypatch, no_turn):
    current, _, reads = profile

    def factory(record, fd):
        current.record = record
        return current

    monkeypatch.setattr(isolation, "Profile", factory)
    before = snapshot(ready["home"]), snapshot(ready["root"] / ".git")
    assert diagnose(ready) == ({"status": "ready", "reason": "checks_passed"}, 0)
    assert len(reads) == 3
    assert (snapshot(ready["home"]), snapshot(ready["root"] / ".git")) == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "invalid",
        "guard",
        "dirty",
        "branch",
        "scope",
        "label",
        "stale",
        "actor",
        "lock",
    ],
)
def test_rejections_preserve_everything(ready, monkeypatch, fault, no_turn):
    if fault == "missing":
        ready["checkpoint"].unlink()
    elif fault == "invalid":
        ready["checkpoint"].write_text('{"secret": true}')
    elif fault == "guard":
        ready["checkpoint"].with_suffix(".execution-guard").write_text("keep")
    elif fault == "dirty":
        (ready["worktree"] / "edit").write_text("preserve")
    elif fault == "branch":
        git(ready["worktree"], "checkout", "-b", "wrong")
    elif fault == "scope":
        ready["fake"].items[1]["body"] += "changed"
    elif fault == "label":
        ready["fake"].items[1]["labels"] = []
    elif fault == "stale":
        ready["remote"]["commit"]["sha"] = "a" * 40
    before = snapshot(ready["home"]), snapshot(ready["root"] / ".git")
    if fault == "lock":
        with state.host_lock():
            result, code = diagnose(ready)
        assert result["reason"] == "lock_busy"
    elif fault == "actor":
        result, code = doctor.diagnose(ready["root"], 1, ["untrusted"])
    else:
        result, code = diagnose(ready)
    assert code != 0 and result["status"] != "ready"
    assert "secret" not in json.dumps(result)
    assert (snapshot(ready["home"]), snapshot(ready["root"] / ".git")) == before


@pytest.mark.parametrize(
    "fault", ["profile", "broker", "identity", "malformed", "network"]
)
def test_real_preflight_fails_closed(ready, profile, monkeypatch, fault, no_turn):
    current, _, _ = profile

    def factory(record, fd):
        current.record = record
        return current

    monkeypatch.setattr(isolation, "Profile", factory)
    if fault == "profile":
        monkeypatch.setattr(isolation, "PROFILE", isolation.PROFILE / "absent")
    elif fault == "broker":
        monkeypatch.setattr(isolation, "BROKER", isolation.BROKER.parent / "absent")
    elif fault in ("identity", "malformed"):
        monkeypatch.setattr(
            isolation,
            "broker_request",
            lambda *a: (200, b"{}" if fault == "identity" else b"not-json"),
        )
    else:
        monkeypatch.setattr(
            isolation.process, "read_command", lambda *a, **kw: b"escape succeeded"
        )
    before = snapshot(ready["home"])
    assert diagnose(ready) == (
        {"status": "unavailable", "reason": "isolation_unavailable"},
        13,
    )
    assert snapshot(ready["home"]) == before


def test_absent_lock_never_created(task, no_turn):
    assert diagnose(task)[1] != 0
    assert not state.LOCK_DIR.exists()
    assert not task["checkpoint"].exists()


def test_cli_fixed_json_for_invalid_target(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-platform", "doctor", "--issue", "1", "--trusted-actor", "maintainer"],
    )
    assert cli.main() == 7
    assert json.loads(capsys.readouterr().out) == {
        "status": "ambiguous",
        "reason": "invalid_target",
    }


def test_paused_readiness_preserves_edits_and_session(prepared, monkeypatch, no_turn):
    # Execute only fake Codex to establish genuine PAUSED lineage.
    from agent_platform import process as proc

    with monkeypatch.context() as patch:
        patch.setattr(state, "write_checkpoint", ORIGINAL_WRITE)
        patch.setattr(proc, "stream_jsonl", ORIGINAL_STREAM)
        set_worker(prepared, events("turn.failed"), exit_code=1)
        assert run(prepared)[1] == 14
    (prepared["worktree"] / "edit").write_text("keep")
    before = snapshot(prepared["home"])
    assert diagnose(prepared, resume=True)[1] == 0
    assert snapshot(prepared["home"]) == before
    assert len(prepared["calls"]) == 1


ORIGINAL_STREAM = process.stream_jsonl


@pytest.mark.parametrize("mutation", ["checkpoint", "guard", "source", "scope"])
def test_changes_during_preflight_rejected(ready, monkeypatch, mutation, no_turn):
    class ChangingProfile:
        def __init__(self, record, fd):
            pass

        def preflight(self):
            if mutation == "checkpoint":
                data = json.loads(ready["checkpoint"].read_text())
                data["generation"] += 1
                ready["checkpoint"].write_text(json.dumps(data))
            elif mutation == "guard":
                ready["checkpoint"].with_suffix(".execution-guard").write_text(
                    "preserve"
                )
            elif mutation == "source":
                git(ready["root"], "branch", "unexpected")
            else:
                ready["fake"].items[1]["body"] += "changed"
            return self

    monkeypatch.setattr(isolation, "Profile", ChangingProfile)
    assert diagnose(ready)[1] != 0


def test_existing_mutex_missing_file_is_not_created(ready, no_turn):
    (state.LOCK_DIR / "prepare.lock").unlink()
    assert diagnose(ready)[1] != 0
    assert not (state.LOCK_DIR / "prepare.lock").exists()


def test_doctor_cli_success_and_resume_flag(ready, monkeypatch, capsys):
    calls = []

    def diagnose(cwd, issue, actors, *, resume):
        calls.append((issue, actors, resume))
        return {"status": "ready", "reason": "checks_passed"}, 0

    monkeypatch.setattr(doctor, "diagnose", diagnose)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-platform",
            "doctor",
            "--issue",
            "1",
            "--trusted-actor",
            "maintainer",
            "--resume",
        ],
    )
    assert cli.main() == 0
    assert calls == [(1, ["maintainer"], True)]
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_report_template_is_redacted_and_not_a_success_claim():
    from pathlib import Path

    data = json.loads((Path(__file__).parents[1] / "docs/e2e-report.json").read_text())
    assert not data["real_live_turn_ran"]
    assert data["ci_status"] == data["e2e_status"] == "NOT_RUN"
    assert all(check["outcome"] == "NOT_RUN" for check in data["checks"])


@pytest.mark.parametrize("fault", ["profile", "runtime", "session", "refs"])
def test_resume_lineage_rejected_without_mutation(
    prepared, monkeypatch, fault, no_turn
):
    with monkeypatch.context() as patch:
        patch.setattr(state, "write_checkpoint", ORIGINAL_WRITE)
        patch.setattr(process, "stream_jsonl", ORIGINAL_STREAM)
        set_worker(prepared, events("turn.failed"), exit_code=1)
        assert run(prepared)[1] == 14
    record = json.loads(prepared["checkpoint"].read_text())
    if fault == "profile":
        original = isolation.Profile.preflight

        def changed(self):
            result = original(self)
            self.digest = "b" * 64
            return result

        monkeypatch.setattr(isolation.Profile, "preflight", changed)
    elif fault == "runtime":
        from pathlib import Path

        (Path(record["codex_home"]) / "changed").write_text("preserve")
    elif fault == "session":
        record["codex_thread_id"] = "--last"
        prepared["checkpoint"].write_text(json.dumps(record))
    else:
        git(prepared["root"], "branch", "unexpected")
    before = snapshot(prepared["home"])
    assert diagnose(prepared, resume=True)[1] != 0
    assert snapshot(prepared["home"]) == before
    assert len(prepared["calls"]) == 1
