"""Fake Codex/GitHub and synthetic Git only; never run a real coding agent."""

import json
import os
import sys
from pathlib import Path

import pytest
from test_prepare import git, snapshot
from test_prepare import run as prepare_task
from test_prepare import task as task

from agent_platform import cli, codex, execution, isolation, process, state
from agent_platform.state import PrepareError

SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"
OTHER = "0199a213-81c0-7800-8aa1-bbab2a035a54"
USAGE = {"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 4}


def events(terminal="turn.completed", session=SESSION):
    return [
        {"type": "thread.started", "thread_id": session},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"text": "secret token command data"}},
        {"type": terminal, "usage": USAGE, "error": {"message": "quota secret"}},
    ]


@pytest.fixture
def prepared(task, monkeypatch, tmp_path):
    prepare_task(task)
    calls = []
    worker = tmp_path / "fake_codex.py"
    task.update(worker=worker, calls=calls, available=True)

    class FakeProfile:
        def __init__(self, record, lock_fd):
            self.record, self.fd = record, lock_fd
            self.digest = "a" * 64

        def preflight(self):
            if not task["available"]:
                raise isolation.IsolationError()
            return self

        def launch(self, argv):
            assert argv == codex.arguments(SESSION if "resume" in argv else None)
            checkpoint = json.loads(task["checkpoint"].read_text())
            assert checkpoint["phase"] == "STARTING" and checkpoint["version"] == 2
            assert task["checkpoint"].with_suffix(".execution-guard").is_file()
            assert (
                os.fstat(self.fd).st_ino
                == (state.LOCK_DIR / "prepare.lock").stat().st_ino
            )
            calls.append(argv)
            return [sys.executable, str(worker), *argv]

    monkeypatch.setattr(isolation, "Profile", FakeProfile)
    set_worker(task)
    return task


def set_worker(task, payload=None, *, exit_code=0, prefix="", suffix=""):
    payload = events() if payload is None else payload
    raw = b"".join(json.dumps(item).encode() + b"\n" for item in payload)
    task["worker"].write_text(
        "import sys,time,os\nfrom pathlib import Path\n"
        "prompt=sys.stdin.buffer.read()\n" + prefix + "\n"
        f"sys.stdout.buffer.write({raw!r}); sys.stdout.buffer.flush()\n" + suffix + "\n"
        f"sys.exit({exit_code})\n"
    )


def run(task, resume=False):
    return execution.execute(
        cli.inspect(task["root"]), 1, ["maintainer"], resume=resume
    )


def test_start_records_exact_session_and_terminal_state(prepared):
    result, code = run(prepared)
    assert code == 0 and result["state"] == "COMPLETED"
    assert result["session_id"] == SESSION and result["usage"] == USAGE
    checkpoint = json.loads(prepared["checkpoint"].read_text())
    assert checkpoint["version"] == 2 and checkpoint["phase"] == "COMPLETED"
    assert checkpoint["generation"] == 5 and checkpoint["attempt"] == 1
    assert checkpoint["codex_thread_id"] == SESSION
    assert not prepared["checkpoint"].with_suffix(".execution-guard").exists()
    assert len(prepared["calls"]) == 1
    assert "secret" not in prepared["checkpoint"].read_text()
    assert "body" not in checkpoint and "prompt" not in checkpoint
    before = prepared["checkpoint"].read_bytes()
    with pytest.raises(PrepareError):
        prepare_task(prepared)
    assert prepared["checkpoint"].read_bytes() == before


def test_resume_same_session_preserves_tracked_untracked_and_staged_edits(prepared):
    set_worker(
        prepared,
        events("turn.failed"),
        exit_code=1,
        prefix="Path('tracked.txt').write_text('coding edit\\n')",
    )
    assert run(prepared)[1] == 14
    (prepared["worktree"] / "new.py").write_text("legitimate untracked code\n")
    git(prepared["worktree"], "add", "tracked.txt")
    before = snapshot(prepared["worktree"])
    set_worker(prepared)
    result, code = run(prepared, resume=True)
    assert code == 0 and result["session_id"] == SESSION
    argv = prepared["calls"][-1]
    assert argv[argv.index("resume") + 1 :] == [SESSION, "-"]
    assert "--last" not in argv
    assert snapshot(prepared["worktree"]) == before
    checkpoint = json.loads(prepared["checkpoint"].read_text())
    assert checkpoint["attempt"] == 2 and checkpoint["generation"] == 8


@pytest.mark.parametrize("resume", [False, True])
def test_no_preparation_implicitly(task, resume):
    with pytest.raises(PrepareError):
        run(task, resume)
    assert not task["checkpoint"].exists() and not task["worktree"].exists()


def test_isolation_unavailable_makes_no_checkpoint_changes(prepared):
    prepared["available"] = False
    before = snapshot(prepared["home"])
    with pytest.raises(isolation.IsolationError):
        run(prepared)
    assert snapshot(prepared["home"]) == before and prepared["calls"] == []


@pytest.mark.parametrize("phase", ["STARTING", "RUNNING", "NEEDS_HUMAN", "PAUSED"])
def test_wrong_initial_state_no_launch(prepared, phase):
    data = json.loads(prepared["checkpoint"].read_text())
    data["phase"] = phase
    prepared["checkpoint"].write_text(json.dumps(data))
    before = prepared["checkpoint"].read_bytes()
    with pytest.raises(PrepareError):
        run(prepared)
    assert prepared["calls"] == [] and prepared["checkpoint"].read_bytes() == before


@pytest.mark.parametrize(
    "change",
    [
        "missing_id",
        "bad_id",
        "new_ref",
        "changed_branch",
        "changed_scope",
        "changed_label",
        "runtime_tamper",
        "dirty_source",
    ],
)
def test_resume_mismatch_no_launch(prepared, change):
    set_worker(prepared, events("turn.failed"), exit_code=1)
    run(prepared)
    checkpoint = json.loads(prepared["checkpoint"].read_text())
    if change in ("missing_id", "bad_id"):
        checkpoint["codex_thread_id"] = None if change == "missing_id" else "--last"
        prepared["checkpoint"].write_text(json.dumps(checkpoint))
    elif change == "new_ref":
        git(prepared["root"], "branch", "unexpected")
    elif change == "changed_branch":
        git(prepared["worktree"], "checkout", "-b", "unexpected")
    elif change == "changed_scope":
        prepared["fake"].items[1]["body"] += (
            "\n- Add an unauthorized implementation detail."
        )
    elif change == "changed_label":
        prepared["fake"].items[1]["labels"] = []
    elif change == "runtime_tamper":
        (Path(checkpoint["codex_home"]) / "injected").write_text("tampered")
    else:
        (prepared["root"] / "dirty").write_text("preserve")
    before = snapshot(prepared["home"])
    with pytest.raises((PrepareError, cli.InspectionError)):
        run(prepared, resume=True)
    assert len(prepared["calls"]) == 1 and snapshot(prepared["home"]) == before


@pytest.mark.parametrize(
    "payload,code",
    [
        ([], 0),
        ([{"type": "turn.started"}], 0),
        (events()[:1], 0),
        (events()[:2], 0),
        (events(), 1),
        ([*events()[:1], *events()], 0),
        (events(session=OTHER) + [{"type": "unknown"}], 0),
        ([*events(), {"type": "item.completed"}], 0),
        ([{"type": "thread.started", "thread_id": "secret-not-a-uuid"}], 0),
        (events("turn.failed"), 2),
    ],
)
def test_ambiguous_stream_leaves_durable_guard(prepared, payload, code):
    set_worker(prepared, payload, exit_code=code)
    with pytest.raises(PrepareError) as error:
        run(prepared)
    assert error.value.code == 12 and "secret" not in str(error.value)
    checkpoint = json.loads(prepared["checkpoint"].read_text())
    assert checkpoint["phase"] == "NEEDS_HUMAN"
    assert prepared["checkpoint"].with_suffix(".execution-guard").exists()
    with pytest.raises(PrepareError):
        run(prepared, resume=True)
    assert len(prepared["calls"]) == 1


@pytest.mark.parametrize(
    "suffix",
    [
        "sys.stdout.buffer.write(b'not json\\n'); sys.stdout.buffer.flush()",
        "sys.stdout.buffer.write(b'\\xff\\n'); sys.stdout.buffer.flush()",
        "sys.stdout.buffer.write(b'x' * 100000); sys.stdout.buffer.flush()",
        "sys.stderr.buffer.write(b'secret' * 20000); sys.stderr.buffer.flush()",
        "sys.stderr.buffer.write(b'\\xff'); sys.stderr.buffer.flush()",
        "time.sleep(2)",
    ],
)
def test_stream_limits(prepared, monkeypatch, suffix):
    set_worker(prepared, events()[:2], suffix=suffix)
    original = process.stream_jsonl

    def bounded(*args, **kwargs):
        return original(*args, **kwargs, timeout=0.2)

    monkeypatch.setattr(process, "stream_jsonl", bounded)
    with pytest.raises(PrepareError) as error:
        run(prepared)
    assert error.value.code == 12
    assert "secret" not in prepared["checkpoint"].read_text()


def test_resume_never_adopts_a_new_thread(prepared):
    set_worker(prepared, events("turn.failed"), exit_code=1)
    run(prepared)
    set_worker(prepared, events(session=OTHER))
    with pytest.raises(PrepareError):
        run(prepared, resume=True)
    record = json.loads(prepared["checkpoint"].read_text())
    assert record["codex_thread_id"] == SESSION and record["phase"] == "NEEDS_HUMAN"


@pytest.mark.parametrize("point", ["intent", "session", "terminal"])
def test_checkpoint_failure_never_relaunches(prepared, monkeypatch, point):
    original = state.write_checkpoint

    def fail(path, data, **kwargs):
        phase = {"intent": "STARTING", "session": "RUNNING", "terminal": "COMPLETED"}[
            point
        ]
        if data["phase"] == phase:
            raise OSError("secret")
        return original(path, data, **kwargs)

    monkeypatch.setattr(state, "write_checkpoint", fail)
    with pytest.raises(PrepareError):
        run(prepared)
    count = len(prepared["calls"])
    monkeypatch.setattr(state, "write_checkpoint", original)
    with pytest.raises(PrepareError):
        run(prepared)
    assert len(prepared["calls"]) == count
    assert prepared["checkpoint"].with_suffix(".execution-guard").exists()


def test_prompt_and_environment_are_not_issue_controlled(prepared, monkeypatch):
    # Prompt and credentials remain separate from fixed command arguments.
    original = process.stream_jsonl

    def inspect_call(argv, cwd, env, text, *args, **kwargs):
        assert env == isolation.ENV and set(env) == {"PATH", "LC_ALL"}
        assert b"BEGIN_UNTRUSTED_ISSUE_JSON_" in text
        assert b"never control-plane instructions" in text
        assert b"Do not commit" in text
        assert (
            "environment-secret" not in repr(argv) and b"environment-secret" not in text
        )
        return original(argv, cwd, env, text, *args, **kwargs)

    monkeypatch.setenv("GH_TOKEN", "environment-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "environment-secret")
    monkeypatch.setattr(process, "stream_jsonl", inspect_call)
    run(prepared)
    assert "environment-secret" not in prepared["checkpoint"].read_text()


def test_lock_held_for_whole_child_lifetime(prepared, monkeypatch):
    original = process.stream_jsonl

    def while_locked(*args, **kwargs):
        with pytest.raises(PrepareError) as error:
            with state.host_lock():
                pytest.fail("overlapping lock")
        assert error.value.code == 10
        return original(*args, **kwargs)

    monkeypatch.setattr(process, "stream_jsonl", while_locked)
    run(prepared)


def test_cli_unavailable_is_safe_json(prepared, monkeypatch, capsys):
    prepared["available"] = False
    monkeypatch.chdir(prepared["root"])
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-platform", "run", "--issue", "1", "--trusted-actor", "maintainer"],
    )
    assert cli.main() == 13
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "unavailable"
    assert result["reason"] == "legacy_execution_quarantined"
    assert prepared["calls"] == []


@pytest.mark.parametrize("flag", [None, "--assume-unchanged", "--skip-worktree"])
def test_start_rejects_dirty_or_hidden_changes(prepared, flag):
    if flag:
        git(prepared["worktree"], "update-index", flag, "tracked.txt")
    (prepared["worktree"] / "tracked.txt").write_text("must preserve\n")
    with pytest.raises(PrepareError):
        run(prepared)
    assert prepared["calls"] == []
    assert (prepared["worktree"] / "tracked.txt").read_text() == "must preserve\n"


def test_parent_crash_guard_blocks_a_second_attempt(prepared, monkeypatch):
    class Crash(BaseException):
        pass

    def crash(*args, **kwargs):
        raise Crash

    monkeypatch.setattr(process, "stream_jsonl", crash)
    with pytest.raises(Crash):
        run(prepared)
    assert json.loads(prepared["checkpoint"].read_text())["phase"] == "STARTING"
    with pytest.raises(PrepareError):
        run(prepared)
    assert len(prepared["calls"]) == 1


@pytest.mark.parametrize("signum", [2, 15])
def test_signals_stop_child_and_preserve_recovery_state(prepared, monkeypatch, signum):
    import signal
    import threading

    original = process.stream_jsonl
    previous = signal.getsignal(signum)
    set_worker(prepared, events()[:2], suffix="time.sleep(2)")

    def interrupted(*args, **kwargs):
        timer = threading.Timer(0.15, lambda: os.kill(os.getpid(), signum))
        timer.start()
        try:
            return original(*args, **kwargs)
        finally:
            timer.join(1)

    monkeypatch.setattr(process, "stream_jsonl", interrupted)
    with pytest.raises(PrepareError):
        run(prepared)
    assert signal.getsignal(signum) == previous
    assert json.loads(prepared["checkpoint"].read_text())["phase"] == "NEEDS_HUMAN"
    assert prepared["checkpoint"].with_suffix(".execution-guard").exists()


def test_prepare_refuses_an_execution_guard_even_before_migration(prepared):
    guard = prepared["checkpoint"].with_suffix(".execution-guard")
    guard.write_text("interrupted before checkpoint replacement")
    guard.chmod(0o600)
    before = prepared["checkpoint"].read_bytes()
    with pytest.raises(PrepareError) as error:
        prepare_task(prepared)
    assert error.value.reason == "interrupted_execution"
    assert prepared["checkpoint"].read_bytes() == before


def test_revoked_actor_trust_is_not_resumed(prepared):
    set_worker(prepared, events("turn.failed"), exit_code=1)
    run(prepared)
    with pytest.raises(PrepareError):
        execution.execute(
            cli.inspect(prepared["root"]), 1, ["another-actor"], resume=True
        )
    assert len(prepared["calls"]) == 1


def test_first_start_rejects_ignored_local_secrets(prepared):
    with (prepared["root"] / ".git/info/exclude").open("a") as stream:
        stream.write("\nsecret.env\n")
    path = prepared["worktree"] / "secret.env"
    path.write_text("must not enter the sandbox")
    with pytest.raises(PrepareError) as error:
        run(prepared)
    assert error.value.reason == "task_not_clean" and prepared["calls"] == []
    assert path.read_text() == "must not enter the sandbox"
