"""Synthetic local status only; fake GitHub is used solely to prepare fixtures."""

import json
import os
import sys

import pytest
from test_prepare import git, snapshot
from test_prepare import run as prepare_task
from test_prepare import task as task

from agent_platform import cli, codex, execution, issues, prepare, publisher, state
from agent_platform import task_status as status

SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"
EXECUTION = "0199a213-81c0-7800-8aa1-bbab2a035a54"
USAGE = {"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 4}


@pytest.fixture
def ready(task):
    prepare_task(task)
    return task


def set_phase(task, phase, *, attempt=1, guard=None, version=2):
    old = state.load_checkpoint(task["checkpoint"])
    base_keys = set(old) - execution.EXTRA_KEYS
    data = {k: v for k, v in old.items() if k in base_keys}
    if phase == "READY" or version == 1:
        data.update(
            version=1,
            phase=phase,
            generation=2 if phase == "READY" else 1,
            last_intent="CONFIRMED" if phase == "READY" else "CREATE_WORKTREE",
            codex_thread_id=None,
            attempt=1,
        )
    else:
        data.update(
            version=2,
            phase=phase,
            attempt=attempt,
            generation=3 * attempt,
            last_intent="RUN" if attempt == 1 else "RESUME",
            codex_thread_id=None if attempt == 1 else SESSION,
            refs_sha256=execution.refs(task["root"]),
            isolation_sha256="a" * 64,
            codex_version=codex.VERSION,
            execution_id=EXECUTION,
            codex_home=str(
                prepare.HOME
                / ".local/share/agent-platform/codex-sessions/12/issue-1"
                / EXECUTION
            ),
            runtime_sha256=None,
            usage=None,
            stop_reason=None,
        )
        if phase != "STARTING":
            data.update(
                codex_thread_id=SESSION,
                generation=3 * attempt + 1,
                last_intent="SESSION_RECORDED",
            )
        if phase in {"PAUSED", "COMPLETED", "NEEDS_HUMAN"}:
            data.update(
                generation=3 * attempt + 2,
                last_intent={
                    "PAUSED": "TURN_STOPPED",
                    "COMPLETED": "TURN_COMPLETED",
                    "NEEDS_HUMAN": "AMBIGUOUS_STOP",
                }[phase],
                stop_reason={
                    "PAUSED": "turn_failed",
                    "COMPLETED": "completed",
                    "NEEDS_HUMAN": "ambiguous",
                }[phase],
            )
        if phase in {"PAUSED", "COMPLETED"}:
            data["runtime_sha256"] = "b" * 64
        if phase == "COMPLETED":
            data["usage"] = dict(USAGE)
    state.write_checkpoint(task["checkpoint"], data, previous=old)
    marker = task["checkpoint"].with_suffix(".execution-guard")
    if guard is None:
        guard = phase in {"STARTING", "RUNNING", "NEEDS_HUMAN"}
    if guard:
        marker.write_text(EXECUTION + "\n")
        marker.chmod(0o600)
    return data


def observe(task):
    report, code = status.diagnose(task["root"], 1)
    raw = json.dumps(report)
    assert len(raw.encode()) < 1024
    assert str(task["home"]) not in raw and "secret" not in raw
    assert report["live_activity"] == "unknown"
    assert report["remote_admission"] == "not_checked"
    assert report["launch_allowed"] is False
    assert report.keys() == status.empty_report(1).keys()
    return report, code


@pytest.mark.parametrize("phase", sorted(status.PHASES))
def test_every_recorded_local_state(ready, phase):
    data = set_phase(ready, phase)
    report, code = observe(ready)
    assert report["recorded_state"] == phase
    assert report["checkpoint_validity"] == "valid"
    assert report["generation"] == data["generation"]
    assert report["identity"] == "verified" and report["host_lock"] == "free"
    assert report["session_id"] == data["codex_thread_id"]
    assert report["stop_reason"] == data.get("stop_reason")
    assert report["usage"] == data.get("usage")
    assert code == (12 if phase in {"STARTING", "RUNNING", "NEEDS_HUMAN"} else 0)


@pytest.mark.parametrize(
    "phase", ["STARTING", "RUNNING", "PAUSED", "COMPLETED", "NEEDS_HUMAN"]
)
def test_resume_lineage_is_supported_without_session_reads(ready, phase):
    set_phase(ready, phase, attempt=2)
    report, _ = observe(ready)
    assert report["recorded_state"] == phase and report["session_id"] == SESSION
    assert report["generation"] in {6, 7, 8}


def test_interrupted_prepare_without_worktree_still_reports_local_intent(ready):
    set_phase(ready, "NEEDS_HUMAN", version=1, guard=False)
    git(ready["root"], "worktree", "remove", str(ready["worktree"]))
    report, code = observe(ready)
    assert code == 12 and report["recorded_state"] == "NEEDS_HUMAN"
    assert report["identity"] == "conflicting" and report["session_id"] is None


@pytest.mark.parametrize("phase", ["READY", "COMPLETED", "PAUSED"])
def test_stale_guard_blocks_terminal_or_ready_observations(ready, phase):
    set_phase(ready, phase, guard=True)
    report, code = observe(ready)
    assert code == 12 and report["execution_guard"] == "present"
    assert report["recorded_state"] == phase and report["status"] == "blocked"


def test_running_without_guard_is_not_live_process_evidence(ready):
    set_phase(ready, "RUNNING", guard=False)
    report, code = observe(ready)
    assert code == 12 and report["recorded_state"] == "RUNNING"
    assert (
        report["execution_guard"] == "absent" and report["live_activity"] == "unknown"
    )


def test_lock_busy_does_not_read_a_changing_checkpoint(ready, monkeypatch):
    def forbidden(*args):
        pytest.fail("busy status must not inspect checkpoints")

    with state.host_lock(create=False):
        monkeypatch.setattr(state, "load_checkpoint", forbidden)
        report, code = observe(ready)
    assert code == 10 and report["host_lock"] == "busy"
    assert (
        report["recorded_state"] is None and report["checkpoint_validity"] == "unknown"
    )


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_missing_lock_is_not_created(task, kind):
    if kind == "file":
        state.LOCK_DIR.mkdir(mode=0o700)
    report, code = observe(task)
    assert code == 12 and report["host_lock"] == "missing"
    assert not (state.LOCK_DIR / "prepare.lock").exists()


def test_missing_checkpoint_never_prepares(task):
    with state.host_lock():
        pass
    report, code = observe(task)
    assert code == 12 and report["checkpoint_validity"] == "missing"
    assert not task["checkpoint"].exists() and not task["worktree"].exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'{"phase":"READY","phase":"RUNNING"}',
        b'{"phase":NaN}',
        b"\xff",
        b"x" * (state.CHECKPOINT_LIMIT + 1),
    ],
)
def test_corrupt_checkpoint_is_redacted(ready, raw):
    ready["checkpoint"].write_bytes(raw)
    report, code = observe(ready)
    assert (
        code == 12 and report["recorded_state"] is None and report["session_id"] is None
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("issue", 2),
        ("repo_id", 13),
        ("repository", "other/repo"),
        ("worktree", "/secret/other"),
        ("source_root", "/secret/other"),
        ("common_dir", "/secret/other"),
        ("branch", "main"),
        ("base_sha", "f" * 40),
        ("phase", "secret-state"),
        ("generation", True),
        ("scope_sha256", "bad"),
        ("scope_revision", "bad"),
        ("unexpected", "secret"),
        ("version", True),
        ("codex_thread_id", "secret"),
    ],
)
def test_checkpoint_identity_and_schema_tampering(ready, field, value):
    data = state.load_checkpoint(ready["checkpoint"])
    data[field] = value
    ready["checkpoint"].write_text(json.dumps(data))
    report, code = observe(ready)
    assert code == 12 and report["recorded_state"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", 6),
        ("attempt", True),
        ("codex_thread_id", "--last"),
        ("execution_id", "--last"),
        ("codex_version", "unknown"),
        ("refs_sha256", "f" * 64),
        ("codex_home", "/secret/auth"),
        ("usage", {"input_tokens": True, "cached_input_tokens": 0, "output_tokens": 1}),
        ("stop_reason", "secret-provider-message"),
        ("runtime_sha256", "bad"),
    ],
)
def test_execution_record_tampering_is_not_reported(ready, field, value):
    data = set_phase(ready, "COMPLETED")
    data[field] = value
    ready["checkpoint"].write_text(json.dumps(data))
    report, code = observe(ready)
    assert code == 12 and report["session_id"] is None and report["usage"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "checkpoint_symlink",
        "checkpoint_hardlink",
        "checkpoint_mode",
        "directory_symlink",
        "guard_symlink",
        "guard_hardlink",
        "guard_mode",
        "guard_mismatch",
        "guard_invalid",
        "temporary",
        "cwd_alias",
        "worktree_alias",
        "git_pointer_alias",
    ],
)
def test_storage_and_guard_aliases_fail_closed(ready, tmp_path, fault):
    cp = ready["checkpoint"]
    guard = cp.with_suffix(".execution-guard")
    if fault.startswith("guard"):
        set_phase(ready, "RUNNING")
        if fault == "guard_symlink":
            guard.unlink()
            guard.symlink_to(tmp_path / "secret-sentinel")
        elif fault == "guard_hardlink":
            os.link(guard, tmp_path / "alias")
        elif fault == "guard_mode":
            guard.chmod(0o644)
        elif fault == "guard_mismatch":
            guard.write_text(SESSION + "\n")
        else:
            guard.write_text("secret text")
    elif fault == "checkpoint_symlink":
        cp.rename(tmp_path / "preserved")
        cp.symlink_to(tmp_path / "preserved")
    elif fault == "checkpoint_hardlink":
        os.link(cp, tmp_path / "alias")
    elif fault == "checkpoint_mode":
        cp.chmod(0o644)
    elif fault == "directory_symlink":
        cp.parent.rename(tmp_path / "preserved")
        cp.parent.symlink_to(tmp_path / "preserved", target_is_directory=True)
    elif fault == "temporary":
        cp.with_name(cp.name + ".tmp-unknown").touch()
    elif fault == "cwd_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(ready["root"], target_is_directory=True)
        ready = {**ready, "root": alias}
    elif fault == "worktree_alias":
        ready["worktree"].rename(tmp_path / "preserved-tree")
        ready["worktree"].symlink_to(
            tmp_path / "preserved-tree", target_is_directory=True
        )
    else:
        pointer = ready["worktree"] / ".git"
        pointer.rename(tmp_path / "preserved-pointer")
        pointer.symlink_to(tmp_path / "preserved-pointer")
    report, code = observe(ready)
    assert (
        code == 12 and report["status"] != "recorded" and report["session_id"] is None
    )


def test_multiple_matching_checkpoints_are_ambiguous(ready):
    other = ready["checkpoint"].parent.parent / "13"
    other.mkdir(mode=0o700)
    (other / "issue-1.json").write_bytes(ready["checkpoint"].read_bytes())
    (other / "issue-1.json").chmod(0o600)
    report, code = observe(ready)
    assert code == 12 and report["recorded_state"] is None


def test_legitimate_working_edits_are_preserved(ready):
    set_phase(ready, "PAUSED")
    (ready["worktree"] / "tracked.txt").write_text("preserve current coding edits")
    (ready["worktree"] / "new.py").write_text("preserve untracked")
    git(ready["worktree"], "add", "tracked.txt")
    before = snapshot(ready["home"])
    assert observe(ready)[1] == 0
    assert snapshot(ready["home"]) == before


def test_no_writes_network_authentication_or_model(ready, monkeypatch):
    set_phase(ready, "COMPLETED")
    original_open = os.open
    original_read = prepare.read_command
    before = snapshot(ready["home"])
    before_refs = execution.refs(ready["root"])

    def readonly(path, flags, *args, **kwargs):
        if str(path) != os.devnull:
            assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        assert "codex-sessions" not in str(path) and ".codex" not in str(path)
        return original_open(path, flags, *args, **kwargs)

    def read(argv, cwd, env, **limits):
        assert argv[0] == "git"  # Sole bounded subprocess exception, never a runner.
        assert not {
            "commit",
            "push",
            "fetch",
            "update-ref",
            "add",
            "reset",
            "clean",
        } & set(argv)
        assert not {"GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY"} & env.keys()
        assert limits["timeout"] <= 5 and limits["limit"] <= 256 * 1024
        return original_read(argv, cwd, env, **limits)

    monkeypatch.setattr(os, "open", readonly)
    monkeypatch.setattr(prepare, "read_command", read)
    monkeypatch.setattr(cli, "read_command", read)
    monkeypatch.setattr(issues, "GitHub", lambda *a: pytest.fail("no GitHub client"))
    monkeypatch.setattr(execution, "execute", lambda *a, **k: pytest.fail("no model"))
    monkeypatch.setattr(
        execution, "runtime_digest", lambda *a: pytest.fail("no session reads")
    )
    monkeypatch.setattr(
        state, "write_checkpoint", lambda *a, **k: pytest.fail("no writes")
    )
    monkeypatch.setattr(publisher, "plan", lambda *a: pytest.fail("no publisher"))
    monkeypatch.setenv("GH_TOKEN", "secret-env")
    assert observe(ready)[1] == 0
    assert snapshot(ready["home"]) == before
    assert execution.refs(ready["root"]) == before_refs


@pytest.mark.parametrize("point", ["checkpoint", "guard", "lock"])
def test_changed_snapshot_is_ambiguous(ready, monkeypatch, point):
    original = prepare.confirm_identity

    def race(root, record):
        original(root, record)
        if point == "checkpoint":
            ready["checkpoint"].write_text("{}")
        elif point == "guard":
            marker = ready["checkpoint"].with_suffix(".execution-guard")
            marker.write_text(EXECUTION + "\n")
            marker.chmod(0o600)
        else:
            lock = state.LOCK_DIR / "prepare.lock"
            lock.rename(state.LOCK_DIR / "original-lock")
            lock.touch(mode=0o600)

    monkeypatch.setattr(prepare, "confirm_identity", race)
    report, code = observe(ready)
    assert (
        code == 12 and report["session_id"] is None and report["status"] == "ambiguous"
    )


def test_cli_stable_json(ready, monkeypatch, capsys):
    monkeypatch.chdir(ready["root"])
    monkeypatch.setattr(sys, "argv", ["agent-platform", "status", "--issue", "1"])
    assert cli.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["recorded_state"] == "READY" and report["live_activity"] == "unknown"


@pytest.mark.parametrize("value", ["0", "-1", str(2**63)])
def test_cli_invalid_issue_does_not_inspect(value, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-platform", "status", "--issue", value])
    monkeypatch.setattr(status, "diagnose", lambda *a: pytest.fail("invalid issue"))
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_origin",
        "changed_base",
        "wrong_branch",
        "extra_refs",
        "dirty_source",
        "foreign_checkout",
    ],
)
def test_local_repository_conflicts(ready, tmp_path, fault):
    if fault == "wrong_origin":
        git(
            ready["root"],
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/repo.git",
        )
    elif fault == "changed_base":
        # A separate local commit advances main; origin/main is left at its old base.
        git(
            ready["root"],
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "new local base",
        )
    elif fault == "wrong_branch":
        git(ready["worktree"], "checkout", "-b", "unexpected")
    elif fault == "extra_refs":
        set_phase(ready, "PAUSED")
        git(ready["root"], "branch", "unexpected")
    elif fault == "dirty_source":
        (ready["root"] / "unexpected").write_text("preserve")
    else:
        other = tmp_path / "other"
        other.mkdir()
        git(other, "init", "-b", "main")
        ready = {**ready, "root": other}
    assert observe(ready)[1] == 12


def test_pre_session_ambiguous_stop_is_supported(ready):
    data = set_phase(ready, "NEEDS_HUMAN")
    data.update(generation=4, codex_thread_id=None)
    ready["checkpoint"].write_text(json.dumps(data))
    report, code = observe(ready)
    assert (
        code == 12
        and report["recorded_state"] == "NEEDS_HUMAN"
        and report["session_id"] is None
    )


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode"])
def test_unsafe_lock_never_repaired(ready, tmp_path, kind):
    lock = state.LOCK_DIR / "prepare.lock"
    if kind == "symlink":
        lock.rename(tmp_path / "original")
        lock.symlink_to(tmp_path / "original")
    elif kind == "hardlink":
        os.link(lock, tmp_path / "alias")
    else:
        lock.chmod(0o644)
    report, code = observe(ready)
    assert code == 12 and report["host_lock"] == "unavailable"
    assert report["recorded_state"] is None


def test_excessive_local_repository_directories_are_bounded(ready):
    store = ready["checkpoint"].parent.parent
    for i in range(1000, 1129):
        (store / str(i)).mkdir(mode=0o700)
    assert observe(ready)[1] == 12


def test_untrusted_exception_text_is_never_echoed(ready, monkeypatch):
    def unavailable(*args):
        raise OSError("secret token /private/auth/path")

    monkeypatch.setattr(status, "find_checkpoint", unavailable)
    report, code = observe(ready)
    assert code == 12 and report["reason"] == "local_state_unavailable"


def test_invalid_api_issue_is_redacted(ready):
    report, code = status.diagnose(ready["root"], "secret-input")
    assert code == 2 and report["issue"] is None
    assert "secret-input" not in json.dumps(report)


@pytest.mark.parametrize("orphan", ["guard", "temporary"])
def test_orphan_recovery_files_without_checkpoint_are_ambiguous(ready, orphan):
    cp = ready["checkpoint"]
    cp.unlink()
    marker = (
        cp.with_suffix(".execution-guard")
        if orphan == "guard"
        else cp.with_name(cp.name + ".tmp-interrupted")
    )
    marker.write_text(EXECUTION + "\n")
    marker.chmod(0o600)
    report, code = observe(ready)
    assert code == 12 and report["status"] == "ambiguous"
    assert marker.exists() and not cp.exists()
