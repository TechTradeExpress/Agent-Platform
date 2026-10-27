"""Synthetic Git and fake gh only; no live tasks or infrastructure."""

import json
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_issues import PREFIX, REPO, FakeGH, event, issue, response

from agent_platform import cli, issues, prepare, state
from agent_platform.state import PrepareError


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        timeout=5,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    return result.stdout.decode().strip()


@pytest.fixture
def task(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-b", "main")
    (root / "tracked.txt").write_text("fixture\n")
    git(root, "add", "tracked.txt")
    git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    git(root, "remote", "add", "origin", f"https://github.com/{REPO}.git")
    sha = git(root, "rev-parse", "HEAD")
    git(root, "update-ref", "refs/remotes/origin/main", sha)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(prepare, "HOME", home)
    monkeypatch.setattr(state, "LOCK_DIR", tmp_path / "host-lock")
    fake = FakeGH(monkeypatch, [issue()])
    fake.overrides[PREFIX] = response(
        {"id": 12, "full_name": REPO, "default_branch": "main"}
    )
    original = fake.read
    remote = {"name": "main", "commit": {"sha": sha}}

    def gh(argv, cwd, env, **limits):
        argv = list(argv)
        pieces = argv[-1].split("/", 3)
        if "/".join(pieces[:3]).casefold() == PREFIX.casefold():
            argv[-1] = PREFIX + ("/" + pieces[3] if len(pieces) == 4 else "")
        if argv[-1] == PREFIX + "/branches/main":
            assert argv[:6] == [
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
            ]
            assert cwd == Path("/")
            fake.calls.append(argv[-1])
            return response(remote)
        return original(argv, cwd, env, **limits)

    monkeypatch.setattr(issues, "read_command", gh)
    return {
        "root": root,
        "sha": sha,
        "home": home,
        "fake": fake,
        "remote": remote,
        "checkpoint": home / ".local/state/agent-platform/12/issue-1.json",
        "worktree": home / ".local/share/agent-platform/worktrees/12/issue-1",
    }


def run(task):
    return prepare.prepare(cli.inspect(task["root"]), 1, ["maintainer"])


def snapshot(root):
    return {
        str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }


def test_prepare_ready_and_idempotent(task):
    result = run(task)
    assert result == {
        "status": "prepared",
        "state": "READY",
        "repository": REPO,
        "issue": 1,
        "branch": "agent/issue-1",
        "worktree": str(task["worktree"]),
    }
    checkpoint = json.loads(task["checkpoint"].read_bytes())
    assert checkpoint["phase"] == "READY" and checkpoint["generation"] == 2
    assert checkpoint["last_intent"] == "CONFIRMED"
    assert checkpoint["attempt"] == 1 and checkpoint["codex_thread_id"] is None
    assert checkpoint["repo_id"] == 12 and checkpoint["base_sha"] == task["sha"]
    assert len(checkpoint["scope_sha256"]) == 64
    assert checkpoint["scope_revision"] == "2026-10-27T12:00:00Z"
    assert len(task["checkpoint"].read_bytes()) <= 16384
    assert stat.S_IMODE(task["checkpoint"].stat().st_mode) == 0o600
    assert stat.S_IMODE(task["checkpoint"].parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(task["worktree"].stat().st_mode) == 0o700
    assert (task["worktree"] / "tracked.txt").read_text() == "fixture\n"
    before = snapshot(task["home"])
    git_before = snapshot(task["root"] / ".git")
    assert run(task)["status"] == "already_prepared"
    assert snapshot(task["home"]) == before
    assert snapshot(task["root"] / ".git") == git_before
    assert len(git(task["root"], "worktree", "list").splitlines()) == 2


def test_no_credentials_or_prohibited_commands(task, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "environment-secret")
    original = subprocess.Popen
    calls = []

    def guarded(argv, **kwargs):
        assert argv[0] == "git"
        assert kwargs["shell"] is False and kwargs["start_new_session"] is True
        assert kwargs["umask"] == 0o077
        assert not {"GH_TOKEN", "GITHUB_TOKEN", "HOME"} & kwargs["env"].keys()
        args = argv[1:]
        if args[: len(prepare.GIT_OPTIONS)] == prepare.GIT_OPTIONS:
            args = args[len(prepare.GIT_OPTIONS) :]
        assert args[0] in {
            "rev-parse",
            "remote",
            "status",
            "config",
            "ls-files",
            "worktree",
            "for-each-ref",
        }
        if args[0] == "worktree" and args[1] == "add":
            assert args == [
                "worktree",
                "add",
                "--no-track",
                "-b",
                "agent/issue-1",
                str(task["worktree"]),
                task["sha"],
            ]
            assert (
                json.loads(task["checkpoint"].read_bytes())["last_intent"]
                == "CREATE_WORKTREE"
            )
        elif args[0] == "config":
            assert args in [
                ["config", "--local", "--no-includes", "--name-only", "--list"],
                ["config", "--local", "--get-all", "remote.origin.url"],
            ]
        elif args[0] == "worktree":
            assert args == ["worktree", "list", "--porcelain", "-z"]
        calls.append(args)
        return original(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", guarded)
    assert run(task)["state"] == "READY"
    assert sum(args[:2] == ["worktree", "add"] for args in calls) == 1
    saved = task["checkpoint"].read_text()
    assert "environment-secret" not in saved and "## Scope" not in saved
    assert issue()["body"] not in saved and "https://" not in saved
    assert all(
        "/branches/main" in call or "/issues/1" in call or call == PREFIX
        for call in task["fake"].calls
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "closed"},
        {"labels": []},
        {"pull_request": {}},
        {"body": ""},
        {"labels": [{"name": "agent:ready"}, {"name": "needs:human"}]},
        {"labels": [{"name": "agent:ready"}, {"name": "agent:working"}]},
    ],
)
def test_ineligible_no_changes(task, changes):
    task["fake"].items[1] = issue(**changes)
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 9
    assert snapshot(task["root"]) == before
    assert not state.LOCK_DIR.exists() and not list(task["home"].iterdir())


def test_missing_or_untrusted_actor(task):
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        prepare.prepare(cli.inspect(task["root"]), 1, [])
    assert error.value.code == 9
    assert task["fake"].calls == []
    task["fake"].histories[1] = [event(actor="attacker")]
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 9
    assert snapshot(task["root"]) == before
    assert not state.LOCK_DIR.exists()


def test_edit_between_admission_checks(task):
    original = task["fake"].items[1]
    edited = issue(
        body=original["body"] + "\n- Add another explicit change with new tests."
    )
    task["fake"].sequences[PREFIX + "/issues/1"] = [
        response(original),
        response(original),
        response(edited),
        response(edited),
    ]
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.reason == "admission_changed"
    assert snapshot(task["root"]) == before and not task["checkpoint"].exists()


@pytest.mark.parametrize(
    "kind",
    [
        "untracked",
        "dirty",
        "staged",
        "detached",
        "stale",
        "diverged",
        "origin",
        "multiple_origins",
        "worktree",
        "branch",
    ],
)
def test_unsafe_git(task, tmp_path, kind):
    root = task["root"]
    if kind == "untracked":
        (root / "untracked").write_text("preserve")
    elif kind in ("dirty", "staged"):
        (root / "tracked.txt").write_text("preserve\n")
        if kind == "staged":
            git(root, "add", "tracked.txt")
    elif kind == "detached":
        git(root, "checkout", "--detach")
    elif kind == "stale":
        git(root, "update-ref", "-d", "refs/remotes/origin/main")
    elif kind == "diverged":
        git(
            root,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "ahead",
        )
    elif kind == "origin":
        git(root, "remote", "set-url", "origin", "https://secret@github.com/a/b")
    elif kind == "multiple_origins":
        git(
            root,
            "config",
            "--add",
            "remote.origin.url",
            "https://github.com/other/repo",
        )
    elif kind == "worktree":
        git(root, "worktree", "add", "-b", "other", str(tmp_path / "other"))
    elif kind == "branch":
        git(root, "branch", "agent/issue-1")
    before = snapshot(root)
    with pytest.raises((PrepareError, cli.InspectionError)):
        run(task)
    assert snapshot(root) == before
    assert not task["checkpoint"].exists() and not task["worktree"].exists()


@pytest.mark.parametrize("kind", ["sha", "default_branch"])
def test_github_base_mismatch(task, kind):
    if kind == "sha":
        task["remote"]["commit"]["sha"] = "f" * 40
    else:
        task["fake"].overrides[PREFIX] = response(
            {
                "id": 12,
                "full_name": REPO,
                "default_branch": "develop",
            }
        )
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 11
    assert snapshot(task["root"]) == before and not state.LOCK_DIR.exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("filter.danger.smudge", "touch /must-not-exist"),
        ("filter.danger.process", "secret-command"),
        ("include.path", "/nonexistent"),
        ("remote.origin.promisor", "true"),
        ("core.sparseCheckout", "true"),
    ],
)
def test_unsafe_configuration(task, key, value):
    git(task["root"], "config", key, value)
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.reason == "unsupported_git_configuration"
    assert snapshot(task["root"]) == before


def test_checkout_hooks_not_run(task):
    hook = task["root"] / ".git/hooks/post-checkout"
    marker = task["root"].parent / "hook-ran"
    hook.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    hook.chmod(0o700)
    assert run(task)["state"] == "READY"
    assert not marker.exists()


def test_existing_path_preserved(task):
    state.private_directory(task["worktree"].parent, prepare.HOME, create=True)
    task["worktree"].mkdir(mode=0o700)
    (task["worktree"] / "sentinel").write_text("preserve")
    before = snapshot(task["home"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.reason == "worktree_path_conflict"
    assert snapshot(task["home"]) == before


def test_lock_contention_no_task_side_effects(task):
    with state.host_lock():
        before = snapshot(task["root"])
        lock_inode = (state.LOCK_DIR / "prepare.lock").stat().st_ino
        with pytest.raises(PrepareError) as error:
            run(task)
        assert error.value.code == 10
        assert snapshot(task["root"]) == before and not list(task["home"].iterdir())
        assert (state.LOCK_DIR / "prepare.lock").stat().st_ino == lock_inode
    assert run(task)["state"] == "READY"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", 2),
        ("repo_id", 13),
        ("issue", 2),
        ("branch", "main"),
        ("worktree", "/somewhere/else"),
        ("phase", "UNKNOWN"),
        ("attempt", True),
        ("generation", 99),
        ("codex_thread_id", "not-null"),
    ],
)
def test_checkpoint_mismatch_never_overwritten(task, field, value):
    run(task)
    record = json.loads(task["checkpoint"].read_text())
    record[field] = value
    task["checkpoint"].write_text(json.dumps(record))
    before = snapshot(task["root"])
    checkpoint_before = task["checkpoint"].read_bytes()
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 12
    assert snapshot(task["root"]) == before
    assert task["checkpoint"].read_bytes() == checkpoint_before


@pytest.mark.parametrize(
    "content",
    [
        "{bad secret",
        "{}",
        "[]",
        '{"phase":NaN}',
        '{"phase":"READY","phase":"READY"}',
        "x" * 16385,
    ],
)
def test_malformed_checkpoint(task, content):
    state.private_directory(
        task["checkpoint"].parent,
        prepare.HOME / ".local/state/agent-platform",
        create=True,
    )
    task["checkpoint"].write_text(content)
    task["checkpoint"].chmod(0o600)
    before = snapshot(task["root"])
    with pytest.raises(PrepareError):
        run(task)
    assert (
        snapshot(task["root"]) == before and task["checkpoint"].read_text() == content
    )


@pytest.mark.parametrize(
    "kind",
    [
        "directory_symlink",
        "checkpoint_symlink",
        "directory_mode",
        "file_mode",
        "hardlink",
    ],
)
def test_unsafe_private_storage(task, tmp_path, kind):
    state.private_directory(
        task["checkpoint"].parent,
        prepare.HOME / ".local/state/agent-platform",
        create=True,
    )
    if kind == "directory_symlink":
        task["worktree"].parent.parent.mkdir(parents=True, mode=0o700)
        task["worktree"].parent.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "checkpoint_symlink":
        outside = tmp_path / "sentinel"
        outside.write_text("preserve")
        task["checkpoint"].symlink_to(outside)
    elif kind == "directory_mode":
        task["checkpoint"].parent.chmod(0o755)
    else:
        task["checkpoint"].write_text("{}")
        task["checkpoint"].chmod(0o644 if kind == "file_mode" else 0o600)
        if kind == "hardlink":
            os.link(task["checkpoint"], tmp_path / "linked-checkpoint")
    before = snapshot(task["root"])
    with pytest.raises(PrepareError):
        run(task)
    assert snapshot(task["root"]) == before
    if kind == "checkpoint_symlink":
        assert outside.read_text() == "preserve"


@pytest.mark.parametrize(
    "point",
    [
        "before_intent",
        "after_intent",
        "git_failure",
        "after_git",
        "confirmation",
        "before_ready",
        "after_ready",
    ],
)
def test_interruption_never_repeats_uncertain_creation(task, monkeypatch, point):
    original_write = state.write_checkpoint
    original_git = prepare.git
    original_confirm = prepare.confirm
    calls = []

    def write(path, data, **kwargs):
        ready = data["phase"] == "READY"
        if (point == "before_intent" and not ready) or (
            point == "before_ready" and ready
        ):
            raise OSError("secret")
        original_write(path, data, **kwargs)
        if (point == "after_intent" and not ready) or (
            point == "after_ready" and ready
        ):
            raise OSError("secret")

    def execute(root, *args):
        if args[:2] == ("worktree", "add"):
            calls.append(args)
            if point == "git_failure":
                raise PrepareError(11, "injected_failure")
            result = original_git(root, *args)
            if point == "after_git":
                raise OSError("secret")
            return result
        return original_git(root, *args)

    def confirm(root, record):
        if point == "confirmation":
            raise PrepareError(12, "injected_confirmation")
        return original_confirm(root, record)

    monkeypatch.setattr(state, "write_checkpoint", write)
    monkeypatch.setattr(prepare, "git", execute)
    monkeypatch.setattr(prepare, "confirm", confirm)
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 12 and "secret" not in str(error.value)
    monkeypatch.setattr(state, "write_checkpoint", original_write)
    monkeypatch.setattr(prepare, "confirm", original_confirm)
    count = len(calls)
    if point in ("before_intent", "after_ready"):
        # No intent means no Git was attempted; READY is independently verified.
        assert run(task)["state"] == "READY"
        assert len(calls) == count + (point == "before_intent")
    else:
        with pytest.raises(PrepareError) as error:
            run(task)
        assert error.value.code == 12
        assert len(calls) == count


@pytest.mark.parametrize(
    "point", ["temp_open", "file_fsync", "replace", "directory_fsync"]
)
def test_atomic_write_failure_is_non_destructive(task, monkeypatch, point):
    directory = task["checkpoint"].parent
    state.private_directory(
        directory, prepare.HOME / ".local/state/agent-platform", create=True
    )
    original = {"preserved": True}
    state.write_checkpoint(task["checkpoint"], original)
    real_open, real_fsync, real_replace = os.open, os.fsync, os.replace
    real_sync = state.sync_directory

    def open_file(path, flags, *args, **kwargs):
        if point == "temp_open" and ".tmp-" in str(path):
            raise OSError("secret")
        return real_open(path, flags, *args, **kwargs)

    def fsync(fd):
        if point == "file_fsync" and stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("secret")
        return real_fsync(fd)

    def replace(source, target):
        if point == "replace":
            raise OSError("secret")
        return real_replace(source, target)

    def sync(path):
        if point == "directory_fsync":
            raise OSError("secret")
        return real_sync(path)

    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(state, "sync_directory", sync)
    with pytest.raises(OSError):
        state.write_checkpoint(task["checkpoint"], {"new": True}, previous=original)
    stored = json.loads(task["checkpoint"].read_text())
    assert stored == ({"new": True} if point == "directory_fsync" else original)
    if point in ("file_fsync", "replace"):
        with pytest.raises(PrepareError) as error:
            state.load_checkpoint(task["checkpoint"])
        assert error.value.reason == "interrupted_checkpoint"


def test_ready_worktree_changed_requires_human(task):
    run(task)
    (task["worktree"] / "tracked.txt").write_text("human changes\n")
    before = snapshot(task["home"])
    with pytest.raises(PrepareError):
        run(task)
    assert snapshot(task["home"]) == before


def test_scope_changed_after_ready_requires_human(task):
    run(task)
    task["fake"].items[1]["body"] += "\n- Add different functionality with extra tests."
    before = snapshot(task["home"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 12
    assert snapshot(task["home"]) == before


def test_cli_prepare_result(task, monkeypatch, capsys):
    monkeypatch.chdir(task["root"])
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-platform", "prepare", "--issue", "1", "--trusted-actor", "maintainer"],
    )
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "prepared"
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["status"] == "already_prepared"


def test_cli_missing_policy_and_required_issue(task, monkeypatch, capsys):
    monkeypatch.chdir(task["root"])
    monkeypatch.setattr(sys, "argv", ["agent-platform", "prepare", "--issue", "1"])
    assert cli.main() == 9
    assert json.loads(capsys.readouterr().out)["status"] == "missing_trusted_actors"
    assert not task["checkpoint"].exists()
    monkeypatch.setattr(sys, "argv", ["agent-platform", "prepare"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


def test_case_insensitive_repository_identity(task):
    git(
        task["root"], "remote", "set-url", "origin", "git@github.com:EXAMPLE/TARGET.git"
    )
    assert run(task)["repository"] == REPO
    assert run(task)["status"] == "already_prepared"


def test_two_concurrent_invocations(task, monkeypatch):
    original = prepare.git
    entered, release = threading.Event(), threading.Event()
    results = []
    failures = []

    def paused(root, *args):
        if args[:2] == ("worktree", "add"):
            entered.set()
            assert release.wait(5)
        return original(root, *args)

    def first():
        try:
            results.append(run(task))
        except BaseException as error:
            failures.append(error)

    monkeypatch.setattr(prepare, "git", paused)
    worker = threading.Thread(target=first)
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(PrepareError) as error:
            run(task)
        assert error.value.code == 10
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and not failures
    assert len(results) == 1 and results[0]["status"] == "prepared"
    assert len(git(task["root"], "worktree", "list").splitlines()) == 2


@pytest.mark.parametrize("location", ["private", "ancestor"])
def test_wrong_storage_ownership(task, monkeypatch, location):
    state.private_directory(
        task["checkpoint"].parent,
        prepare.HOME / ".local/state/agent-platform",
        create=True,
    )
    actual = Path.lstat
    wrong_path = (
        task["checkpoint"].parent if location == "private" else prepare.HOME / ".local"
    )

    def wrong_owner(path, *args, **kwargs):
        info = actual(path, *args, **kwargs)
        if path == wrong_path:
            values = list(info)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", wrong_owner)
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 7
    assert not task["worktree"].exists()


def test_unknown_checkpoint_cannot_be_replaced(task):
    state.private_directory(
        task["checkpoint"].parent,
        prepare.HOME / ".local/state/agent-platform",
        create=True,
    )
    state.write_checkpoint(task["checkpoint"], {"preserve": True})
    before = task["checkpoint"].read_bytes()
    with pytest.raises(PrepareError) as error:
        state.write_checkpoint(task["checkpoint"], {"replacement": True})
    assert error.value.reason == "checkpoint_conflict"
    assert task["checkpoint"].read_bytes() == before


def test_partial_checkpoint_write_leaves_recovery_marker(task, monkeypatch):
    state.private_directory(
        task["checkpoint"].parent,
        prepare.HOME / ".local/state/agent-platform",
        create=True,
    )
    original = os.fdopen

    class PartialWrite:
        def __init__(self, fd, *args, **kwargs):
            self.stream = original(fd, *args, **kwargs)

        def __enter__(self):
            return self

        def write(self, data):
            self.stream.write(data[:5])
            self.stream.flush()
            raise OSError("secret")

        def __exit__(self, *args):
            self.stream.close()

    monkeypatch.setattr(os, "fdopen", PartialWrite)
    with pytest.raises(OSError):
        state.write_checkpoint(task["checkpoint"], {"phase": "NEEDS_HUMAN"})
    with pytest.raises(PrepareError) as error:
        state.load_checkpoint(task["checkpoint"])
    assert error.value.reason == "interrupted_checkpoint"
    assert not task["checkpoint"].exists()


@pytest.mark.parametrize("kind", ["nested", "non_git"])
def test_invalid_cwd_no_prepare_side_effects(task, tmp_path, monkeypatch, capsys, kind):
    root = task["root"] / "nested" if kind == "nested" else tmp_path / "outside"
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.setattr(
        sys,
        "argv",
        ["agent-platform", "prepare", "--issue", "1", "--trusted-actor", "maintainer"],
    )
    assert cli.main() == (3 if kind == "nested" else 2)
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_target"
    assert not task["fake"].calls and not state.LOCK_DIR.exists()


def test_symlinked_git_namespace_cannot_escape(task, tmp_path):
    outside = tmp_path / "outside-refs"
    outside.mkdir()
    (outside / "sentinel").write_text("preserve")
    (task["root"] / ".git/refs/heads/agent").symlink_to(
        outside, target_is_directory=True
    )
    with pytest.raises(PrepareError):
        run(task)
    assert (outside / "sentinel").read_text() == "preserve"
    assert not (outside / "issue-1").exists() and not task["checkpoint"].exists()


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_hidden_tracked_changes_rejected(task, flag):
    git(task["root"], "update-index", flag, "tracked.txt")
    (task["root"] / "tracked.txt").write_text("hidden changes\n")
    before = snapshot(task["root"])
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.reason == "unsupported_index_flags"
    assert snapshot(task["root"]) == before


def test_preexisting_dangling_reflog_preserved(task):
    log = task["root"] / ".git/logs/refs/heads/agent/issue-1"
    log.parent.mkdir()
    log.write_text("preserve historical data\n")
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.reason == "branch_conflict"
    assert log.read_text() == "preserve historical data\n"
    assert not task["checkpoint"].exists()


def test_missing_label_history_no_side_effects(task):
    task["fake"].histories[1] = []
    with pytest.raises(issues.AdmissionError):
        run(task)
    assert not state.LOCK_DIR.exists() and not list(task["home"].iterdir())


def test_confirmation_inspection_failure_leaves_intent(task, monkeypatch):
    original = prepare.inspect

    def fail(path):
        if path == task["worktree"]:
            raise cli.InspectionError(6, "secret")
        return original(path)

    monkeypatch.setattr(prepare, "inspect", fail)
    with pytest.raises(PrepareError) as error:
        run(task)
    assert error.value.code == 12 and "secret" not in str(error.value)
    assert json.loads(task["checkpoint"].read_text())["phase"] == "NEEDS_HUMAN"
