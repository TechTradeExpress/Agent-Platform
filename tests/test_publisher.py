"""Offline fake admission + synthetic Git; no real publisher/authentication."""

import hashlib
import json
import os
import socket
from dataclasses import FrozenInstanceError, asdict, replace

import pytest
from test_prepare import git, snapshot
from test_prepare import run as prepare_task
from test_prepare import task as task

from agent_platform import cli, codex, execution, issues, prepare, publisher, state

SESSION = "0199a213-81c0-7800-8aa1-bbab2a035a53"
EXECUTION = "0199a213-81c0-7800-8aa1-bbab2a035a54"


def admission(task):
    # Real admission/provenance code traverses only FakeGH, never the network.
    approved = prepare.approved(
        issues.GitHub("example/target"), "example/target", 1, ["maintainer"]
    )
    return publisher.Admission(**approved)


def evidence(task):
    changes, _, tree_digest = publisher._inventory(task["worktree"])
    record = state.load_checkpoint(task["checkpoint"])
    return publisher.TestEvidence(
        checkpoint_sha256=publisher.digest(record),
        tree_sha256=tree_digest,
        expected_changes=changes,
        checks=tuple(
            publisher.TestCheck(name, "PASS", hashlib.sha256(name.encode()).hexdigest())
            for name in publisher.CHECKS
        ),
    )


@pytest.fixture
def completed(task):
    prepare_task(task)
    task["root"].chmod(0o700)
    (task["root"] / ".git").chmod(0o700)
    tree = task["worktree"]
    # New fixture files only: normalize test umask, never repair production state.
    for path in tree.iterdir():
        path.chmod(0o600)
    (tree / "tracked.txt").write_text("proposed coding change\n")
    old = state.load_checkpoint(task["checkpoint"])
    record = {
        **old,
        "version": 2,
        "phase": "COMPLETED",
        "generation": 5,
        "last_intent": "TURN_COMPLETED",
        "codex_thread_id": SESSION,
        "refs_sha256": execution.refs(task["root"]),
        "isolation_sha256": "a" * 64,
        "codex_version": codex.VERSION,
        "execution_id": EXECUTION,
        "codex_home": str(
            prepare.HOME
            / ".local/share/agent-platform/codex-sessions/12/issue-1"
            / EXECUTION
        ),
        "runtime_sha256": "b" * 64,
        "stop_reason": "completed",
        "usage": {"input_tokens": 10, "cached_input_tokens": 2, "output_tokens": 4},
    }
    state.write_checkpoint(task["checkpoint"], record, previous=old)
    task.update(admission=admission(task), evidence=evidence(task))
    return task


def plan(task):
    return publisher.plan(task["root"], task["admission"], task["evidence"])


def diagnostic(task):
    report = publisher.diagnose(task["root"], task["admission"], task["evidence"])
    text = json.dumps(report)
    assert len(text.encode()) <= 1024
    assert str(task["root"]) not in text and "secret" not in text
    assert report["publish_authorized"] is False
    return report


def blocked(task):
    report = diagnostic(task)
    assert report["status"] == "BLOCKED"
    return report


def rewrite(task, **changes):
    record = state.load_checkpoint(task["checkpoint"])
    record.update(changes)
    task["checkpoint"].write_text(json.dumps(record))


def test_immutable_plan_identity_digest_and_idempotency(completed):
    a = plan(completed)
    b = plan(completed)
    assert a == b
    assert a.admission == completed["admission"]
    assert a.worktree == str(completed["worktree"])
    assert a.common_dir == str(completed["root"] / ".git")
    assert a.branch == "agent/issue-1" and a.base_branch == "main" and a.draft
    assert a.session_id == SESSION and a.execution_id == EXECUTION
    assert a.checkpoint_generation == 5
    assert a.changes[0].path == "tracked.txt" and a.changes[0].status == " M"
    assert a.inventory_sha256 == publisher.digest([asdict(c) for c in a.changes])
    assert a.idempotency_key == publisher.digest(asdict(replace(a, idempotency_key="")))
    assert a.body.startswith("Closes #1\n")
    for value, key in [
        (a, "branch"),
        (a.admission, "repo_id"),
        (a.changes[0], "path"),
        (completed["evidence"].checks[0], "outcome"),
    ]:
        with pytest.raises(FrozenInstanceError):
            setattr(value, key, "arbitrary")
    assert diagnostic(completed)["status"] == "INSPECTED_PUBLISH_CANDIDATE"


def test_no_network_writes_secrets_sessions_or_model_execution(completed, monkeypatch):
    calls = []
    original_open = os.open
    original_read = prepare.read_command
    before = snapshot(completed["home"])
    refs = execution.refs(completed["root"])
    cp = completed["checkpoint"].read_bytes()
    lock = (state.LOCK_DIR / "prepare.lock").stat()

    def readonly(path, flags, *args, **kwargs):
        if str(path) != os.devnull:
            assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        assert "codex-sessions" not in str(path)
        assert ".codex" not in str(path)
        return original_open(path, flags, *args, **kwargs)

    def read(argv, cwd, env, **limits):
        assert argv[0] == "git"
        assert not {"GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY"} & env.keys()
        assert limits["timeout"] <= 5 and limits["limit"] <= 256 * 1024
        assert not {
            "push",
            "commit",
            "add",
            "update-ref",
            "fetch",
            "reset",
            "clean",
            "checkout",
        } & set(argv)
        calls.append(tuple(argv))
        return original_read(argv, cwd, env, **limits)

    monkeypatch.setattr(os, "open", readonly)
    monkeypatch.setattr(prepare, "read_command", read)
    monkeypatch.setattr(cli, "read_command", read)
    monkeypatch.setattr(
        issues, "GitHub", lambda *a: pytest.fail("offline planner has no GitHub client")
    )
    monkeypatch.setattr(
        state, "write_checkpoint", lambda *a, **k: pytest.fail("no checkpoint writes")
    )
    monkeypatch.setattr(
        execution, "runtime_digest", lambda *a: pytest.fail("no native session access")
    )
    monkeypatch.setenv("GH_TOKEN", "secret-auth-value")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-auth-value")
    assert plan(completed).publish_authorized is False
    assert calls and completed["checkpoint"].read_bytes() == cp
    assert execution.refs(completed["root"]) == refs
    assert snapshot(completed["home"]) == before
    after = (state.LOCK_DIR / "prepare.lock").stat()
    assert (after.st_ino, after.st_mtime_ns) == (lock.st_ino, lock.st_mtime_ns)


@pytest.mark.parametrize(
    "kind",
    [
        "staged",
        "mixed",
        "untracked",
        "deleted",
        "staged_deleted",
        "added",
        "added_modified",
        "mode",
    ],
)
def test_exact_change_inventory(completed, kind):
    root = completed["worktree"]
    path = root / "tracked.txt"
    if kind in {"staged", "mixed"}:
        git(root, "add", "tracked.txt")
        if kind == "mixed":
            path.write_text("unstaged after staging\n")
    elif kind in {"untracked", "added", "added_modified"}:
        new = root / "new.py"
        new.write_text("print('synthetic')\n")
        new.chmod(0o600)
        if kind != "untracked":
            git(root, "add", "new.py")
        if kind == "added_modified":
            new.write_text("print('modified synthetic')\n")
    elif kind in {"deleted", "staged_deleted"}:
        path.unlink()
        if kind == "staged_deleted":
            git(root, "add", "tracked.txt")
    else:
        path.chmod(0o700)
    completed["evidence"] = evidence(completed)
    result = plan(completed)
    expected = {
        "staged": "M ",
        "mixed": "MM",
        "untracked": "??",
        "deleted": " D",
        "staged_deleted": "D ",
        "added": "A ",
        "added_modified": "AM",
        "mode": " M",
    }[kind]
    assert expected in {c.status for c in result.changes}
    if "deleted" in kind:
        assert result.changes[0].sha256 is None and result.changes[0].bytes is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("phase", "PAUSED"),
        ("phase", "READY"),
        ("phase", "NEEDS_HUMAN"),
        ("phase", "RUNNING"),
        ("generation", 8),
        ("generation", True),
        ("last_intent", "TURN_STOPPED"),
        ("stop_reason", "ambiguous"),
        ("branch", "main"),
        ("base_sha", "f" * 40),
        ("repo_id", 13),
        ("issue", 2),
        ("issue_id", 999),
        ("common_dir", "/secret/elsewhere"),
        ("source_root", "/secret/elsewhere"),
        ("worktree", "/secret/elsewhere"),
        ("codex_thread_id", "--last"),
        ("execution_id", "--last"),
        ("codex_version", "unknown"),
        ("runtime_sha256", "bad"),
        ("codex_home", "/secret/account"),
        ("usage", None),
        ("usage", {"input_tokens": True, "cached_input_tokens": 1, "output_tokens": 2}),
        ("publisher_url", "https://secret.invalid"),
        ("token", "secret-auth"),
    ],
)
def test_checkpoint_identity_and_terminal_state_fail_closed(completed, field, value):
    rewrite(completed, **{field: value})
    blocked(completed)


@pytest.mark.parametrize(
    "fault", ["repo", "repo_id", "issue", "scope", "revision", "history", "base"]
)
def test_trusted_admission_change_invalidates_checkpoint(completed, fault):
    a = completed["admission"]
    changes = {
        "repo": {"repository": "other/repo"},
        "repo_id": {"repo_id": 13},
        "issue": {"issue": 2},
        "scope": {"scope_sha256": "c" * 64},
        "revision": {"scope_revision": "2026-10-28T12:00:00Z"},
        "history": {"admission_sha256": "c" * 64},
        "base": {"base_sha": "f" * 40},
    }[fault]
    completed["admission"] = replace(a, **changes)
    blocked(completed)


def test_changed_fake_github_issue_rejected(completed):
    completed["fake"].items[1]["body"] += (
        "\n- Implement unauthorized behavior with additional work."
    )
    completed["admission"] = admission(completed)
    blocked(completed)


def test_revoked_fake_github_authority_never_produces_new_admission(completed):
    completed["fake"].items[1]["labels"] = []
    with pytest.raises(state.PrepareError):
        admission(completed)


@pytest.mark.parametrize(
    "fault",
    [
        "new_ref",
        "dirty_source",
        "wrong_origin",
        "changed_head",
        "wrong_common",
        "extra_worktree",
        "hidden",
        "renamed",
        "staged_recreated",
        "ignored",
        "filter",
    ],
)
def test_repository_and_git_ambiguity(completed, tmp_path, fault):
    root = completed["root"]
    tree = completed["worktree"]
    if fault == "new_ref":
        git(root, "branch", "unexpected")
    elif fault == "dirty_source":
        (root / "unexpected").write_text("preserve")
    elif fault == "wrong_origin":
        git(
            root,
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/repository.git",
        )
    elif fault == "changed_head":
        git(tree, "add", "tracked.txt")
        git(
            tree,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "unauthorized fixture commit",
        )
    elif fault == "wrong_common":
        (tree / ".git").write_text(f"gitdir: {tmp_path}/other\n")
    elif fault == "extra_worktree":
        git(root, "worktree", "add", "-b", "unexpected", str(tmp_path / "extra"))
    elif fault == "hidden":
        git(tree, "update-index", "--assume-unchanged", "tracked.txt")
    elif fault == "renamed":
        git(tree, "mv", "tracked.txt", "renamed.txt")
    elif fault == "staged_recreated":
        git(tree, "rm", "-f", "tracked.txt")
        (tree / "tracked.txt").write_text("recreated after staged deletion")
    elif fault == "ignored":
        with (root / ".git/info/exclude").open("a") as stream:
            stream.write("\nignored-fixture\n")
        (tree / "ignored-fixture").write_text("preserve")
    else:
        git(root, "config", "filter.attack.clean", "never-execute-secret-command")
    blocked(completed)


@pytest.mark.parametrize(
    "fault",
    [
        "symlink",
        "hardlink",
        "directory_symlink",
        "fifo",
        "socket",
        "mode",
        "setuid",
        "private_path",
        "unsafe_name",
        "large",
        "too_many",
    ],
)
def test_unsafe_tree_refused_without_reading_aliases(
    completed, tmp_path, monkeypatch, fault
):
    root = completed["worktree"]
    path = root / "tracked.txt"
    sock = None
    if fault == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "secret-sentinel")
    elif fault == "hardlink":
        os.link(path, tmp_path / "alias")
    elif fault == "directory_symlink":
        (root / "alias").symlink_to(tmp_path, target_is_directory=True)
    elif fault in {"fifo", "socket"}:
        if fault == "fifo":
            os.mkfifo(root / "special")
        else:
            sock = socket.socket(socket.AF_UNIX)
            monkeypatch.chdir(root)
            sock.bind("special")
    elif fault in {"mode", "setuid"}:
        path.chmod(0o666 if fault == "mode" else 0o4600)
    elif fault in {"private_path", "unsafe_name"}:
        target = root / (".codex" if fault == "private_path" else "unsafe\nsecret")
        target.mkdir(mode=0o700)
    elif fault == "large":
        with path.open("r+b") as stream:
            stream.truncate(publisher.MAX_FILE_BYTES + 1)
    else:
        for i in range(publisher.MAX_FILES + 1):
            (root / f"new-{i}").touch(mode=0o600)
    try:
        blocked(completed)
    finally:
        if sock:
            sock.close()


@pytest.mark.parametrize(
    "fault",
    [
        "guard",
        "dangling_guard",
        "temp_checkpoint",
        "checkpoint_symlink",
        "checkpoint_hardlink",
        "checkpoint_mode",
        "missing_lock",
        "lock_busy",
    ],
)
def test_recovery_and_lock_invariants(completed, tmp_path, fault):
    cp = completed["checkpoint"]
    guard = cp.with_suffix(".execution-guard")
    if fault == "guard":
        guard.write_text("uncertain")
    elif fault == "dangling_guard":
        guard.symlink_to(tmp_path / "missing")
    elif fault == "temp_checkpoint":
        cp.with_name(cp.name + ".tmp-unknown").touch()
    elif fault == "checkpoint_symlink":
        cp.rename(tmp_path / "original-checkpoint")
        cp.symlink_to(tmp_path / "original-checkpoint")
    elif fault == "checkpoint_hardlink":
        os.link(cp, tmp_path / "alias")
    elif fault == "checkpoint_mode":
        cp.chmod(0o644)
    elif fault == "missing_lock":
        (state.LOCK_DIR / "prepare.lock").unlink()
    else:
        with state.host_lock(create=False):
            assert blocked(completed)["reason"] == "lock_busy"
        return
    before = snapshot(completed["home"])
    blocked(completed)
    assert snapshot(completed["home"]) == before
    if fault == "missing_lock":
        assert not (state.LOCK_DIR / "prepare.lock").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "wrong_receipt",
        "wrong_tree",
        "wrong_changes",
        "reordered",
        "file_drift",
        "staged_drift",
    ],
)
def test_missing_stale_or_mismatched_test_evidence(completed, fault):
    e = completed["evidence"]
    if fault == "missing":
        completed["evidence"] = None
    elif fault == "wrong_receipt":
        completed["evidence"] = replace(e, checkpoint_sha256="c" * 64)
    elif fault == "wrong_tree":
        completed["evidence"] = replace(e, tree_sha256="c" * 64)
    elif fault == "wrong_changes":
        completed["evidence"] = replace(
            e, expected_changes=(replace(e.expected_changes[0], sha256="c" * 64),)
        )
    elif fault == "reordered":
        completed["evidence"] = replace(e, checks=tuple(reversed(e.checks)))
    elif fault == "file_drift":
        (completed["worktree"] / "tracked.txt").write_text("unreviewed changes")
    else:
        git(completed["worktree"], "add", "tracked.txt")
    blocked(completed)


def test_model_metadata_is_inert_artifact(completed):
    raw = {
        "repo": "other/repo",
        "url": "https://secret.invalid",
        "token": "secret",
        "branch": "main",
        "command": "rm -rf /",
        "reviewers": ["attacker"],
        "labels": ["ready"],
        "publish_authorized": True,
    }
    path = completed["worktree"] / "publisher.json"
    path.write_text(json.dumps(raw))
    path.chmod(0o600)
    completed["evidence"] = evidence(completed)
    result = plan(completed)
    assert (
        result.admission.repository == "example/target"
        and result.branch == "agent/issue-1"
    )
    assert "secret" not in json.dumps(asdict(result))
    assert result.title == "Issue #1: proposed changes" and "secret" not in result.body
    assert result.publish_authorized is False
    assert "publisher.json" not in json.dumps(result.diagnostic())
    assert "url" not in asdict(result) and "token" not in asdict(result)


@pytest.mark.parametrize("point", ["file", "checkpoint", "guard", "refs", "lock"])
def test_race_between_snapshots_refused(completed, monkeypatch, point):
    original = publisher._inventory
    calls = 0

    def racing(root):
        nonlocal calls
        result = original(root)
        calls += 1
        if calls == 1:
            if point == "file":
                (root / "tracked.txt").write_text("racing edit")
            elif point == "checkpoint":
                rewrite(
                    completed,
                    usage={
                        "input_tokens": 11,
                        "cached_input_tokens": 2,
                        "output_tokens": 4,
                    },
                )
            elif point == "guard":
                completed["checkpoint"].with_suffix(".execution-guard").touch()
            elif point == "refs":
                git(completed["root"], "branch", "racing")
            else:
                lock = state.LOCK_DIR / "prepare.lock"
                lock.rename(state.LOCK_DIR / "original-lock")
                lock.touch(mode=0o600)
        return result

    monkeypatch.setattr(publisher, "_inventory", racing)
    blocked(completed)


def test_nested_mount_without_real_mounting(completed, monkeypatch):
    original = open
    import io

    def mounted(path, *args, **kwargs):
        if str(path) == "/proc/self/mountinfo":
            root = completed["worktree"]
            return io.BytesIO(f"1 0 0:1 / {root}/nested rw - tmpfs x rw\n".encode())
        return original(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mounted)
    blocked(completed)


@pytest.mark.parametrize(
    "args",
    [
        dict(version="bad"),
        dict(repo_id=True),
        dict(base_sha="x"),
        dict(scope_sha256="x"),
        dict(repository="https://secret.invalid"),
    ],
)
def test_admission_schema_rejects_malicious_fields(completed, args):
    with pytest.raises((publisher.PlanError, cli.InspectionError, TypeError)):
        replace(completed["admission"], **args)


def test_missing_evidence_fields_and_false_pass_cannot_be_constructed():
    with pytest.raises(publisher.PlanError):
        publisher.TestCheck("pytest", "FAIL", "a" * 64)
    with pytest.raises(publisher.PlanError):
        publisher.TestCheck("arbitrary shell command", "PASS", "a" * 64)
    with pytest.raises(publisher.PlanError):
        publisher.TestEvidence("a" * 64, "a" * 64, (), ())


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "lock", "owner_mode"])
def test_git_metadata_aliases_and_writers_refused(completed, tmp_path, fault):
    common = completed["root"] / ".git"
    if fault == "symlink":
        (common / "alias").symlink_to(tmp_path / "secret-sentinel")
    elif fault == "hardlink":
        os.link(common / "config", tmp_path / "alias")
    elif fault == "lock":
        (common / "index.lock").touch(mode=0o600)
    else:
        common.chmod(0o777)
    blocked(completed)


@pytest.mark.parametrize(
    "raw",
    [
        b" M tracked.txt",
        b"UU tracked.txt\0",
        b" M ../secret\0",
        b" M tracked.txt\0 M tracked.txt\0",
        b"R  new\0old\0",
        b"!! secret\0",
        b"?? utf8-\xff\0",
    ],
)
def test_ambiguous_fake_git_status_refused(completed, monkeypatch, raw):
    original = prepare.git

    def fake(root, *args):
        if root == completed["worktree"] and args[0] == "status":
            return raw
        return original(root, *args)

    monkeypatch.setattr(prepare, "git", fake)
    blocked(completed)


def test_untrusted_errors_never_reach_diagnostics(completed, monkeypatch):
    def fail(*args):
        raise publisher.PlanError("secret token /private/path")

    monkeypatch.setattr(publisher, "plan", fail)
    assert blocked(completed)["reason"] == "local_state_unavailable"


def test_same_content_checkpoint_replacement_is_still_a_race(completed, monkeypatch):
    original = publisher._inventory
    calls = 0

    def replace_checkpoint(root):
        nonlocal calls
        result = original(root)
        calls += 1
        if calls == 1:
            cp = completed["checkpoint"]
            replacement = cp.with_name("replacement")
            replacement.write_bytes(cp.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, cp)
        return result

    monkeypatch.setattr(publisher, "_inventory", replace_checkpoint)
    assert blocked(completed)["reason"] == "checkpoint_changed"


def test_nonempty_inventory_cannot_claim_no_changes(completed):
    (completed["worktree"] / "tracked.txt").write_text("fixture\n")
    assert blocked(completed)["reason"] == "empty_or_large_inventory"


def test_cumulative_worktree_byte_budget(completed, monkeypatch):
    monkeypatch.setattr(publisher, "MAX_BYTES", 10)
    assert blocked(completed)["reason"] == "inventory_limit"


def test_full_tree_hash_and_new_evidence_change_idempotency(completed):
    old = plan(completed)
    (completed["worktree"] / "tracked.txt").write_text(
        "independently retested change\n"
    )
    completed["evidence"] = evidence(completed)
    new = plan(completed)
    assert old.idempotency_key != new.idempotency_key
    assert old.tree_sha256 != new.tree_sha256
    assert new.publish_authorized is False


def test_constructor_rejects_mutable_and_numeric_lookalikes(completed):
    entry = completed["evidence"].expected_changes[0]
    with pytest.raises(publisher.PlanError):
        replace(entry, bytes=float(entry.bytes))
    with pytest.raises(publisher.PlanError):
        replace(
            completed["evidence"],
            expected_changes=list(completed["evidence"].expected_changes),
        )
    with pytest.raises(publisher.PlanError):
        replace(completed["evidence"], checks=[])
