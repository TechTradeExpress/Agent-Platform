import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_platform import cli


def run_git(path, *args):
    return subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        timeout=5,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    run_git(root, "init", "-b", "main")
    run_git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "--allow-empty",
        "-m",
        "fixture",
    )
    run_git(root, "remote", "add", "origin", "https://github.com/example/target.git")
    return root


def test_normal_target_and_no_writes(repo, monkeypatch):
    before = {
        p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()
    }
    monkeypatch.setenv("GIT_DIR", "/nonexistent")
    monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent")
    result = cli.inspect(repo)
    assert result == {
        "repository": "example/target",
        "root": str(repo),
        "linked_worktree": False,
        "branch": "main",
    }
    after = {
        p.relative_to(repo): p.read_bytes() for p in repo.rglob("*") if p.is_file()
    }
    assert after == before


def test_linked_worktree(repo, tmp_path):
    linked = tmp_path / "linked"
    run_git(repo, "worktree", "add", "-b", "feature", str(linked))
    assert (linked / ".git").is_file()
    result = cli.inspect(linked)
    assert result["linked_worktree"] is True
    assert result["root"] == str(linked)
    assert result["branch"] == "feature"
    assert result["repository"] == "example/target"


def test_detached(repo):
    run_git(repo, "checkout", "--detach")
    assert cli.inspect(repo)["branch"] is None


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
        "https://github.com/owner/repo",
    ],
)
def test_origin(url):
    assert cli.parse_origin(url) == "owner/repo"


@pytest.mark.parametrize(
    "url",
    [
        "https://secret@github.com/owner/repo",
        "https://user:secret@github.com/owner/repo",
        "ssh://git:secret@github.com/owner/repo",
        "https://github.com.evil/owner/repo",
        "http://github.com/owner/repo",
        "https://github.com/owner/repo?token=secret",
        "https://github.com/owner/repo#secret",
        "git://github.com/owner/repo",
        "ssh://git@github.com:22/owner/repo",
        "https://github.com/owner/..",
        "https://github.com/owner/.git",
        "https://github.com/owner/repo/extra",
        "https://github.com/owner/repo\n",
        "file:///secret",
        "",
    ],
)
def test_untrusted_origin(url):
    with pytest.raises(cli.InspectionError) as error:
        cli.parse_origin(url)
    assert error.value.code == 4
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("kind,code", [("nested", 3), ("outside", 2), ("missing", 4)])
def test_rejections(repo, tmp_path, kind, code):
    target = repo
    if kind == "nested":
        target = repo / "nested"
        target.mkdir()
    elif kind == "outside":
        target = tmp_path
    else:
        run_git(repo, "remote", "remove", "origin")
    with pytest.raises(cli.InspectionError) as error:
        cli.inspect(target)
    assert error.value.code == code


def test_unsafe_path(repo, tmp_path):
    unsafe = tmp_path / "unsafe\nname"
    repo.rename(unsafe)
    with pytest.raises(cli.InspectionError) as error:
        cli.inspect(unsafe)
    assert error.value.code == 7


def test_symlink(repo, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(repo, target_is_directory=True)
    assert cli.inspect(alias)["root"] == str(repo)


def test_only_fixed_read_only_commands(repo, monkeypatch):
    original = subprocess.Popen
    calls = []

    def record(args, **kwargs):
        calls.append(args)
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
        assert kwargs["cwd"] == repo
        return original(args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", record)
    cli.inspect(repo)
    assert calls == [
        ["git", "rev-parse", "--show-toplevel"],
        ["git", "rev-parse", "--git-common-dir"],
        ["git", "rev-parse", "--absolute-git-dir"],
        ["git", "remote", "get-url", "origin"],
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
    ]


@pytest.mark.parametrize(
    "script,code",
    [
        ("import time; time.sleep(2)", 5),
        ('import sys; sys.stdout.write("s" * 100000)', 6),
        ('import sys; sys.stderr.write("secret" * 20000)', 6),
        ('import sys; sys.stderr.write("secret"); sys.exit(1)', 6),
        ('import sys; sys.stdout.buffer.write(b"bad\\x00value")', 7),
        ('import sys; sys.stdout.buffer.write(b"\\xff")', 7),
    ],
)
def test_bounded_safe_subprocess_errors(tmp_path, monkeypatch, script, code):
    original = subprocess.Popen
    children = []

    def controlled(args, **kwargs):
        process = original([sys.executable, "-c", script], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", controlled)
    monkeypatch.setattr(cli, "TIMEOUT", 0.2)
    with pytest.raises(cli.InspectionError) as error:
        cli.git(tmp_path, "rev-parse", "--show-toplevel")
    assert error.value.code == code
    assert "secret" not in str(error.value)
    assert all(child.poll() is not None for child in children)


def test_missing_git(tmp_path, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("secret")

    monkeypatch.setattr(subprocess, "Popen", missing)
    with pytest.raises(cli.InspectionError) as error:
        cli.git(tmp_path, "rev-parse", "--show-toplevel")
    assert error.value.code == 6
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("value", ["", "missing-directory"])
def test_unresolvable_paths(tmp_path, value):
    with pytest.raises(cli.InspectionError) as error:
        cli.resolve_path(value, tmp_path)
    assert error.value.code == 7


def test_bare_repository(tmp_path):
    run_git(tmp_path, "init", "--bare")
    with pytest.raises(cli.InspectionError) as error:
        cli.inspect(tmp_path)
    assert error.value.code == 2


def test_unborn_head(tmp_path):
    run_git(tmp_path, "init", "-b", "main")
    run_git(tmp_path, "remote", "add", "origin", "git@github.com:owner/repo.git")
    with pytest.raises(cli.InspectionError) as error:
        cli.inspect(tmp_path)
    assert error.value.code == 6


def test_installed_entry_point(repo):
    executable = Path(sys.executable).parent / "agent-platform"
    help_result = subprocess.run(
        [str(executable), "--help"], capture_output=True, timeout=5
    )
    assert help_result.returncode == 0
    assert b"inspect" in help_result.stdout
    result = subprocess.run(
        [str(executable), "inspect"], cwd=repo, capture_output=True, timeout=5
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["root"] == str(repo)
    run_git(repo, "remote", "set-url", "origin", "https://secret@github.com/a/b")
    result = subprocess.run(
        [str(executable), "inspect"], cwd=repo, capture_output=True, timeout=5
    )
    assert result.returncode == 4
    assert result.stdout == b""
    assert b"secret" not in result.stderr
