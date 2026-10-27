"""Fake namespace probes and root-owned broker contract, never live Codex/inference."""

import hashlib
import json
import os
import socket
from pathlib import Path

import pytest

from agent_platform import isolation


@pytest.fixture
def profile(tmp_path, monkeypatch):
    image = tmp_path / "profile"
    image.mkdir()
    root = image / "rootfs"
    for relative in ("usr/bin/codex", "usr/bin/python3", "bin/sh"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"trusted runtime fixture")
        path.chmod(0o555)
    metadata = {
        "version": 1,
        "codex_version": "0.164.0",
        "broker_id": "b" * 64,
        "codex_sha256": hashlib.sha256(b"trusted runtime fixture").hexdigest(),
    }
    (image / "profile.json").write_text(json.dumps(metadata))
    for path in [image, *image.rglob("*")]:
        path.chmod(
            0o755
            if path.is_dir()
            else (0o555 if path.stat().st_mode & 0o111 else 0o644)
        )
    binary = tmp_path / "bwrap"
    binary.write_text("fake executable")
    binary.chmod(0o555)
    broker = tmp_path / "broker"
    broker.mkdir()
    broker.chmod(0o755)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(broker / "inference.sock"))
    (broker / "inference.sock").chmod(0o660)
    tree = tmp_path / "worktree"
    tree.mkdir(mode=0o700)
    (tree / ".git").write_text("gitdir: /not-mounted\n")
    record = {
        "worktree": str(tree),
        "source_root": str(tmp_path / "source"),
        "common_dir": str(tmp_path / "source/.git"),
        "checkpoint": str(tmp_path / "state/issue.json"),
        "codex_home": str(tmp_path / "runtime"),
    }
    fd = os.open(tmp_path / "lock", os.O_CREAT | os.O_RDWR, 0o600)
    monkeypatch.setattr(isolation, "PROFILE", image)
    monkeypatch.setattr(isolation, "BWRAP", binary)
    monkeypatch.setattr(isolation, "BROKER", broker / "inference.sock")
    monkeypatch.setattr(isolation, "OWNER_UID", os.getuid())
    reads = []

    def fake_command(argv, cwd, env, **limits):
        assert env == isolation.ENV and limits["pass_fds"] == (fd,)
        assert "--unshare-net" in argv and "--share-net" not in argv
        assert argv[argv.index("--sync-fd") + 1] == str(fd)
        reads.append(argv)
        return b"codex-cli 0.164.0\n" if "--version" in argv else b"isolated\n"

    def fake_broker(method, endpoint):
        if endpoint == "/agent-platform/health":
            return 200, json.dumps(
                {
                    "protocol": 1,
                    "broker_id": "b" * 64,
                    "inference_only": True,
                    "credentials_exposed": False,
                    "network_tools": False,
                }
            ).encode()
        return 403, b""

    monkeypatch.setattr(isolation.process, "read_command", fake_command)
    monkeypatch.setattr(isolation, "broker_request", fake_broker)
    actual = Path.read_text

    def read_text(path, *args, **kwargs):
        if path == Path("/proc/sys/kernel/yama/ptrace_scope"):
            return "1"
        return actual(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    try:
        yield isolation.Profile(record, fd), metadata, reads
    finally:
        sock.close()
        os.close(fd)


def test_profile_requires_outer_native_and_version_probes(profile):
    current, metadata, reads = profile
    assert len(current.preflight().digest) == 64
    assert len(reads) == 3
    assert any("linux" in command for command in reads)
    command = current.launch(["/usr/bin/codex", "exec", "--json"])
    assert command[:2] == [str(isolation.BWRAP), "--die-with-parent"]
    assert "--clearenv" in command and "--cap-drop" in command
    assert "--share-net" not in command and "--dev-bind" not in command
    bound = [
        command[i + 1 : i + 3]
        for i, arg in enumerate(command)
        if arg in ("--bind", "--ro-bind")
    ]
    assert [str(isolation.PROFILE / "rootfs"), "/"] in bound
    assert [current.record["worktree"], "/workspace"] in bound
    assert [str(isolation.BROKER), "/inference.sock"] in bound
    assert not any(pair[0] in ("/", "/home", "/usr", "/run") for pair in bound)
    assert [str(Path(current.record["worktree"]) / ".git"), "/workspace/.git"] in bound


@pytest.mark.parametrize(
    "fault",
    [
        "missing_codex",
        "bad_version",
        "bad_hash",
        "bad_runtime_mode",
        "symlink_runtime",
        "credentials_exposed",
        "broker_allows_admin",
        "forbidden_access",
        "native_not_enforced",
        "wrong_cli_version",
    ],
)
def test_profile_failure_never_launches(profile, monkeypatch, fault):
    current, metadata, reads = profile
    if fault == "missing_codex":
        (isolation.PROFILE / "rootfs/usr/bin/codex").rename(isolation.PROFILE / "saved")
    elif fault in ("bad_version", "bad_hash"):
        metadata["codex_version" if fault == "bad_version" else "codex_sha256"] = (
            "wrong"
        )
        (isolation.PROFILE / "profile.json").write_text(json.dumps(metadata))
    elif fault == "bad_runtime_mode":
        (isolation.PROFILE / "rootfs/bin/sh").chmod(0o777)
    elif fault == "symlink_runtime":
        (isolation.PROFILE / "rootfs/escape").symlink_to("/home")
    elif fault in ("credentials_exposed", "broker_allows_admin"):
        original = isolation.broker_request

        def bad_broker(method, endpoint):
            status, body = original(method, endpoint)
            if fault == "credentials_exposed" and status == 200:
                data = json.loads(body)
                data["credentials_exposed"] = True
                return status, json.dumps(data).encode()
            return (200, b"") if fault == "broker_allows_admin" else (status, body)

        monkeypatch.setattr(isolation, "broker_request", bad_broker)
    else:
        original = isolation.process.read_command

        def bad_probe(argv, *args, **kwargs):
            if fault == "forbidden_access" or (
                fault == "native_not_enforced" and "linux" in argv
            ):
                return b"forbidden access unexpectedly succeeded\n"
            if fault == "wrong_cli_version" and "--version" in argv:
                return b"codex-cli 0.999.0\n"
            return original(argv, *args, **kwargs)

        monkeypatch.setattr(isolation.process, "read_command", bad_probe)
    with pytest.raises(isolation.IsolationError):
        current.preflight()
    assert current.digest is None
    with pytest.raises(isolation.IsolationError):
        current.launch(["/usr/bin/codex", "exec"])


def test_worktree_hardlinks_cannot_expose_host_files(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("sentinel")
    os.link(secret, tree / "alias")
    with pytest.raises(isolation.IsolationError):
        isolation.check_worktree(tree)
    assert secret.read_text() == "sentinel"


def test_worktree_socket_rejected(tmp_path):
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.bind(str(tmp_path / "host-channel"))
        with pytest.raises(isolation.IsolationError):
            isolation.check_worktree(tmp_path)
    finally:
        sock.close()


def test_missing_profile_fails_without_codex_start(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, "PROFILE", tmp_path / "absent")

    def forbidden(*args, **kwargs):
        pytest.fail("no subprocess is needed when the runtime is missing")

    monkeypatch.setattr(isolation.process, "read_command", forbidden)
    with pytest.raises(isolation.IsolationError):
        isolation.Profile({}, -1).preflight()


def test_runner_installation_cannot_be_inside_the_writable_task(profile):
    current, _, reads = profile
    current.record["worktree"] = str(Path(isolation.__file__).resolve().parent)
    with pytest.raises(isolation.IsolationError):
        current.preflight()
    assert reads == []


def test_ambiguous_profile_schema_is_rejected(profile):
    current, metadata, reads = profile
    metadata["version"] = True
    (isolation.PROFILE / "profile.json").write_text(json.dumps(metadata))
    with pytest.raises(isolation.IsolationError):
        current.preflight()
    assert reads == []


def test_optimized_probe_cannot_report_success():
    import subprocess
    import sys

    data = {"namespaces": {}, "private": [], "lock_inode": [-1, -1]}
    result = subprocess.run(
        [sys.executable, "-I", "-O", str(isolation.HELPER), "probe", json.dumps(data)],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode != 0 and result.stdout == b"" and result.stderr == b""


def test_privileged_runtime_is_not_a_fallback(profile):
    current, _, reads = profile
    (isolation.PROFILE / "rootfs/bin/sh").chmod(0o4755)
    with pytest.raises(isolation.IsolationError):
        current.preflight()
    assert reads == []
