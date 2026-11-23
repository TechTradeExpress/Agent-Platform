"""The off-worker ledger performs actual exclusive filesystem writes."""

import fcntl
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_observer as observer
from agent_platform import worker_publish_pre_spend as pre_spend


@pytest.mark.parametrize("fault", [None, "file", "directory", "lock", "symlink"])
def test_create_only_ledger(tmp_path, monkeypatch, fault):
    raw = art.encoded(pre_spend.challenge("a" * 64, "b" * 64, 100))
    key = Ed25519PrivateKey.generate()
    tmp_path.chmod(0o700)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    record = tmp_path / pre_spend.RECORD
    sync = os.fsync

    def fail(descriptor):
        kind = (
            "directory"
            if os.path.samestat(os.fstat(descriptor), os.fstat(fd))
            else "file"
        )
        if kind == fault:
            raise OSError("synthetic fsync failure")
        sync(descriptor)

    monkeypatch.setattr(pre_spend.os, "fsync", fail)
    try:
        if fault == "lock":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(BlockingIOError):
                pre_spend.reserve(fd, raw, key, 99)
            assert not record.exists()
        elif fault == "symlink":
            record.symlink_to("absent")
            with pytest.raises(FileExistsError):
                pre_spend.reserve(fd, raw, key, 99)
            assert record.is_symlink()
        else:
            if fault is None:
                sig = pre_spend.reserve(fd, raw, key, 99)
                public = key.public_key().public_bytes_raw()
                assert observer.verify(
                    public, art.digest(public), pre_spend.PURPOSE, raw, sig
                ) == art.decode(raw)
            else:
                with pytest.raises(OSError, match="synthetic fsync failure"):
                    pre_spend.reserve(fd, raw, key, 99)
            assert record.read_bytes() == raw
            with pytest.raises(FileExistsError):
                pre_spend.reserve(fd, raw, key, 99)
    finally:
        os.close(fd)


def test_operator_command_commits_before_returning_signature(tmp_path):
    ledger = tmp_path / "ledger"
    ledger.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "synthetic-key"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    value = pre_spend.challenge("a" * 64, "b" * 64, int(time.time()) + 90)
    raw = art.encoded(value)
    # Only the inherited fixture descriptor replaces the privileged path walk.
    # The write, lock, fsync, stdout protocol and CLI run in a separate process.
    with key_path.open("rb") as secret:
        fd = os.open(ledger, os.O_RDONLY | os.O_DIRECTORY)
        try:
            code = (
                "import os; from contextlib import nullcontext; "
                "from agent_platform import worker_publish_pre_spend as p; "
                f"p.private_directory = lambda _: nullcontext({fd}); "
                f"os.dup2({secret.fileno()}, 3); "
                "raise SystemExit(p.main(['--ledger', '/fixture']));"
            )
            argv = [sys.executable, "-I", "-B", "-c", code]
            subprocess_env = {"PATH": "/usr/bin:/bin"}
            for expected in (0, 1):
                result = subprocess.run(
                    argv,
                    input=raw,
                    pass_fds=(secret.fileno(), fd),
                    capture_output=True,
                    env=subprocess_env,
                    cwd=Path(ledger),
                    timeout=10,
                )
                assert result.returncode == expected, result.stderr
                if expected == 0:
                    public = key.public_key().public_bytes_raw()
                    assert (
                        observer.verify(
                            public,
                            art.digest(public),
                            pre_spend.PURPOSE,
                            raw,
                            bytes.fromhex(result.stdout.decode()),
                        )
                        == value
                    )
                else:
                    assert not result.stdout and result.stderr == b"PRE_SPEND_STOP\n"
                secret.seek(0)
        finally:
            os.close(fd)
    assert (ledger / pre_spend.RECORD).read_bytes() == raw
