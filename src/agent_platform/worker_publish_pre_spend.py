"""Operator-held, one-record ledger for the fixed worker01 recovery generation."""

import argparse
import fcntl
import os
import stat
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from . import worker_publish_artifact as art
from . import worker_publish_observer as observer
from . import worker_publish_reconciliation as reconciliation
from . import worker_publish_recovery_paths as recovery

RECORD = "worker01-169-v4-recovery-1.pre-spent.json"
LIVE_RECORD = "worker01-169-v4-recovery-1.live-authorized.json"
PURPOSE = recovery.PRE_SPEND_PURPOSE
challenge = recovery.pre_spend_challenge


def retain(directory, leaf, raw):
    """Durably create an external ledger record under the caller's lock."""
    fd = os.open(
        leaf,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        info = os.fstat(fd)
        art.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        art.need(stat.S_IMODE(info.st_mode) == 0o600)
        art.need(info.st_uid == os.getuid() and info.st_gid == os.getgid())
        art.need(os.write(fd, raw) == len(raw))
        os.fsync(fd)
        art.need(os.pread(fd, len(raw) + 1, 0) == raw)
        art.need(
            os.path.samestat(
                os.fstat(fd), os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            )
        )
        os.fsync(directory)
    finally:
        os.close(fd)


def reserve(directory, raw, key, now):
    """Reserve the entire generation, not merely the supplied launch ID."""
    value = reconciliation._canonical(raw)
    art.need(
        value
        == challenge(value["approval_sha256"], value["launch_id"], value["expires"])
    )
    art.need(now < value["expires"] <= now + observer.WINDOW)
    locked = os.open(
        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
    )
    try:
        info = os.fstat(locked)
        art.need(stat.S_IMODE(info.st_mode) == 0o700)
        art.need(info.st_uid == os.getuid() == os.geteuid())
        art.need(info.st_gid == os.getgid() == os.getegid())
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        retain(locked, RECORD, raw)
        return observer.sign(key, PURPOSE, value)
    finally:
        os.close(locked)


@contextmanager
def private_directory(path):
    """Open an operator-selected store with only root or operator ancestry."""
    directory = Path(path)
    art.need(directory.is_absolute() and ".." not in directory.parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in directory.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            art.need(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
        yield fd
    finally:
        os.close(fd)


def sign_grant(directory, role, raw, key, now):
    grant = reconciliation._canonical(raw)
    art.need(role in ("signer", "publisher", "publisher-live"))
    live = role == "publisher-live"
    grant_role = "publisher" if live else role
    unit = recovery.LIVE_UNIT if live else recovery.role_unit(role)
    art.need(grant["schema"] == "AP-worker01-recovery-grant/1")
    art.need(grant["role"] == grant_role and grant["audience"] == unit)
    art.need(("live" in grant) == live)
    fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fd = os.open(RECORD, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        art.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        art.need(info.st_uid == os.getuid() and info.st_gid == os.getgid())
        art.need(stat.S_IMODE(info.st_mode) == 0o600)
        reserved = reconciliation._canonical(os.read(fd, observer.LIMIT + 1))
        art.need(now < grant["expires"] <= reserved["expires"])
        for name in ("case", "generation", "launch_id", "approval_sha256"):
            art.need(grant[name] == reserved[name])
        if live:
            art.need(grant["live"]["purpose"] == "create-draft-live")
            # Spend the live decision separately, before signing. A lost response
            # or partial record consumes the allowance and requires reconciliation.
            retain(directory, LIVE_RECORD, raw)
        return observer.sign(key, "recovery-" + role, grant)
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True)
    parser.add_argument(
        "--grant-role", choices=("signer", "publisher", "publisher-live")
    )
    args = parser.parse_args(argv)
    try:
        # fd 3 is the operator-supplied approval private-key stream. Only the
        # canonical challenge arrives on stdin. Only a signature leaves here.
        with os.fdopen(3, "rb") as stream:
            pem = stream.read(4097)
        art.need(len(pem) <= 4096)
        key = serialization.load_pem_private_key(pem, password=None)
        raw = sys.stdin.buffer.read(observer.LIMIT + 1)
        art.need(0 < len(raw) <= observer.LIMIT)
        with private_directory(args.ledger) as directory:
            now = int(time.time())
            if args.grant_role is None:
                signature = reserve(directory, raw, key, now)
            else:
                signature = sign_grant(directory, args.grant_role, raw, key, now)
        sys.stdout.buffer.write(signature.hex().encode("ascii") + b"\n")
        return 0
    except Exception:
        print("PRE_SPEND_STOP", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
