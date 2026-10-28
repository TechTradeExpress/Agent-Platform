"""Private local storage and a single, fixed host mutex. Never delete recovery data."""

import fcntl
import json
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

LOCK_DIR = Path("/var/tmp/agent-platform")
CHECKPOINT_LIMIT = 16 * 1024


class PrepareError(Exception):
    def __init__(self, code: int, reason: str):
        self.code = code
        self.reason = reason
        super().__init__(reason)


def check(condition: bool, code: int = 7, reason: str = "unsafe_storage") -> None:
    if not condition:
        raise PrepareError(code, reason)


def no_symlinks(path: Path) -> None:
    check(path.is_absolute() and ".." not in path.parts)
    for part in [*reversed(path.parents), path]:
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            continue
        check(not stat.S_ISLNK(mode))


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path: Path, private_root: Path, *, create: bool) -> bool:
    """Check all ancestors; never repair an existing directory's permissions."""
    no_symlinks(path)
    # The filesystem-root owner also covers root ownership in user namespaces.
    ancestor_owners = {0, os.stat("/").st_uid, os.getuid()}
    for current in [*reversed(path.parents), path]:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if not create:
                return False
            try:
                current.mkdir(mode=0o700)
                sync_directory(current.parent)
            except FileExistsError:
                pass  # Another contender may have created the fixed lock directory.
            info = current.lstat()
        check(stat.S_ISDIR(info.st_mode))
        if current.is_relative_to(private_root):
            check(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        else:
            check(info.st_uid in ancestor_owners)
            sticky_temp = current in (Path("/tmp"), Path("/var/tmp")) and (
                info.st_mode & stat.S_ISVTX
            )
            check(not info.st_mode & 0o022 or bool(sticky_temp))
    return True


def private_file(info: os.stat_result) -> None:
    check(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid())
    check(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)


@contextmanager
def host_lock(*, create=True):
    check(private_directory(LOCK_DIR, LOCK_DIR, create=create), 12, "missing_lock")
    fd = os.open(
        LOCK_DIR / "prepare.lock",
        (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
        | os.O_NOFOLLOW
        | os.O_NONBLOCK,
        0o600,
    )
    try:
        private_file(os.fstat(fd))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PrepareError(10, "lock_busy") from None
        yield fd
    finally:
        os.close(fd)  # Never unlink: all invocations must lock the same inode.


def load_checkpoint(path: Path) -> dict | None:
    if next(path.parent.glob(path.name + ".tmp-*"), None) is not None:
        raise PrepareError(12, "interrupted_checkpoint")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    private_file(info)
    check(info.st_size <= CHECKPOINT_LIMIT, 12, "invalid_checkpoint")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        private_file(os.fstat(fd))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(CHECKPOINT_LIMIT + 1)
        check(len(raw) <= CHECKPOINT_LIMIT, 12, "invalid_checkpoint")
        # Duplicate keys, non-JSON constants and unexpected structures fail closed.
        from agent_platform.issues import (
            AdmissionError,
            invalid_constant,
            unique_object,
        )

        try:
            data = json.loads(
                raw, object_pairs_hook=unique_object, parse_constant=invalid_constant
            )
        except (ValueError, RecursionError, AdmissionError):
            raise PrepareError(12, "invalid_checkpoint") from None
        check(isinstance(data, dict), 12, "invalid_checkpoint")
        return data
    finally:
        os.close(fd)


def write_checkpoint(path: Path, data: dict, *, previous: dict | None = None) -> None:
    raw = (json.dumps(data, sort_keys=True) + "\n").encode("ascii")
    check(len(raw) <= CHECKPOINT_LIMIT, 12, "checkpoint_too_large")
    check(load_checkpoint(path) == previous, 12, "checkpoint_conflict")
    before = path.stat() if previous is not None else None
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    # On any failure leave the temporary file for manual reconciliation.
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if previous is not None:
        private_file(path.lstat())
        after = path.stat()
        check(
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)
            == (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size),
            12,
            "checkpoint_conflict",
        )
    else:
        check(not path.exists() and not path.is_symlink(), 12, "checkpoint_conflict")
    os.replace(temp, path)
    sync_directory(path.parent)
