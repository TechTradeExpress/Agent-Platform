"""Offline native artifact eligibility only. No execution, install or promotion."""

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from agent_platform import _native_elf
from agent_platform import runtime_manifest as legacy

NATIVE_LIMIT = 384 * 1024 * 1024
LIBRARY_LIMIT = 64 * 1024 * 1024
TOTAL_LIMIT = 512 * 1024 * 1024
CHUNK = 65536
MAX_FILES = 128
BINARY = "usr/bin/codex"
PIN = {
    "version": "0.164.0",
    "source_sha": "6aaac694803004a63c6f393d153c96d22521a6b9",
    "target": "x86_64-unknown-linux-musl",
    "bytes": 308139304,
    "sha256": "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306",
}
need = legacy.need


def _fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory(info, *, ancestor=False):
    owners = {0, os.getuid()}
    if ancestor:
        owners.add(
            os.stat("/").st_uid
        )  # Read-only namespace anchor, not root attestation.
    need(stat.S_ISDIR(info.st_mode) and info.st_uid in owners, "unsafe_directory")
    need(not info.st_mode & (stat.S_ISUID | stat.S_ISGID), "unsafe_directory")
    need(not info.st_mode & 0o022, "unsafe_directory")


def _path(value):
    p = Path(value)
    need(
        p.is_absolute()
        and ".." not in p.parts
        and len(str(p)) <= 4096
        and len(p.parts) <= 64,
        "unsafe_path",
    )
    need(
        not any(
            n.casefold()
            in {
                ".codex",
                ".ssh",
                ".aws",
                ".config",
                "codex-sessions",
                "auth.json",
                "credentials",
            }
            for n in p.parts
        ),
        "private_path_forbidden",
    )
    return p


class Snapshot:
    def __init__(self, stack):
        self.stack, self.checks = stack, []
        self.deadline = time.monotonic() + 60
        self.io = 0

    def tick(self, count=0):
        self.io += count
        need(self.io <= TOTAL_LIMIT + 16 * 1024 * 1024, "io_limit")
        need(time.monotonic() <= self.deadline, "inspection_timeout")

    def open(self, name, flags, parent=None):
        self.tick()
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        self.stack.callback(os.close, fd)
        return fd

    def directory(self, path):
        path = _path(path)
        fd = self.open("/", os.O_RDONLY | os.O_DIRECTORY)
        anchor = os.fstat(fd)
        need(
            stat.S_ISDIR(anchor.st_mode) and not anchor.st_mode & 0o022,
            "unsafe_directory",
        )
        current = Path("/")
        for name in path.parts[1:]:
            current /= name
            previous = fd
            fd = self.open(name, os.O_RDONLY | os.O_DIRECTORY, previous)
            info = os.fstat(fd)
            sticky = current in (Path("/tmp"), Path("/var/tmp")) and bool(
                info.st_mode & stat.S_ISVTX
            )
            if sticky:
                need(info.st_uid in (0, os.getuid(), anchor.st_uid), "unsafe_directory")
            else:
                _directory(info, ancestor=True)
            self.checks.append((previous, name, info, False))
        return fd

    def file(self, parent, name, limit, observed=None):
        fd = self.open(name, os.O_RDONLY, parent)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe_file")
        need(
            info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
            "unsafe_mode_or_owner",
        )
        try:
            capability = os.getxattr(fd, "security.capability")
        except OSError as exc:
            need(exc.errno in (errno.ENODATA, errno.ENOTSUP), "unsafe_capability")
        else:
            need(not capability, "unsafe_capability")
        need(0 < info.st_size <= limit, "size_limit")
        if observed is not None:
            need(_fingerprint(observed) == _fingerprint(info), "file_changed")
        self.checks.append((parent, name, info, True))
        return Reader(self, fd, info)

    def verify(self):
        for parent, name, info, full in self.checks:
            self.tick()
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if full:
                need(_fingerprint(after) == _fingerprint(info), "file_changed")
            else:
                need(
                    (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                        after.st_uid,
                        after.st_gid,
                    )
                    == (
                        info.st_dev,
                        info.st_ino,
                        info.st_mode,
                        info.st_uid,
                        info.st_gid,
                    ),
                    "path_changed",
                )


class Reader:
    def __init__(self, snapshot, fd, info):
        self.snapshot, self.fd, self.info = snapshot, fd, info
        self.size = info.st_size

    def read(self, position, count):
        need(
            0 <= position <= self.size
            and 0 < count <= CHUNK
            and count <= self.size - position,
            "invalid_elf_range",
        )
        self.snapshot.tick(count)
        data = os.pread(self.fd, count, position)
        need(len(data) == count, "truncated_file")
        return data

    def hash(self):
        digest = hashlib.sha256()
        for position in range(0, self.size, CHUNK):
            digest.update(self.read(position, min(CHUNK, self.size - position)))
        return digest.hexdigest()

    def stable(self):
        need(_fingerprint(os.fstat(self.fd)) == _fingerprint(self.info), "file_changed")


def _catalog(snapshot, path):
    path = _path(path)
    parent = snapshot.directory(path.parent)
    reader = snapshot.file(parent, path.name, 256 * 1024)
    raw = b"".join(
        reader.read(p, min(CHUNK, reader.size - p))
        for p in range(0, reader.size, CHUNK)
    )
    reader.stable()
    data = legacy.decode(raw)
    need(
        type(data) is dict
        and set(data) == {"schema_version", "artifact", "files", "libraries"},
        "invalid_catalog",
    )
    need(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "invalid_catalog",
    )
    need(
        type(data["artifact"]) is dict
        and data["artifact"] == PIN
        and all(type(data["artifact"][k]) is type(v) for k, v in PIN.items()),
        "artifact_pin_mismatch",
    )
    files, libraries = data["files"], data["libraries"]
    need(
        type(files) is dict and 0 < len(files) <= MAX_FILES and BINARY in files,
        "invalid_catalog",
    )
    for name, item in files.items():
        need(
            legacy.relative(name)
            and type(item) is dict
            and set(item) == {"bytes", "sha256"}
            and legacy.sha(item["sha256"])
            and type(item["bytes"]) is int
            and item["bytes"] > 0,
            "invalid_catalog",
        )
        need(
            name == BINARY
            or name.startswith(("lib/", "lib64/", "usr/lib/", "usr/lib64/")),
            "invalid_catalog",
        )
        need(
            all(
                not p.startswith(".") and p not in ("auth.json", "credentials")
                for p in name.split("/")
            ),
            "private_path_forbidden",
        )
        need(
            item["bytes"] <= (NATIVE_LIMIT if name == BINARY else LIBRARY_LIMIT),
            "size_limit",
        )
    need(
        files[BINARY] == {"bytes": PIN["bytes"], "sha256": PIN["sha256"]},
        "artifact_pin_mismatch",
    )
    need(type(libraries) is dict and len(libraries) <= 64, "invalid_catalog")
    for soname, name in libraries.items():
        need(
            isinstance(soname, str)
            and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", soname)
            and isinstance(name, str)
            and name in files
            and Path(name).name == soname
            and name != BINARY,
            "invalid_catalog",
        )
    need(sum(x["bytes"] for x in files.values()) <= TOTAL_LIMIT, "size_limit")
    return data, hashlib.sha256(raw).hexdigest()


def _mounts(root):
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    need(len(raw) <= 1024 * 1024, "mount_limit")
    for line in raw.decode().splitlines():
        fields = line.split()
        need(
            len(fields) >= 10
            and "-" in fields
            and 6 <= fields.index("-") < len(fields) - 2,
            "unknown_mounts",
        )

        def unescape(s):
            return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), s)

        point = Path(unescape(fields[4]))
        origin = unescape(fields[3])
        need(not point.is_relative_to(root), "mount_alias")
        if root.is_relative_to(point):
            need(point == Path("/") or origin == "/", "mount_alias")
            need(
                fields[fields.index("-") + 1]
                in {"overlay", "ext4", "xfs", "btrfs", "tmpfs"},
                "unsupported_filesystem",
            )
    return hashlib.sha256(raw).digest()


def inspect_candidate(root, catalog):
    root = _path(root)
    with ExitStack() as stack:
        snapshot = Snapshot(stack)
        expected, catalog_digest = _catalog(snapshot, catalog)
        mount_digest = _mounts(root)
        rootfd = snapshot.directory(root)
        root_info = os.fstat(rootfd)
        _directory(root_info)
        allowed_dirs = {
            str(p)
            for name in expected["files"]
            for p in Path(name).parents
            if str(p) != "."
        }
        names, metadata = set(), {}
        total = entries = 0
        all_root = os.fstat(rootfd).st_uid == 0

        def visit(fd, prefix, depth):
            nonlocal total, entries, all_root
            snapshot.tick()
            need(depth <= 32, "tree_limit")
            before = os.fstat(fd)
            with os.scandir(fd) as listing:
                children = []
                for entry in listing:
                    entries += 1
                    need(entries <= 512, "tree_limit")
                    children.append(entry.name)
            for name in sorted(children):
                item = prefix / name
                relative = item.as_posix()
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(info.st_dev == before.st_dev, "mount_alias")
                if stat.S_ISDIR(info.st_mode):
                    need(relative in allowed_dirs, "unknown_directory")
                    _directory(info)
                    child = snapshot.open(name, os.O_RDONLY | os.O_DIRECTORY, fd)
                    need(
                        _fingerprint(os.fstat(child)) == _fingerprint(info),
                        "path_changed",
                    )
                    snapshot.checks.append((fd, name, info, True))
                    visit(child, item, depth + 1)
                    all_root &= info.st_uid == 0
                    continue
                need(relative in expected["files"], "unknown_file")
                reader = snapshot.file(
                    fd,
                    name,
                    NATIVE_LIMIT if relative == BINARY else LIBRARY_LIMIT,
                    info,
                )
                record = expected["files"][relative]
                need(reader.size == record["bytes"], "size_mismatch")
                total += reader.size
                need(total <= TOTAL_LIMIT, "size_limit")
                need(reader.hash() == record["sha256"], "hash_mismatch")
                reader.stable()
                metadata[relative] = _native_elf.inspect(
                    reader.read, reader.size, executable=relative == BINARY
                )
                reader.stable()
                names.add(relative)
                all_root &= info.st_uid == 0
            need(_fingerprint(os.fstat(fd)) == _fingerprint(before), "tree_changed")

        visit(rootfd, Path(), 0)
        need(names == expected["files"].keys(), "missing_file")
        reached = set()
        pending = [BINARY]
        while pending:
            name = pending.pop()
            if name in reached:
                continue
            reached.add(name)
            interpreter, needed, soname = metadata[name]
            if interpreter:
                target = interpreter[1:]
                need(target in names, "missing_interpreter")
                pending.append(target)
            for lib in needed:
                need(lib in expected["libraries"], "unknown_library")
                pending.append(expected["libraries"][lib])
            for lib, target in expected["libraries"].items():
                if target == name:
                    need(soname in (None, lib), "library_identity_mismatch")
        need(reached == names, "unused_file")
        snapshot.verify()
        need(_fingerprint(os.fstat(rootfd)) == _fingerprint(root_info), "tree_changed")
        need(mount_digest == _mounts(root), "mounts_changed")
        return {
            "status": "INSPECTED_NATIVE_CANDIDATE",
            "version": PIN["version"],
            "target": PIN["target"],
            "sha256": PIN["sha256"],
            "bytes": PIN["bytes"],
            "native_limit_bytes": NATIVE_LIMIT,
            "elf_closure_files": len(names),
            "elf_closure_bytes": total,
            "runtime_limit_bytes": TOTAL_LIMIT,
            "remaining_runtime_budget_bytes": TOTAL_LIMIT - total,
            "catalog_sha256": catalog_digest,
            "visible_root_owned": bool(all_root),
            "source_equivalence": "UNVERIFIED",
            "signature_verification": "NOT_VERIFIED",
            "version_evidence": "EXACT_RELEASE_DIGEST_BINDING",
            "runtime_admitted": False,
            "execution_enabled": False,
        }


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "native_artifact_invalid_arguments\n")


def main(argv=None):
    parser = _Parser(
        prog="agent-platform-native-artifact",
        description="Offline pinned native artifact inspection; never executes",
    )
    parser.add_argument("root")
    parser.add_argument("catalog")
    args = parser.parse_args(argv)
    try:
        result = inspect_candidate(Path(args.root), Path(args.catalog))
        code = 0
    except legacy.InvalidRuntime as exc:
        result = {
            "status": "BLOCKED",
            "reason": exc.reason,
            "runtime_admitted": False,
            "execution_enabled": False,
        }
        code = 13
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        result = {
            "status": "BLOCKED",
            "reason": "unavailable_or_unsafe",
            "runtime_admitted": False,
            "execution_enabled": False,
        }
        code = 13
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
