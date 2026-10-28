"""Bounded static inspection only: never execute a candidate runtime binary."""

import errno
import hashlib
import json
import os
import re
import stat
import struct
from pathlib import Path

from agent_platform.broker_policy import decode

MAX_FILES = 2048
MAX_BYTES = 512 * 1024 * 1024
BINARY_LIMIT = 256 * 1024 * 1024  # Same bound as isolation.Profile.
REQUIRED = ("usr/bin/codex", "usr/bin/python3", "bin/sh")


class InvalidRuntime(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def need(value, reason):
    if not value:
        raise InvalidRuntime(reason)


def sha(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None


def relative(value):
    return (
        isinstance(value, str)
        and len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9_+./-]+", value) is not None
        and not value.startswith("/")
        and all(p not in ("", ".", "..") for p in value.split("/"))
    )


def safe_ancestors(path):
    need(path.is_absolute() and ".." not in path.parts, "unsafe_path")
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        need(
            stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()),
            "unsafe_path",
        )
        sticky = (
            parent in (Path("/tmp"), Path("/var/tmp")) and info.st_mode & stat.S_ISVTX
        )
        need(not info.st_mode & 0o022 or sticky, "unsafe_path")


def bounded_file(path, limit, *, dir_fd=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe_file")
        need(
            info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
            "unsafe_mode_or_owner",
        )
        try:
            capabilities = os.getxattr(fd, "security.capability")
        except OSError as exc:
            need(exc.errno in (errno.ENODATA, errno.ENOTSUP), "unsafe_capability")
        else:
            need(not capabilities, "unsafe_capability")
        need(info.st_size <= limit, "size_limit")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        need(len(raw) == info.st_size and len(raw) <= limit, "size_limit")
        need(
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            == (info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            "file_changed",
        )
        return raw
    finally:
        os.close(fd)


def catalog(path):
    safe_ancestors(path.parent)
    data = decode(bounded_file(path, 256 * 1024))
    need(
        isinstance(data, dict)
        and data.keys()
        == {
            "schema_version",
            "source_sha",
            "codex_version",
            "broker_id",
            "files",
            "libraries",
        },
        "invalid_catalog",
    )
    need(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "invalid_catalog",
    )
    need(
        isinstance(data["source_sha"], str)
        and re.fullmatch("[a-f0-9]{40}", data["source_sha"]),
        "invalid_catalog",
    )
    need(
        data["codex_version"] == "0.164.0" and sha(data["broker_id"]), "invalid_catalog"
    )
    files, libraries = data["files"], data["libraries"]
    need(isinstance(files, dict) and 1 <= len(files) <= MAX_FILES, "invalid_catalog")
    for name, entry in files.items():
        need(
            relative(name)
            and isinstance(entry, dict)
            and entry.keys() == {"sha256", "kind"},
            "invalid_catalog",
        )
        need(
            sha(entry["sha256"]) and entry["kind"] in ("elf", "script", "data"),
            "invalid_catalog",
        )
    need(
        all(name in files and files[name]["kind"] == "elf" for name in REQUIRED),
        "missing_binary",
    )
    need(isinstance(libraries, dict) and len(libraries) <= 256, "invalid_catalog")
    for soname, name in libraries.items():
        need(
            re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", soname)
            and relative(name)
            and name in files
            and files[name]["kind"] == "elf"
            and Path(name).name == soname
            and str(Path(name).parent)
            in (
                "lib",
                "lib64",
                "usr/lib",
                "usr/lib64",
                "lib/x86_64-linux-gnu",
                "usr/lib/x86_64-linux-gnu",
            ),
            "invalid_catalog",
        )
    need(
        not any(name in files for name in ("etc/ld.so.cache", "etc/ld.so.preload")),
        "dynamic_search_path",
    )
    return data


def elf_dependencies(raw):
    """ELF64 little-endian x86-64; no ldd, loaders, shell or binary execution."""
    need(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01", "unsupported_binary")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, version, _, offset, _, _, size, entry_size, count, *_ = header
    need(
        kind in (2, 3)
        and machine == 62
        and version == 1
        and size == 64
        and entry_size == 56
        and 0 < count <= 128,
        "unsupported_binary",
    )
    need(offset + count * 56 <= len(raw), "invalid_binary")
    segments, dynamic, interpreter = [], None, None
    for n in range(count):
        tag, _, start, address, _, length, _, _ = struct.unpack_from(
            "<IIQQQQQQ", raw, offset + n * 56
        )
        need(start + length <= len(raw), "invalid_binary")
        if tag == 1:
            segments.append((address, start, length))
        elif tag == 2:
            need(
                dynamic is None and length <= 65536 and length % 16 == 0,
                "invalid_binary",
            )
            dynamic = (start, length)
        elif tag == 3:
            need(interpreter is None and 1 < length <= 256, "invalid_binary")
            value = raw[start : start + length]
            need(value[-1:] == b"\x00", "invalid_binary")
            interpreter = value[:-1].decode("ascii")
            need(
                interpreter.startswith("/") and relative(interpreter[1:]),
                "invalid_binary",
            )
    if dynamic is None:
        return interpreter, [], None
    entries = []
    start, length = dynamic
    terminated = False
    for n in range(start, start + length, 16):
        tag, value = struct.unpack_from("<qQ", raw, n)
        if tag == 0:
            terminated = True
            break
        need(
            tag
            not in (15, 29, 0x6FFFFEFA, 0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF),
            "dynamic_search_path",
        )  # RPATH/RUNPATH forbidden.
        entries.append((tag, value))
    need(terminated, "invalid_binary")
    strings = [value for tag, value in entries if tag == 5]
    sizes = [value for tag, value in entries if tag == 10]
    needed = [value for tag, value in entries if tag == 1]
    sonames = [value for tag, value in entries if tag == 14]
    if not needed and not sonames:
        return interpreter, [], None
    need(
        len(strings) == len(sizes) == 1
        and 0 < sizes[0] <= 1024 * 1024
        and len(sonames) <= 1,
        "invalid_binary",
    )
    location = [
        pos + strings[0] - addr
        for addr, pos, length in segments
        if addr <= strings[0] and strings[0] + sizes[0] <= addr + length
    ]
    need(len(location) == 1, "invalid_binary")
    table = raw[location[0] : location[0] + sizes[0]]

    def string(index):
        need(index < len(table), "invalid_binary")
        end = table.find(b"\x00", index)
        need(end >= index, "invalid_binary")
        value = table[index:end].decode("ascii")
        need(re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", value), "invalid_binary")
        return value

    return (
        interpreter,
        [string(n) for n in needed],
        string(sonames[0]) if sonames else None,
    )


def mounts(root):
    with open("/proc/self/mountinfo", "rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    need(len(raw) <= 1024 * 1024, "mount_limit")
    for row in raw.decode().splitlines():
        value = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), row.split()[4])
        point = Path(value)
        need(point == root or not point.is_relative_to(root), "nested_mount")


def walk(root):
    """Descriptor-relative, bounded traversal; never follow a swapped symlink."""
    count = 0
    device = root.stat().st_dev

    def visit(fd, relative_path, depth):
        nonlocal count
        need(depth <= 32, "tree_limit")
        children = []
        with os.scandir(fd) as listing:
            for entry in listing:
                count += 1
                need(count <= 4096, "tree_limit")
                children.append(entry.name)
        for name in sorted(children):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(info.st_dev == device, "nested_mount")
            value = relative_path / name
            yield value, info, fd
            if stat.S_ISDIR(info.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                try:
                    need(os.fstat(child).st_ino == info.st_ino, "file_changed")
                    yield from visit(child, value, depth + 1)
                finally:
                    os.close(child)

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield from visit(fd, Path(), 0)
    finally:
        os.close(fd)


def inspect_runtime(root, expected, *, require_root=False):
    safe_ancestors(root)
    root_info = root.stat()
    need(not root_info.st_mode & (stat.S_ISUID | stat.S_ISGID), "unsafe_mode_or_owner")
    mounts(root)
    names = set()
    entries = total = 0
    all_root = True
    dependencies, sonames = {}, {}
    for relative_path, info, parent_fd in walk(root):
        entries += 1
        need(entries <= 4096, "tree_limit")
        need(
            info.st_uid in (0, os.getuid())
            and not info.st_mode & 0o022
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
            "unsafe_mode_or_owner",
        )
        all_root &= info.st_uid == 0
        need(not require_root or info.st_uid == 0, "root_ownership_required")
        if stat.S_ISDIR(info.st_mode):
            continue
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe_file")
        relative_name = str(relative_path)
        need(relative_name in expected["files"], "unknown_file")
        names.add(relative_name)
        need(len(names) <= MAX_FILES and info.st_size <= BINARY_LIMIT, "size_limit")
        total += info.st_size
        need(total <= MAX_BYTES, "size_limit")
        raw = bounded_file(Path(relative_name).name, BINARY_LIMIT, dir_fd=parent_fd)
        entry = expected["files"][relative_name]
        need(hashlib.sha256(raw).hexdigest() == entry["sha256"], "hash_mismatch")
        if relative_name in REQUIRED:
            need(info.st_mode & 0o111, "binary_not_executable")
        if entry["kind"] == "elf":
            interpreter, needed, soname = elf_dependencies(raw)
            dependencies[relative_name] = [interpreter[1:]] if interpreter else []
            for lib in needed:
                need(lib in expected["libraries"], "missing_library")
                dependencies[relative_name].append(expected["libraries"][lib])
            sonames[relative_name] = soname
        elif entry["kind"] == "script":
            first = raw.split(b"\n", 1)[0]
            need(first in (b"#!/bin/sh", b"#!/usr/bin/python3"), "unsupported_binary")
            dependencies[relative_name] = [first[3:].decode()]
            need(info.st_mode & 0o111, "binary_not_executable")
        else:
            need(
                not info.st_mode & 0o111
                and not raw.startswith((b"\x7fELF", b"MZ", b"#!")),
                "unknown_binary",
            )
    need(names == expected["files"].keys(), "missing_file")
    for values in dependencies.values():
        need(
            all(
                name in names and expected["files"][name]["kind"] == "elf"
                for name in values
            ),
            "missing_library",
        )
    for soname, name in expected["libraries"].items():
        need(sonames[name] in (None, soname), "library_identity_mismatch")
    # Profile also validates the root directory itself as trusted.
    need(not require_root or root.stat().st_uid == 0, "root_ownership_required")
    return {
        "files": len(names),
        "bytes": total,
        "codex_sha256": expected["files"]["usr/bin/codex"]["sha256"],
        "catalog_sha256": hashlib.sha256(
            json.dumps(expected, sort_keys=True).encode()
        ).hexdigest(),
        "visible_root_owned": bool(all_root and root.stat().st_uid == 0),
    }
