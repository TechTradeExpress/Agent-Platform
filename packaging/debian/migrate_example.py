#!/usr/bin/python3 -I
"""Explicit AP-PKG example only. Never called by dpkg or application runtime."""

import argparse
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

MARKER = b"AP-PKG-EXAMPLE-ONLY v1\n"
FILES = {"EXAMPLE_ONLY", "example.json", "v1.backup", "migration.json", ".lock"}


def need(ok):
    if not ok:
        raise ValueError("unsafe_or_unreconciled_example")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    need(len(raw) <= 4096)
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and value.get("format") == "AP-PKG-SYNTHETIC")
    need(type(value.get("schema")) is int and value["schema"] in (1, 2))
    field = "label" if value["schema"] == 1 else "display_name"
    need(set(value) == {"format", "schema", field})
    text = value[field]
    need(type(text) is str and 1 <= len(text) <= 80)
    need(all(c.isascii() and (c.isalnum() or c in " _-") for c in text))
    return value


def directory(path):
    need(path.is_absolute() and ".." not in path.parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        meta = os.fstat(fd)
        need(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700)
        need(not os.path.ismount(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(fd, name):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        meta = os.fstat(child)
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1)
        need(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o600)
        need(meta.st_size <= 4096)
        data = os.read(child, 4097)
        need(len(data) == meta.st_size)
        after = os.fstat(child)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        need(all(getattr(after, key) == getattr(meta, key) for key in fields))
        return data
    finally:
        os.close(child)


def create(fd, name, data):
    child = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
    )
    try:
        need(os.write(child, data) == len(data))
        os.fsync(child)
    finally:
        os.close(child)
    os.fsync(fd)


def inspect(fd):
    need(set(os.listdir(fd)) <= FILES)
    need(read(fd, "EXAMPLE_ONLY") == MARKER)
    raw = read(fd, "example.json")
    return raw, parse(raw)


def plan(fd):
    raw, value = inspect(fd)
    names = set(os.listdir(fd))
    if value["schema"] == 1:
        old = raw
        new = encoded(
            {"format": "AP-PKG-SYNTHETIC", "schema": 2, "display_name": value["label"]}
        )
    else:
        need({"v1.backup", "migration.json"} <= names)
        old = read(fd, "v1.backup")
        prior = parse(old)
        need(prior["schema"] == 1)
        new = encoded(
            {"format": "AP-PKG-SYNTHETIC", "schema": 2, "display_name": prior["label"]}
        )
        need(raw == new)
    intent = encoded({"from": 1, "to": 2, "before": digest(old), "after": digest(new)})
    if "v1.backup" in names:
        need(read(fd, "v1.backup") == old)
    if "migration.json" in names:
        need(read(fd, "migration.json") == intent)
    return old, new, intent, value["schema"], names


def migrate(path):
    fd = directory(path)
    lock = None
    try:
        # Validate all retained evidence before any write, then repeat under lock.
        plan(fd)
        if ".lock" not in os.listdir(fd):
            create(fd, ".lock", b"")
        read(fd, ".lock")
        lock = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=fd)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old, new, intent, schema, names = plan(fd)
        if schema == 2:
            return "already_migrated"
        if "v1.backup" not in names:
            create(fd, "v1.backup", old)
        if "migration.json" not in names:
            create(fd, "migration.json", intent)
        # A partial/retained temporary file is deliberately not auto-repaired.
        create(fd, "next.tmp", new)
        need(read(fd, "example.json") == old)
        os.replace("next.tmp", "example.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        need(read(fd, "example.json") == new)
        return "migrated"
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        outcome = migrate(args.directory)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('{"status":"BLOCKED","reason":"unsafe_or_unreconciled_example"}')
        return 13
    print(json.dumps({"status": "SYNTHETIC_ONLY", "outcome": outcome}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
