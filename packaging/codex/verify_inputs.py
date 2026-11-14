"""Bounded offline input inspection; never execute, extract or admit Codex."""

import hashlib
import json
import os
import stat
import struct
import tarfile
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCK_SHA256 = "7d6e97f31d1d41d2676fba508740059d4b3af653c52e894b0eca2793d74c28dc"
CHUNK = 128 * 1024
MAX_ARCHIVE = 122_000_000
MAX_BINARY = 320_000_000


class Blocked(ValueError):
    """Fixed diagnostic only; never include input paths or exception text."""


def identity(meta):
    return (
        meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink, meta.st_uid,
        meta.st_gid, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns,
    )


@contextmanager
def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise Blocked("unsafe_input")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            yield stream
        if (
            identity(before) != identity(os.fstat(fd))
            or identity(before) != identity(os.lstat(path))
        ):
            raise Blocked("input_changed")
    finally:
        os.close(fd)


def digest(stream, size):
    h = hashlib.sha256()
    remaining = size
    while remaining:
        data = stream.read(min(CHUNK, remaining))
        if not data:
            raise Blocked("truncated_input")
        remaining -= len(data)
        h.update(data)
    if stream.read(1):
        raise Blocked("unexpected_input")
    return h.hexdigest()


def read_lock():
    with regular(ROOT / "release-inputs.json", 32_768) as stream:
        raw = stream.read(32_769)
    if hashlib.sha256(raw).hexdigest() != LOCK_SHA256:
        raise Blocked("release_lock_changed")
    pin = json.loads(raw)
    with regular(ROOT / "license-investigation.json", 131_072) as stream:
        report = stream.read(131_073)
    if hashlib.sha256(report).hexdigest() != pin["license"]["followup_report_sha256"]:
        raise Blocked("license_evidence_changed")
    return pin


def inspect_elf(stream, size):
    """Inspect bounded ELF tables only; no ldd, loading or executable invocation."""
    header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise Blocked("unsupported_elf")
    fields = struct.unpack("<16sHHIQQQIHHHHHH", header)
    kind, machine, phoff, ehsize, phsize, phnum = (
        fields[1], fields[2], fields[5], fields[8], fields[9], fields[10]
    )
    if (
        kind != 3 or machine != 62 or ehsize != 64 or phsize != 56
        or not 0 < phnum <= 32 or phoff < 64
        or phoff + phnum * phsize > min(size, 4096)
    ):
        raise Blocked("unsupported_elf")
    stream.seek(phoff)
    table = stream.read(phnum * phsize)
    if len(table) != phnum * phsize:
        raise Blocked("truncated_elf")
    dynamic = []
    for i in range(phnum):
        ptype, _, offset, _, _, length, _, _ = struct.unpack_from(
            "<IIQQQQQQ", table, i * phsize
        )
        if offset + length > size:
            raise Blocked("unsupported_elf")
        if ptype == 3:
            raise Blocked("unexpected_interpreter")
        if ptype == 2:
            dynamic.append((offset, length))
    if len(dynamic) != 1:
        raise Blocked("unsupported_elf")
    offset, length = dynamic[0]
    if not 16 <= length <= 4096 or length % 16:
        raise Blocked("unsupported_elf")
    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise Blocked("truncated_elf")
    terminated = False
    for tag, _ in struct.iter_unpack("<qQ", data):
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            raise Blocked("unexpected_dynamic_dependency")
    if not terminated:
        raise Blocked("unsupported_elf")
    return {"elf_class": 64, "machine": 62, "type": 3,
            "interpreter": None, "dt_needed": []}


def inspect_archive(path, pin):
    archive_pin, binary = pin["archive"], pin["binary"]
    if (
        type(archive_pin["size"]) is not int
        or not 0 < archive_pin["size"] <= MAX_ARCHIVE
        or type(binary["size"]) is not int
        or not 0 < binary["size"] <= MAX_BINARY
    ):
        raise Blocked("input_limit")
    with regular(path, MAX_ARCHIVE) as stream:
        if digest(stream, archive_pin["size"]) != archive_pin["sha256"]:
            raise Blocked("archive_digest_mismatch")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:gz") as archive:
            member = archive.next()
            if (
                member is None or not member.isfile()
                or member.name != binary["member"]
                or member.size != binary["size"] or member.mode != binary["mode"]
                or member.pax_headers or member.linkname
            ):
                raise Blocked("archive_inventory_mismatch")
            payload = archive.extractfile(member)
            with payload:
                elf = inspect_elf(payload, member.size)
                payload.seek(0)
                if digest(payload, binary["size"]) != binary["sha256"]:
                    raise Blocked("binary_digest_mismatch")
            if archive.next() is not None:
                raise Blocked("archive_inventory_mismatch")
    return {"archive_sha256": archive_pin["sha256"],
            "binary_sha256": binary["sha256"], "elf": elf}


def inspect_sources(directory, pins):
    for source in pins:
        # All relative paths originate in the hash-pinned reviewed lock.
        path = directory / source["path"]
        with regular(path, 2_097_152) as stream:
            if digest(stream, source["size"]) != source["sha256"]:
                raise Blocked("source_digest_mismatch")


def inspect(archive, sources):
    pin = read_lock()
    facts = inspect_archive(archive, pin)
    inspect_sources(sources, pin["sources"])
    # No saved report, lock flag, env or valid digest grants license clearance.
    return {
        "schema": "AP-CODEX-PREFLIGHT/1", "status": "BLOCKED",
        "code": "binary_license_closure_unverified", "inputs_verified": True,
        "version": pin["version"], **facts, "redistribution_allowed": False,
        "package_built": False, "version_executed": False,
        "runtime_authorized": False, "live_status": "LIVE_NO_GO",
    }
