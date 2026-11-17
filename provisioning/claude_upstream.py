#!/usr/bin/python3 -IB
"""Operator-only, source-only Claude Code toolchain verifier/provisioner (HAR-04).

Offline by construction: no network, no subprocess and no execution of the
candidate (not even ``--version``). It never selects a harness, never creates a
command link and never reads any user home, login store or session. A verified
install is toolchain inventory only and grants no runtime authority.
"""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import resource
import stat
import struct
import sys
from pathlib import Path

BASE = "/opt/agent-platform-claude"
SYSTEM_COMMANDS = ("/usr/bin", "/usr/local/bin")
OWNER = 0
PLATFORM = "linux-x64"
MEMBER = "claude"
FINGERPRINT = "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
DOWNLOAD_BASE = "https://downloads.claude.ai/claude-code-releases"
MAX_BINARY = 512 * 1024**2
MAX_VERSIONS = 3
MIN_AGENTS_MD = (2, 1, 281)
LOCK_SHA256 = "3ed33b3eceec0b643a5c70d63cf6d645829236db4bea2118f952c5fa15914ced"
MARKER = {"schema": "AP-CLAUDE-STORE/1"}
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
BAD_XATTRS = {
    "system.posix_acl_access",
    "system.posix_acl_default",
    "security.capability",
}
HASHES = {
    # OpenPGP hash id -> (name, PKCS#1 v1.5 DigestInfo prefix)
    8: (
        "sha256",
        bytes.fromhex("3031300d060960864801650304020105000420"),
    ),
    10: (
        "sha512",
        bytes.fromhex("3051300d060960864801650304020305000440"),
    ),
}


class Blocked(Exception):
    """Only fixed, nonsecret reason identifiers cross the CLI boundary."""


def need(condition, reason):
    if not condition:
        raise Blocked(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def version_tuple(version):
    need(
        isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version),
        "invalid_version",
    )
    return tuple(map(int, version.split(".")))


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out

    def constant(_):
        raise ValueError

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Blocked("invalid_json") from exc


# --------------------------------------------------------------------------
# Minimal OpenPGP (RFC 4880) detached-signature verification, stdlib only.
# Scope: one pinned RSA v4 public key, signature type 0x00 (binary), PKCS#1 v1.5
# over SHA-256/SHA-512. No key import, trust database, web of trust, expiry or
# revocation handling: those need online/clock facts and are NOT_RUN offline.
# --------------------------------------------------------------------------


def dearmor(data):
    need(isinstance(data, bytes) and 0 < len(data) <= 65536, "invalid_armor")
    try:
        lines = data.decode("ascii").replace("\r\n", "\n").split("\n")
    except UnicodeError as exc:
        raise Blocked("invalid_armor") from exc
    need(
        len(lines) >= 4
        and lines[0].startswith("-----BEGIN PGP ")
        and lines[0].endswith("-----"),
        "invalid_armor",
    )
    body, index = [], 1
    while index < len(lines) and lines[index].strip():  # armor headers
        index += 1
    index += 1
    while index < len(lines) and not lines[index].startswith(("=", "-----")):
        body.append(lines[index].strip())
        index += 1
    need(index < len(lines), "invalid_armor")
    try:
        raw = base64.b64decode("".join(body), validate=True)
    except ValueError as exc:
        raise Blocked("invalid_armor") from exc
    need(0 < len(raw) <= 49152, "invalid_armor")
    return raw


def packets(raw):
    index = 0
    while index < len(raw):
        tag = raw[index]
        index += 1
        need(tag & 0x80, "invalid_packet")
        if tag & 0x40:
            kind = tag & 0x3F
            need(index < len(raw), "invalid_packet")
            first = raw[index]
            index += 1
            if first < 192:
                length = first
            elif first < 224:
                need(index < len(raw), "invalid_packet")
                length = ((first - 192) << 8) + raw[index] + 192
                index += 1
            elif first == 255:
                need(index + 4 <= len(raw), "invalid_packet")
                length = struct.unpack_from(">I", raw, index)[0]
                index += 4
            else:
                raise Blocked("invalid_packet")  # Partial lengths are refused.
        else:
            kind = (tag >> 2) & 0x0F
            width = {0: 1, 1: 2, 2: 4}.get(tag & 3)
            need(width is not None and index + width <= len(raw), "invalid_packet")
            length = int.from_bytes(raw[index : index + width], "big")
            index += width
        need(index + length <= len(raw), "invalid_packet")
        yield kind, raw[index : index + length]
        index += length


def mpi(body, offset):
    need(offset + 2 <= len(body), "invalid_mpi")
    bits = struct.unpack_from(">H", body, offset)[0]
    size = (bits + 7) // 8
    need(0 < bits <= 8192 and offset + 2 + size <= len(body), "invalid_mpi")
    value = int.from_bytes(body[offset + 2 : offset + 2 + size], "big")
    need(value.bit_length() == bits, "invalid_mpi")
    return value, offset + 2 + size


def public_key(armored):
    """Return (n, e, fingerprint) of the sole primary RSA v4 key."""
    primary = None
    for kind, body in packets(dearmor(armored)):
        if kind == 6:
            need(primary is None, "multiple_public_keys")
            primary = body
        elif kind in (14, 5, 7):
            raise Blocked("unexpected_key_packet")  # No subkeys/secret keys.
    need(primary is not None and len(primary) >= 6, "missing_public_key")
    need(primary[0] == 4 and primary[5] == 1, "unsupported_public_key")
    modulus, offset = mpi(primary, 6)
    exponent, offset = mpi(primary, offset)
    need(offset == len(primary), "invalid_public_key")
    need(modulus.bit_length() >= 3072 and exponent & 1, "weak_public_key")
    digest = hashlib.sha1(b"\x99" + struct.pack(">H", len(primary)) + primary)
    return modulus, exponent, digest.hexdigest().upper()


def subpackets(area):
    index, found = 0, []
    while index < len(area):
        first = area[index]
        index += 1
        if first < 192:
            length = first
        elif first < 255:
            need(index < len(area), "invalid_signature")
            length = ((first - 192) << 8) + area[index] + 192
            index += 1
        else:
            need(index + 4 <= len(area), "invalid_signature")
            length = struct.unpack_from(">I", area, index)[0]
            index += 4
        need(length >= 1 and index + length <= len(area), "invalid_signature")
        found.append((area[index] & 0x7F, area[index + 1 : index + length]))
        index += length
    return found


def verify_detached(data, signature, key, fingerprint=FINGERPRINT):
    """True only for a valid binary signature by the exact pinned RSA key."""
    modulus, exponent, actual = public_key(key)
    need(actual == fingerprint, "key_fingerprint_mismatch")
    parsed = [p for p in packets(dearmor(signature))]
    need(len(parsed) == 1 and parsed[0][0] == 2, "invalid_signature")
    body = parsed[0][1]
    need(len(body) >= 10 and body[0] == 4, "unsupported_signature")
    kind, algorithm, hash_id = body[1], body[2], body[3]
    need(kind == 0 and algorithm == 1 and hash_id in HASHES, "unsupported_signature")
    hashed_length = struct.unpack_from(">H", body, 4)[0]
    hashed_end = 6 + hashed_length
    need(hashed_end + 2 <= len(body), "invalid_signature")
    unhashed_length = struct.unpack_from(">H", body, hashed_end)[0]
    tail = hashed_end + 2 + unhashed_length
    need(tail + 2 <= len(body), "invalid_signature")
    issuers = [
        value
        for area in (body[6:hashed_end], body[hashed_end + 2 : tail])
        for number, value in subpackets(area)
        if number in (16, 33)
    ]
    need(
        issuers
        and all(
            v == bytes([4]) + bytes.fromhex(fingerprint)
            or v == bytes.fromhex(fingerprint[-16:])
            for v in issuers
        ),
        "signature_issuer_mismatch",
    )
    name, prefix = HASHES[hash_id]
    digest = hashlib.new(name, data)
    digest.update(body[:hashed_end])
    digest.update(b"\x04\xff" + struct.pack(">I", hashed_end))
    value = digest.digest()
    need(body[tail : tail + 2] == value[:2], "signature_digest_mismatch")
    signature_int, end = mpi(body, tail + 2)
    need(end == len(body), "invalid_signature")
    size = (modulus.bit_length() + 7) // 8
    need(0 < signature_int < modulus, "invalid_signature")
    block = pow(signature_int, exponent, modulus).to_bytes(size, "big")
    padding = size - len(prefix) - len(value) - 3
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + prefix + value
    need(padding >= 8 and block == expected, "bad_signature")
    return True


# --------------------------------------------------------------------------
# Trusted file access (copied discipline from PKG-03R, independent namespace).
# --------------------------------------------------------------------------


def checked_meta(fd, directory=False, mode=None):
    meta = os.fstat(fd)
    need(meta.st_uid == OWNER and meta.st_gid == OWNER, "unsafe_owner")
    need(
        stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode),
        "unsafe_type",
    )
    if directory:
        need(not meta.st_mode & 0o7022, "unsafe_directory_mode")
    else:
        need(meta.st_nlink == 1, "aliased_file")
    if mode is not None:
        need(stat.S_IMODE(meta.st_mode) == mode, "unsafe_mode")
    need(not BAD_XATTRS.intersection(os.listxattr(fd)), "unsafe_attributes")
    return meta


@contextlib.contextmanager
def directory(path):
    need(path.startswith("/") and ".." not in path.split("/"), "invalid_fixed_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        checked_meta(fd, True)
        for part in path.split("/")[1:]:
            if not part:
                continue
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            checked_meta(fd, True)
        yield fd
    finally:
        os.close(fd)


def exists(fd, name):
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


@contextlib.contextmanager
def child_dir(fd, name, mode=0o755):
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
    try:
        checked_meta(child, True, mode)
        need(os.fstat(child).st_dev == os.fstat(fd).st_dev, "foreign_mount")
        yield child
    finally:
        os.close(child)


def stable(meta):
    return (
        meta.st_dev,
        meta.st_ino,
        meta.st_mode,
        meta.st_nlink,
        meta.st_uid,
        meta.st_gid,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    )


def read_file(fd, name, maximum, mode=0o644):
    file = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=fd)
    try:
        before = checked_meta(file, mode=mode)
        need(0 < before.st_size <= maximum, "invalid_file_size")
        with os.fdopen(file, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(file)
        need(
            len(data) == before.st_size and stable(before) == stable(after),
            "file_changed",
        )
        need(
            stable(os.stat(name, dir_fd=fd, follow_symlinks=False)) == stable(after),
            "file_changed",
        )
        return data
    finally:
        os.close(file)


# --------------------------------------------------------------------------
# Reviewed release lock + signed manifest evidence.
# --------------------------------------------------------------------------

PIN_FIELDS = {
    "version",
    "platform",
    "binary_name",
    "binary_sha256",
    "binary_size",
    "manifest_sha256",
    "signature_sha256",
    "key_sha256",
    "key_fingerprint",
    "evidence",
    "evidence_sha256",
}


def hex64(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def validate_pin(pin):
    need(isinstance(pin, dict) and set(pin) == PIN_FIELDS, "invalid_release_pin")
    version_tuple(pin["version"])
    need(
        pin["platform"] == PLATFORM and pin["binary_name"] == MEMBER,
        "unsupported_platform",
    )
    need(pin["key_fingerprint"] == FINGERPRINT, "unreviewed_signing_key")
    need(
        type(pin["binary_size"]) is int and 0 < pin["binary_size"] <= MAX_BINARY,
        "invalid_size_pin",
    )
    for key in (
        "binary_sha256",
        "manifest_sha256",
        "signature_sha256",
        "key_sha256",
        "evidence_sha256",
    ):
        need(hex64(pin[key]), "invalid_digest_pin")
    need(
        pin["evidence"] == f"evidence/claude-{pin['version']}-provenance.json",
        "invalid_provenance_path",
    )
    need(
        version_tuple(pin["version"]) >= MIN_AGENTS_MD,
        "agents_md_support_unverified",
    )


def source_urls(version):
    """Informational operator guidance, derived from the version; never fetched."""
    root = f"{DOWNLOAD_BASE}/{version}"
    return {
        "manifest": root + "/manifest.json",
        "signature": root + "/manifest.json.sig",
        "binary": root + f"/{PLATFORM}/{MEMBER}",
    }


def verify_manifest(pin, manifest_bytes, signature, key):
    need(sha(manifest_bytes) == pin["manifest_sha256"], "manifest_changed")
    need(sha(signature) == pin["signature_sha256"], "signature_changed")
    need(sha(key) == pin["key_sha256"], "signing_key_changed")
    verify_detached(manifest_bytes, signature, key, pin["key_fingerprint"])
    manifest = strict_json(manifest_bytes)
    need(isinstance(manifest, dict), "invalid_manifest")
    need(manifest.get("version") == pin["version"], "manifest_version_mismatch")
    platforms = manifest.get("platforms")
    need(isinstance(platforms, dict) and PLATFORM in platforms, "manifest_platform")
    entry = platforms[PLATFORM]
    need(
        isinstance(entry, dict)
        and entry.get("binary") == MEMBER
        and entry.get("checksum") == pin["binary_sha256"]
        and entry.get("size") == pin["binary_size"],
        "manifest_binary_mismatch",
    )
    return manifest


def load_lock(lock_sha256=None):
    expected = LOCK_SHA256 if lock_sha256 is None else lock_sha256
    path = Path(__file__).with_name("claude-release-lock.json")
    with directory(str(path.parent)) as fd:
        data = read_file(fd, path.name, 32768)
        need(sha(data) == expected, "unreviewed_release_lock")
        lock = strict_json(data)
        need(
            set(lock) == {"schema", "releases"}
            and lock["schema"] == "AP-CLAUDE-RELEASE/1",
            "invalid_release_lock",
        )
        releases = lock["releases"]
        need(
            isinstance(releases, list) and 1 <= len(releases) <= MAX_VERSIONS,
            "invalid_release_lock",
        )
        pins = {}
        with child_dir(fd, "evidence") as evidence:
            for pin in releases:
                validate_pin(pin)
                need(pin["version"] not in pins, "duplicate_version")
                version = pin["version"]
                proof = read_file(evidence, f"claude-{version}-provenance.json", 32768)
                need(sha(proof) == pin["evidence_sha256"], "provenance_changed")
                report = strict_json(proof)
                need(
                    isinstance(report, dict)
                    and report.get("schema") == "AP-CLAUDE-PROVENANCE/1"
                    and report.get("version") == version
                    and report.get("binary_sha256") == pin["binary_sha256"]
                    and report.get("manifest_sha256") == pin["manifest_sha256"],
                    "provenance_changed",
                )
                verify_manifest(
                    pin,
                    read_file(evidence, f"claude-{version}-manifest.json", 65536),
                    read_file(evidence, f"claude-{version}-manifest.json.sig", 4096),
                    read_file(evidence, "claude-code-release-key.asc", 8192),
                )
                pins[version] = pin
    return pins


# --------------------------------------------------------------------------
# Artifact and store verification.
# --------------------------------------------------------------------------


def elf(data):
    """Header sanity only. Dynamic closure/ABI of the vendor binary is NOT_RUN."""
    need(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "invalid_elf")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    need(
        header[1] in (2, 3) and header[2] == 62 and header[3] == 1 and header[8] == 64,
        "unsupported_elf",
    )
    offset, size, count = header[5], header[9], header[10]
    need(
        size == 56 and 1 <= count <= 128 and 64 <= offset <= len(data) - count * size,
        "invalid_elf_headers",
    )
    loads = 0
    for index in range(count):
        kind, flags, pos, _, _, length, memory, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + index * size
        )
        need(pos <= len(data) and length <= len(data) - pos, "invalid_elf_segment")
        if kind == 1:
            loads += 1
            need(length <= memory and not (flags & 2 and flags & 1), "invalid_elf_load")
    need(loads > 0, "invalid_elf_load")


def artifact(path, pin):
    """Operator-supplied official bytes: no-follow, single-link, stable, exact."""
    need(isinstance(path, (str, os.PathLike)), "unsafe_artifact_input")
    try:
        fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    except OSError as exc:  # Symlink, missing or unreadable operator input.
        raise Blocked("unsafe_artifact_input") from exc
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size == pin["binary_size"]
            and not before.st_mode & 0o022,
            "unsafe_artifact_input",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(pin["binary_size"] + 1)
        need(stable(os.fstat(fd)) == stable(before), "artifact_changed")
        need(
            len(data) == pin["binary_size"] and sha(data) == pin["binary_sha256"],
            "artifact_integrity",
        )
    finally:
        os.close(fd)
    elf(data)
    return data


def key(pin):
    return pin["version"] + "-" + pin["binary_sha256"]


def record(pin):
    return {
        "schema": "AP-CLAUDE-INSTALL/1",
        "version": pin["version"],
        "release_pin_sha256": sha(encoded(pin)),
        "binary_sha256": pin["binary_sha256"],
        "binary_size": pin["binary_size"],
        "manifest_sha256": pin["manifest_sha256"],
        "purpose": "toolchain_inventory_only",
    }


def link(fd, name, target):
    meta = exists(fd, name)
    need(
        meta is not None
        and stat.S_ISLNK(meta.st_mode)
        and meta.st_uid == OWNER
        and meta.st_gid == OWNER
        and meta.st_nlink == 1,
        "unsafe_link",
    )
    need(os.readlink(name, dir_fd=fd) == target, "foreign_link")


def path_check(operator_path):
    need(
        isinstance(operator_path, str) and 0 < len(operator_path) <= 4096,
        "invalid_operator_path",
    )
    parts = operator_path.split(":")
    need(
        len(parts) <= 32
        and all(p.startswith("/") and ".." not in p.split("/") for p in parts),
        "invalid_operator_path",
    )
    for part in parts:
        # lstat only; never read HOME, user binaries, auth or session data.
        need(
            not os.path.lexists(part.rstrip("/") + "/" + MEMBER),
            "path_collision",
        )


def check_system(command_fds, operator_path):
    path_check(operator_path)
    for fd in command_fds:
        need(exists(fd, MEMBER) is None, "foreign_claude_command")


def inspect_store(root, pins, *, recovering=False):
    names = set(os.listdir(root))
    required = {"store.json", "versions"}
    allowed = required | {"current", "transaction.json", ".current.next"}
    need(required <= names <= allowed, "unknown_store_contents")
    need(
        read_file(root, "store.json", 4096) == encoded(MARKER), "unknown_store_identity"
    )
    transaction = None
    if "transaction.json" in names:
        need(recovering, "reconciliation_required")
        raw_intent = read_file(root, "transaction.json", 4096)
        transaction = strict_json(raw_intent)
        need(raw_intent == encoded(transaction), "transaction_changed")
        need(
            isinstance(transaction, dict)
            and set(transaction) == {"schema", "before", "after", "action"}
            and transaction["schema"] == "AP-CLAUDE-TRANSACTION/1"
            and transaction["action"] in ("install", "rollback"),
            "unknown_transaction",
        )
    else:
        need(not recovering and ".current.next" not in names, "reconciliation_required")
    installed = {}
    known = {key(pin): pin for pin in pins.values()}
    with child_dir(root, "versions") as versions:
        entries = set(os.listdir(versions))
        need(
            0 < len(entries) <= MAX_VERSIONS and entries <= known.keys(),
            "unknown_or_partial_version",
        )
        for name in sorted(entries):
            pin = known[name]
            with child_dir(versions, name) as version:
                need(
                    set(os.listdir(version)) == {MEMBER, "record.json"},
                    "unknown_version_contents",
                )
                need(
                    read_file(version, "record.json", 8192) == encoded(record(pin)),
                    "install_record_changed",
                )
                binary = read_file(version, MEMBER, pin["binary_size"], 0o755)
                need(
                    len(binary) == pin["binary_size"]
                    and sha(binary) == pin["binary_sha256"],
                    "installed_binary_changed",
                )
                elf(binary)
            installed[name] = pin
    current = None
    if "current" in names:
        target = os.readlink("current", dir_fd=root)
        need(
            target.startswith("versions/") and target[9:] in installed,
            "unknown_current",
        )
        current = target[9:]
        link(root, "current", "versions/" + current)
    need(current is not None or transaction is not None, "incomplete_store")
    if transaction is not None:
        need(
            transaction["after"] in installed
            and transaction["before"] in ({None} | installed.keys())
            and current in (transaction["before"], transaction["after"]),
            "transaction_state_changed",
        )
        before, after = transaction["before"], transaction["after"]
        need(before != after, "invalid_transaction_direction")
        if before is None:
            need(transaction["action"] == "install", "invalid_transaction_direction")
        else:
            previous = version_tuple(installed[before]["version"])
            selected = version_tuple(installed[after]["version"])
            need(
                selected > previous
                if transaction["action"] == "install"
                else selected < previous,
                "invalid_transaction_direction",
            )
        if ".current.next" in names:
            link(root, ".current.next", "versions/" + transaction["after"])
    return current, installed, transaction


def create_file(fd, name, data, mode=0o644):
    file = os.open(
        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=fd
    )
    try:
        os.fchmod(file, mode)
        with os.fdopen(file, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(file)
    finally:
        os.close(file)
    os.fsync(fd)


def mkdir(fd, name, mode=0o755):
    os.mkdir(name, mode, dir_fd=fd)
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
    try:
        checked_meta(child, True)
        os.fchmod(child, mode)
        os.fsync(child)
    finally:
        os.close(child)
    os.fsync(fd)


def checkpoint(_phase):
    """Offline fault injection seam; no production switch or environment override."""


def activate(root, transaction):
    if exists(root, ".current.next") is None:
        os.symlink("versions/" + transaction["after"], ".current.next", dir_fd=root)
        os.fsync(root)
    else:
        link(root, ".current.next", "versions/" + transaction["after"])
    checkpoint("pointer_staged")
    os.replace(".current.next", "current", src_dir_fd=root, dst_dir_fd=root)
    os.fsync(root)
    checkpoint("pointer_committed")
    need(
        read_file(root, "transaction.json", 4096) == encoded(transaction),
        "transaction_changed",
    )
    os.unlink("transaction.json", dir_fd=root)  # Only our verified completed intent.
    os.fsync(root)


def result(pin, outcome):
    return {
        "schema": "AP-CLAUDE-PROVISION/1",
        "outcome": outcome,
        "version": pin["version"],
        "binary_sha256": pin["binary_sha256"],
        "executable": BASE + "/versions/" + key(pin) + "/" + MEMBER,
        "runtime": "LIVE_NO_GO",
        "launch_allowed": False,
        "authentication": "NOT_RUN",
        "harness_selection": "UNCHANGED",
    }


def check_platform():
    need(
        sys.platform == "linux" and platform.machine() == "x86_64",
        "unsupported_platform",
    )
    with directory("/usr/lib") as fd:
        release = read_file(fd, "os-release", 8192)
    need(
        (b'VERSION_ID="13"' in release or b"VERSION_ID=13\n" in release)
        and b"ID=debian\n" in release,
        "unsupported_distribution",
    )


def operate(
    pins,
    version,
    *,
    path=None,
    operator_path,
    action="install",
    upgrade=False,
):
    need(action in ("install", "rollback", "recover", "verify"), "invalid_operation")
    need(os.geteuid() == OWNER, "operator_root_required")
    check_platform()
    need(version in pins or action in ("recover", "verify"), "unreviewed_version")
    need(1 <= len(pins) <= MAX_VERSIONS, "invalid_release_lock")
    for pin in pins.values():
        validate_pin(pin)
    parent, name = BASE.rsplit("/", 1)
    with contextlib.ExitStack() as stack:
        parent_fd = stack.enter_context(directory(parent))
        commands = [stack.enter_context(directory(p)) for p in SYSTEM_COMMANDS]
        # Lock trusted directories without writing a validation-time lock file.
        for fd in (parent_fd, *commands):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Blocked("provisioner_busy") from exc
        checked_meta(parent_fd, True, 0o755)
        for fd in commands:
            checked_meta(fd, True, 0o755)
        check_system(commands, operator_path)
        root = None
        current, installed, transaction = None, {}, None
        if exists(parent_fd, name) is not None:
            root = stack.enter_context(child_dir(parent_fd, name))
            current, installed, transaction = inspect_store(
                root, pins, recovering=action == "recover"
            )
        else:
            need(action == "install", "foreign_or_missing_store")
        if action == "verify":
            selected = pins[version] if version else installed.get(current)
            need(selected is not None, "nothing_to_verify")
            if path is not None:
                artifact(path, selected)
            return result(selected, "verified")
        if action == "recover":
            need(transaction is not None, "no_recoverable_transaction")
            activate(root, transaction)
            return result(installed[transaction["after"]], "recovered")
        selected = pins[version]
        target = key(selected)
        if current == target:
            need(action == "install", "rollback_not_required")
            if path is not None:
                artifact(path, selected)
            return result(selected, "already_installed")
        binary = None
        if action == "rollback":
            need(path is None and not upgrade, "rollback_takes_no_artifact")
            need(target in installed, "rollback_not_retained")
            need(
                version_tuple(version) < version_tuple(installed[current]["version"]),
                "rollback_not_older",
            )
        else:
            need(path is not None, "artifact_required")
            if current:
                need(upgrade, "explicit_upgrade_required")
                need(
                    version_tuple(version)
                    > version_tuple(installed[current]["version"]),
                    "downgrade_denied",
                )
            need(
                len(installed) < MAX_VERSIONS or target in installed,
                "retention_limit",
            )
            binary = artifact(path, selected)
        # Entire validation completes before the first persistent write.
        check_system(commands, operator_path)
        if root is None:
            mkdir(parent_fd, name)
            root = stack.enter_context(child_dir(parent_fd, name))
            mkdir(root, "versions")
            create_file(root, "store.json", encoded(MARKER))
            checkpoint("store_created")
        transaction = {
            "schema": "AP-CLAUDE-TRANSACTION/1",
            "action": action,
            "before": current,
            "after": target,
        }
        create_file(root, "transaction.json", encoded(transaction))
        checkpoint("intent")
        if target not in installed:
            with child_dir(root, "versions") as versions:
                mkdir(versions, ".stage", 0o700)
                with child_dir(versions, ".stage", 0o700) as stage:
                    create_file(stage, MEMBER, binary, 0o755)
                    checkpoint("binary_staged")
                    create_file(stage, "record.json", encoded(record(selected)))
                    checkpoint("record_staged")
                    os.fchmod(stage, 0o755)
                    os.fsync(stage)
                os.rename(".stage", target, src_dir_fd=versions, dst_dir_fd=versions)
                os.fsync(versions)
            checkpoint("version_published")
        activate(root, transaction)
        return result(selected, action)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "install", "rollback", "recover"))
    parser.add_argument("--version")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--operator-path", required=True)
    parser.add_argument("--upgrade", action="store_true")
    parser.add_argument("--approve", action="store_true")
    args = parser.parse_args(argv)
    if args.action != "verify" and not args.approve:
        parser.error("explicit --approve is required")
    if args.action == "verify" and (args.approve or args.upgrade):
        parser.error("verify is read-only and takes no approval or upgrade")
    if args.action == "recover" and (args.version or args.artifact or args.upgrade):
        parser.error("recover takes no version, artifact or upgrade")
    if args.action in ("install", "rollback") and not args.version:
        parser.error("explicit version required")
    if args.action == "install" and not args.artifact:
        parser.error("install requires a locally supplied --artifact")
    try:
        for limit, maximum in (
            (resource.RLIMIT_AS, 2 * 1024**3),
            (resource.RLIMIT_CPU, 180),
            (resource.RLIMIT_FSIZE, MAX_BINARY),
        ):
            soft, hard = resource.getrlimit(limit)
            resource.setrlimit(
                limit, (min(soft, maximum) if soft >= 0 else maximum, hard)
            )
        # A privileged entrypoint cannot run trusted policy from agentdev's checkout.
        with directory(str(Path(__file__).absolute().parent)) as fd:
            read_file(fd, Path(__file__).name, 131072)
        report = operate(
            load_lock(),
            args.version,
            path=args.artifact,
            operator_path=args.operator_path,
            action=args.action,
            upgrade=args.upgrade,
        )
        print(json.dumps(report, sort_keys=True))
        return 0
    except Blocked as exc:
        print(
            json.dumps(
                {"status": "BLOCKED", "reason": str(exc), "launch_allowed": False},
                sort_keys=True,
            )
        )
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        print(
            '{"status":"BLOCKED","reason":"io_or_state_uncertain","launch_allowed":false}'
        )
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
