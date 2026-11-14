#!/usr/bin/python3 -IB
"""Operator-only, source-only Codex provisioner. Never executes the candidate."""

import argparse
import contextlib
import fcntl
import gzip
import hashlib
import http.client
import io
import json
import os
import platform
import re
import resource
import signal
import ssl
import stat
import struct
import sys
import tarfile
import time
import zlib
from pathlib import Path
from urllib.parse import urljoin, urlsplit

BASE = "/opt/agent-platform-codex"
BIN = "/usr/local/bin"
SYSTEM_BIN = "/usr/bin"
OWNER = 0
MAX_ARCHIVE = 160 * 1024**2
MAX_BINARY = 384 * 1024**2
MAX_VERSIONS = 3
NETWORK_SECONDS = 120
LOCK_SHA256 = "18a479cc1c140a46a11f50cb166ac655a4d47006f931ce4a45fa1ffe0741e68c"
MARKER = {"schema": "AP-CODEX-STORE/1"}
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
BAD_XATTRS = {
    "system.posix_acl_access",
    "system.posix_acl_default",
    "security.capability",
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


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate_json_key")
            out[key] = value
        return out

    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Blocked("invalid_json") from exc


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
    """Open every ancestor without following links; hold the final directory FD."""
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


def load_lock():
    path = Path(__file__).with_name("codex-release-lock.json")
    with directory(str(path.parent)) as fd:
        data = read_file(fd, path.name, 32768)
    need(sha(data) == LOCK_SHA256, "unreviewed_release_lock")
    lock = strict_json(data)
    need(
        set(lock) == {"schema", "releases"} and lock["schema"] == "AP-CODEX-RELEASE/1",
        "invalid_release_lock",
    )
    releases = lock["releases"]
    need(
        isinstance(releases, list) and 1 <= len(releases) <= MAX_VERSIONS,
        "invalid_release_lock",
    )
    pins = {}
    for pin in releases:
        validate_pin(pin)
        need(pin["version"] not in pins, "duplicate_version")
        evidence = pin["provenance"].get("evidence")
        need(
            evidence == f"evidence/codex-{pin['version']}-provenance.json",
            "invalid_provenance_path",
        )
        with directory(str(path.parent)) as parent:
            with child_dir(parent, "evidence") as evidence_fd:
                payload = read_file(evidence_fd, evidence.split("/")[1], 32768)
                need(
                    sha(payload) == pin["provenance"]["evidence_sha256"],
                    "provenance_changed",
                )
                proof = strict_json(payload)
                need(
                    proof["archive_sha256"] == pin["archive_sha256"]
                    and proof["binary_sha256"] == pin["binary_sha256"],
                    "provenance_changed",
                )
                for field, filename in (
                    ("sigstore_bundle_sha256", f"codex-{pin['version']}.sigstore"),
                    (
                        "trusted_root_sha256",
                        "sigstore-trusted-root-"
                        + proof["trusted_root_sha256"]
                        + ".json",
                    ),
                ):
                    need(
                        isinstance(proof[field], str)
                        and re.fullmatch("[0-9a-f]{64}", proof[field]),
                        "invalid_provenance_digest",
                    )
                    need(
                        sha(read_file(evidence_fd, filename, 65536)) == proof[field],
                        "provenance_changed",
                    )
        pins[pin["version"]] = pin
    return pins


def validate_pin(pin):
    fields = {
        "version",
        "tag",
        "release_id",
        "asset_id",
        "url",
        "member",
        "archive_size",
        "archive_sha256",
        "binary_size",
        "binary_sha256",
        "platform",
        "abi",
        "provenance",
    }
    need(isinstance(pin, dict) and set(pin) == fields, "invalid_release_pin")
    version = pin["version"]
    need(
        isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version),
        "invalid_version",
    )
    need(pin["tag"] == "rust-v" + version, "version_mismatch")
    need(
        pin["platform"] == "x86_64-unknown-linux-musl"
        and pin["abi"] == "static-elf64-amd64-no-interpreter-no-needed",
        "unsupported_platform",
    )
    need(pin["member"] == "codex-x86_64-unknown-linux-musl", "invalid_member_pin")
    need(
        pin["url"]
        == f"https://github.com/openai/codex/releases/download/{pin['tag']}/{pin['member']}.tar.gz",
        "invalid_asset_url",
    )
    for key, limit in (("archive_size", MAX_ARCHIVE), ("binary_size", MAX_BINARY)):
        need(type(pin[key]) is int and 0 < pin[key] <= limit, "invalid_size_pin")
    for key in ("archive_sha256", "binary_sha256"):
        need(
            isinstance(pin[key], str) and re.fullmatch("[0-9a-f]{64}", pin[key]),
            "invalid_digest_pin",
        )
    need(
        type(pin["release_id"]) is int
        and pin["release_id"] > 0
        and type(pin["asset_id"]) is int
        and pin["asset_id"] > 0,
        "invalid_release_identity",
    )
    need(
        isinstance(pin["provenance"], dict)
        and pin["provenance"].get("evidence_sha256"),
        "missing_provenance",
    )


def validate_url(url, initial):
    try:
        parsed = urlsplit(url)
        need(
            parsed.scheme == "https"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment,
            "unsafe_redirect",
        )
        need(not any(ord(c) <= 32 or ord(c) >= 127 for c in url), "unsafe_redirect")
        if url != initial:
            need(
                parsed.hostname == "release-assets.githubusercontent.com"
                and parsed.path.startswith("/github-production-release-asset/"),
                "unsafe_redirect",
            )
        else:
            need(parsed.hostname == "github.com", "unsafe_asset_origin")
        return parsed
    except ValueError as exc:
        raise Blocked("unsafe_redirect") from exc


@contextlib.contextmanager
def deadline(seconds):
    # The standalone one-shot owns this main-thread timer. Never silently
    # replace another caller's active timer or run an unbounded thread fallback.
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "timer_busy")
    old = signal.getsignal(signal.SIGALRM)

    def expired(*_):
        raise Blocked("operation_timeout")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def connect(host, timeout):
    # No proxy, netrc, keylog or custom CA environment discovery.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile="/etc/ssl/certs/ca-certificates.crt")
    return http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)


def download(pin, *, connector=connect):
    url = initial = pin["url"]
    with deadline(NETWORK_SECONDS):
        start = time.monotonic()
        for redirect in range(3):
            parsed = validate_url(url, initial)
            connection = connector(
                parsed.hostname, min(10, NETWORK_SECONDS - (time.monotonic() - start))
            )
            try:
                connection.request(
                    "GET",
                    parsed.path + (("?" + parsed.query) if parsed.query else ""),
                    headers={
                        "Accept": "application/octet-stream",
                        "Accept-Encoding": "identity",
                        "User-Agent": "Agent-Platform-PKG03R/1",
                    },
                )
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    need(
                        isinstance(location, str)
                        and len(location) <= 8192
                        and redirect < 2,
                        "redirect_limit",
                    )
                    url = urljoin(url, location)
                    validate_url(url, initial)
                    continue
                need(response.status == 200, "download_status")
                need(
                    response.getheader("Content-Encoding", "identity") == "identity"
                    and response.getheader("Transfer-Encoding") is None,
                    "encoded_response",
                )
                need(
                    response.getheader("Content-Length") == str(pin["archive_size"]),
                    "download_size",
                )
                output = io.BytesIO()
                while chunk := response.read1(65536):
                    need(
                        output.tell() + len(chunk) <= pin["archive_size"],
                        "download_size",
                    )
                    output.write(chunk)
                data = output.getvalue()
                need(
                    len(data) == pin["archive_size"]
                    and sha(data) == pin["archive_sha256"],
                    "archive_integrity",
                )
                return data
            finally:
                connection.close()
    raise Blocked("redirect_limit")


def offline(path, pin):
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size == pin["archive_size"],
            "unsafe_archive_input",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(pin["archive_size"] + 1)
        need(stable(os.fstat(fd)) == stable(before), "archive_changed")
        need(
            len(data) == pin["archive_size"] and sha(data) == pin["archive_sha256"],
            "archive_integrity",
        )
        return data
    finally:
        os.close(fd)


def elf(data):
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
        need(kind != 3, "elf_interpreter")
        if kind == 1:
            loads += 1
            need(length <= memory and not (flags & 2 and flags & 1), "invalid_elf_load")
        if kind == 2:
            need(length <= 65536 and length % 16 == 0, "invalid_dynamic_table")
            terminated = False
            for cursor in range(pos, pos + length, 16):
                tag, _ = struct.unpack_from("<qQ", data, cursor)
                need(tag not in (1, 15, 22, 29), "elf_dynamic_dependency")
                if tag == 0:
                    terminated = True
                    break
            need(terminated, "invalid_dynamic_table")
    need(loads > 0, "invalid_elf_load")


def unpack(data, pin):
    need(
        len(data) == pin["archive_size"] and sha(data) == pin["archive_sha256"],
        "archive_integrity",
    )
    # Deliberately accept only the official single-header regular-file layout.
    # No filesystem extraction, PAX/GNU extension parser or archive hooks.
    with deadline(60), gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        try:
            header = stream.read(512)
            item = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            need(
                item.name == pin["member"]
                and item.isreg()
                and not item.linkname
                and item.mode == 0o755
                and item.size == pin["binary_size"],
                "unsafe_tar_member",
            )
            binary = stream.read(pin["binary_size"] + (-pin["binary_size"] % 512))
            need(
                len(binary) == pin["binary_size"] + (-pin["binary_size"] % 512),
                "truncated_tar",
            )
            need(not any(binary[pin["binary_size"] :]), "invalid_tar_padding")
            binary = binary[: pin["binary_size"]]
            tail = stream.read(10241)
            need(1024 <= len(tail) <= 10240 and not any(tail), "extra_tar_data")
            need(stream.read(1) == b"", "decompression_limit")
        except (tarfile.TarError, EOFError, ValueError, OSError, zlib.error) as exc:
            raise Blocked("invalid_archive") from exc
    need(sha(binary) == pin["binary_sha256"], "binary_integrity")
    elf(binary)
    return binary


def key(pin):
    return pin["version"] + "-" + pin["binary_sha256"]


def record(pin):
    return {
        "schema": "AP-CODEX-INSTALL/1",
        "version": pin["version"],
        "release_pin_sha256": sha(encoded(pin)),
        "binary_sha256": pin["binary_sha256"],
        "binary_size": pin["binary_size"],
        "archive_sha256": pin["archive_sha256"],
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
        if part == BIN:
            return
        # lstat only; never read user binaries, HOME, .codex or login stores.
        need(not os.path.lexists(part.rstrip("/") + "/codex"), "path_shadowing")
    raise Blocked("managed_command_not_on_path")


def check_system(bin_fd, system_fd, operator_path):
    path_check(operator_path)
    need(exists(system_fd, "codex") is None, "foreign_usr_bin_codex")
    need(exists(bin_fd, ".ap-codex.next") is None, "foreign_link_temporary")


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
            and transaction["schema"] == "AP-CODEX-TRANSACTION/1"
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
                    set(os.listdir(version)) == {"codex", "record.json"},
                    "unknown_version_contents",
                )
                need(
                    read_file(version, "record.json", 8192) == encoded(record(pin)),
                    "install_record_changed",
                )
                binary = read_file(version, "codex", pin["binary_size"], 0o755)
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
            previous = tuple(map(int, installed[before]["version"].split(".")))
            selected = tuple(map(int, installed[after]["version"].split(".")))
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


def activate(root, bin_fd, transaction):
    if exists(bin_fd, "codex") is None:
        need(transaction["before"] is None, "missing_managed_link")
        os.symlink(BASE + "/current/codex", "codex", dir_fd=bin_fd)
        os.fsync(bin_fd)
    else:
        link(bin_fd, "codex", BASE + "/current/codex")
    checkpoint("command_link")
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


def operate(
    pins,
    version,
    *,
    archive=None,
    operator_path,
    action="install",
    upgrade=False,
    connector=connect,
):
    need(action in ("install", "rollback", "recover"), "invalid_operation")
    need(os.geteuid() == OWNER, "operator_root_required")
    check_platform()
    need(version in pins or action == "recover", "unreviewed_version")
    for pin in pins.values():
        validate_pin(pin)
    need(1 <= len(pins) <= MAX_VERSIONS, "invalid_release_lock")
    parent, name = BASE.rsplit("/", 1)
    with (
        directory(parent) as parent_fd,
        directory(BIN) as bin_fd,
        directory(SYSTEM_BIN) as system_fd,
    ):
        # Lock trusted directories without writing a validation-time lock file.
        for fd in (parent_fd, bin_fd):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Blocked("provisioner_busy") from exc
        checked_meta(parent_fd, True, 0o755)
        checked_meta(bin_fd, True, 0o755)
        checked_meta(system_fd, True, 0o755)
        check_system(bin_fd, system_fd, operator_path)
        with contextlib.ExitStack() as stack:
            root = None
            current, installed, transaction = None, {}, None
            if exists(parent_fd, name) is not None:
                root = stack.enter_context(child_dir(parent_fd, name))
                current, installed, transaction = inspect_store(
                    root, pins, recovering=action == "recover"
                )
                if exists(bin_fd, "codex") is not None:
                    link(bin_fd, "codex", BASE + "/current/codex")
                else:
                    need(
                        transaction is not None and transaction["before"] is None,
                        "missing_managed_link",
                    )
            else:
                need(
                    action == "install" and exists(bin_fd, "codex") is None,
                    "foreign_or_missing_store",
                )
            if action == "recover":
                need(transaction is not None, "no_recoverable_transaction")
                activate(root, bin_fd, transaction)
                selected = installed[transaction["after"]]
            else:
                selected = pins[version]
                target = key(selected)
                if current == target:
                    need(action == "install", "rollback_not_required")
                    return result(selected, "already_installed")
                if action == "rollback":
                    need(target in installed, "rollback_not_retained")
                    need(
                        tuple(map(int, version.split(".")))
                        < tuple(map(int, installed[current]["version"].split("."))),
                        "rollback_not_older",
                    )
                    binary = None
                else:
                    if current:
                        need(upgrade, "explicit_upgrade_required")
                        need(
                            tuple(map(int, version.split(".")))
                            > tuple(map(int, installed[current]["version"].split("."))),
                            "downgrade_denied",
                        )
                    need(
                        len(installed) < MAX_VERSIONS or target in installed,
                        "retention_limit",
                    )
                    data = (
                        offline(archive, selected)
                        if archive is not None
                        else download(selected, connector=connector)
                    )
                    binary = unpack(data, selected)
                # Entire validation completes before the first persistent write.
                check_system(bin_fd, system_fd, operator_path)
                if root is None:
                    mkdir(parent_fd, name)
                    root = stack.enter_context(child_dir(parent_fd, name))
                    mkdir(root, "versions")
                    create_file(root, "store.json", encoded(MARKER))
                    checkpoint("store_created")
                transaction = {
                    "schema": "AP-CODEX-TRANSACTION/1",
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
                            create_file(stage, "codex", binary, 0o755)
                            checkpoint("binary_staged")
                            create_file(stage, "record.json", encoded(record(selected)))
                            checkpoint("record_staged")
                            os.fchmod(stage, 0o755)
                            os.fsync(stage)
                        os.rename(
                            ".stage", target, src_dir_fd=versions, dst_dir_fd=versions
                        )
                        os.fsync(versions)
                    checkpoint("version_published")
                activate(root, bin_fd, transaction)
            return result(selected, "recovered" if action == "recover" else action)


def result(pin, outcome):
    return {
        "schema": "AP-CODEX-PROVISION/1",
        "outcome": outcome,
        "version": pin["version"],
        "binary_sha256": pin["binary_sha256"],
        "executable": BASE + "/versions/" + key(pin) + "/codex",
        "runtime": "LIVE_NO_GO",
        "launch_allowed": False,
        "authentication": "NOT_RUN",
    }


def check_platform():
    need(
        sys.platform == "linux" and platform.machine() == "x86_64",
        "unsupported_platform",
    )
    # No external process or candidate execution even for --version.
    with directory("/usr/lib") as fd:
        release = read_file(fd, "os-release", 8192)
    need(
        (b'VERSION_ID="13"' in release or b"VERSION_ID=13\n" in release)
        and b"ID=debian\n" in release,
        "unsupported_distribution",
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "rollback", "recover"))
    parser.add_argument("--version")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--operator-path", required=True)
    parser.add_argument("--upgrade", action="store_true")
    parser.add_argument("--approve", action="store_true")
    args = parser.parse_args(argv)
    if not args.approve:
        parser.error("explicit --approve is required")
    if args.action == "recover":
        if args.version or args.archive or args.upgrade:
            parser.error("recover takes no version, archive or upgrade")
    elif not args.version or (
        args.action == "rollback" and (args.archive or args.upgrade)
    ):
        parser.error("explicit version required; rollback takes no archive or upgrade")
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
        pins = load_lock()
        report = operate(
            pins,
            args.version,
            archive=args.archive,
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
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        struct.error,
        http.client.HTTPException,
    ):
        print(
            '{"status":"BLOCKED","reason":"io_or_state_uncertain","launch_allowed":false}'
        )
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
