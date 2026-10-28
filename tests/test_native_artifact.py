"""Synthetic static artifacts, never real Codex execution or runtime promotion."""

import hashlib
import io
import json
import os
import struct
import subprocess
import tracemalloc
from contextlib import ExitStack
from types import SimpleNamespace

import pytest
from test_deployment import elf

from agent_platform import _native_elf as parser
from agent_platform import native_artifact as native
from agent_platform import runtime_manifest as legacy


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def dynamic_elf():
    raw = bytearray(elf(needed=True))
    offset = struct.unpack_from("<Q", raw, 64 + 112 + 8)[0]
    struct.pack_into("<Q", raw, 64 + 112 + 16, 0x400000 + offset)
    return raw


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    root = tmp_path / "image"
    catalog = tmp_path / "catalog.json"
    data = {"schema_version": 1, "artifact": {}, "files": {}, "libraries": {}}
    # Host mount fixtures are synthetic; successful tests do not attest kernel mounts.
    monkeypatch.setattr(native, "_mounts", lambda root: b"synthetic-mount-snapshot")

    def put(name, raw):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        for directory in [root, *[p for p in root.rglob("*") if p.is_dir()]]:
            directory.chmod(0o700)
        data["files"][name] = {"bytes": len(raw), "sha256": digest(raw)}
        if name == native.BINARY:
            pin = {**native.PIN, **data["files"][name]}
            monkeypatch.setattr(native, "PIN", pin)
            data["artifact"] = dict(pin)
        save()

    def save():
        catalog.write_text(json.dumps(data))
        catalog.chmod(0o600)

    put(native.BINARY, elf())
    return SimpleNamespace(root=root, catalog=catalog, data=data, put=put, save=save)


def inspect(c):
    return native.inspect_candidate(c.root, c.catalog)


def rejected(c, reason=None):
    with pytest.raises((legacy.InvalidRuntime, OSError), match=reason):
        inspect(c)


def test_readonly_static_pass_never_admits_or_executes(candidate, monkeypatch, capsys):
    c = candidate
    before = {p: (p.read_bytes(), p.stat()) for p in c.root.rglob("*") if p.is_file()}
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("no child"))
    original = os.open

    def readonly(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", readonly)
    assert native.main([str(c.root), str(c.catalog)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "INSPECTED_NATIVE_CANDIDATE"
    assert result["runtime_admitted"] is result["execution_enabled"] is False
    assert result["signature_verification"] == "NOT_VERIFIED"
    assert result["elf_closure_files"] == 1
    assert str(c.root) not in json.dumps(result)
    for p, (raw, info) in before.items():
        assert p.read_bytes() == raw
        after = p.stat()
        assert (info.st_mode, info.st_mtime_ns) == (after.st_mode, after.st_mtime_ns)


@pytest.mark.parametrize(
    "field", ["version", "source_sha", "target", "sha256", "bytes"]
)
def test_exact_pinned_identity_required(candidate, field):
    candidate.data["artifact"][field] = "untrusted"
    candidate.save()
    rejected(candidate, "artifact_pin_mismatch")


@pytest.mark.parametrize(
    "fault",
    [
        "hash",
        "size",
        "mode",
        "setuid",
        "setgid",
        "hardlink",
        "symlink",
        "fifo",
        "unknown",
        "empty_directory",
        "missing",
        "ancestor_symlink",
        "root_symlink",
        "root_mode",
        "catalog_mode",
        "catalog_symlink",
    ],
)
def test_unsafe_files_and_paths_fail_closed(candidate, tmp_path, fault):
    c = candidate
    path = c.root / native.BINARY
    if fault == "hash":
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
    elif fault == "size":
        with path.open("ab") as f:
            f.write(b"x")
    elif fault in {"mode", "setuid", "setgid"}:
        path.chmod({"mode": 0o622, "setuid": 0o4600, "setgid": 0o2600}[fault])
    elif fault == "hardlink":
        os.link(path, tmp_path / "alias")
    elif fault in {"symlink", "fifo"}:
        path.unlink()
        if fault == "fifo":
            os.mkfifo(path, 0o600)
        else:
            path.symlink_to(tmp_path / "never-read-secret")
    elif fault == "unknown":
        (c.root / "unexpected").write_bytes(b"do not read")
    elif fault == "empty_directory":
        (c.root / "unexpected").mkdir(mode=0o700)
    elif fault == "missing":
        path.unlink()
    elif fault == "ancestor_symlink":
        (c.root / "usr").rename(c.root / "other")
        (c.root / "usr").symlink_to(c.root / "other", target_is_directory=True)
    elif fault == "root_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(c.root, target_is_directory=True)
        c.root = alias
    elif fault == "root_mode":
        c.root.chmod(0o777)
    elif fault == "catalog_mode":
        c.catalog.chmod(0o666)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(c.catalog)
        c.catalog = alias
    rejected(c)


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "duplicate",
        "version_bool",
        "path",
        "private",
        "file_hash",
        "file_bytes_bool",
        "file_unknown_key",
        "binary_pin",
        "library_size",
        "native_size",
        "library_map",
        "unused_library",
        "too_many",
        "total_budget",
    ],
)
def test_hostile_catalog(candidate, fault):
    c = candidate
    data = c.data
    if fault == "extra":
        data["untrusted"] = "secret"
    elif fault == "duplicate":
        c.catalog.write_text('{"schema_version":1,"schema_version":1}')
        return rejected(c)
    elif fault == "version_bool":
        data["schema_version"] = True
    elif fault in {"path", "private"}:
        data["files"]["../escape" if fault == "path" else "lib/.codex/token"] = data[
            "files"
        ][native.BINARY]
    elif fault == "file_hash":
        data["files"][native.BINARY]["sha256"] = "bad"
    elif fault == "file_bytes_bool":
        data["files"][native.BINARY]["bytes"] = True
    elif fault == "file_unknown_key":
        data["files"][native.BINARY]["kind"] = "execute"
    elif fault == "binary_pin":
        data["files"][native.BINARY]["sha256"] = "0" * 64
    elif fault == "native_size":
        data["files"][native.BINARY]["bytes"] = native.NATIVE_LIMIT + 1
    elif fault in {"library_size", "total_budget", "too_many"}:
        count = {"library_size": 1, "total_budget": 9, "too_many": 128}[fault]
        size = native.LIBRARY_LIMIT + (fault == "library_size")
        for i in range(count):
            data["files"][f"lib/lib{i}.so"] = {"bytes": size, "sha256": "0" * 64}
    elif fault == "library_map":
        data["libraries"]["libc.so"] = "lib/not-present.so"
    else:
        c.put("lib/unused.so", elf())
    c.save()
    rejected(c)


def test_closed_interpreter_library_graph(candidate):
    c = candidate
    c.put(native.BINARY, dynamic_elf())
    rejected(c, "missing_interpreter")
    c.put("lib/ld-linux-x86-64.so.2", elf())
    rejected(c, "unknown_library")
    c.put("lib/libc.so.6", elf())
    c.data["libraries"]["libc.so.6"] = "lib/libc.so.6"
    c.save()
    assert inspect(c)["elf_closure_files"] == 3


@pytest.mark.parametrize(
    "fault",
    [
        "magic",
        "class",
        "endian",
        "abi",
        "machine",
        "header",
        "phcount",
        "phoffset",
        "truncated",
        "wx",
        "memsz",
        "overflow",
        "alignment",
        "entry",
        "missing_load",
        "dynamic_address",
        "dynamic_size",
        "string_address",
        "string_size",
        "needed_offset",
        "needed_slash",
        "rpath",
        "unknown_tag",
        "dynamic_unterminated",
        "interp_traversal",
    ],
)
def test_malformed_elf_is_rejected(candidate, fault):
    raw = (
        dynamic_elf()
        if fault
        in {
            "dynamic_address",
            "dynamic_size",
            "string_address",
            "string_size",
            "needed_offset",
            "needed_slash",
            "rpath",
            "unknown_tag",
            "dynamic_unterminated",
            "interp_traversal",
        }
        else bytearray(elf())
    )
    dyn = struct.unpack_from("<Q", raw, 64 + 112 + 8)[0] if len(raw) > 120 else 0
    if fault in {"magic", "class", "endian", "abi"}:
        raw[{"magic": 0, "class": 4, "endian": 5, "abi": 7}[fault]] = 255
    elif fault == "machine":
        struct.pack_into("<H", raw, 18, 183)
    elif fault == "header":
        struct.pack_into("<H", raw, 52, 0)
    elif fault == "phcount":
        struct.pack_into("<H", raw, 56, 129)
    elif fault == "phoffset":
        struct.pack_into("<Q", raw, 32, 2**64 - 1)
    elif fault == "truncated":
        raw = raw[:80]
    elif fault == "wx":
        struct.pack_into("<I", raw, 68, 7)
    elif fault == "memsz":
        struct.pack_into("<Q", raw, 64 + 40, 1)
    elif fault == "overflow":
        struct.pack_into("<Q", raw, 64 + 16, 2**64 - 64)
    elif fault == "alignment":
        struct.pack_into("<Q", raw, 64 + 48, 3)
    elif fault == "entry":
        struct.pack_into("<Q", raw, 24, 0)
    elif fault == "missing_load":
        struct.pack_into("<I", raw, 64, 0)
    elif fault == "dynamic_address":
        struct.pack_into("<Q", raw, 64 + 112 + 16, 0)
    elif fault == "dynamic_size":
        struct.pack_into("<Q", raw, 64 + 112 + 32, 65552)
    elif fault == "string_address":
        struct.pack_into("<Q", raw, dyn + 8, 2**64 - 1)
    elif fault == "string_size":
        struct.pack_into("<Q", raw, dyn + 16 + 8, 1024 * 1024 + 1)
    elif fault == "needed_offset":
        struct.pack_into("<Q", raw, dyn + 32 + 8, 99)
    elif fault == "needed_slash":
        raw[-10] = ord("/")
    elif fault in {"rpath", "unknown_tag"}:
        struct.pack_into("<q", raw, dyn + 32, 29 if fault == "rpath" else 9999)
    elif fault == "dynamic_unterminated":
        struct.pack_into("<q", raw, dyn + 48, 12)
    else:
        raw[232:236] = b"/../"
    candidate.put(native.BINARY, raw)
    rejected(candidate)


def test_file_mutation_after_digest_read_is_detected(candidate, monkeypatch):
    path = candidate.root / native.BINARY
    original = os.pread
    changed = False

    def mutate(fd, count, offset):
        nonlocal changed
        data = original(fd, count, offset)
        if os.fstat(fd).st_ino == path.stat().st_ino and not changed:
            changed = True
            with path.open("r+b") as f:
                f.seek(119)
                f.write(b"x")
        return data

    monkeypatch.setattr(os, "pread", mutate)
    rejected(candidate, "file_changed")
    assert changed


def test_same_content_path_replacement_detected(candidate, monkeypatch):
    path = candidate.root / native.BINARY
    original = native.Reader.hash

    def replace(reader):
        value = original(reader)
        replacement = path.with_name("replacement")
        replacement.write_bytes(elf())
        replacement.chmod(0o600)
        os.replace(replacement, path)
        return value

    monkeypatch.setattr(native.Reader, "hash", replace)
    rejected(candidate, "file_changed|tree_changed")


def test_catalog_mutation_during_binary_inspection(candidate, monkeypatch):
    original = native.Reader.hash

    def mutate(reader):
        result = original(reader)
        candidate.catalog.write_text("{}")
        return result

    monkeypatch.setattr(native.Reader, "hash", mutate)
    rejected(candidate, "file_changed")


@pytest.mark.parametrize("kind", ["capability", "cap_error", "foreign_owner"])
def test_security_metadata_fail_closed(candidate, monkeypatch, kind):
    if kind == "capability":
        monkeypatch.setattr(os, "getxattr", lambda *a: b"cap")
    elif kind == "cap_error":

        def error(*args):
            raise PermissionError("nonsecret synthetic denial")

        monkeypatch.setattr(os, "getxattr", error)
    else:
        original = native._directory

        def foreign(info, **kwargs):
            if not kwargs.get("ancestor"):
                info = SimpleNamespace(st_uid=987654321, st_mode=info.st_mode)
            return original(info, **kwargs)

        monkeypatch.setattr(native, "_directory", foreign)
    rejected(candidate)


@pytest.mark.parametrize(
    "fault", ["nested", "bind", "filesystem", "large", "malformed"]
)
def test_mount_restrictions_without_real_mounts(tmp_path, monkeypatch, fault):
    root = tmp_path / "image"
    raw = {
        "nested": f"1 0 0:1 / {root}/usr rw - tmpfs x rw\n",
        "bind": f"1 0 0:1 /other {tmp_path} rw - ext4 x rw\n",
        "filesystem": "1 0 0:1 / / rw - nfs x rw\n",
        "large": "x" * (1024 * 1024 + 1),
        "malformed": "unknown\n",
    }[fault].encode()
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.BytesIO(raw))
    with pytest.raises(legacy.InvalidRuntime):
        native._mounts(root)


def test_mount_snapshot_change_fails_closed(candidate, monkeypatch):
    snapshots = iter([b"before", b"after"])
    monkeypatch.setattr(native, "_mounts", lambda root: next(snapshots))
    rejected(candidate, "mounts_changed")


def test_private_paths_rejected_before_open(monkeypatch, capsys):
    monkeypatch.setattr(os, "open", lambda *a, **k: pytest.fail("private path touched"))
    assert native.main(["/tmp/.codex/vendor", "/tmp/catalog"]) == 13
    assert "private_path_forbidden" in capsys.readouterr().out


def test_errors_are_generic(candidate, monkeypatch, capsys):
    def deny(*args):
        raise PermissionError("secret token /private/location")

    monkeypatch.setattr(native, "inspect_candidate", deny)
    assert native.main([str(candidate.root), str(candidate.catalog)]) == 13
    text = capsys.readouterr().out
    assert "secret" not in text and "/private" not in text
    assert json.loads(text)["execution_enabled"] is False


def test_time_and_io_budgets():
    with ExitStack() as stack:
        snapshot = native.Snapshot(stack)
        snapshot.deadline = 0
        with pytest.raises(legacy.InvalidRuntime, match="inspection_timeout"):
            snapshot.tick()
        snapshot.deadline = float("inf")
        with pytest.raises(legacy.InvalidRuntime, match="io_limit"):
            snapshot.tick(native.TOTAL_LIMIT + 16 * 1024 * 1024 + 1)


def test_sparse_native_above_legacy_cap_has_bounded_memory(candidate, monkeypatch):
    c = candidate
    size = legacy.BINARY_LIMIT + 1
    path = c.root / native.BINARY
    with path.open("r+b") as stream:
        stream.truncate(size)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(native.CHUNK):
            h.update(chunk)
    pin = {**native.PIN, "bytes": size, "sha256": h.hexdigest()}
    monkeypatch.setattr(native, "PIN", pin)
    c.data["artifact"] = dict(pin)
    c.data["files"][native.BINARY] = {"bytes": size, "sha256": pin["sha256"]}
    c.save()
    original = os.pread
    maximum = calls = 0

    def bounded(fd, count, offset):
        nonlocal maximum, calls
        maximum = max(maximum, count)
        calls += 1
        assert count <= native.CHUNK
        return original(fd, count, offset)

    monkeypatch.setattr(os, "pread", bounded)
    tracemalloc.start()
    try:
        result = inspect(c)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result["bytes"] == size > 256 * 1024 * 1024
    assert maximum <= 65536 and calls > 4096 and peak < 4 * 1024 * 1024
    assert legacy.BINARY_LIMIT == 256 * 1024 * 1024
    assert native.NATIVE_LIMIT == 384 * 1024 * 1024
    assert native.TOTAL_LIMIT == 512 * 1024 * 1024


def test_parser_does_not_read_whole_string_table():
    raw = dynamic_elf()
    reads = []

    def read(offset, count):
        reads.append(count)
        assert count <= native.CHUNK
        return raw[offset : offset + count]

    assert parser.inspect(read, len(raw), executable=True)[1] == ["libc.so.6"]
    assert max(reads) <= 168


def test_production_pin_not_fixture_override():
    assert native.PIN == {
        "version": "0.164.0",
        "source_sha": "6aaac694803004a63c6f393d153c96d22521a6b9",
        "target": "x86_64-unknown-linux-musl",
        "bytes": 308139304,
        "sha256": "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306",
    }


def test_actual_sparse_file_just_above_native_ceiling_rejected(candidate):
    path = candidate.root / native.BINARY
    with path.open("r+b") as stream:
        stream.truncate(native.NATIVE_LIMIT + 1)
    rejected(candidate, "size_limit")


def test_short_descriptor_read_fails_closed(candidate, monkeypatch):
    original = os.pread
    monkeypatch.setattr(os, "pread", lambda fd, n, p: original(fd, n, p)[:-1])
    rejected(candidate, "truncated_file")


def test_descriptor_size_change_fails_closed(candidate, monkeypatch):
    original = native.Reader.hash

    def grow(reader):
        result = original(reader)
        with (candidate.root / native.BINARY).open("ab") as stream:
            stream.write(b"x")
        return result

    monkeypatch.setattr(native.Reader, "hash", grow)
    rejected(candidate, "file_changed")


def test_tree_entry_count_is_bounded(candidate):
    for i in range(513):
        (candidate.root / f"unexpected-{i}").touch(mode=0o600)
    rejected(candidate, "tree_limit")


def test_bounded_large_declared_string_table():
    raw = dynamic_elf()
    dyn = struct.unpack_from("<Q", raw, 64 + 112 + 8)[0]
    strings = struct.unpack_from("<Q", raw, dyn + 8)[0] - 0x400000
    raw.extend(b"\0" * (1024 * 1024 - (len(raw) - strings)))
    struct.pack_into("<Q", raw, dyn + 24, 1024 * 1024)
    struct.pack_into("<Q", raw, 64 + 32, len(raw))
    struct.pack_into("<Q", raw, 64 + 40, len(raw))
    reads = []

    def read(offset, count):
        reads.append(count)
        assert count <= native.CHUNK
        return raw[offset : offset + count]

    assert parser.inspect(read, len(raw), executable=True)[1] == ["libc.so.6"]
    assert max(reads) == 168
    assert sum(reads) < 1024


@pytest.mark.parametrize(
    "fault",
    ["overlap", "stack", "dependencies", "duplicate_strings", "soname", "flags_origin"],
)
def test_additional_elf_boundary_cases(candidate, fault):
    raw = dynamic_elf()
    dyn = struct.unpack_from("<Q", raw, 64 + 112 + 8)[0]
    if fault in {"overlap", "stack"}:
        # Reinterpret the interpreter program header, requiring no extra read.
        struct.pack_into("<I", raw, 64 + 56, 1 if fault == "overlap" else 0x6474E551)
        if fault == "overlap":
            struct.pack_into("<Q", raw, 64 + 56 + 16, 0x400000)
            struct.pack_into("<Q", raw, 64 + 56 + 48, 1)
        else:
            struct.pack_into("<I", raw, 64 + 56 + 4, 7)
    elif fault == "dependencies":
        strings = struct.unpack_from("<Q", raw, dyn + 8)[0]
        table = [(5, strings), (10, 11)] + [(1, i) for i in range(65)] + [(0, 0)]
        raw[dyn:] = b"".join(struct.pack("<qQ", *p) for p in table) + b"\0libc.so.6\0"
        struct.pack_into("<Q", raw, 64 + 112 + 32, len(table) * 16)
        struct.pack_into("<Q", raw, 64 + 112 + 40, len(table) * 16)
        struct.pack_into("<Q", raw, 64 + 32, len(raw))
        struct.pack_into("<Q", raw, 64 + 40, len(raw))
    elif fault == "duplicate_strings":
        struct.pack_into("<q", raw, dyn + 32, 5)
    elif fault == "soname":
        struct.pack_into("<qQ", raw, dyn + 32, 14, 999)
    else:
        struct.pack_into("<qQ", raw, dyn + 32, 30, 1)
    candidate.put(native.BINARY, raw)
    rejected(candidate)


def test_catalog_numeric_equivalence_is_not_identity(candidate):
    candidate.data["artifact"]["bytes"] = float(native.PIN["bytes"])
    candidate.save()
    rejected(candidate, "artifact_pin_mismatch")


def test_documented_catalog_and_evidence_match_compiled_policy():
    from pathlib import Path

    docs = Path(__file__).parents[1] / "docs"
    catalog = json.loads((docs / "native-artifact.example.json").read_text())
    evidence = json.loads((docs / "native-artifact-evidence.json").read_text())
    assert catalog["artifact"] == native.PIN
    assert catalog["files"][native.BINARY] == {
        "bytes": native.PIN["bytes"],
        "sha256": native.PIN["sha256"],
    }
    assert evidence["candidate"]["sha256"] == native.PIN["sha256"]
    assert evidence["candidate"]["bytes"] == native.PIN["bytes"]
    assert evidence["candidate"]["runtime_admitted"] is False
    assert evidence["sigstore"]["verification"] == "NOT_VERIFIED"
    assert native.TOTAL_LIMIT == legacy.MAX_BYTES
