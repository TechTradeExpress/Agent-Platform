"""Backend-independent static inspection and fake host diagnostics only."""

import hashlib
import json
import os
import socket
import stat
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_platform import deployment as dep
from agent_platform import isolation
from agent_platform import runtime_manifest as runtime

SOURCE = "a" * 40


def elf(*, needed=False, rpath=False):
    interpreter = b"/lib/ld-linux-x86-64.so.2\x00" if needed else b""
    count = 3 if needed else 1
    dynamic_offset = 64 + 56 * count + len(interpreter)
    tags = [(5, 0), (10, 11), (1, 1)] + ([(29, 1)] if rpath else []) + [(0, 0)]
    strings_offset = dynamic_offset + len(tags) * 16
    size = strings_offset + 11 if needed else 120
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    header = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 0, 0, 64, 56, count, 0, 0, 0
    )
    raw = bytearray(ident + header)
    raw.extend(struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, size, size, 4096))
    if needed:
        raw.extend(
            struct.pack(
                "<IIQQQQQQ",
                3,
                4,
                64 + count * 56,
                0,
                0,
                len(interpreter),
                len(interpreter),
                1,
            )
        )
        raw.extend(
            struct.pack(
                "<IIQQQQQQ",
                2,
                4,
                dynamic_offset,
                0,
                0,
                len(tags) * 16,
                len(tags) * 16,
                8,
            )
        )
        raw.extend(interpreter)
        tags[0] = (5, 0x400000 + strings_offset)
        for pair in tags:
            raw.extend(struct.pack("<qQ", *pair))
        raw.extend(b"\x00libc.so.6\x00")
    return bytes(raw)


@pytest.fixture
def image(tmp_path):
    root = tmp_path / "rootfs"
    files = {}
    for name in ("usr/bin/tool", "usr/bin/python3", "bin/sh"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(elf())
        path.chmod(0o755)
        files[name] = {
            "kind": "elf",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    data = {
        "schema_version": 2,
        "source_sha": SOURCE,
        "executables": ["usr/bin/tool", "usr/bin/python3", "bin/sh"],
        "files": files,
        "libraries": {},
    }
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(data))
    catalog.chmod(0o644)
    for directory in [root, *[p for p in root.rglob("*") if p.is_dir()]]:
        directory.chmod(0o755)
    return root, data, catalog


def update(root, data, name, raw, kind="elf"):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    for directory in [root, *[p for p in root.rglob("*") if p.is_dir()]]:
        directory.chmod(0o755)
    path.chmod(0o755 if kind != "data" else 0o644)
    data["files"][name] = {"kind": kind, "sha256": hashlib.sha256(raw).hexdigest()}


def snapshot(root):
    return {
        str(p.relative_to(root)): (
            p.read_bytes(),
            p.stat().st_mode,
            p.stat().st_mtime_ns,
        )
        for p in root.rglob("*")
        if p.is_file()
    }


def test_manifest_deterministic_readonly_redacted(image):
    root, data, path = image
    before = snapshot(root)
    a = runtime.inspect_runtime(root, runtime.catalog(path))
    b = runtime.inspect_runtime(root, data)
    assert a == b and a["files"] == 3
    assert str(root) not in json.dumps(a) and "usr/bin" not in json.dumps(a)
    assert snapshot(root) == before


def test_elf_loader_and_library_closure(image):
    root, data, _ = image
    update(root, data, "usr/bin/tool", elf(needed=True))
    with pytest.raises(runtime.InvalidRuntime, match="missing_library"):
        runtime.inspect_runtime(root, data)
    update(root, data, "lib/libc.so.6", elf())
    data["libraries"]["libc.so.6"] = "lib/libc.so.6"
    with pytest.raises(runtime.InvalidRuntime, match="missing_library"):
        runtime.inspect_runtime(root, data)
    update(root, data, "lib/ld-linux-x86-64.so.2", elf())
    assert runtime.inspect_runtime(root, data)["files"] == 5


@pytest.mark.parametrize(
    "fault",
    [
        "symlink",
        "hardlink",
        "mode",
        "setuid",
        "missing",
        "hash",
        "unknown",
        "binary",
        "rpath",
        "special",
        "huge",
        "data_exec",
        "script",
        "root_symlink",
    ],
)
def test_unsafe_runtime_rejected(image, tmp_path, fault):
    root, data, _ = image
    target = root / "usr/bin/tool"
    sock = None
    if fault == "symlink":
        target.unlink()
        target.symlink_to(tmp_path / "secret")
    elif fault == "hardlink":
        os.link(target, tmp_path / "outside")
    elif fault == "mode":
        target.chmod(0o777)
    elif fault == "setuid":
        target.chmod(0o4755)
    elif fault == "missing":
        target.unlink()
    elif fault == "hash":
        target.write_bytes(b"hostile token data")
    elif fault == "unknown":
        (root / "unexpected").write_bytes(b"preserve")
    elif fault == "binary":
        update(root, data, "usr/bin/tool", b"MZunknown")
    elif fault == "rpath":
        update(root, data, "usr/bin/tool", elf(needed=True, rpath=True))
    elif fault == "special":
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(root / "socket"))
    elif fault == "huge":
        with target.open("r+b") as stream:
            stream.truncate(runtime.BINARY_LIMIT + 1)
    elif fault == "data_exec":
        update(root, data, "data", b"ELF-like", kind="data")
        (root / "data").chmod(0o755)
    elif fault == "script":
        update(root, data, "script", b"#!/usr/bin/env sh\necho unsafe", kind="script")
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    try:
        with pytest.raises((runtime.InvalidRuntime, OSError)):
            runtime.inspect_runtime(root, data)
    finally:
        if sock:
            sock.close()


def test_foreign_ownership_fails_without_privileged_changes(image, monkeypatch):
    root, data, _ = image
    bad = SimpleNamespace(st_uid=123456789, st_mode=stat.S_IFREG | 0o755)
    monkeypatch.setattr(
        runtime, "walk", lambda root: iter([(Path("usr/bin/tool"), bad, -1)])
    )
    with pytest.raises(runtime.InvalidRuntime, match="unsafe_mode_or_owner"):
        runtime.inspect_runtime(root, data)


def test_unprivileged_manifest_does_not_attest_root(image):
    if os.getuid() == 0:
        pytest.skip("unprivileged ownership test")
    root, data, _ = image
    assert runtime.inspect_runtime(root, data)["visible_root_owned"] is False
    with pytest.raises(runtime.InvalidRuntime, match="root_ownership_required"):
        runtime.inspect_runtime(root, data, require_root=True)


@pytest.mark.parametrize(
    "fault",
    [
        "path",
        "unknown",
        "hash",
        "missing",
        "duplicate",
        "source",
        "mode",
        "symlink",
        "kind",
    ],
)
def test_hostile_catalog_rejected(image, tmp_path, fault):
    _, data, path = image
    if fault == "path":
        data["files"]["../secret"] = data["files"].pop("bin/sh")
    elif fault == "unknown":
        data["token"] = "secret-data"
    elif fault == "hash":
        data["files"]["bin/sh"]["sha256"] = "bad"
    elif fault == "missing":
        del data["files"]["bin/sh"]
    elif fault == "source":
        data["source_sha"] = "secret host path"
    elif fault == "kind":
        data["files"]["bin/sh"]["kind"] = "execute"
    if fault == "duplicate":
        path.write_text('{"files":{},"files":{}}')
    else:
        path.write_text(json.dumps(data))
    if fault == "mode":
        path.chmod(0o666)
    elif fault == "symlink":
        alias = tmp_path / "catalog-alias"
        alias.symlink_to(path)
        path = alias
    with pytest.raises((runtime.InvalidRuntime, OSError)):
        runtime.catalog(path)


def test_nested_mount_and_tree_limits(image, monkeypatch):
    root, data, _ = image
    original_open = open
    import io

    def mounted(path, *args, **kwargs):
        if str(path) == "/proc/self/mountinfo":
            return io.BytesIO(f"1 0 0:1 / {root}/usr rw - tmpfs x rw\n".encode())
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", mounted)
    with pytest.raises(runtime.InvalidRuntime, match="nested_mount"):
        runtime.inspect_runtime(root, data)


def test_many_entries_bounded(image, monkeypatch):
    root, data, _ = image
    monkeypatch.setattr(runtime, "MAX_FILES", 2)
    with pytest.raises(runtime.InvalidRuntime, match="size_limit"):
        runtime.inspect_runtime(root, data)


def test_catalog_must_use_default_loader_paths(image):
    root, data, path = image
    update(root, data, "opt/arbitrary/libc.so.6", elf())
    data["libraries"]["libc.so.6"] = "opt/arbitrary/libc.so.6"
    path.write_text(json.dumps(data))
    with pytest.raises(runtime.InvalidRuntime, match="invalid_catalog"):
        runtime.catalog(path)


def test_file_capability_metadata_is_denied(image, monkeypatch):
    root, data, _ = image
    monkeypatch.setattr(runtime.os, "getxattr", lambda *a, **kw: b"capability-data")
    with pytest.raises(runtime.InvalidRuntime, match="unsafe_capability"):
        runtime.inspect_runtime(root, data)


def test_script_with_explicit_approved_interpreter(image):
    root, data, _ = image
    update(
        root,
        data,
        "bin/offline-test",
        b'#!/usr/bin/python3\nprint("fixture")\n',
        kind="script",
    )
    assert runtime.inspect_runtime(root, data)["files"] == 4


def test_manifest_cli_does_not_spawn_or_write(image, monkeypatch, capsys):
    root, _, catalog = image
    before = snapshot(root)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "deployment",
            "manifest",
            "--source-sha",
            SOURCE,
            "--root",
            str(root),
            "--catalog",
            str(catalog),
        ],
    )
    monkeypatch.setattr(
        dep.process,
        "read_command",
        lambda *a, **kw: pytest.fail("manifest cannot execute"),
    )
    original = os.open

    def readonly(path, flags, *a, **kw):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        return original(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", readonly)
    assert dep.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["checks"]["runtime_manifest"]["outcome"] == "PASS"
    assert result["evidence"]["real_kernel"] == "NOT_RUN"
    assert snapshot(root) == before
    schema = json.loads(
        (Path(__file__).parents[1] / "docs/deployment-report.schema.json").read_text()
    )
    assert result.keys() <= schema["properties"].keys()
    assert set(schema["required"]) <= result.keys()
    assert str(root) not in json.dumps(result)


def test_report_and_example_schema_never_assert_e2e():
    docs = Path(__file__).parents[1] / "docs"
    example = json.loads((docs / "deployment-report.example.json").read_text())
    schema = json.loads((docs / "deployment-report.schema.json").read_text())
    assert example["result"] == "E2E_BLOCKED" and not schema["additionalProperties"]
    assert set(schema["$defs"]["outcome"]["enum"]) == {
        "PASS",
        "FAIL",
        "BLOCKED",
        "NOT_RUN",
    }
    assert example["evidence"]["live_inference"] == "NOT_RUN"


def test_host_hints_are_readonly_and_backend_independent(tmp_path, monkeypatch):
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"root-trusted executable fixture")
    executable.chmod(0o755)
    monkeypatch.setattr(dep, "BWRAP", executable)
    monkeypatch.setattr(dep, "namespace_policy", lambda: None)
    monkeypatch.setattr(isolation, "trusted", lambda *a: None)
    monkeypatch.setattr(
        isolation, "broker_request", lambda *a: pytest.fail("no broker request")
    )
    monkeypatch.setattr(
        isolation, "Profile", lambda *a: pytest.fail("no launch preflight")
    )
    monkeypatch.setattr(socket, "socket", lambda *a: pytest.fail("no socket"))
    original = os.open

    def readonly(path, flags, *a, **kw):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        return original(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", readonly)
    calls = []

    def read(argv, cwd, env, **limits):
        assert argv == [str(executable), "--version"]
        assert cwd == Path("/") and env == {"PATH": os.defpath, "LC_ALL": "C"}
        assert limits == {"timeout": 5, "limit": 128}
        calls.append(argv)
        return b"bubblewrap 0.9.0\n"

    monkeypatch.setattr(dep.process, "read_command", read)
    result = dep.audit(SOURCE)
    assert result["host_status"] == "host_hints_pass" and len(calls) == 1
    assert result["result"] == "E2E_BLOCKED"
    assert all(value == "NOT_RUN" for value in result["evidence"].values())
    assert "broker" not in json.dumps(result) and str(tmp_path) not in json.dumps(
        result
    )
    assert list(tmp_path.iterdir()) == [executable]


def test_host_hint_failures_do_not_leak_or_create_files(tmp_path, monkeypatch):
    def unavailable(*args):
        raise PermissionError("secret token /identifying/host/path")

    monkeypatch.setattr(dep, "namespace_policy", unavailable)
    monkeypatch.setattr(dep, "bubblewrap", unavailable)
    result = dep.audit(SOURCE)
    assert result["host_status"] == "host_hints_blocked"
    assert all(check["outcome"] == "BLOCKED" for check in result["checks"].values())
    assert "secret" not in json.dumps(result) and "/identifying" not in json.dumps(
        result
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("argument", ["rehearse", "--broker-policy"])
def test_removed_backend_deployment_options_cannot_run(argument, monkeypatch, capsys):
    argv = (
        ["deployment", argument]
        if argument == "rehearse"
        else ["deployment", "audit", "--source-sha", SOURCE, argument, "/never-read"]
    )
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(
        dep.process, "read_command", lambda *a, **kw: pytest.fail("no execution")
    )
    with pytest.raises(SystemExit) as error:
        dep.main()
    assert error.value.code == 2
    assert capsys.readouterr().out == ""


def test_catalog_is_generic_and_rejects_legacy_broker_authority(image):
    root, data, path = image
    assert not any("codex" in key for key in data["files"])
    assert runtime.inspect_runtime(root, runtime.catalog(path))["files"] == 3
    data["broker_id"] = "b" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(runtime.InvalidRuntime, match="invalid_catalog"):
        runtime.catalog(path)
