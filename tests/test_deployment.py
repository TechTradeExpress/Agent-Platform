"""Synthetic ELF/files/socket metadata and fake tools only; no real kernel in CI."""

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
from agent_platform.broker_policy import Rejected

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
    for name in runtime.REQUIRED:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(elf())
        path.chmod(0o755)
        files[name] = {
            "kind": "elf",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    data = {
        "schema_version": 1,
        "source_sha": SOURCE,
        "codex_version": "0.164.0",
        "broker_id": "b" * 64,
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
    update(root, data, "usr/bin/codex", elf(needed=True))
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
    target = root / "usr/bin/codex"
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
        update(root, data, "usr/bin/codex", b"MZunknown")
    elif fault == "rpath":
        update(root, data, "usr/bin/codex", elf(needed=True, rpath=True))
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
        runtime, "walk", lambda root: iter([(Path("usr/bin/codex"), bad, -1)])
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
    with pytest.raises((runtime.InvalidRuntime, Rejected, OSError)):
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


def test_probe_matches_existing_profile_command(image, monkeypatch):
    root, _, _ = image
    monkeypatch.setattr(isolation, "PROFILE", root.parent)
    current = isolation.Profile({"worktree": "/unused"}, 123)
    argv = ["/usr/bin/python3", "-I", "/agent-platform-sandbox.py", "probe", "{}"]
    assert dep.probe_command(root, 123, argv) == current.command(argv, probe=True)


def test_opt_in_fake_rehearsal_has_no_credentials_or_production_mounts(
    image, tmp_path, monkeypatch
):
    root, _, _ = image
    monkeypatch.setattr(dep, "namespace_policy", lambda: None)
    calls = []

    def read(argv, cwd, env, **kwargs):
        assert (
            env == isolation.ENV and kwargs["timeout"] == 10 and kwargs["limit"] == 4096
        )
        assert kwargs["pass_fds"] == (int(argv[argv.index("--sync-fd") + 1]),)
        assert "--unshare-net" in argv and "--clearenv" in argv
        assert str(isolation.BROKER) not in argv
        calls.append(argv)
        return b"codex-cli 0.164.0\n" if "--version" in argv else b"isolated\n"

    monkeypatch.setattr(dep.process, "read_command", read)
    scratch = tmp_path / "scratch"
    dep.rehearse(root, scratch)
    assert (
        len(calls) == 3 and (scratch / "synthetic-private/fabricated-canary").exists()
    )
    with pytest.raises(runtime.InvalidRuntime, match="scratch_conflict"):
        dep.rehearse(root, scratch)
    assert len(calls) == 3


def test_namespace_failure_preserves_no_scratch(image, tmp_path, monkeypatch):
    def denied():
        raise runtime.InvalidRuntime("namespaces_unavailable")

    monkeypatch.setattr(dep, "namespace_policy", denied)
    with pytest.raises(runtime.InvalidRuntime):
        dep.rehearse(image[0], tmp_path / "absent")
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize("fault", ["uid", "gid", "mode", "world", "type", "link"])
def test_socket_policy_rejects_unsafe_identity(monkeypatch, fault):
    values = {
        "st_uid": 0,
        "st_gid": os.getgid(),
        "st_mode": stat.S_IFSOCK | 0o660,
        "st_nlink": 1,
    }
    if fault == "uid":
        values["st_uid"] = 123456789
    elif fault == "gid":
        values["st_gid"] += 1
    elif fault == "mode":
        values["st_mode"] = stat.S_IFSOCK | 0o600
    elif fault == "world":
        values["st_mode"] = stat.S_IFSOCK | 0o666
    elif fault == "type":
        values["st_mode"] = stat.S_IFLNK | 0o777
    else:
        values["st_nlink"] = 2

    class FakePath:
        parent = Path("/not-read")

        def exists(self):
            return True

        def is_symlink(self):
            return False

        def lstat(self):
            return SimpleNamespace(**values)

    monkeypatch.setattr(isolation, "BROKER", FakePath())
    monkeypatch.setattr(isolation, "trusted", lambda *a: None)
    with pytest.raises(runtime.InvalidRuntime):
        dep.socket_policy()


def test_broker_health_exact_contract_and_no_inference(image, monkeypatch):
    expected = image[1]
    calls = []

    def request(method, endpoint):
        calls.append((method, endpoint))
        if endpoint == "/agent-platform/health":
            return 200, json.dumps(
                {
                    "protocol": 1,
                    "broker_id": "b" * 64,
                    "inference_only": True,
                    "credentials_exposed": False,
                    "network_tools": False,
                }
            ).encode()
        return 403, b""

    monkeypatch.setattr(isolation, "broker_request", request)
    dep.broker_health(expected)
    assert calls == [
        ("GET", "/agent-platform/health"),
        ("GET", "/auth"),
        ("POST", "/v1/admin"),
        ("GET", "/v1/models"),
    ]
    monkeypatch.setattr(
        isolation, "broker_request", lambda *a: (200, b'{"secret":"token host path"}')
    )
    with pytest.raises(runtime.InvalidRuntime):
        dep.broker_health(expected)


def test_audit_missing_prerequisites_never_writes_or_calls_provider(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(isolation, "BROKER", tmp_path / "missing/inference.sock")

    def deny(*a, **kw):
        raise PermissionError("secret token host path")

    monkeypatch.setattr(dep, "namespace_policy", deny)
    monkeypatch.setattr(dep, "bubblewrap", deny)
    monkeypatch.setattr(
        isolation,
        "broker_request",
        lambda *a: pytest.fail("no socket means no request"),
    )
    result = dep.audit(SOURCE)
    assert (
        result["host_status"] == "host_audit_blocked"
        and result["result"] == "E2E_BLOCKED"
    )
    assert result["evidence"] == {
        key: "NOT_RUN"
        for key in ("offline_ci", "real_kernel", "audited_broker", "live_inference")
    }
    assert "secret" not in json.dumps(result) and str(tmp_path) not in json.dumps(
        result
    )
    assert list(tmp_path.iterdir()) == []


def test_cli_missing_manifest_and_rehearsal_are_blocked(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "deployment",
            "rehearse",
            "--source-sha",
            SOURCE,
            "--root",
            str(tmp_path / "missing"),
            "--scratch",
            str(tmp_path / "scratch"),
            "--consent-kernel-probe",
        ],
    )
    assert dep.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["evidence"]["real_kernel"] == "BLOCKED"
    assert not (tmp_path / "scratch").exists()
    assert str(tmp_path) not in json.dumps(result)


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


def test_rehearsal_rejects_scratch_inside_image(image, monkeypatch):
    root, _, _ = image
    monkeypatch.setattr(dep, "namespace_policy", lambda: None)
    with pytest.raises(runtime.InvalidRuntime, match="scratch_conflict"):
        dep.rehearse(root, root / "scratch")
    assert not (root / "scratch").exists()


def test_fake_probe_failure_is_fail_not_kernel_pass(image, tmp_path, monkeypatch):
    monkeypatch.setattr(dep, "namespace_policy", lambda: None)
    calls = []

    def denied(argv, *a, **kw):
        calls.append(argv)
        return b"isolated\n" if len(calls) == 1 else b"hostile stderr token data"

    monkeypatch.setattr(dep.process, "read_command", denied)
    result = dep.report(SOURCE)
    scratch = tmp_path / "preserve"
    dep.record(result, "kernel_probe", lambda: dep.rehearse(image[0], scratch))
    assert result["checks"]["kernel_probe"] == {
        "outcome": "FAIL",
        "reason": "kernel_probe_failed",
    }
    assert len(calls) == 2 and scratch.exists()
    assert result["evidence"]["real_kernel"] == "NOT_RUN"
    assert b"hostile" not in json.dumps(result).encode()


def test_valid_socket_grant_requires_primary_gid(monkeypatch):
    class SocketPath:
        parent = Path("/metadata-only")

        def exists(self):
            return True

        def is_symlink(self):
            return False

        def lstat(self):
            return SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=2001, st_nlink=1
            )

    monkeypatch.setattr(isolation, "BROKER", SocketPath())
    monkeypatch.setattr(isolation, "trusted", lambda *a: None)
    monkeypatch.setattr(dep.os, "getuid", lambda: 2000)
    monkeypatch.setattr(dep.os, "getgid", lambda: 2001)
    dep.socket_policy()
    monkeypatch.setattr(dep.os, "getgid", lambda: 2002)
    with pytest.raises(
        runtime.InvalidRuntime, match="broker_primary_gid_access_required"
    ):
        dep.socket_policy()


def test_broker_policy_pair_and_identity_are_exact(image, tmp_path):
    data = {
        "version": 1,
        "endpoint": "https://api.openai.com/v1/responses",
        "broker_id": "b" * 64,
        "models": ["fixture-model"],
        "peers": [[os.getuid(), os.getgid()]],
    }
    path = tmp_path / "broker-policy"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    dep.broker_policy(path, image[1])
    data["peers"][0][1] += 1
    path.write_text(json.dumps(data))
    with pytest.raises(runtime.InvalidRuntime, match="broker_peer_pair_mismatch"):
        dep.broker_policy(path, image[1])
    data["peers"] = [[os.getuid(), os.getgid()]]
    data["broker_id"] = "c" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(runtime.InvalidRuntime, match="broker_identity_mismatch"):
        dep.broker_policy(path, image[1])


def test_profile_metadata_hash_and_identity_match_catalog(image, tmp_path, monkeypatch):
    path = tmp_path / "profile"
    path.mkdir(mode=0o755)
    data = {
        "version": 1,
        "codex_version": "0.164.0",
        "broker_id": "b" * 64,
        "codex_sha256": image[1]["files"]["usr/bin/codex"]["sha256"],
    }
    metadata = path / "profile.json"
    metadata.write_text(json.dumps(data))
    metadata.chmod(0o644)
    monkeypatch.setattr(isolation, "PROFILE", path)
    monkeypatch.setattr(isolation, "trusted", lambda *a: None)
    result = dep.report(SOURCE)
    dep.profile_metadata(result, image[1])
    assert len(result["profile_sha256"]) == 64
    data["codex_sha256"] = "f" * 64
    metadata.write_text(json.dumps(data))
    with pytest.raises(runtime.InvalidRuntime, match="profile_mismatch"):
        dep.profile_metadata(result, image[1])


def test_host_audit_pass_is_not_deployment_or_e2e_pass(image, monkeypatch):
    monkeypatch.setattr(dep, "namespace_policy", lambda: None)
    monkeypatch.setattr(dep, "installed_profile", lambda: None)
    monkeypatch.setattr(dep, "bubblewrap", lambda r: None)
    monkeypatch.setattr(dep, "manifest", lambda *a, **kw: None)
    monkeypatch.setattr(dep, "profile_metadata", lambda *a: None)
    monkeypatch.setattr(dep, "socket_policy", lambda: None)
    monkeypatch.setattr(dep, "broker_policy", lambda *a: None)
    monkeypatch.setattr(dep, "broker_health", lambda *a: None)
    result = dep.audit(SOURCE, image[2])
    assert result["host_status"] == "host_audit_pass"
    assert result["result"] == "E2E_BLOCKED"
    assert all(v == "NOT_RUN" for v in result["evidence"].values())


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
