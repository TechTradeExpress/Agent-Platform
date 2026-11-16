"""PKG-05 read-only diagnostics; synthetic observations are never host evidence."""

import contextlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path="packaging/worker-provisioning/worker_doctor.py"):
    spec = importlib.util.spec_from_file_location("pkg05_test", ROOT / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def doctor(monkeypatch):
    module = load()

    def absent_network(*_args):
        raise FileNotFoundError

    # Existing tests model an unconfigured install; never inspect the host.
    monkeypatch.setattr(module, "network_read", absent_network)
    return module


class GoodObservations:
    artifacts = None

    def path(self):
        return "NOT_RUN", "coding_environment_scope_unverified"

    def caller_path(self):
        return "NOT_RUN", "caller_path_only"

    def bpf(self):
        return "NOT_RUN", "bpf_attachment_evidence_missing"

    def managed_executable(self):
        return "NOT_RUN", "codex_verification_required"

    def harness_selection(self):
        return "NOT_RUN", "harness_selection_missing"

    def claude(self):
        return "NOT_RUN", "claude_not_installed"

    def claude_path(self):
        return "BLOCKED", "claude_verification_required"

    def __getattr__(self, name):
        return lambda: (
            "INSTALLED"
            if name in ("package", "codex", "dependencies")
            else "CONFIGURED",
            "verified_local_package",
        )


def test_report_has_closed_redacted_deterministic_shape_and_never_ready(doctor):
    first = doctor.report(GoodObservations())
    assert json.dumps(first, sort_keys=True) == json.dumps(
        doctor.report(GoodObservations()), sort_keys=True
    )
    assert set(first) == {
        "schema",
        "status",
        "checks",
        "harness",
        "artifacts",
        "launch_allowed",
        "installation",
        "configuration",
        "host_evidence",
        "runtime",
        "subscription",
        "gate_73",
    }
    assert set(first["checks"]) == set(doctor.CHECKS)
    assert first["status"] == "BLOCKED" and first["configuration"] == "BLOCKED"
    assert first["host_evidence"] == "HOST_NOT_RUN"
    assert first["runtime"] == "LIVE_NO_GO" and first["gate_73"] == "BLOCKED"
    assert not first["launch_allowed"]
    assert all(first["checks"][n]["state"] == "NOT_RUN" for n in doctor.DEFERRED_CHECKS)
    assert "READY_FOR_SUPERVISED_PUBLISHING" not in json.dumps(first)


@pytest.mark.parametrize(
    "error,reason,state",
    [
        (FileNotFoundError("secret"), "object_missing", "BLOCKED"),
        (PermissionError("token"), "observation_denied", "NOT_RUN"),
        (OSError("PEM"), "observation_failed", "BLOCKED"),
        (ValueError("session"), "observation_failed", "BLOCKED"),
        (TypeError("password"), "observation_failed", "BLOCKED"),
    ],
)
def test_errors_are_fixed_categories_without_exception_data(
    doctor, error, reason, state
):
    observed = GoodObservations()

    def fail():
        raise error

    observed.package = fail
    report = doctor.report(observed)
    assert report["checks"]["package"] == {"state": state, "reason": reason}
    assert str(error) not in json.dumps(report)


def test_unknown_blocked_reason_is_redacted(doctor):
    observed = GoodObservations()

    def fail():
        raise doctor.Blocked("secret-untrusted-contents")

    observed.package = fail
    assert (
        doctor.report(observed)["checks"]["package"]["reason"] == "observation_failed"
    )


def test_import_and_construction_do_not_observe_or_launch(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("launch"))
    monkeypatch.setattr(os, "open", lambda *_a, **_k: pytest.fail("filesystem"))
    m = load()
    assert m.Observer().artifacts is None


def test_new_doctor_dispatch_is_fixed_and_unprivileged(monkeypatch):
    m = load("packaging/worker-provisioning/worker_cli.py")
    monkeypatch.setattr(sys, "argv", ["agent-platform-worker", "doctor"])
    monkeypatch.setattr(os, "geteuid", lambda: pytest.fail("root check"))
    seen = []

    def execute(path, argv):
        seen.append((path, argv))
        raise SystemExit(13)

    monkeypatch.setattr(os, "execv", execute)
    with pytest.raises(SystemExit):
        m.main()
    assert seen == [
        (
            "/usr/bin/python3",
            [
                "/usr/bin/python3",
                "-IB",
                "/usr/lib/agent-platform-worker/provisioning/worker_doctor.py",
            ],
        )
    ]


@pytest.mark.parametrize("option", ["--resume", "--trusted-actor=somebody"])
def test_legacy_options_never_select_new_doctor(monkeypatch, option):
    m = load("packaging/worker-provisioning/worker_cli.py")
    monkeypatch.setattr(sys, "argv", ["agent-platform-worker", "doctor", option])
    monkeypatch.setattr(os, "execv", lambda *_: pytest.fail("launch"))
    with pytest.raises(SystemExit) as error:
        m.main()
    assert error.value.code == 2


@pytest.mark.parametrize(
    "path,exists,reason",
    [
        ("/foreign:/usr/local/bin:/usr/bin", "/foreign/codex", "path_shadowing"),
        (":/usr/local/bin", "", "path_invalid"),
        ("relative:/usr/local/bin", "", "path_invalid"),
        ("/usr/bin", "", "path_invalid"),
        ("/usr/local/bin/../bin", "", "path_invalid"),
    ],
)
def test_caller_shadowing_uses_names_only(doctor, monkeypatch, path, exists, reason):
    monkeypatch.setenv("PATH", path)
    monkeypatch.setattr(
        doctor.Observer, "exists_name", staticmethod(lambda p: p == exists)
    )
    monkeypatch.setattr(os, "open", lambda *_a, **_k: pytest.fail("content read"))
    with pytest.raises(doctor.Blocked, match=reason):
        doctor.Observer().caller_path()


def test_clean_caller_path_never_confirms_coding_environment(doctor, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setattr(doctor.Observer, "exists_name", staticmethod(lambda _: False))
    observer = doctor.Observer()
    assert observer.caller_path() == ("NOT_RUN", "caller_path_only")
    with pytest.raises(doctor.Blocked, match="codex_verification_required"):
        observer.path()


@pytest.mark.parametrize(
    "field,value",
    [
        ("st_uid", 17),
        ("st_gid", 17),
        ("st_mode", stat.S_IFREG | 0o666),
        ("st_mode", stat.S_IFREG | 0o4644),
        ("st_mode", stat.S_IFIFO | 0o644),
        ("st_nlink", 2),
    ],
)
def test_metadata_rejects_foreign_owner_modes_types_aliases(
    doctor, monkeypatch, field, value
):
    base = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1)
    base[field] = value
    monkeypatch.setattr(os, "fstat", lambda _: SimpleNamespace(**base))
    monkeypatch.setattr(os, "listxattr", lambda _: [])
    with pytest.raises(doctor.Blocked, match="unsafe_metadata"):
        doctor.meta(123, mode=0o644)


@pytest.mark.parametrize("attribute", sorted(load().BAD_ATTRS))
def test_acl_and_capabilities_rejected(doctor, monkeypatch, attribute):
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _: SimpleNamespace(
            st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1
        ),
    )
    monkeypatch.setattr(os, "listxattr", lambda _: [attribute])
    with pytest.raises(doctor.Blocked, match="unsafe_attributes"):
        doctor.meta(123)


@pytest.mark.parametrize("raw", [b"[]", b'{"a":1,"a":2}', b"null", b"{bad"])
def test_malformed_public_records_rejected(doctor, raw):
    with pytest.raises((doctor.Blocked, ValueError)):
        doctor.parse(raw)


def test_no_helper_execution_after_package_failure(doctor, monkeypatch):
    monkeypatch.setattr(doctor, "sibling", lambda _: pytest.fail("unverified code"))
    observer = doctor.Observer()
    for name in ("codex", "identities"):
        with pytest.raises(doctor.Blocked, match="package_verification_required"):
            getattr(observer, name)()


@pytest.mark.parametrize("kind", ["missing", "inactive", "complain"])
def test_apparmor_missing_inactive_and_complain_fail(doctor, monkeypatch, kind):
    def opened(*_a, **_k):
        if kind == "missing":
            raise FileNotFoundError
        return 23

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "close", lambda _: None)
    monkeypatch.setattr(
        os,
        "read",
        lambda *_: b"ap-worker-publisher (complain)\n" if kind == "complain" else b"",
    )
    with pytest.raises((doctor.Blocked, FileNotFoundError)):
        doctor.Observer().apparmor()


@pytest.mark.parametrize(
    "field,value",
    [
        ("LoadState", "not-found"),
        ("NoNewPrivileges", "no"),
        ("User", "agentdev"),
        ("CapabilityBoundingSet", "cap_sys_admin"),
        ("AppArmorProfile", ""),
        ("DropInPaths", "/tmp/foreign.conf"),
        ("TasksMax", "infinity"),
        ("ProtectProc", "default"),
        ("MemoryMax", "infinity"),
        ("CPUQuotaPerSecUSec", "infinity"),
        ("ReadWritePaths", "/"),
        ("InaccessiblePaths", ""),
        ("LimitNOFILESoft", "1024"),
        ("TimeoutStartUSec", "infinity"),
    ],
)
def test_effective_unit_mismatch_blocked(doctor, monkeypatch, field, value):
    def query(argv):
        return unit_response(argv, {field: value})

    monkeypatch.setattr(doctor, "query", query)
    with pytest.raises(doctor.Blocked, match="unit_"):
        doctor.Observer().units()


def test_query_bounds_output_and_does_not_echo_stderr(doctor):
    with pytest.raises(doctor.Blocked, match="observation_failed"):
        doctor.query([sys.executable, "-I", "-c", "print('x'*70000)"])
    assert (
        doctor.query(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys;sys.stderr.write('secret');print('ok')",
            ]
        )
        == "ok\n"
    )


def test_query_timeout_reaps_own_child(doctor, monkeypatch):
    times = iter([0, 0, 6])
    monkeypatch.setattr(doctor.time, "monotonic", lambda: next(times, 6))
    with pytest.raises(doctor.Blocked, match="observation_failed"):
        doctor.query([sys.executable, "-I", "-c", "import time;time.sleep(20)"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "unknown"),
        ("accounts", {}),
        ("paths", {}),
        ("intent_sha256", "unknown"),
        ("extra", "secret"),
    ],
)
def test_incomplete_unknown_receipt_fails_closed(doctor, monkeypatch, field, value):
    observer = doctor.Observer()
    observer.accounts = {
        r: {"uid": 999 - i, "gid": 989 - i} for i, r in enumerate(doctor.ROLES)
    }
    receipt = {
        "schema": "AP-WORKER-PROVISION/1",
        "accounts": observer.accounts,
        "paths": {},
        "intent_sha256": "a" * 64,
    }
    receipt[field] = value
    monkeypatch.setattr(doctor, "read", lambda *_: json.dumps(receipt).encode())
    monkeypatch.setattr(
        doctor,
        "directory",
        lambda *_: (_ for _ in ()).throw(doctor.Blocked("state_metadata_invalid")),
    )
    with pytest.raises(doctor.Blocked, match="state_metadata_invalid"):
        observer.state()


def test_doctor_codex_uses_existing_strict_store_validation(doctor, monkeypatch):
    # The actual store tests below are shared with #116, without weakening it.
    spec = importlib.util.spec_from_file_location(
        "pkg03r_helpers", ROOT / "tests/test_codex_upstream_provisioning.py"
    )
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    m = helpers.module()
    monkeypatch.setattr(doctor, "sibling", lambda name: m)
    monkeypatch.setattr(m, "check_platform", lambda: None)
    monkeypatch.setattr(m, "load_lock", lambda: {})

    @contextlib.contextmanager
    def directory(_):
        yield 123

    monkeypatch.setattr(m, "directory", directory)
    monkeypatch.setattr(
        m,
        "inspect_store",
        lambda *_: (_ for _ in ()).throw(m.Blocked("installed_binary_changed")),
    )
    observer = doctor.Observer()
    observer.artifacts = {}
    with pytest.raises(doctor.Blocked, match="codex_verification_failed"):
        observer.codex()


def test_report_schema_file_is_closed(doctor):
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(doctor.report(GoodObservations()))
    assert set(schema["properties"]["checks"]["required"]) == set(doctor.CHECKS)


def test_current_publisher_and_legacy_doctor_are_not_imported():
    text = (ROOT / "packaging/worker-provisioning/worker_doctor.py").read_text()
    assert "agent_platform" not in text
    assert 'sibling("provision")' in text and 'sibling("codex_upstream")' in text


@pytest.fixture
def installed(doctor, tmp_path, monkeypatch):
    import io
    import tarfile

    builder = load("packaging/build_deb.py")
    packages = builder.build(ROOT, tmp_path / "packages", 6, "b" * 40, 1700000000)
    root = tmp_path / "root"
    root.mkdir()
    data = subprocess.check_output(
        ["dpkg-deb", "--fsys-tarfile", str(packages["worker"])]
    )
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        assert all(m.isfile() or m.isdir() for m in archive)
        archive.extractall(root, filter="data")
    real_meta = doctor.meta

    def symbolic_meta(fd, uid=0, gid=0, **kwargs):
        assert uid == gid == 0  # Only root-owned public package fixtures here.
        return real_meta(fd, os.getuid(), os.getgid(), **kwargs)

    monkeypatch.setattr(doctor, "meta", symbolic_meta)

    @contextlib.contextmanager
    def mapped(path):
        # Test-only fixed fixture authority; production offers no root override.
        relative = path.removeprefix("/")
        assert ".." not in relative.split("/")
        fd = os.open(root, doctor.FLAGS | os.O_DIRECTORY)
        try:
            for part in relative.split("/"):
                if part:
                    nxt = os.open(part, doctor.FLAGS | os.O_DIRECTORY, dir_fd=fd)
                    os.close(fd)
                    fd = nxt
                    symbolic_meta(fd, directory=True)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(doctor, "directory", mapped)
    monkeypatch.setattr(doctor, "query", lambda argv: "install ok installed\n0.1.0-6\n")
    return doctor, root


def test_real_archive_doctor_provenance_and_payload(installed):
    m, root = installed
    observer = m.Observer()
    assert observer.package() == ("INSTALLED", "verified_local_package")
    assert observer.artifacts["source_commit"] == "b" * 40
    assert observer.artifacts["worker_version"] == "0.1.0-6"
    assert (root / m.PREFIX.lstrip("/") / "worker_doctor.py").read_bytes() == (
        ROOT / "packaging/worker-provisioning/worker_doctor.py"
    ).read_bytes()


@pytest.mark.parametrize(
    "defect",
    [
        "binary",
        "symlink",
        "hardlink",
        "mode",
        "duplicate",
        "traversal",
        "missing_doctor",
        "foreign_path",
        "unknown_schema",
        "version",
    ],
)
def test_real_package_negative_provenance_is_read_only(installed, defect):
    m, root = installed
    manifest_path = root / m.DOC.lstrip("/") / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    code = root / m.PREFIX.lstrip("/") / "provision.py"
    if defect == "binary":
        code.write_bytes(code.read_bytes() + b"\n# changed\n")
    elif defect == "symlink":
        code.unlink()
        code.symlink_to("/nonexistent/private-sentinel")
    elif defect == "hardlink":
        os.link(code, root / "alias")
    elif defect == "mode":
        code.chmod(0o666)
    elif defect == "duplicate":
        manifest["files"].append(dict(manifest["files"][0]))
    elif defect == "traversal":
        manifest["files"][0]["path"] = "/usr/lib/agent-platform-worker/../../private"
    elif defect == "missing_doctor":
        manifest["files"] = [
            i for i in manifest["files"] if not i["path"].endswith("/worker_doctor.py")
        ]
    elif defect == "foreign_path":
        manifest["files"][0]["path"] = "/home/private/auth.json"
    elif defect == "unknown_schema":
        manifest["schema"] = 999
    elif defect == "version":
        build_path = root / m.DOC.lstrip("/") / "build.json"
        build = json.loads(build_path.read_bytes())
        build["debian_version"] = "0.1.0-5"
        build_path.write_text(json.dumps(build))
    if defect in {
        "duplicate",
        "traversal",
        "missing_doctor",
        "foreign_path",
        "unknown_schema",
    }:
        manifest_path.write_text(json.dumps(manifest))
    before = (manifest_path.read_bytes(), m.stamp(code.lstat()))
    with pytest.raises((m.Blocked, OSError)):
        m.Observer().package()
    assert (manifest_path.read_bytes(), m.stamp(code.lstat())) == before


def test_closed_schema_validates_all_actual_report_fields(doctor):
    # Dependency-free subset validation; no network schema resolver or new dependency.
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    report = doctor.report(GoodObservations())
    for name, item in report["checks"].items():
        definition = schema["$defs"]["check"]
        assert set(item) == set(definition["required"])
        assert item["state"] in definition["properties"]["state"]["enum"]
        assert item["reason"] in definition["properties"]["reason"]["enum"]
        assert name in schema["properties"]["checks"]["properties"]


def test_path_permission_denial_is_not_absence(doctor, monkeypatch):
    def denied(_):
        raise PermissionError("private")

    monkeypatch.setattr(os, "lstat", denied)
    with pytest.raises(PermissionError):
        doctor.Observer.exists_name("/synthetic/codex")


@pytest.mark.parametrize(
    "defect",
    [
        "missing",
        "unmounted",
        "no_allow",
        "broad_allow",
        "no_deny",
        "bind",
        "families",
        "duplicate",
    ],
)
def test_bpf_prerequisites_fail_closed(doctor, monkeypatch, defect):
    def metadata(_):
        if defect == "missing":
            raise FileNotFoundError
        return SimpleNamespace(
            st_mode=stat.S_IFREG if defect == "unmounted" else stat.S_IFDIR
        )

    monkeypatch.setattr(os, "lstat", metadata)
    values = {
        "IPAddressDeny": "0.0.0.0/0 ::/0",
        "IPAddressAllow": "192.0.2.1/32",
        "SocketBindDeny": "any",
        "RestrictAddressFamilies": "AF_INET",
    }
    for name, value in {
        "no_allow": ("IPAddressAllow", ""),
        "broad_allow": ("IPAddressAllow", "0.0.0.0/0"),
        "no_deny": ("IPAddressDeny", ""),
        "bind": ("SocketBindDeny", ""),
        "families": ("RestrictAddressFamilies", "AF_UNIX AF_INET"),
    }.items():
        if defect == name:
            values[value[0]] = value[1]
    monkeypatch.setattr(
        doctor,
        "query",
        lambda _: (
            "\n".join(k + "=" + v for k, v in values.items())
            + ("\nIPAddressAllow=192.0.2.2/32" if defect == "duplicate" else "")
        ),
    )
    with pytest.raises((doctor.Blocked, FileNotFoundError)):
        doctor.Observer().bpf()


def test_configured_bpf_policy_is_still_not_attachment_evidence(doctor, monkeypatch):
    monkeypatch.setattr(os, "lstat", lambda _: SimpleNamespace(st_mode=stat.S_IFDIR))
    monkeypatch.setattr(
        doctor,
        "query",
        lambda _: (
            "IPAddressDeny=0.0.0.0/0 ::/0\nIPAddressAllow=192.0.2.1/32\n"
            "SocketBindDeny=any\nRestrictAddressFamilies=AF_INET\n"
        ),
    )
    # IP syntax alone, without root operator approval, is no longer accepted.
    with pytest.raises(doctor.Blocked, match="bpf_egress_policy_missing"):
        doctor.Observer().bpf()


@pytest.mark.parametrize(
    "defect", [None, "binary", "record", "pin", "intent", "owner", "link"]
)
def test_doctor_real_synthetic_codex_store_never_executes_or_repairs(
    doctor, tmp_path, monkeypatch, defect
):
    spec = importlib.util.spec_from_file_location(
        "pkg03r_reused", ROOT / "tests/test_codex_upstream_provisioning.py"
    )
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    # Reuse #116's explicit temporary-path/current-owner model, not host authority.
    m, operate, pins, _, root = helpers.env.__wrapped__(tmp_path, monkeypatch)
    operate("1.0.0")
    monkeypatch.setattr(m, "load_lock", lambda: {"1.0.0": pins["1.0.0"]})
    monkeypatch.setattr(doctor, "sibling", lambda name: m)
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("execution"))
    version = Path(m.BASE) / "versions" / m.key(pins["1.0.0"])
    if defect == "binary":
        (version / "codex").write_bytes(b"modified")
    elif defect == "record":
        (version / "record.json").write_bytes(b'{"schema":"unknown"}\n')
    elif defect == "pin":
        pins["1.0.0"]["archive_sha256"] = "0" * 64
    elif defect == "intent":
        (Path(m.BASE) / "transaction.json").write_bytes(b'{"unknown":true}\n')
    elif defect == "owner":
        monkeypatch.setattr(m, "OWNER", os.getuid() + 1)
    elif defect == "link":
        link = Path(m.BIN) / "codex"
        link.unlink()
        link.symlink_to("/foreign/codex")
    before = helpers.snapshot(root)
    observer = doctor.Observer()
    observer.artifacts = {
        "worker_version": "0.1.0-6",
        "source_commit": "b" * 40,
        "manifest_sha256": "a" * 64,
    }
    if defect is None:
        assert observer.codex() == ("INSTALLED", "verified_managed_codex")
        assert observer.artifacts["binary_sha256"] == pins["1.0.0"]["binary_sha256"]
        assert observer.artifacts["archive_sha256"] == pins["1.0.0"]["archive_sha256"]
    else:
        with pytest.raises(doctor.Blocked, match="codex_verification_failed"):
            observer.codex()
    assert helpers.snapshot(root) == before


@pytest.mark.parametrize(
    "defect", [None, "uid_alias", "root", "same_gid", "shell", "extra_member"]
)
def test_doctor_local_public_identity_policy(doctor, monkeypatch, defect):
    users = [
        "ap-publisher:x:999:989::/var/lib/ap-publisher:/usr/sbin/nologin",
        "ap-publisher-signer:x:998:988::/var/lib/ap-publisher-signer:/usr/sbin/nologin",
    ]
    groups = ["ap-publisher:x:989:", "ap-publisher-signer:x:988:"]
    if defect == "uid_alias":
        users.append("foreign:x:999:45::/nonexistent:/bin/false")
    if defect == "root":
        users[0] = users[0].replace(":999:", ":0:")
    if defect == "same_gid":
        users[1] = users[1].replace(":988:", ":989:")
    if defect == "shell":
        users[0] = users[0].replace("/usr/sbin/nologin", "/bin/sh")
    if defect == "extra_member":
        groups[0] += "foreign"
    data = {
        "/etc/passwd": "\n".join(users).encode(),
        "/etc/group": "\n".join(groups).encode(),
    }
    monkeypatch.setattr(doctor, "read", lambda path, *_: data[path])
    monkeypatch.setattr(
        doctor, "sibling", lambda _: load("packaging/worker-provisioning/provision.py")
    )
    observer = doctor.Observer()
    observer.artifacts = {}
    if defect is None:
        assert observer.identities() == ("CONFIGURED", "verified_local_identities")
        assert observer.accounts["ap-publisher"] == {"uid": 999, "gid": 989}
    else:
        with pytest.raises(doctor.Blocked, match="identity_invalid"):
            observer.identities()


def unit_response(argv, overrides=None):
    """Translate the actual inert unit fixture to v257 show-property rendering."""
    name = argv[-1].removesuffix(".service")
    values = dict(
        line.split("=", 1)
        for line in (ROOT / "packaging/worker-publisher" / (name + ".service"))
        .read_text()
        .splitlines()
        if "=" in line and not line.startswith("#")
    )
    values.update(
        LoadState="loaded",
        NeedDaemonReload="no",
        ActiveState="inactive",
        UnitFileState="static",
        DropInPaths="",
        FragmentPath="/usr/lib/systemd/system/" + name + ".service",
    )
    values["IPAddressDeny"] = "0.0.0.0/0 ::/0"
    values["IPAddressAllow"] = ""
    values["MemoryMax"] = str(int(values["MemoryMax"].removesuffix("M")) * 1024**2)
    values["CPUQuotaPerSecUSec"] = "1s"
    values["LimitCORESoft"] = values["LimitCORE"]
    values["LimitNOFILESoft"] = values["LimitNOFILE"]
    values["TimeoutStartUSec"] = (
        "5min 10s" if values["TimeoutStartSec"] == "310" else "10s"
    )
    values["TimeoutStopUSec"] = "5s"
    values.update(overrides or {})
    props = argv[3].removeprefix("--property=").split(",")
    return "\n".join(p + "=" + values[p] for p in props)


def test_effective_unit_checks_match_both_packaged_inert_templates(doctor, monkeypatch):
    seen = []

    def query(argv):
        seen.append(argv[-1])
        return unit_response(argv)

    monkeypatch.setattr(doctor, "query", query)
    assert doctor.Observer().units() == (
        "CONFIGURED",
        "verified_effective_unit_settings",
    )
    assert seen == [name + ".service" for name in doctor.UNITS]


@pytest.mark.parametrize("defect", ["missing", "duplicate", "unknown"])
def test_effective_unit_response_must_be_complete_and_unique(
    doctor, monkeypatch, defect
):
    def query(argv):
        text = unit_response(argv)
        if defect == "missing":
            return "\n".join(
                line
                for line in text.splitlines()
                if not line.startswith("NoNewPrivileges=")
            )
        if defect == "duplicate":
            return text + "\nNoNewPrivileges=yes"
        return text + "\nFutureUnknown=yes"

    monkeypatch.setattr(doctor, "query", query)
    with pytest.raises(doctor.Blocked):
        doctor.Observer().units()


@pytest.fixture
def coding_scope(doctor, monkeypatch):
    observer = doctor.Observer()
    # Test-only correlation seam. Real production pin comes solely from codex().
    observer.artifacts = {
        "effective_path": "/opt/agent-platform-codex/versions/fixture/codex",
        "binary_sha256": "a" * 64,
        "release_pin_sha256": "b" * 64,
    }
    observer._codex_identity = tuple(
        observer.artifacts[k]
        for k in ("effective_path", "binary_sha256", "release_pin_sha256")
    )

    def public_passwd(path, *_):
        assert path == "/etc/passwd"
        return (
            b"root:x:0:0::/root:/bin/bash\n"
            b"agentdev:x:1001:1001::/home/agentdev:/bin/bash\n"
        )

    monkeypatch.setattr(doctor, "read", public_passwd)
    return observer


@pytest.mark.parametrize("artifacts", [None, {}, {"binary_sha256": "a" * 64}])
def test_path_requires_successful_codex_identity_not_artifact_claims(
    doctor, monkeypatch, artifacts
):
    observer = doctor.Observer()
    observer.artifacts = artifacts
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setattr(
        doctor, "read", lambda *_: pytest.fail("scope before Codex verification")
    )
    with pytest.raises(doctor.Blocked, match="codex_verification_required"):
        observer.path()


@pytest.mark.parametrize(
    "uid,home",
    [(0, "/root"), (1001, "/home/agentdev"), (1001, "/root"), (1234, "/home/foreign")],
)
def test_caller_uid_home_path_never_confirm_agentdev(
    doctor, coding_scope, monkeypatch, uid, home
):
    monkeypatch.setattr(os, "getuid", lambda: uid)
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    seen = []

    def names_only(path):
        seen.append(path)
        return False

    monkeypatch.setattr(doctor.Observer, "exists_name", staticmethod(names_only))
    assert coding_scope.path() == ("NOT_RUN", "coding_environment_scope_unverified")
    assert seen == ["/home/agentdev/.local/bin/codex"]
    assert coding_scope.caller_path() == ("NOT_RUN", "caller_path_only")


def test_root_clean_environment_cannot_hide_agentdev_codex(
    doctor, coding_scope, monkeypatch
):
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        doctor.Observer,
        "exists_name",
        staticmethod(lambda path: path == "/home/agentdev/.local/bin/codex"),
    )
    with pytest.raises(doctor.Blocked, match="personal_codex_requires_exec_binding"):
        coding_scope.path()
    assert coding_scope.caller_path() == ("NOT_RUN", "caller_path_only")


@pytest.mark.parametrize("denial", ["passwd", "home", "caller"])
def test_missing_access_never_becomes_clean_scope(
    doctor, coding_scope, monkeypatch, denial
):
    def denied(*_):
        raise PermissionError("SECRET/private/path")

    if denial == "passwd":
        monkeypatch.setattr(doctor, "read", denied)
    else:
        monkeypatch.setattr(doctor.Observer, "exists_name", staticmethod(denied))
    if denial == "caller":
        monkeypatch.setenv("PATH", "/private:/usr/local/bin")
    observed = GoodObservations()
    if denial == "caller":
        observed.caller_path = coding_scope.caller_path
    else:
        observed.path = coding_scope.path
    result = doctor.report(observed)
    check = "caller_path" if denial == "caller" else "path"
    assert result["checks"][check] == {
        "state": "NOT_RUN",
        "reason": "observation_denied",
    }
    assert "SECRET" not in json.dumps(result)
    assert result["configuration"] == "BLOCKED"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"root:x:0:0::/root:/bin/sh\n",
        b"agentdev:x:0:0::/root:/bin/sh\n",
        b"agentdev:x:1001:1001::/home/agentdev:/bin/sh\nother:x:01001:5::/home/other:/bin/sh\n",
        b"agentdev:x:1001:1001::/home/../private:/bin/sh\n",
        b"agentdev:x:1001:1001::/home/agentdev:/bin/sh\nagentdev:x:1002:1002::/home/other:/bin/sh\n",
    ],
)
def test_unknown_or_ambiguous_coding_identity_blocks(
    doctor, coding_scope, monkeypatch, data
):
    monkeypatch.setattr(doctor, "read", lambda *_: data)
    monkeypatch.setattr(
        doctor.Observer,
        "exists_name",
        staticmethod(lambda _: pytest.fail("ambiguous home inspection")),
    )
    with pytest.raises(doctor.Blocked, match="coding_identity_invalid"):
        coding_scope.path()


def test_mutated_codex_correlation_cannot_confirm_scope(doctor, coding_scope):
    coding_scope.artifacts["binary_sha256"] = "c" * 64
    with pytest.raises(doctor.Blocked, match="codex_verification_required"):
        coding_scope.path()


def test_failed_codex_recheck_discards_previous_identity(doctor, coding_scope):
    coding_scope.artifacts = None
    with pytest.raises(doctor.Blocked, match="package_verification_required"):
        coding_scope.codex()
    assert coding_scope._codex_identity is None


@pytest.mark.parametrize("name", ["path", "caller_path"])
def test_report_refuses_positive_scope_claim(doctor, name):
    observed = GoodObservations()
    setattr(observed, name, lambda: ("CONFIGURED", "verified_managed_codex"))
    result = doctor.report(observed)
    assert result["checks"][name] == {
        "state": "BLOCKED",
        "reason": "observation_failed",
    }
    assert result["configuration"] == "BLOCKED"


def test_scoped_report_is_deterministic_redacted_and_schema_constrained(
    doctor, coding_scope, monkeypatch
):
    monkeypatch.setenv("HOME", "/root/SECRET")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setattr(doctor.Observer, "exists_name", staticmethod(lambda _: False))
    observed = GoodObservations()
    observed.path = coding_scope.path
    observed.caller_path = coding_scope.caller_path
    first = doctor.report(observed)
    assert json.dumps(first, sort_keys=True) == json.dumps(
        doctor.report(observed), sort_keys=True
    )
    assert all(
        word not in json.dumps(first) for word in ("SECRET", "/home/agentdev", "/root")
    )
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    assert set(first["checks"]) == set(schema["properties"]["checks"]["required"])
    for name in ("path", "caller_path"):
        ref = schema["properties"]["checks"]["properties"][name]["$ref"]
        definition = schema["$defs"][ref.rsplit("/", 1)[1]]
        assert definition["properties"]["state"]["enum"] == ["BLOCKED", "NOT_RUN"]
        assert (
            first["checks"][name]["reason"]
            in definition["properties"]["reason"]["enum"]
        )
        assert (
            "verified_managed_codex" not in definition["properties"]["reason"]["enum"]
        )


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "mode",
        "symlink",
        "hardlink",
        "missing",
        "foreign_owner",
        "extra_reader",
        "missing_reader",
        "signer_candidate",
        "directory_acl",
        "duplicate_file",
        "duplicate_directory",
        "descriptor_metadata",
        "file_metadata",
        "directory_metadata",
        "parent_metadata",
        "root_metadata",
        "directory_identity",
        "parent_identity",
        "file_identity",
        "earlier_job",
        "earlier_receipts",
    ],
)
def test_staged_job_access_is_metadata_only_and_exact(
    doctor, tmp_path, monkeypatch, defect
):
    # Explicit symbolic root metadata, never real root/DAC evidence.
    (tmp_path / "etc").mkdir()
    base = tmp_path / "etc/ap-publisher"
    base.mkdir(mode=0o750)
    base.chmod(0o750)
    for name in ["job", "receipts", "candidate"]:
        p = base / (name + ".json")
        p.write_bytes(b"MUST_NOT_READ")
        p.chmod(0o440)
    if defect == "mode":
        (base / "job.json").chmod(0o444)
    if defect == "symlink":
        (base / "job.json").unlink()
        (base / "job.json").symlink_to(base / "candidate.json")
    if defect == "hardlink":
        os.link(base / "job.json", tmp_path / "alias")
    if defect == "missing":
        (base / "job.json").unlink()
    acl_queried = set()
    job_inode = (
        (base / "job.json").stat().st_ino if defect == "descriptor_metadata" else None
    )
    real_meta = doctor.meta

    def metadata(fd, uid=0, gid=0, **kw):
        assert uid == gid == 0
        wanted = os.getuid()
        if defect == "foreign_owner" and stat.S_ISREG(os.fstat(fd).st_mode):
            wanted += 1
        m = real_meta(fd, wanted, os.getgid(), **kw)
        values = {
            k: getattr(m, k)
            for k in [
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ]
        }
        if (
            defect == "descriptor_metadata"
            and m.st_ino == job_inode
            and "/etc/ap-publisher/job.json" in acl_queried
        ):
            values["st_mtime_ns"] += 1
        return SimpleNamespace(**values, st_uid=0, st_gid=0)

    real_open = os.open

    def opened(path, *args, **kwargs):
        # Only the root descriptor is mapped; production traverses every child.
        return real_open(tmp_path if path == "/" else path, *args, **kwargs)

    def query(argv):
        assert argv[:4] == [
            "/usr/bin/getfacl",
            "--absolute-names",
            "--numeric",
            "--omit-header",
        ]
        path = argv[-1]
        readers = [999] if path.endswith("candidate.json") else [999, 998]
        perm = "r-x" if path == "/etc/ap-publisher" else "r--"
        rows = {
            "user::rwx" if perm == "r-x" else "user::r--",
            "group::" + perm,
            "mask::" + perm,
            "other::---",
        }
        rows |= {f"user:{u}:{perm}" for u in readers}
        if defect in ("extra_reader", "directory_acl") and (
            defect != "directory_acl" or perm == "r-x"
        ):
            rows.add("user:2000:" + perm)
        if defect == "missing_reader" and path.endswith("job.json"):
            rows.remove("user:999:r--")
        if defect == "signer_candidate" and path.endswith("candidate.json"):
            rows.add("user:998:r--")
        acl_queried.add(path)
        if defect in ("duplicate_file", "duplicate_directory") and (
            path.endswith("job.json") if defect == "duplicate_file" else perm == "r-x"
        ):
            return "\n".join(sorted(rows) + [sorted(rows)[0]])
        if defect in (
            "file_metadata",
            "directory_metadata",
            "parent_metadata",
            "root_metadata",
        ) and path.endswith("job.json"):
            target = {
                "file_metadata": base / "job.json",
                "directory_metadata": base,
                "parent_metadata": base.parent,
                "root_metadata": tmp_path,
            }[defect]
            observed = target.stat()
            os.utime(
                target, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1000000000)
            )
        if defect in ("directory_identity", "parent_identity") and perm == "r-x":
            target = base if defect == "directory_identity" else base.parent
            target.rename(tmp_path / "retained")
            base.mkdir(parents=True)
            base.chmod(0o750)
            for name in ("job", "receipts", "candidate"):
                replacement = base / (name + ".json")
                replacement.write_bytes(b"MUST_NOT_READ")
                replacement.chmod(0o440)
        if defect in ("earlier_job", "earlier_receipts") and path.endswith(
            "candidate.json"
        ):
            target = base / ("job.json" if defect == "earlier_job" else "receipts.json")
            observed = target.stat()
            os.utime(
                target, ns=(observed.st_atime_ns, observed.st_mtime_ns + 1000000000)
            )
        if defect == "file_identity" and path.endswith("job.json"):
            target = base / "job.json"
            target.rename(tmp_path / "retained-job")
            target.write_bytes(b"MUST_NOT_READ")
            target.chmod(0o440)
        return "\n".join(sorted(rows))

    # Stable path recheck must use the same explicitly modeled owner.
    real_stat = os.stat

    def metadata_stat(path, *args, **kwargs):
        m = real_stat(path, *args, **kwargs)
        if kwargs.get("dir_fd") is None:
            return m
        values = {
            k: getattr(m, k)
            for k in [
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ]
        }
        return SimpleNamespace(**values, st_uid=0, st_gid=0)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(doctor, "meta", metadata)
    monkeypatch.setattr(doctor, "query", query)
    monkeypatch.setattr(os, "stat", metadata_stat)
    monkeypatch.setattr(os, "read", lambda *a: pytest.fail("private content read"))
    monkeypatch.setattr(os, "pread", lambda *a: pytest.fail("private content read"))
    observer = doctor.Observer()
    observer.accounts = {
        "ap-publisher": {"uid": 999, "gid": 989},
        "ap-publisher-signer": {"uid": 998, "gid": 988},
    }
    if defect is None:
        assert observer.job_access() == ("CONFIGURED", "verified_job_access_metadata")
    else:
        with pytest.raises((doctor.Blocked, OSError)):
            observer.job_access()


def test_job_namespace_and_handoff_are_always_deferred(doctor):
    report = doctor.report(GoodObservations())
    for name in ["job_namespace", "credential_handoff"]:
        assert report["checks"][name]["state"] == "NOT_RUN"
    assert report["status"] == "BLOCKED" and report["launch_allowed"] is False
