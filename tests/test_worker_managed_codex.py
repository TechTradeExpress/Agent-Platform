"""PKG-07 fabricated stores/identities only, NEVER real host or exec evidence."""

import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_worker_doctor import GoodObservations, load

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def managed(tmp_path, monkeypatch):
    helpers = load("tests/test_codex_upstream_provisioning.py")
    m, operate, pins, _, root = helpers.env.__wrapped__(tmp_path, monkeypatch)
    operate("1.0.0")
    doctor = load()
    monkeypatch.setattr(
        m, "load_lock", lambda: {k: pins[k] for k in ("1.0.0", "2.0.0")}
    )
    monkeypatch.setattr(doctor, "sibling", lambda _: m)
    # Explicit temporary-root/current-owner model. Production has no such option.
    monkeypatch.setattr(doctor, "MANAGED_BASE", m.BASE)
    monkeypatch.setattr(doctor, "directory", m.directory)
    original_meta = doctor.meta
    monkeypatch.setattr(
        doctor,
        "meta",
        lambda fd, **kw: original_meta(fd, uid=os.getuid(), gid=os.getgid(), **kw),
    )
    observer = doctor.Observer()
    observer.artifacts = {
        "worker_version": "0.1.0-6",
        "source_commit": "b" * 40,
        "manifest_sha256": "a" * 64,
    }
    monkeypatch.setattr(
        doctor,
        "read",
        lambda path, *_: (
            b"root:x:0:0::/root:/bin/sh\nagentdev:x:1001:1001::/home/agentdev:/bin/sh\n"
            if path == "/etc/passwd"
            else pytest.fail("unexpected input")
        ),
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("process"))
    return SimpleNamespace(
        m=m,
        doctor=doctor,
        observer=observer,
        pins=pins,
        root=root,
        operate=operate,
        helpers=helpers,
        monkeypatch=monkeypatch,
    )


@pytest.mark.parametrize("personal", [False, True])
def test_absolute_candidate_is_independent_of_personal_name_but_not_exec_proof(
    managed, personal
):
    n = managed
    n.monkeypatch.setenv("HOME", "/root")
    n.monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    seen = []

    def names_only(path):
        assert path == "/home/agentdev/.local/bin/codex"
        seen.append(path)
        return personal

    n.monkeypatch.setattr(n.doctor.Observer, "exists_name", staticmethod(names_only))
    before = n.helpers.snapshot(n.root)
    assert n.observer.codex() == ("INSTALLED", "verified_managed_codex")
    assert n.observer.managed_executable() == (
        "INSTALLED",
        "verified_absolute_codex_candidate",
    )
    identity = n.observer.artifacts["managed_identity_sha256"]
    assert len(identity) == 64
    assert n.observer.managed_executable()[0] == "INSTALLED"
    assert n.observer.artifacts["managed_identity_sha256"] == identity
    if personal:
        with pytest.raises(
            n.doctor.Blocked, match="personal_codex_requires_exec_binding"
        ):
            n.observer.path()
    else:
        assert n.observer.path() == ("NOT_RUN", "coding_environment_scope_unverified")
    assert seen == ["/home/agentdev/.local/bin/codex"]
    assert n.observer.caller_path() == ("NOT_RUN", "caller_path_only")
    assert n.helpers.snapshot(n.root) == before  # No repair, launch or user changes.


@pytest.mark.parametrize(
    "field", ["effective_path", "binary_sha256", "release_pin_sha256"]
)
def test_artifact_drift_invalidates_candidate_correlation(managed, field):
    n = managed
    n.observer.codex()
    n.observer.artifacts[field] = "foreign"
    with pytest.raises(n.doctor.Blocked, match="codex_verification_required"):
        n.observer.managed_executable()
    assert n.observer._codex_identity is None and n.observer._managed_identity is None


def test_user_json_cannot_supply_internal_selection_authority(managed):
    n = managed
    n.observer.codex()
    claim = dict(n.observer.artifacts, managed_identity_sha256="a" * 64)
    unverified = n.doctor.Observer()
    unverified.artifacts = json.loads(json.dumps(claim))
    with pytest.raises(n.doctor.Blocked, match="codex_verification_required"):
        unverified.managed_executable()


@pytest.mark.parametrize(
    "defect",
    [
        "binary",
        "symlink",
        "hardlink",
        "mode",
        "record",
        "current_missing",
        "current_foreign",
        "transaction",
    ],
)
def test_changed_store_blocks_new_candidate_without_repair(managed, defect):
    n = managed
    n.observer.codex()
    path = Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"]) / "codex"
    if defect == "binary":
        path.write_bytes(b"changed")
    elif defect == "symlink":
        path.unlink()
        path.symlink_to("/never-read-personal-sentinel")
    elif defect == "hardlink":
        os.link(path, n.root / "alias")
    elif defect == "mode":
        path.chmod(0o777)
    elif defect == "record":
        path.with_name("record.json").write_bytes(b"{}")
    elif defect == "transaction":
        (Path(n.m.BASE) / "transaction.json").write_bytes(b"{}")
    else:
        current = Path(n.m.BASE) / "current"
        current.unlink()
        if defect == "current_foreign":
            current.symlink_to("versions/foreign")
    with pytest.raises((n.doctor.Blocked, OSError)):
        n.observer.managed_executable()
    assert n.observer._codex_identity is None
    assert "managed_identity_sha256" not in n.observer.artifacts


def test_valid_upgrade_still_requires_fresh_correlated_observation(
    managed, monkeypatch
):
    n = managed
    n.observer.codex()
    n.observer.managed_executable()
    # Fixture-only operator, no subprocess, download, real binary or host changes.
    n.operate("2.0.0", upgrade=True)
    with pytest.raises(n.doctor.Blocked, match="managed_selection_changed"):
        n.observer.managed_executable()
    assert n.observer._codex_identity is None
    n.observer.codex()
    assert n.observer.managed_executable()[0] == "INSTALLED"


@pytest.mark.parametrize("target", ["codex", "record.json", "current"])
def test_byte_identical_inode_replacement_invalidates_existing_observation(
    managed, target
):
    n = managed
    n.observer.codex()
    n.observer.managed_executable()
    version = Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"])
    path = (Path(n.m.BASE) / target) if target == "current" else version / target
    replacement = n.root / "replacement"
    if target == "current":
        replacement.symlink_to(path.readlink())
    else:
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(stat.S_IMODE(path.stat().st_mode))
    os.replace(replacement, path)
    with pytest.raises(n.doctor.Blocked, match="managed_selection_changed"):
        n.observer.managed_executable()
    assert n.observer._managed_identity is None


@pytest.mark.parametrize("name", ["codex", "record.json"])
def test_direct_candidate_rejects_foreign_device(managed, monkeypatch, name):
    n = managed
    n.observer.codex()
    inode = (
        (Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"]) / name).stat().st_ino
    )
    original = n.doctor.meta

    def foreign(fd, **kw):
        value = original(fd, **kw)
        if value.st_ino == inode:
            fields = {k: getattr(value, k) for k in dir(value) if k.startswith("st_")}
            fields["st_dev"] += 1
            return SimpleNamespace(**fields)
        return value

    monkeypatch.setattr(n.doctor, "meta", foreign)
    with pytest.raises(n.doctor.Blocked, match="unsafe_metadata"):
        n.observer.managed_executable()


def test_hash_read_namespace_replacement_is_refused(managed, monkeypatch):
    n = managed
    n.observer.codex()
    path = Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"]) / "codex"
    inode = path.stat().st_ino
    original = os.read
    changed = False

    def mutate(fd, size):
        nonlocal changed
        data = original(fd, size)
        if os.fstat(fd).st_ino == inode and not changed:
            changed = True
            replacement = n.root / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o755)
            os.replace(replacement, path)
        return data

    monkeypatch.setattr(os, "read", mutate)
    # The replaced, still-open inode now has nlink=0: reject at meta() first.
    with pytest.raises(n.doctor.Blocked, match="unsafe_metadata"):
        n.observer.managed_executable()
    assert changed


@pytest.mark.parametrize("state", ["CONFIGURED", "READY_FOR_SUPERVISED_PUBLISHING"])
def test_no_static_candidate_or_forged_producer_can_promote_readiness(state):
    doctor = load()
    observed = GoodObservations()
    observed.managed_executable = lambda: (state, "verified_absolute_codex_candidate")
    observed.execution_binding = lambda: (
        "CONFIGURED",
        "verified_absolute_codex_candidate",
    )
    result = doctor.report(observed)
    assert result["checks"]["managed_executable"] == {
        "state": "BLOCKED",
        "reason": "observation_failed",
    }
    assert result["checks"]["execution_binding"] == {
        "state": "NOT_RUN",
        "reason": "trusted_absolute_exec_unobserved",
    }
    assert result["configuration"] == result["status"] == "BLOCKED"
    assert not result["launch_allowed"]


def test_worker01_observation_is_a_pin_not_personal_or_runtime_authority():
    lock = json.loads((ROOT / "provisioning/codex-release-lock.json").read_text())
    pin = next(p for p in lock["releases"] if p["version"] == "0.166.0")
    digest = "b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8"
    assert pin["binary_sha256"] == digest
    assert load().MANAGED_BASE + "/versions/" + pin[
        "version"
    ] + "-" + digest + "/codex" == (
        "/opt/agent-platform-codex/versions/0.166.0-" + digest + "/codex"
    )
    # The synthetic personal-present case above remains blocked without a trusted
    # exec binding. Neither this committed pin nor Issue prose is host evidence.


@pytest.mark.parametrize("uid", [0, 1001])
def test_caller_name_shadowing_remains_blocked_even_with_verified_candidate(
    managed, monkeypatch, uid
):
    n = managed
    n.observer.codex()
    n.observer.managed_executable()
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    monkeypatch.setenv("PATH", "/home/agentdev/.local/bin:/usr/local/bin:/usr/bin")
    monkeypatch.setattr(
        n.doctor.Observer, "exists_name", staticmethod(lambda path: True)
    )
    with pytest.raises(n.doctor.Blocked, match="path_shadowing"):
        n.observer.caller_path()
    assert n.observer._managed_identity is not None  # Separate observation scopes.


@pytest.mark.parametrize(
    "attribute,reason",
    [
        ("security.capability", "codex_verification_failed"),
        ("system.posix_acl_access", "codex_verification_failed"),
        ("system.nfs4_acl", "unsafe_attributes"),
    ],
)
def test_candidate_attributes_never_create_exec_authority(
    managed, monkeypatch, attribute, reason
):
    n = managed
    n.observer.codex()
    path = Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"]) / "codex"
    inode = path.stat().st_ino
    original = os.listxattr
    monkeypatch.setattr(
        os,
        "listxattr",
        lambda fd: [attribute] if os.fstat(fd).st_ino == inode else original(fd),
    )
    with pytest.raises(n.doctor.Blocked, match=reason):
        n.observer.managed_executable()
    assert n.observer._codex_identity is None


def test_permission_denial_is_not_a_candidate_or_binding_proof(managed, monkeypatch):
    n = managed

    def denied(*_):
        raise PermissionError("SECRET")

    monkeypatch.setattr(n.doctor, "absolute_codex_candidate", denied)
    observed = GoodObservations()
    observed.codex, observed.managed_executable = (
        n.observer.codex,
        n.observer.managed_executable,
    )
    report = n.doctor.report(observed)
    assert report["checks"]["managed_executable"] == {
        "state": "NOT_RUN",
        "reason": "observation_denied",
    }
    assert report["checks"]["execution_binding"]["state"] == "NOT_RUN"
    assert report["configuration"] == "BLOCKED" and not report["launch_allowed"]
    assert "SECRET" not in json.dumps(report)


def test_install_record_nfs4_acl_is_not_selection_evidence(managed, monkeypatch):
    n = managed
    n.observer.codex()
    path = Path(n.m.BASE) / "versions" / n.m.key(n.pins["1.0.0"]) / "record.json"
    inode = path.stat().st_ino
    original = os.listxattr
    monkeypatch.setattr(
        os,
        "listxattr",
        lambda fd: (
            ["system.nfs4_acl"] if os.fstat(fd).st_ino == inode else original(fd)
        ),
    )
    with pytest.raises(n.doctor.Blocked, match="unsafe_attributes"):
        n.observer.managed_executable()
    assert n.observer._codex_identity is None
