"""Account policy and transaction tests use explicit symbolic ownership models.

Real multi-UID ownership/lifecycle belongs to the disposable Docker testbed;
no test here calls useradd, chown or account tools on the development host.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModelSystem:
    def __init__(self):
        self.snapshot = {"users": [], "groups": []}
        self.mutations = []
        self.busy = False
        self.busy_uids = set()
        self.checked_uids = []
        self.payload_bad = False

    def accounts(self):
        return copy.deepcopy(self.snapshot)

    def payload(self):
        if self.payload_bad:
            raise self.module.Blocked("installed_payload_changed")

    def quiescent(self, accounts):
        uids = {a["uid"] for a in accounts.values()}
        self.checked_uids.append(uids)
        if self.busy_uids & uids:
            raise self.module.Blocked("principal_has_processes")
        if self.busy:
            raise self.module.Blocked("unit_not_quiescent")

    def new_account(self, name, uid=None, gid=None):
        self.mutations.append(name)
        number = 0 if name == "ap-publisher" else 1
        self.snapshot["users"].append(
            {
                "name": name,
                "uid": 999 - number if uid is None else uid,
                "gid": 989 - number if gid is None else gid,
                "home": "/var/lib/" + name,
                "shell": "/usr/sbin/nologin",
            }
        )
        self.snapshot["groups"].append(
            {"name": name, "gid": 989 - number if gid is None else gid, "members": []}
        )

    def acl(self, path, ids, create_acl=False):
        assert ids == [999, 998]
        if create_acl:
            self.mutations.append("new-config-acl")


@pytest.fixture
def model(tmp_path, monkeypatch):
    m = load("worker_provision", "packaging/worker-provisioning/provision.py")
    system = ModelSystem()
    system.module = m
    parents = {"/var/lib": tmp_path / "var-lib", "/etc": tmp_path / "etc"}
    for p in parents.values():
        p.mkdir()
        p.chmod(0o755)
    monkeypatch.setattr(m, "ROOT", os.getuid())

    @contextlib.contextmanager
    def mapped_directory(path):
        assert path in parents
        fd = os.open(parents[path], os.O_RDONLY | os.O_DIRECTORY | m.FLAGS)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(m, "directory", mapped_directory)
    raw_metadata = m.metadata

    def symbolic_metadata(fd, uid, gid, mode, directory=False, acl=False):
        # Explicit unit-only mapping, NOT a kernel ownership/isolation PASS.
        value = raw_metadata(fd, os.getuid(), os.getgid(), mode, directory, acl)
        value.update(uid=uid, gid=gid)
        return value

    monkeypatch.setattr(m, "metadata", symbolic_metadata)
    monkeypatch.setattr(m.os, "fchown", lambda *args: None)
    return m, system, parents, tmp_path


def files(root):
    return {
        str(p.relative_to(root)): (
            p.lstat().st_mode,
            os.readlink(p)
            if p.is_symlink()
            else p.read_bytes()
            if p.is_file()
            else None,
        )
        for p in root.rglob("*")
    }


def seed(model):
    m, system, parents, _ = model
    for role in m.ROLES:
        system.new_account(role)
        path = parents["/var/lib"] / role
        path.mkdir()
        path.chmod(0o700)
        (path / "journal").write_bytes(b"UNKNOWN retained history\n")
        (path / "journal").chmod(0o600)
        (path / "anchor").write_bytes(b"independent retained evidence\n")
        (path / "anchor").chmod(0o600)
    config = parents["/etc"] / "ap-publisher"
    config.mkdir()
    config.chmod(0o750)
    (config / "operator-note").write_text("retain\n")
    system.mutations.clear()


def test_explicit_initialization_and_idempotent_new_provisioning(model):
    m, system, _, root = model
    before = files(root)
    with pytest.raises(m.Blocked, match="explicit_initialization_required"):
        m.provision(system)
    assert files(root) == before and not system.mutations
    assert m.provision(system, initialize=True)["status"] == "PROVISIONED_NOT_ACTIVATED"
    after = files(root)
    mutations = list(system.mutations)
    assert m.provision(system)["status"] == "VERIFIED_NOT_ACTIVATED"
    assert files(root) == after and system.mutations == mutations


def test_existing_999_989_no_uid_change_chown_or_history_reset(model):
    m, system, parents, _ = model
    seed(model)
    old = system.accounts()
    journals = {r: (parents["/var/lib"] / r / "journal").read_bytes() for r in m.ROLES}
    m.provision(system)
    assert system.accounts() == old and not system.mutations
    assert all(
        (parents["/var/lib"] / r / "journal").read_bytes() == journals[r]
        for r in m.ROLES
    )


@pytest.mark.parametrize(
    "defect",
    [
        "uid",
        "gid-alias",
        "member",
        "supplementary",
        "home",
        "shell",
        "shared-primary",
        "partial",
    ],
)
def test_account_conflicts_refuse_before_writes(model, defect):
    m, system, _, root = model
    seed(model)
    if defect == "uid":
        system.snapshot["users"].append(
            {**system.snapshot["users"][0], "name": "foreign"}
        )
    if defect == "gid-alias":
        system.snapshot["groups"].append(
            {**system.snapshot["groups"][0], "name": "foreign"}
        )
    if defect == "member":
        system.snapshot["groups"][0]["members"] = ["agentdev"]
    if defect == "supplementary":
        system.snapshot["groups"].append(
            {"name": "other", "gid": 300, "members": ["ap-publisher"]}
        )
    if defect == "home":
        system.snapshot["users"][0]["home"] = "/home/agentdev"
    if defect == "shell":
        system.snapshot["users"][0]["shell"] = "/bin/bash"
    if defect == "shared-primary":
        system.snapshot["users"].append(
            {**system.snapshot["users"][0], "name": "foreign", "uid": 50}
        )
    if defect == "partial":
        system.snapshot["users"].pop(0)
    before = files(root)
    with pytest.raises(m.Blocked):
        m.provision(system, initialize=True)
    assert files(root) == before and not system.mutations


@pytest.mark.parametrize(
    "defect",
    [
        "mode",
        "hardlink",
        "symlink",
        "missing-journal",
        "extra-unsafe",
        "stage",
        "busy",
        "payload",
    ],
)
def test_filesystem_or_activation_conflicts_never_repair(model, defect):
    m, system, parents, root = model
    seed(model)
    path = parents["/var/lib"] / "ap-publisher"
    if defect == "mode":
        (path / "journal").chmod(0o666)
    if defect == "hardlink":
        os.link(path / "journal", root / "alias")
    if defect == "symlink":
        (path / "journal").unlink()
        (path / "journal").symlink_to(root / "foreign")
    if defect == "missing-journal":
        (path / "journal").unlink()
    if defect == "extra-unsafe":
        (path / "unknown").write_text("foreign")
        (path / "unknown").chmod(0o644)
    if defect == "stage":
        (parents["/var/lib"] / ".ap-pkg-stage-ap-publisher").mkdir()
    if defect == "busy":
        system.busy = True
    if defect == "payload":
        system.payload_bad = True
    before = files(root)
    with pytest.raises((m.Blocked, OSError)):
        m.provision(system, initialize=True)
    assert files(root) == before and not system.mutations


@pytest.mark.parametrize("phase", ["intent", "account", "state_staged", "receipt"])
def test_interruption_and_complete_only_recovery(model, monkeypatch, phase):
    m, system, _, root = model

    def fail(actual):
        if actual == phase:
            raise OSError("fabricated interruption")

    monkeypatch.setattr(m, "checkpoint", fail)
    with pytest.raises(OSError):
        m.provision(system, initialize=True)
    monkeypatch.setattr(m, "checkpoint", lambda _: None)
    before = files(root)
    mutations = list(system.mutations)
    with pytest.raises(m.Blocked):
        m.provision(system, initialize=True)
    assert files(root) == before and system.mutations == mutations
    if phase == "receipt":
        assert m.provision(system, recover=True)["status"] == "VERIFIED_NOT_ACTIVATED"
    else:
        with pytest.raises(m.Blocked):
            m.provision(system, recover=True)
        assert files(root) == before and system.mutations == mutations


def test_real_owner_check_is_not_symbolic_outside_model(tmp_path):
    m = load("ownership_provision", "packaging/worker-provisioning/provision.py")
    path = tmp_path / "file"
    path.write_text("fixture")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(m.Blocked):
            m.metadata(fd, os.getuid() + 1, os.getgid(), 0o600)
    finally:
        os.close(fd)


def test_p1_archives_exact_payload_no_activation_and_repeatability(tmp_path):
    b = load("p1_builder", "packaging/build_deb.py")
    one = b.build(ROOT, tmp_path / "one", 5, "a" * 40, 1700000000)
    two = b.build(ROOT, tmp_path / "two", 5, "a" * 40, 1700000000)
    next_ = b.build(ROOT, tmp_path / "next", 6, "a" * 40, 1700000000)
    for role in ("worker", "control"):
        assert one[role].read_bytes() == two[role].read_bytes()
        assert one[role].read_bytes() != next_[role].read_bytes()
    package = one["worker"]
    fields = subprocess.check_output(["dpkg-deb", "-f", str(package)], text=True)
    assert (
        "Depends: " + b.P1_DEPENDENCIES in fields
        and "agent-platform-codex" not in fields
    )
    with tarfile.open(
        fileobj=io.BytesIO(
            subprocess.check_output(["dpkg-deb", "--ctrl-tarfile", str(package)])
        )
    ) as tar:
        names = {m.name.removeprefix("./") for m in tar if m.isfile()}
        assert names == {"control", "conffiles", "md5sums", "preinst"}
        preinst = tar.extractfile("./preinst").read()
        assert b"@OWNED_PATHS@" not in preinst
        assert all(
            word not in preinst
            for word in [
                b"systemctl start",
                b"useradd",
                b"groupadd",
                b"codex install",
                b"curl",
            ]
        )
        conffiles = tar.extractfile("./conffiles").read().decode().splitlines()
        assert conffiles == [
            "/etc/agent-platform-worker/package.conf",
            "/etc/apparmor.d/ap-worker-publisher",
            "/etc/apparmor.d/ap-worker-publisher-signer",
        ]
    with tarfile.open(
        fileobj=io.BytesIO(
            subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
        )
    ) as tar:
        files_ = {
            m.name.removeprefix("./"): tar.extractfile(m).read()
            for m in tar
            if m.isfile()
        }
        manifest = json.loads(
            files_["usr/share/doc/agent-platform-worker/manifest.json"]
        )
        assert {x["path"].lstrip("/") for x in manifest["files"]} == files_.keys()
        assert not any(
            "sysusers.d" in x or "tmpfiles.d" in x or "worker.pem" in x for x in files_
        )
        for name in b.PUBLISHER_MODULES:
            assert (
                files_["usr/lib/ap-worker-publisher/agent_platform/" + name + ".py"]
                == (ROOT / "src/agent_platform" / f"{name}.py").read_bytes()
            )
        assert files_["usr/lib/ap-worker-publisher/agent_platform/__init__.py"] == b""
        assert (
            files_["usr/lib/agent-platform-worker/provisioning/codex_upstream.py"]
            == (ROOT / "provisioning/codex_upstream.py").read_bytes()
        )
        for name in ["ap-worker-publisher", "ap-worker-publisher-signer"]:
            assert (
                files_["usr/lib/systemd/system/" + name + ".service"]
                == (
                    ROOT / "packaging/worker-publisher" / f"{name}.service"
                ).read_bytes()
            )
            assert (
                b"\n[Install]"
                not in files_["usr/lib/systemd/system/" + name + ".service"]
            )
        assert not any(
            "/app_signer" in x or "/custody_journal" in x or "/cli.py" in x
            for x in files_
        )
        for item in manifest["files"]:
            if item["sha256"]:
                assert (
                    hashlib.sha256(files_[item["path"].lstrip("/")]).hexdigest()
                    == item["sha256"]
                )


def test_orphan_primary_group_ids_are_not_reallocated(model):
    m, system, _, _ = model
    system.snapshot["users"].append(
        {
            "name": "foreign",
            "uid": 12,
            "gid": 999,
            "home": "/nonexistent",
            "shell": "/usr/sbin/nologin",
        }
    )
    m.provision(system, initialize=True)
    assert m.identities(system.accounts())["ap-publisher"]["gid"] != 999


def test_no_implicit_ledger_adoption_or_unknown_receipt_recovery(model):
    m, system, parents, root = model
    ledger = parents["/var/lib"] / "agent-platform-worker-provisioning"
    ledger.mkdir()
    ledger.chmod(0o700)
    before = files(root)
    with pytest.raises(m.Blocked, match="unknown_ledger"):
        m.provision(system, initialize=True)
    assert files(root) == before and not system.mutations


@pytest.mark.parametrize("command", ["run", "resume", "doctor"])
def test_p1_cli_preserves_pre_io_quarantine(command, monkeypatch, capsys):
    cli = load("p1_cli", "packaging/worker-provisioning/worker_cli.py")
    monkeypatch.setattr("sys.argv", ["agent-platform-worker", command, "--issue", "1"])
    monkeypatch.setattr(cli.os, "execv", lambda *_: pytest.fail("execution"))
    monkeypatch.setattr(cli.os, "geteuid", lambda: pytest.fail("identity inspection"))
    assert cli.main() == 13
    assert json.loads(capsys.readouterr().out)["launch_allowed"] is False


def test_p1_cli_codex_is_explicit_fixed_path_dispatch(monkeypatch):
    cli = load("p1_codex_cli", "packaging/worker-provisioning/worker_cli.py")
    monkeypatch.setattr(
        "sys.argv",
        [
            "agent-platform-worker",
            "codex",
            "install",
            "--version",
            "0.166.0",
            "--archive",
            "/fixture/data.tar.gz",
            "--approve",
            "--operator-path",
            "/usr/local/bin:/usr/bin",
        ],
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    seen = []

    def execv(path, argv):
        seen.append((path, argv))
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execv", execv)
    with pytest.raises(SystemExit):
        cli.main()
    assert seen[0][0] == "/usr/bin/python3"
    assert seen[0][1][1:4] == [
        "-IB",
        "/usr/lib/agent-platform-worker/provisioning/codex_upstream.py",
        "install",
    ]
    assert "--approve" in seen[0][1] and "--archive" in seen[0][1]


def test_p1_preinst_template_has_no_configure_or_remove_activation():
    text = (ROOT / "packaging/worker-provisioning/preinst").read_text()
    assert "systemctl show --property=ActiveState" in text
    assert not any(
        "systemctl " + verb in text
        for verb in ["start", "restart", "enable", "stop", "daemon-reload"]
    )
    assert "@CLOSED_ROOT_ENTRIES@" in text


def test_empty_existing_service_directory_requires_explicit_new_store_attestation(
    model,
):
    m, system, parents, root = model
    seed(model)
    for role in m.ROLES:
        (parents["/var/lib"] / role / "journal").unlink()
        (parents["/var/lib"] / role / "anchor").unlink()
    before = files(root)
    with pytest.raises(m.Blocked, match="explicit_initialization_required"):
        m.provision(system)
    assert files(root) == before
    assert m.provision(system, initialize=True)["status"] == "PROVISIONED_NOT_ACTIVATED"
    assert not system.mutations
    assert all(
        (parents["/var/lib"] / r / "journal").read_bytes() == b"" for r in m.ROLES
    )


def test_recovery_binds_exact_completed_intent(model, monkeypatch):
    m, system, parents, root = model

    def interrupt(phase):
        if phase == "receipt":
            raise OSError("fabricated interruption")

    monkeypatch.setattr(m, "checkpoint", interrupt)
    with pytest.raises(OSError):
        m.provision(system, initialize=True)
    intent = parents["/var/lib"] / "agent-platform-worker-provisioning/intent.json"
    data = json.loads(intent.read_bytes())
    data["initialize"] = False
    intent.write_bytes(m.encoded(data))
    before = files(root)
    with pytest.raises(m.Blocked, match="unknown_intent"):
        m.provision(system, recover=True)
    assert files(root) == before


@pytest.mark.parametrize("value", [[], None, True, "fixture", 1])
def test_non_object_ledger_is_bounded_blocked(value):
    m = load("non_object_ledger", "packaging/worker-provisioning/provision.py")
    with pytest.raises(m.Blocked, match="invalid_state"):
        m.parse(m.encoded(value))


@pytest.mark.parametrize("extra", [None, "file", "directory", "link"])
def test_closed_private_code_inventory_rejects_unknown_entries(
    tmp_path, monkeypatch, extra
):
    m = load("closed_private_code", "packaging/worker-provisioning/provision.py")
    (tmp_path / "safe.py").write_bytes(b"fixture")
    if extra == "file":
        (tmp_path / "foreign.py").write_bytes(b"foreign")
    elif extra == "directory":
        (tmp_path / "__pycache__").mkdir()
    elif extra == "link":
        (tmp_path / "alias").symlink_to(tmp_path / "safe.py")

    @contextlib.contextmanager
    def directory(path):
        assert path == "/fixture"
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(m, "directory", directory)
    if extra is None:
        m.closed_tree("/fixture", ["/fixture/safe.py"])
    else:
        with pytest.raises(m.Blocked, match="unknown_installed_code"):
            m.closed_tree("/fixture", ["/fixture/safe.py"])


@pytest.mark.parametrize("busy_uid", [999, 998])
def test_orphan_process_on_planned_uid_blocks_before_any_write(model, busy_uid):
    m, system, parents, root = model
    assert not system.snapshot["users"]  # Orphan process has no NSS identity.
    system.busy_uids.add(busy_uid)
    before = files(root)
    with pytest.raises(m.Blocked, match="principal_has_processes"):
        m.provision(system, initialize=True)
    assert files(root) == before
    assert not (parents["/var/lib"] / "agent-platform-worker-provisioning").exists()
    assert not system.mutations  # No group/user creation or configuration ACL.
    assert not system.snapshot["users"] and not system.snapshot["groups"]
    assert system.checked_uids[-1] == {999, 998}


def test_account_creation_retains_post_creation_process_check(model):
    m, system, _, _ = model
    assert m.provision(system, initialize=True)["status"] == "PROVISIONED_NOT_ACTIVATED"
    assert system.checked_uids[-2:] == [{999, 998}, {999, 998}]


@pytest.mark.parametrize("defect", [None, "acl", "pending", "receipt", "journal-mode"])
def test_pkg05_reads_only_receipt_and_metadata_not_protected_history(
    model, monkeypatch, defect
):
    from types import SimpleNamespace

    m, system, parents, _ = model
    seed(model)
    m.provision(system)
    d = load("pkg05_state", "packaging/worker-provisioning/worker_doctor.py")
    observer = d.Observer()
    observer.accounts = m.identities(system.accounts())
    ledger = parents["/var/lib"] / "agent-platform-worker-provisioning"
    receipt = ledger / "receipt.json"
    value = json.loads(receipt.read_bytes())
    # Symbolic unit ownership only, as in PKG-04 model: no host chown or UID proof.
    value["paths"]["/etc/ap-publisher"].update(uid=0, gid=0)
    if defect == "receipt":
        value["paths"]["/var/lib/ap-publisher"]["inode"] += 1
    receipt.write_bytes(m.encoded(value))
    if defect == "pending":
        (ledger / "intent.json").write_text("unknown retained intent")
    if defect == "journal-mode":
        (parents["/var/lib"] / "ap-publisher/journal").chmod(0o644)
    before = files(model[3])

    @contextlib.contextmanager
    def mapped(path):
        assert path in (
            "/var/lib",
            "/etc",
            "/var/lib/agent-platform-worker-provisioning",
        )
        actual = ledger if path.endswith("provisioning") else parents[path]
        fd = os.open(actual, os.O_RDONLY | os.O_DIRECTORY | d.FLAGS)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(d, "directory", mapped)
    raw_meta = d.meta

    def symbolic(fd, uid=0, gid=0, **kwargs):
        value = raw_meta(fd, os.getuid(), os.getgid(), **kwargs)
        fields = {
            key: getattr(value, key)
            for key in (
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
        }
        fields.update(st_uid=uid, st_gid=gid)
        return SimpleNamespace(**fields)

    monkeypatch.setattr(d, "meta", symbolic)

    def receipt_only(path, limit=262144, mode=0o644):
        assert path == "/var/lib/agent-platform-worker-provisioning/receipt.json"
        with mapped("/var/lib/agent-platform-worker-provisioning") as fd:
            return m.read(fd, "receipt.json", limit, mode)

    monkeypatch.setattr(d, "read", receipt_only)
    acl = "user::rwx\nuser:999:r-x\nuser:998:r-x\ngroup::r-x\nmask::r-x\nother::---\n"
    monkeypatch.setattr(
        d, "query", lambda _: "user::rwx\nother::rwx\n" if defect == "acl" else acl
    )
    journal_inodes = {
        (parents["/var/lib"] / r / "journal").stat().st_ino for r in m.ROLES
    }
    original_read = os.read

    def no_history(fd, size):
        assert os.fstat(fd).st_ino not in journal_inodes, "protected history read"
        return original_read(fd, size)

    monkeypatch.setattr(os, "read", no_history)
    if defect is None:
        assert observer.state() == ("CONFIGURED", "verified_state_metadata")
    else:
        with pytest.raises(d.Blocked):
            observer.state()
    assert files(model[3]) == before
