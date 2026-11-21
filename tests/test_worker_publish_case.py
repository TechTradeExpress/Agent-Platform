"""Create-only case custody failures against disposable files only."""

import os
from types import SimpleNamespace

import pytest
from test_worker_publish_reconciliation import case as evidence_case  # noqa: F401

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_case as case
from agent_platform import worker_publish_operator as operator


@pytest.fixture
def store(tmp_path, monkeypatch):
    class Filesystem:
        def __getattr__(self, name):
            return getattr(os, name)

        def metadata(self, info):
            names = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            return SimpleNamespace(
                st_uid=0, st_gid=0, **{k: getattr(info, k) for k in names}
            )

        def fstat(self, fd):
            return self.metadata(os.fstat(fd))

        def stat(self, *args, **kwargs):
            return self.metadata(os.stat(*args, **kwargs))

    fs = Filesystem()
    monkeypatch.setattr(case, "os", fs)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield fs, directory, tmp_path
    finally:
        os.close(directory)


@pytest.fixture
def inputs(store, evidence_case, monkeypatch):  # noqa: F811
    _, fd, path = store
    args = evidence_case.args()
    monkeypatch.setattr(case, "OBJECT", args["object_id"])
    for filename, key in (
        ("proposed-job.json", "proposed_job"),
        ("proposed-candidate.json", "proposed_artifact"),
        ("evidence.json", "evidence"),
        ("decision.json", "decision"),
    ):
        leaf = path / filename
        leaf.write_bytes(args[key])
        leaf.chmod(0o600)
    return case._inputs(fd, evidence_case.snapshot, args["pins"], args["now"])


def test_record_requires_separate_exact_confirmation(store, inputs):
    _, fd, path = store
    pin = case._record(fd, *inputs)
    before = {p.name: p.read_bytes() for p in path.iterdir()}
    with pytest.raises(art.Blocked):
        case._confirm(fd, *inputs, "0" * 64)
    other = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        case._confirm(other, *inputs, pin)
        with pytest.raises(art.Blocked):
            case._record(other, *inputs)
    finally:
        os.close(other)
    assert before == {p.name: p.read_bytes() for p in path.iterdir()}
    assert art.decode(before[case.RESOLUTION])["admission_allowed"] is False


@pytest.mark.parametrize("boundary", range(1, 21))
def test_uncertain_fsync_never_retries_or_repairs(store, inputs, monkeypatch, boundary):
    fs, fd, path = store
    attempts = 0

    def fail(descriptor):
        nonlocal attempts
        attempts += 1
        if attempts == boundary:
            raise OSError("synthetic lost fsync")
        os.fsync(descriptor)

    monkeypatch.setattr(fs, "fsync", fail)
    with pytest.raises(OSError):
        case._record(fd, *inputs)
    assert (path / case.INTENT).exists()
    before = {p.name: p.read_bytes() for p in path.iterdir()}
    with pytest.raises(art.Blocked):
        case._confirm(fd, *inputs, None)
    with pytest.raises(art.Blocked):
        case._record(fd, *inputs)
    assert before == {p.name: p.read_bytes() for p in path.iterdir()}


@pytest.mark.parametrize("fault", ["changed", "symlink", "hardlink", "mode", "missing"])
def test_confirmation_requires_original_archive_bytes_and_metadata(
    store, inputs, fault
):
    _, fd, path = store
    pin = case._record(fd, *inputs)
    leaf = path / "original-publisher.jsonl"
    if fault == "changed":
        leaf.write_bytes(b"changed")
    elif fault == "mode":
        leaf.chmod(0o644)
    elif fault == "missing":
        leaf.unlink()
    else:
        other = path / "copied"
        leaf.rename(other)
        if fault == "symlink":
            leaf.symlink_to(other)
        else:
            os.link(other, leaf)
    with pytest.raises((art.Blocked, OSError)):
        case._confirm(fd, *inputs, pin)


def test_nonroot_cli_stops_before_host_reads(monkeypatch, capsys):
    monkeypatch.setattr(case.os, "getuid", lambda: 1001)
    monkeypatch.setattr(
        operator, "exclusive_config", lambda: pytest.fail("config lock attempted")
    )
    assert (
        operator.main(["reconcile-v4", "inspect", "--snapshot-sha256", "a" * 64]) == 1
    )
    report = art.decode(capsys.readouterr().out.encode())
    assert report["status"] == "STOP" and report["check"] == "root_required"
    assert report["admission_allowed"] is report["publish_allowed"] is False


@pytest.mark.parametrize("fault", ["none", "queued", "mode", "wrong_exit"])
def test_frozen_host_checks_only_metadata(monkeypatch, fault):
    def show(*args):
        unit = args[-1]
        publisher = unit == operator.unit("publisher")
        result = {
            "ActiveState": "failed" if publisher else "inactive",
            "SubState": "failed" if publisher else "dead",
            "Result": "exit-code" if publisher else "success",
            "ExecMainStatus": "1" if publisher else "0",
            "Job": "42" if fault == "queued" else "",
            "IPAddressAllow": "140.82.112.6/32" if publisher else "",
        }
        if fault == "wrong_exit":
            result["ExecMainStatus"] = "233"
        return "\n".join(f"{key}={value}" for key, value in result.items())

    class MetadataOnly:
        class path:
            @staticmethod
            def lexists(name):
                assert name == operator.PENDING
                return False

        @staticmethod
        def lstat(name):
            assert name == operator.SIGNER_OUTPUT
            return SimpleNamespace(
                st_mode=0o100644 if fault == "mode" else 0o100400,
                st_nlink=1,
                st_uid=1001,
                st_size=512,
            )

    monkeypatch.setattr(case, "os", MetadataOnly)
    monkeypatch.setattr(operator, "systemctl", show)
    job = {"github_ipv4": "140.82.112.6", "signer_uid": 1001}
    if fault == "none":
        case._frozen_host(operator, job)
    else:
        with pytest.raises(art.Blocked):
            case._frozen_host(operator, job)
