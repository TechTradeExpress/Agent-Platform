"""Offline fixtures only: no production units, credentials or public network."""

import errno
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load():
    spec = importlib.util.spec_from_file_location(
        "isolation_readiness",
        ROOT / "packaging/worker-publisher/isolation_readiness.py",
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def attempt(m, error=None):
    def connect():
        if error is not None:
            raise error

    return m.tcp_attempt(connect)


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("PRIVATE"),
        PermissionError(errno.EACCES, "PRIVATE"),
        OSError(errno.EPERM, "PRIVATE"),
    ],
)
def test_expected_denial_requires_both_positive_control_and_no_server_receipt(error):
    m = load()
    allow, deny = attempt(m), attempt(m, error)
    result = m.network_result(allow, deny, allow_received=True, deny_received=False)
    assert result["status"] == "PASS" and result["production_bpf"] == "NOT_RUN"
    assert result["launch_allowed"] is False and "PRIVATE" not in str(result)
    if isinstance(error, TimeoutError):
        assert deny["type"] == "TimeoutError" and deny["errno"] is None
    assert (
        m.network_result(allow, deny, allow_received=False, deny_received=False)[
            "status"
        ]
        == "UNKNOWN"
    )
    assert (
        m.network_result(allow, deny, allow_received=True, deny_received=None)["status"]
        == "UNKNOWN"
    )
    assert (
        m.network_result(allow, deny, allow_received=True, deny_received=True)["status"]
        == "FAIL"
    )


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError(errno.ECONNREFUSED, "PRIVATE"),
        OSError(errno.ENETUNREACH, "PRIVATE"),
        OSError("PRIVATE"),
        ValueError("PRIVATE"),
    ],
)
def test_unexpected_failures_never_become_denial_pass(error):
    m = load()
    result = m.network_result(
        attempt(m), attempt(m, error), allow_received=True, deny_received=False
    )
    assert result["status"] == "FAIL" and "PRIVATE" not in str(result)


def test_deny_connection_is_failure_even_without_a_server_receipt():
    m = load()
    assert (
        m.network_result(
            attempt(m), attempt(m), allow_received=True, deny_received=False
        )["status"]
        == "FAIL"
    )


def test_unit_ordering_is_not_activation_or_automatic_cleanup():
    root = ROOT / "packaging/worker-publisher"
    publisher = (root / "ap-worker-publisher.service").read_text()
    signer = (root / "ap-worker-publisher-signer.service").read_text()
    assert "After=network-online.target ap-worker-publisher-signer.service" in publisher
    assert "LoadCredential=app-jwt:/run/ap-publisher-signer/app-jwt" in publisher
    assert "RuntimeDirectoryPreserve=yes" in signer
    for text in [publisher, signer]:
        assert all(
            x
            not in "\n".join(
                line for line in text.splitlines() if not line.lstrip().startswith("#")
            )
            for x in [
                "Requires=",
                "Wants=",
                "[Install]",
                "ExecStartPre=",
                "ExecStopPost=",
            ]
        )
        assert "Restart=no" in text


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_exact_credential_namespace(role, monkeypatch):
    from agent_platform.worker_publish_artifact import Blocked
    from agent_platform.worker_publish_io import credential_path

    unit = "ap-worker-publisher" + ("-signer" if role == "signer" else "")
    root = "/run/credentials/" + unit + ".service"
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", root)
    assert credential_path(role) == root + (
        "/app-key" if role == "signer" else "/app-jwt"
    )
    for wrong in ["", root + "/", root + "/../other", "/tmp/PRIVATE"]:
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", wrong)
        with pytest.raises(Blocked):
            credential_path(role)


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", "PRIVATE"),
        ("outcome", "PRIVATE"),
        ("errno", True),
        ("errno", 99999),
        ("stage", "PRIVATE"),
    ],
)
def test_probe_records_are_closed_before_reporting(field, value):
    m = load()
    bad = attempt(m, TimeoutError())
    bad[field] = value
    with pytest.raises(ValueError, match="^invalid_probe_record$"):
        m.network_result(attempt(m), bad, allow_received=True, deny_received=False)


def test_fixture_primitive_is_source_only_not_a_worker_payload(tmp_path):
    import io
    import subprocess
    import tarfile

    spec = importlib.util.spec_from_file_location(
        "builder128", ROOT / "packaging/build_deb.py"
    )
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    packages = builder.build(ROOT, tmp_path / "packages", 6, "f" * 40, 1700000000)
    for package in packages.values():
        data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(package)])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            names = {item.name for item in archive}
            assert not any("isolation_readiness" in name for name in names)
            if package == packages["worker"]:
                assert (
                    "./usr/share/doc/agent-platform-worker/publisher-isolation-readiness.md"
                    in names
                )
