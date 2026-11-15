"""Test-only diagnostic evidence never substitutes for real Docker observations."""

import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location("metadata_fixture", ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "defect,control",
    [
        ("owner", "OWNER"),
        ("group", "OWNER"),
        ("type", "TYPE"),
        ("links", "LINK_COUNT"),
        ("setuid", "FORBIDDEN_MODE_BITS"),
        ("write", "FORBIDDEN_MODE_BITS"),
        ("mode", "EXACT_MODE"),
        ("acl", "ATTRIBUTES"),
        ("capability", "ATTRIBUTES"),
    ],
)
def test_capture_preserves_actual_validator_and_identifies_first_control(
    monkeypatch, defect, control
):
    helper = load("packaging/debian/worker_metadata_evidence.py")
    doctor = load("packaging/worker-provisioning/worker_doctor.py")
    value = dict(
        st_uid=0,
        st_gid=0,
        st_mode=stat.S_IFREG | 0o644,
        st_nlink=1,
        st_dev=1,
        st_ino=2,
        st_size=1,
        st_mtime_ns=1,
        st_ctime_ns=1,
    )
    attrs = []
    if defect == "owner":
        value["st_uid"] = 17
    if defect == "group":
        value["st_gid"] = 6
    if defect == "type":
        value["st_mode"] = stat.S_IFIFO | 0o644
    if defect == "links":
        value["st_nlink"] = 2
    if defect == "setuid":
        value["st_mode"] |= 0o4000
    if defect == "write":
        value["st_mode"] |= 0o002
    if defect == "mode":
        value["st_mode"] = stat.S_IFREG | 0o600
    if defect == "acl":
        attrs.append("system.posix_acl_access")
    if defect == "capability":
        attrs.append("security.capability")
    monkeypatch.setattr(os, "fstat", lambda _: SimpleNamespace(**value))
    monkeypatch.setattr(os, "listxattr", lambda _: attrs)
    monkeypatch.setattr(os, "readlink", lambda _: "/usr/bin/agent-platform-worker")
    original = doctor.meta
    with pytest.raises(doctor.Blocked):
        original(23, mode=0o644)

    def package():
        original_result = doctor.meta(23, mode=0o644)
        return original_result

    monkeypatch.setattr(doctor, "Observer", lambda: SimpleNamespace(package=package))
    result = helper.capture(doctor)
    assert result["status"] == "REPRODUCED"
    assert result["failure"]["control"] == control
    assert result["failure"]["actual"]["uid"] == value["st_uid"]
    assert result["host"] == "HOST_NOT_RUN" and result["launch_allowed"] is False
    assert doctor.meta is original
    with pytest.raises(doctor.Blocked):
        original(23, mode=0o644)


def test_no_reproduction_is_not_claimed_as_failure_proof():
    helper = load("packaging/debian/worker_metadata_evidence.py")

    class Blocked(Exception):
        pass

    def original(*_):
        return None

    doctor = SimpleNamespace(
        meta=original,
        Blocked=Blocked,
        Observer=lambda: SimpleNamespace(package=lambda: None),
    )
    result = helper.capture(doctor)
    assert result["status"] == "NOT_REPRODUCED" and result["failure"] is None
    assert doctor.meta is original


@pytest.mark.parametrize(
    "path", ["/home/private/SECRET", "/usr/lib/../private", "/proc/self/environ"]
)
def test_private_or_ambiguous_names_are_not_emitted(path):
    helper = load("packaging/debian/worker_metadata_evidence.py")
    assert helper.public_name(path) == "UNRECOGNIZED"


def test_xattr_values_and_unknown_names_are_never_serialized():
    helper = load("packaging/debian/worker_metadata_evidence.py")
    value = SimpleNamespace(
        st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1, st_dev=1, st_ino=1
    )
    result = helper.metadata(value, ["user.SECRET"])
    assert "SECRET" not in json.dumps(result) and result["other_xattr_count"] == 1


@pytest.mark.parametrize("failed", ["clean", "existing", "none"])
def test_ci_attempts_both_p1_variants_and_propagates_failure(tmp_path, failed):
    workflow = (ROOT / ".github/workflows/debian-package.yml").read_text()
    section = workflow.split("      - name: Multi-UID P1", 1)[1].split(
        "      - name:", 1
    )[0]
    command = section.split("        run: |\n", 1)[1]
    command = "\n".join(
        line.removeprefix("          ") for line in command.splitlines()
    )
    fake = tmp_path / "bin"
    fake.mkdir()
    log = tmp_path / "calls"
    tool = fake / "docker"
    tool.write_text("""#!/bin/sh
case "$1" in
build) exit 0;;
run)
  for last do :; done
  case "$last" in
    *-clean) fixture_case=clean;;
    *-existing) fixture_case=existing;;
    *) exit 97;;
  esac
  printf '%s\\n' "$fixture_case" >> "$FIXTURE_LOG"
  if [ "$fixture_case" = "$FIXTURE_FAILED" ]; then exit 42; fi
  mkdir -p "$RUNNER_TEMP/ap-evidence"
  printf '{}\\n' > "$RUNNER_TEMP/ap-evidence/worker-p1-lifecycle-$fixture_case.json"
  ;;
*) exit 98;;
esac
""")
    tool.chmod(0o755)
    env = {
        "PATH": str(fake) + ":" + os.defpath,
        "RUNNER_TEMP": str(tmp_path),
        "FIXTURE_LOG": str(log),
        "FIXTURE_FAILED": failed,
    }
    result = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
        cwd=ROOT,
        env=env,
        capture_output=True,
        timeout=10,
    )
    assert log.read_text().splitlines() == ["clean", "existing"]
    assert (result.returncode == 0) == (failed == "none")
    synthetic = workflow.split("      - name: Separate synthetic Codex", 1)[1].split(
        "      - name:", 1
    )[0]
    assert "if: ${{ !cancelled() }}" in synthetic


def test_lifecycle_installed_assertion_is_not_weakened():
    source = (ROOT / "packaging/debian/worker_p1_lifecycle.py").read_text()
    assert (
        'assert diagnostic["installation"] == "INSTALLED", '
        'diagnostic["checks"]["package"]' in source
    )
    assert '"/evidence/worker-p1-metadata-" + case + ".json"' in source


def test_successful_public_ancestor_is_retained_with_failure(monkeypatch):
    helper = load("packaging/debian/worker_metadata_evidence.py")
    doctor = load("packaging/worker-provisioning/worker_doctor.py")

    def fake_stat(fd):
        return SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_nlink=2 if fd == 23 else 1,
            st_mode=(stat.S_IFDIR | 0o755) if fd == 23 else (stat.S_IFREG | 0o600),
            st_dev=1,
            st_ino=fd,
            st_size=1,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

    monkeypatch.setattr(os, "fstat", fake_stat)
    monkeypatch.setattr(os, "listxattr", lambda _: [])
    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: (
            "/usr" if path.endswith("/23") else "/usr/bin/agent-platform-worker"
        ),
    )

    def package():
        doctor.meta(23, directory=True)
        doctor.meta(24, mode=0o644)

    monkeypatch.setattr(doctor, "Observer", lambda: SimpleNamespace(package=package))
    result = helper.capture(doctor)
    assert result["failure"]["control"] == "EXACT_MODE"
    assert result["ancestors"][0]["object"] == "/usr"
    assert result["ancestors"][0]["actual"]["type"] == "directory"
