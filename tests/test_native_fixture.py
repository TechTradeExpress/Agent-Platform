"""Offline evidence correlation and inert fixture audits; never kernel evidence."""

import hashlib
import io
import json
import os
import subprocess
from pathlib import Path

import pytest
from test_native_canary import runtime as runtime

from agent_platform import isolation, state
from agent_platform import native_canary as canary

BUNDLE = Path(__file__).resolve().parents[1] / "docs/fixtures/native-canary-v1"


def load(name):
    return json.loads((BUNDLE / name).read_bytes())


def test_saved_operator_report_has_negative_verdict_and_source_correlation():
    measured = load("sandbox01-report.json")
    provenance = load("sandbox01-provenance.json")
    assert (
        provenance["report_file_sha256"]
        == hashlib.sha256((BUNDLE / "sandbox01-report.json").read_bytes()).hexdigest()
    )
    assert provenance["comment_id"] == 6589316861
    assert provenance["provenance"] == "operator_reported_remote_snapshot"
    assert provenance["independent_artifact_audit"] == "NOT_RUN"
    assert provenance["reported_exit_code"] == 13
    for key in (
        "kernel_run_performed_by_this_pr",
        "raw_vm_report_supplied",
        "experiment_scripts_supplied",
        "runtime_manifest_supplied",
    ):
        assert provenance[key] is False
    assert set(measured) == set(canary.report()) | {
        "fixture_id",
        "probe_sha256",
        "runtime_sha256",
    }
    assert (
        measured["probe_sha256"]
        == hashlib.sha256(canary.PROBE.read_bytes()).hexdigest()
    )
    assert measured["evidence"] == "REAL_KERNEL_SYNTHETIC"
    assert measured["status"] == "BLOCKED"
    assert measured["reason"] == "same_domain_credential_exposure"
    assert measured["launch_allowed"] is False
    assert measured["authentication"] == "AUTH_E2E_NOT_RUN"
    assert measured["codex_internal_routes"] == "UNKNOWN"
    assert measured["host_containment"] == measured["worker_codex_home"] == "PASS"
    assert measured["same_domain_codex_home"] == "FAIL"
    for mode, exposed in (("worker", False), ("same-domain", True)):
        checks = measured["checks"][mode]
        assert canary._parse(json.dumps(checks).encode()) == checks
        assert checks["home_readable"] is exposed
        assert all(v is True for k, v in checks.items() if k != "home_readable")
    assert measured["artifact_admission"] == canary.report()["artifact_admission"]
    artifact = measured["artifact_admission"]
    assert artifact["status"] == "BLOCKED"
    assert artifact["recorded_candidate_bytes"] > artifact["unchanged_cap_bytes"]


def test_plan_cannot_promote_missing_external_artifacts_to_reproducible_build():
    plan = load("fixture-plan.json")
    assert plan["reproduction_status"] == "BLOCKED_MISSING_INPUTS"
    assert plan["required_missing_inputs"]
    assert all(v is None for v in plan["required_missing_inputs"].values())
    assert all(v is False for v in plan["authority"].values())
    reported = plan["reported_inputs"]["runtime"]
    assert (
        reported["manifest_sha256"] == load("sandbox01-report.json")["runtime_sha256"]
    )
    assert 0 < reported["files"] <= plan["limits"]["max_files"] == 512
    assert (
        reported["files"]
        <= reported["entries"]
        <= plan["limits"]["max_entries"]
        == 2048
    )
    assert reported["file_bytes"] < plan["limits"]["max_file_bytes"] == 64 * 1024 * 1024
    assert plan["vm"]["nic_count"] == 0
    # These paths are data in the review plan, never paths to inspect on dev01.
    assert reported["path"] == str(canary.RUNTIME)
    assert plan["reported_inputs"]["bubblewrap"]["binary_path"] == str(canary.BWRAP)


@pytest.mark.parametrize(
    "change", ["missing", "unknown", "integer", "string", "duplicate"]
)
def test_malformed_copied_checks_cannot_be_accepted_as_probe_output(change):
    checks = load("sandbox01-report.json")["checks"]["worker"]
    if change == "missing":
        checks.pop("fds")
    elif change == "unknown":
        checks["fake_pass"] = True
    elif change in {"integer", "string"}:
        checks["caps"] = 1 if change == "integer" else "true"
    raw = json.dumps(checks).encode()
    if change == "duplicate":
        raw = raw[:-1] + b', "caps": true}'
    with pytest.raises(canary.Blocked):
        canary._parse(raw)


@pytest.fixture
def inert_audit(runtime, monkeypatch):
    """Mock prerequisite observations only for this inert synthetic fixture."""
    original = Path.read_text
    original_open = Path.open

    def open_file(path, *args, **kwargs):
        if path == Path("/proc/self/status"):
            return io.StringIO(
                "\n".join(f"{k}:\t0" for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
            )
        return original_open(path, *args, **kwargs)

    def read_text(path, *args, **kwargs):
        if path == Path("/proc/self/mountinfo"):
            return ""
        return original(path, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("offline audit attempted a process or kernel canary")

    monkeypatch.setattr(Path, "open", open_file)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(canary, "_run", forbidden)
    return runtime


def test_inert_read_only_runtime_audit_has_no_execution_or_mutation(inert_audit):
    root, binary, manifest = inert_audit
    files = [manifest, binary, *[p for p in root.rglob("*") if p.is_file()]]
    before = {p: (p.read_bytes(), p.stat()) for p in files}
    assert canary._runtime() == hashlib.sha256(manifest.read_bytes()).hexdigest()
    for p, (data, info) in before.items():
        assert p.read_bytes() == data
        assert p.stat().st_mtime_ns == info.st_mtime_ns
        assert p.stat().st_mode == info.st_mode


@pytest.mark.parametrize(
    "change",
    [
        "internal_hardlink",
        "directory_write",
        "credential_name",
        "unknown_top",
        "bwrap_size",
        "file_count",
        "nested_mount",
        "manifest_changed",
    ],
)
def test_inert_audit_rejects_unsafe_or_unreviewed_build(
    inert_audit, monkeypatch, change
):
    root, binary, manifest = inert_audit
    if change == "internal_hardlink":
        os.link(root / "usr/bin/python3", root / "usr/bin/alias")
    elif change == "directory_write":
        (root / "usr").chmod(0o777)
    elif change == "credential_name":
        (root / "usr/bin/auth.json").write_text("fabricated only")
    elif change == "unknown_top":
        (root / "unreviewed").mkdir()
    elif change == "bwrap_size":
        binary.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    elif change == "file_count":
        data = json.loads(manifest.read_bytes())
        data["files"] = {f"usr/file-{n}": "0" * 64 for n in range(513)}
        data["files"]["usr/bin/python3"] = "0" * 64
        manifest.write_text(json.dumps(data))
    elif change == "manifest_changed":
        data = json.loads(manifest.read_bytes())
        data["bwrap_sha256"] = "f" * 64
        manifest.write_text(json.dumps(data))
    else:
        original = Path.read_text
        monkeypatch.setattr(
            Path,
            "read_text",
            lambda p, *a, **kw: (
                f"1 0 0:1 / {root / 'usr'} ro - tmpfs tmpfs ro\n"
                if p == Path("/proc/self/mountinfo")
                else original(p, *a, **kw)
            ),
        )
    with pytest.raises((canary.Blocked, isolation.IsolationError, state.PrepareError)):
        canary._runtime()
