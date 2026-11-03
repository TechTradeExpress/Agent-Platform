"""Data-only no-account security classification; no VM, tools or kernel probe."""

import builtins
import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from agent_platform import codex, native_artifact, native_codex, state, subscription
from agent_platform import native_security as security

DOCS = Path(__file__).resolve().parents[1] / "docs"


def checked(probes=(), *, pin=security.PIN):
    result = security.assess(probes, pin=pin)
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    assert len(raw) <= security.MAX_REPORT_BYTES
    assert b"secret-sentinel" not in raw
    assert result["status"] == "BLOCKED"
    assert result["activation_decision"] == "NO-GO"
    assert result["security_decision"] == "NO"
    assert result["runtime_status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert result["runtime_exit_code"] == 13
    assert result["authentication"] == "AUTH_E2E_NOT_RUN"
    assert result["kernel_probes_this_assessment"] == "NOT_RUN"
    assert result["complete_mediation"] == "UNKNOWN"
    for key in (
        "launch_allowed",
        "resume_authorized",
        "publish_authorized",
        "mutations_allowed",
    ):
        assert result[key] is False
    for row in result["routes"]:
        assert row["enforced_boundary"] == "UNKNOWN"
        assert row["verified_mediated"] is False
    for row in result["synthetic_trace"]:
        assert row["evidence"] == "OFFLINE_SYNTHETIC"
        assert row["real_probe"] == "NOT_RUN"
    body = {k: v for k, v in result.items() if k != "report_sha256"}
    assert (
        result["report_sha256"]
        == hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    return result


def test_baseline_matches_versioned_record_and_original_pins():
    result = checked()
    assert result == json.loads((DOCS / "native-security-assessment.json").read_bytes())
    old = json.loads((DOCS / "tool-dispatch-evidence.json").read_bytes())
    assert security.PIN.version == codex.VERSION == native_artifact.PIN["version"]
    assert (
        security.PIN.source_commit
        == old["source"]["commit"]
        == native_artifact.PIN["source_sha"]
    )
    assert (
        security.PIN.artifact_sha256
        == old["artifact"]["sha256"]
        == native_artifact.PIN["sha256"]
    )
    assert (
        security.PIN.artifact_bytes
        == old["artifact"]["bytes"]
        == native_artifact.PIN["bytes"]
    )
    assert security.PIN.target == native_artifact.PIN["target"]
    assert (
        result["unchanged_runtime_cap_bytes"]
        == old["artifact"]["unchanged_runtime_byte_cap"]
    )
    assert result["subject"]["source_binary_equivalence"] == "UNKNOWN"
    assert result["subject"]["current_installation_inspected"] is False
    assert result["unlisted_routes"] == "UNKNOWN_BLOCKING"
    assert all(r["verdict"] == "NOT_RUN" for r in result["synthetic_trace"])


def test_operator_snapshot_cannot_be_promoted_to_independent_kernel_audit():
    result = checked()
    prior = result["prior_kernel_snapshot"]
    measured = json.loads(
        (DOCS / "fixtures/native-canary-v1/sandbox01-report.json").read_bytes()
    )
    for key in (
        "host_containment",
        "worker_codex_home",
        "same_domain_codex_home",
        "status",
        "reason",
    ):
        assert prior[key] == measured[key]
    assert prior["provenance"] == "OPERATOR_REPORTED_REMOTE_SNAPSHOT"
    assert prior["independently_reenacted"] is False
    assert prior["fixture_reproduction"] == "BLOCKED_MISSING_INPUTS"
    assert result["artifact_admission"] == measured["artifact_admission"]["status"]


def test_inventory_is_unique_and_covers_required_alternate_paths():
    result = checked()
    expected = {
        "dynamic_tools",
        "shell_exec",
        "pty",
        "write_stdin",
        "patch",
        "file_reads",
        "file_mutations",
        "mcp_connectors",
        "plugins_skills",
        "js_code_mode",
        "hooks",
        "background_children",
        "subagents",
        "hosted_tools",
        "resume_fork_replay",
        "cancellation",
        "credential_refresh_persistence",
        "implicit_config_session_reads",
        "remote_alternate_dispatch",
        "approvals_control_tools",
    }
    assert {r["route"] for r in result["routes"]} == expected
    assert len(result["routes"]) == len(expected)
    assert result["routes"][0]["external_callback_dispatch"] == "SUPPORTED_SUBSET"
    assert any(
        r["external_callback_dispatch"] == "UNSUPPORTED" for r in result["routes"]
    )


@pytest.mark.parametrize("kind", list(security.ProbeKind))
@pytest.mark.parametrize("verdict", list(security.Verdict))
def test_each_scripted_mock_outcome_stays_offline_and_no_go(kind, verdict):
    observation = security.SyntheticProbe(kind, verdict)
    result = checked((observation,))
    row = next(r for r in result["synthetic_trace"] if r["probe"] == kind.value)
    assert row["verdict"] == verdict.value
    assert sum(r["verdict"] != "NOT_RUN" for r in result["synthetic_trace"]) <= 1


def test_all_pass_and_all_fail_traces_cannot_remove_any_blocker():
    baseline = checked()
    for verdict in (security.Verdict.PASS, security.Verdict.FAIL):
        probes = tuple(security.SyntheticProbe(k, verdict) for k in security.ProbeKind)
        result = checked(probes)
        assert result["blockers"] == baseline["blockers"]
        assert all(r["verdict"] == verdict.value for r in result["synthetic_trace"])
        assert result["prior_kernel_snapshot"] == baseline["prior_kernel_snapshot"]
        assert result["report_sha256"] != baseline["report_sha256"]
        assert checked(probes) == result


@pytest.mark.parametrize(
    "changes",
    [
        {"version": "0.166.0"},
        {"source_commit": "f" * 40},
        {"artifact_sha256": "f" * 64},
        {"artifact_bytes": 1},
        {"artifact_bytes": True},
        {"target": "secret-sentinel"},
        {"version": None},
    ],
)
def test_version_source_binary_size_target_drift_blocks(changes):
    result = checked(pin=replace(security.PIN, **changes))
    assert result["reason"] == "pinned_build_unverified"
    assert result["subject"]["input_pin_matched"] is False
    assert result["subject"]["version"] == "0.164.0"
    assert all(r["verdict"] == "NOT_RUN" for r in result["synthetic_trace"])


@pytest.mark.parametrize("pin", [None, {}, "secret-sentinel", True])
def test_raw_or_claimed_build_identity_is_not_authority(pin):
    assert checked(pin=pin)["reason"] == "pinned_build_unverified"


@pytest.mark.parametrize(
    "probes",
    [
        None,
        [],
        {},
        "secret-sentinel",
        ({"provenance": "REAL_KERNEL_SYNTHETIC", "launch_allowed": True},),
        (security.SyntheticProbe("secret-sentinel", security.Verdict.PASS),),
        (security.SyntheticProbe(security.ProbeKind.FILE_KEYRING, "PASS"),),
        (security.SyntheticProbe(security.ProbeKind.FILE_KEYRING, True),),
        (
            security.SyntheticProbe(
                security.ProbeKind.FILE_KEYRING, security.Verdict.PASS
            ),
        )
        * 2,
        (None,) * 11,
    ],
)
def test_unknown_duplicate_oversized_and_forged_real_evidence_fails_closed(probes):
    result = checked(probes)
    assert result["reason"] == "invalid_synthetic_evidence"
    assert all(r["verdict"] == "NOT_RUN" for r in result["synthetic_trace"])


def test_partial_valid_prefix_is_discarded_and_order_has_no_authority():
    a = security.SyntheticProbe(security.ProbeKind.FILE_KEYRING, security.Verdict.PASS)
    b = security.SyntheticProbe(
        security.ProbeKind.PROC_PARENT_MEMORY, security.Verdict.FAIL
    )
    assert checked((a, b)) == checked((b, a))
    bad = checked((a, {"secret-sentinel": "PASS"}))
    assert all(r["verdict"] == "NOT_RUN" for r in bad["synthetic_trace"])
    changed = checked()
    changed["blockers"].clear()
    changed["launch_allowed"] = True
    assert checked()["blockers"]


def test_assessment_and_existing_gates_have_no_io_or_runtime(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("offline assessment crossed an I/O, credential or runtime boundary")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(state, "host_lock", forbidden)
    monkeypatch.setattr(state, "write_checkpoint", forbidden)
    assert checked()["activation_decision"] == "NO-GO"
    assert subscription.readiness()["launch_allowed"] is False
    with pytest.raises(state.PrepareError) as exc:
        native_codex.execute({}, 1, ["maintainer"])
    assert exc.value.code == 13
    assert exc.value.reason == "subscription_isolation_blocked"
