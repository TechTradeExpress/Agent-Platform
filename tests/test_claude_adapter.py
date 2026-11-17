"""HAR-03 entirely synthetic recordings. No SDK, CLI, account or host probes."""

import copy
import hashlib
import importlib
import json
import socket
import subprocess
from dataclasses import FrozenInstanceError, asdict, replace
from pathlib import Path

import pytest
from test_harness_admission import fixture as harness_fixture
from test_harness_design_contract import matches as matches_design

from agent_platform import claude_adapter as claude
from agent_platform import codex, native_codex
from agent_platform import harness_admission as har
from agent_platform.state import PrepareError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/claude"
SID = "11111111-1111-4111-8111-111111111111"


def context(harness="claude_code"):
    assignment = harness_fixture(harness)["assignment"]
    session = claude.ClaudeSession(
        assignment.binding, assignment.digest, "claude_fixture_session", SID
    )
    return claude.Context(assignment, session, assignment.binding, assignment.digest)


def recording(name="complete"):
    return (FIXTURES / (name + ".jsonl")).read_bytes()


def events(name="complete"):
    return [json.loads(line) for line in recording(name).splitlines()]


def wire(items):
    return b"".join(har.encoded(item) for item in items)


def observation(raw, ctx, **changes):
    values = dict(
        assignment_sha256=ctx.assignment.digest,
        stream_sha256=hashlib.sha256(raw).hexdigest(),
        exit_code=0,
        eof=True,
        effects="FIXTURE_QUIESCENT",
    )
    return claude.ProcessFixture(**(values | changes))


def check(raw=None, ctx=None, **kwargs):
    raw = recording() if raw is None else raw
    ctx = context() if ctx is None else ctx
    result = claude.parse(raw, ctx, **kwargs)
    assert result["launch_allowed"] is result["resume_authorized"] is False
    assert result["publish_authorized"] is False
    assert result["host_evidence"] == "HOST_NOT_RUN"
    assert result["runtime_exit_code"] == 13 and result["runtime"] == "LIVE_NO_GO"
    assert result["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert result["gate_73"] == "BLOCKED"
    encoded = har.encoded(result)
    assert SID.encode() not in encoded
    assert b"secret sentinel" not in encoded and b"/private" not in encoded
    if result["event"] is not None:
        assert matches_design(result["event"], {"$ref": "#/$defs/event"})
        assert result["event"]["seq"] == ctx.next_seq
        assert matches_design(result["session"], {"$ref": "#/$defs/session"})
    return result


@pytest.mark.parametrize("name", ["complete", "tool_complete", "partial_text"])
def test_complete_documented_shape_requires_independent_bound_fixture_evidence(name):
    raw, ctx = recording(name), context()
    result = check(raw, ctx, process=observation(raw, ctx))
    assert result["protocol"] == "PASS" and result["outcome"] == "COMPLETED"
    assert result["effects"] == "FIXTURE_QUIESCENT"
    assert result["event"]["state"] == "COMPLETED"
    assert result == check(raw, ctx, process=observation(raw, ctx))


def test_json_final_object_uses_separate_framing_but_same_closed_result_contract():
    raw, ctx = (FIXTURES / "complete.json").read_bytes(), context()
    assert check(raw, ctx, output_format="json")["outcome"] == "UNKNOWN"
    result = check(raw, ctx, output_format="json", process=observation(raw, ctx))
    assert result["protocol"] == "PASS" and result["outcome"] == "COMPLETED"
    assert check(raw, ctx)["protocol"] == "FAIL"
    assert check(recording(), ctx, output_format="json")["protocol"] == "FAIL"


@pytest.mark.parametrize(
    "process_change",
    [{}, {"effects": "UNKNOWN"}, {"eof": False}, {"exit_code": None}, {"exit_code": 1}],
)
def test_session_result_zero_exit_and_claimed_success_do_not_prove_effects(
    process_change,
):
    raw, ctx = recording("injection"), context()
    process = None if not process_change else observation(raw, ctx, **process_change)
    result = check(raw, ctx, process=process)
    assert result["outcome"] == "UNKNOWN"
    assert result["event"]["state"] == "NEEDS_HUMAN"
    assert result["effects"] == "UNKNOWN"


@pytest.mark.parametrize(
    "name,protocol,diagnostic,reason",
    [
        ("auth_error", "PASS", "AUTH_ERROR", "AUTH_UNVERIFIED"),
        ("rate_limit", "PASS", "RATE_LIMIT", "RESOURCE_LIMIT"),
        ("tool_denied", "PASS", "TOOL_DENIED", "OUTCOME_UNKNOWN"),
        ("cancelled", "PASS", "CANCELLED", "CANCEL_UNCONFIRMED"),
        ("interrupted", "FAIL", "INCOMPLETE_STREAM", "OUTCOME_UNKNOWN"),
        ("unresolved_tool", "FAIL", "UNRESOLVED_TOOL", "OUTCOME_UNKNOWN"),
        ("replay", "FAIL", "EVENT_REPLAY", "PROTOCOL_INVALID"),
        ("wrong_session", "FAIL", "PROTOCOL_INVALID", "PROTOCOL_INVALID"),
        ("out_of_order", "FAIL", "PROTOCOL_INVALID", "PROTOCOL_INVALID"),
        ("background", "PASS", "BACKGROUND_UNVERIFIED", "OUTCOME_UNKNOWN"),
    ],
)
def test_positive_and_negative_recordings_never_grant_live_completion(
    name, protocol, diagnostic, reason
):
    result = check(recording(name))
    assert result["protocol"] == protocol and result["outcome"] == "UNKNOWN"
    assert result["diagnostic"] == diagnostic
    assert result["event"]["reason"] == reason


def test_background_completed_notifications_and_zero_exit_still_are_not_quiescence():
    raw, ctx = recording("background"), context()
    result = check(raw, ctx, process=observation(raw, ctx))
    assert result["outcome"] == "UNKNOWN" and result["effects"] == "UNKNOWN"


@pytest.mark.parametrize(
    "signal,exit_code,reason",
    [
        ("SIGTERM", 143, "CANCEL_UNCONFIRMED"),
        ("SIGINT", -2, "CANCEL_UNCONFIRMED"),
        ("TIMEOUT", None, "RESOURCE_LIMIT"),
    ],
)
def test_interruption_evidence_does_not_finish_or_authorize_resume(
    signal, exit_code, reason
):
    raw, ctx = recording("interrupted"), context()
    result = check(
        raw, ctx, process=observation(raw, ctx, termination=signal, exit_code=exit_code)
    )
    assert result["outcome"] == "UNKNOWN" and result["event"]["reason"] == reason
    assert result["diagnostic"] == "INTERRUPTED"


def test_known_native_failure_can_only_pause_with_separate_quiescence_fixture():
    items = events("auth_error")
    items[1].pop("error")
    raw, ctx = wire(items), context()
    result = check(raw, ctx, process=observation(raw, ctx, exit_code=1))
    assert result["protocol"] == "PASS" and result["outcome"] == "PAUSED"
    assert result["event"]["reason"] == "NATIVE_TURN_FAILED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("terminal_reason", "unknown_future_reason"),
        ("result_index", 1),
        ("result_index", True),
        ("is_error", "false"),
        ("num_turns", True),
        ("permission_denials", {}),
        ("stop_reason", "unknown"),
        ("subtype", "approved"),
        ("launch_allowed", True),
    ],
)
def test_unknown_control_fields_types_and_versions_never_succeed(field, value):
    items = events()
    items[-1][field] = value
    raw, ctx = wire(items), context()
    assert check(raw, ctx, process=observation(raw, ctx))["protocol"] == "FAIL"


@pytest.mark.parametrize(
    "field", ["terminal_reason", "queued_turn_count", "result_index"]
)
def test_missing_optional_correlation_evidence_is_unknown_not_a_silent_default(field):
    items = events()
    items[-1].pop(field)
    raw, ctx = wire(items), context()
    result = check(raw, ctx, process=observation(raw, ctx))
    assert result["outcome"] == "UNKNOWN"


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_init",
        "post_result",
        "missing_init",
        "missing_result",
        "missing_assistant",
        "duplicate_message",
        "orphan_tool",
        "duplicate_tool_result",
        "task_run_drift",
    ],
)
def test_sequence_corruption_is_fail_closed(mutation):
    items = events("tool_complete" if "tool" in mutation else "complete")
    if mutation == "duplicate_init":
        items.insert(1, copy.deepcopy(items[0]))
    elif mutation == "post_result":
        items.append(copy.deepcopy(items[1]))
    elif mutation == "missing_init":
        items.pop(0)
    elif mutation == "missing_result":
        items.pop()
    elif mutation == "missing_assistant":
        items.pop(1)
    elif mutation == "duplicate_message":
        duplicate = copy.deepcopy(items[1])
        duplicate["uuid"] = "33333333-3333-4333-8333-333333333333"
        items.insert(2, duplicate)
    elif mutation == "orphan_tool":
        items[2]["message"]["content"][0]["tool_use_id"] = "unknown_tool"
    elif mutation == "duplicate_tool_result":
        duplicate = copy.deepcopy(items[2])
        duplicate["uuid"] = "33333333-3333-4333-8333-333333333333"
        items.insert(3, duplicate)
    else:
        items = events("background")
        items[4]["run_id"] = "stale_run"
    assert check(wire(items))["protocol"] == "FAIL"


@pytest.mark.parametrize(
    "mutation",
    [
        "bad_index",
        "bool_index",
        "delta_before_start",
        "missing_stop",
        "missing_full_message",
        "different_full_text",
        "unknown_delta",
    ],
)
def test_partial_stream_is_verified_against_complete_message(mutation):
    items = events("partial_text")
    if mutation == "bad_index":
        items[3]["event"]["index"] = 1
    elif mutation == "bool_index":
        items[3]["event"]["index"] = False
    elif mutation == "delta_before_start":
        items[2], items[3] = items[3], items[2]
    elif mutation == "missing_stop":
        items.pop(6)
    elif mutation == "missing_full_message":
        items.pop(7)
    elif mutation == "different_full_text":
        items[7]["message"]["content"][0]["text"] = "tampered"
    else:
        items[3]["event"]["delta"] = {"type": "thinking_delta", "thinking": "private"}
    assert check(wire(items))["protocol"] == "FAIL"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff\n",
        b"{}\n{}",
        b'{"type":NaN}\n',
        b'{"type":Infinity}\n',
        b'{"type":1e400}\n',
        b'{"type":"result","type":"result"}\n',
        b'{"x":{"key":1,"key":2}}\n',
        b"[" * 9 + b"0" + b"]" * 9 + b"\n",
        b" " * (claude.MAX_EVENT + 1) + b"\n",
        b"x" * (claude.MAX_STREAM + 1),
        b"{}\n" * (claude.MAX_EVENTS + 1),
    ],
)
def test_json_bounds_duplicates_nonfinite_encoding_and_framing(raw):
    assert check(raw)["protocol"] == "FAIL"


def test_quoted_brackets_are_content_not_nesting_and_node_limits_are_enforced():
    items = events()
    items[1]["message"]["content"][0]["text"] = '[{\\"' * 100
    assert check(wire(items))["protocol"] == "PASS"
    with pytest.raises(claude.Invalid):
        claude.decode(har.encoded({"items": [0] * (claude.MAX_ITEMS + 1)}))


def test_deadline_and_fixture_duration_limits_are_fail_closed(monkeypatch):
    ctx = context()
    raw = recording()
    process = observation(raw, ctx, duration_ms=15_001)
    assert check(raw, ctx, process=process)["diagnostic"] == "RESOURCE_LIMIT"
    ticks = iter([0, 0, 3])
    monkeypatch.setattr(claude.time, "monotonic", lambda: next(ticks, 3))
    assert check(raw, ctx)["diagnostic"] == "RESOURCE_LIMIT"


@pytest.mark.parametrize(
    "field,value", [("stream_sha256", "f" * 64), ("assignment_sha256", "f" * 64)]
)
def test_process_fixture_cannot_be_rebound_to_another_capture_or_assignment(
    field, value
):
    raw, ctx = recording(), context()
    result = check(raw, ctx, process=replace(observation(raw, ctx), **{field: value}))
    assert result["protocol"] == "FAIL" and result["event"] is None


def test_dictionaries_or_forged_host_evidence_do_not_become_typed_evidence():
    raw, ctx = recording(), context()
    assert check(raw, ctx, process=asdict(observation(raw, ctx)))["protocol"] == "FAIL"
    with pytest.raises(claude.Invalid):
        observation(raw, ctx, effects="HOST_PASS")
    with pytest.raises(claude.Invalid):
        observation(raw, ctx, schema="AP-CLAUDE-PROCESS-FIXTURE/2")


def test_prior_event_registry_rejects_replay_across_fresh_parser_instances():
    ctx = context()
    first = events()[0]
    key = har.digest({"namespace": "claude_code", "uuid": first["uuid"]})
    result = check(ctx=replace(ctx, seen_event_sha256=(key,)))
    assert result["diagnostic"] == "EVENT_REPLAY"


@pytest.mark.parametrize(
    "field,value",
    [
        ("selection_epoch", 2),
        ("worker_ref", "other_worker"),
        ("enrollment_ref", "other_boot"),
        ("configuration_sha256", "f" * 64),
        ("harness_id", har.HarnessId.CODEX),
    ],
)
def test_wrong_worker_epoch_config_or_harness_is_rejected_before_vendor_data(
    field, value
):
    ctx = context()
    wrong = replace(ctx.expected_binding, **{field: value})
    with pytest.raises((ValueError, claude.Invalid)):
        replace(ctx, expected_binding=wrong)
    object.__setattr__(ctx, "expected_binding", wrong)
    result = check(ctx=ctx)
    assert result["protocol"] == "FAIL" and result["event"] is None


@pytest.mark.parametrize(
    "value",
    [
        "latest",
        "named-session",
        "../session.jsonl",
        "session_cloud",
        SID.upper(),
        "01900000-0000-7000-8000-000000000000",
    ],
)
def test_only_explicit_canonical_project_uuid_policy_is_accepted(value):
    if (
        value == SID
    ):  # This fixture ID contains only digits; use a real uppercase hex ID.
        value = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
    with pytest.raises(ValueError):
        replace(context().session, native_id=value)


def test_codex_session_and_event_are_never_interpreted_as_claude():
    with pytest.raises(ValueError):
        context("codex")
    ctx = context()
    assert (
        check(har.encoded({"type": "thread.started", "thread_id": SID}), ctx)[
            "protocol"
        ]
        == "FAIL"
    )
    with pytest.raises(ValueError):
        replace(ctx, session=codex.session_id(SID))
    assert SID not in repr(ctx.session)


def continuation():
    ctx = context()
    next_assignment = replace(ctx.assignment, assignment_ref="fresh_fixture_attempt")
    intent = claude.ContinuationIntent(
        ctx.session,
        ctx.assignment,
        next_assignment,
        ctx.expected_binding,
        "a" * 64,
        "PAUSED",
    )
    next_session = replace(ctx.session, assignment_sha256=next_assignment.digest)
    return claude.Context(
        next_assignment,
        next_session,
        ctx.expected_binding,
        next_assignment.digest,
        continuation=intent,
    )


def test_typed_continuation_projects_namespaced_checkpoint_without_resuming():
    ctx = continuation()
    result = check(ctx=ctx)
    assert result["session"]["mode"] == "RESUME"
    assert result["session"]["parent_checkpoint_sha256"] == "a" * 64
    assert result["resume_authorized"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("previous_outcome", "UNKNOWN"),
        ("checkpoint_sha256", "0" * 64),
        ("schema", "AP-CLAUDE-CONTINUATION/2"),
        ("previous", SID),
    ],
)
def test_missing_uncertain_foreign_or_future_continuation_is_blocked(field, value):
    with pytest.raises(ValueError):
        replace(continuation().continuation, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_policy_ref", "other_account"),
        ("model_policy_sha256", "f" * 64),
        ("task_authorization_sha256", "f" * 64),
    ],
)
def test_resume_cannot_cross_account_model_or_task_authority(field, value):
    intent = continuation().continuation
    with pytest.raises(ValueError):
        replace(
            intent, next_assignment=replace(intent.next_assignment, **{field: value})
        )


def test_resume_cannot_fork_or_silently_take_a_different_native_session():
    ctx = continuation()
    with pytest.raises(ValueError):
        replace(
            ctx,
            session=replace(
                ctx.session, native_id="33333333-3333-4333-8333-333333333333"
            ),
        )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        ctx.session.native_id = "other"


def test_injection_is_discarded_content_and_never_a_control_signal():
    result = check(recording("injection"))
    assert result["protocol"] == "PASS" and result["outcome"] == "UNKNOWN"
    ordinary = check()
    assert (
        result == ordinary
    )  # Neither payload text nor its hidden instructions affect state.
    for field in ("launch_allowed", "harness_id", "selection_epoch", "approval"):
        items = events()
        items[-1][field] = "model-provided authority"
        assert check(wire(items))["protocol"] == "FAIL"


def test_no_invocation_credentials_or_codex_parser_used_during_import_and_parse(
    monkeypatch,
):
    def forbidden(*_args, **_kwargs):
        pytest.fail("forbidden integration")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(native_codex, "arguments", forbidden)
    monkeypatch.setattr(codex.Events, "accept", forbidden)
    importlib.reload(claude)
    assert check()["protocol"] == "PASS"
    assert not hasattr(claude, "execute") and not hasattr(claude, "arguments")


@pytest.mark.parametrize("resume", [False, True])
def test_original_native_run_resume_gate_still_blocks_before_io(resume):
    with pytest.raises(PrepareError) as error:
        native_codex.execute(None, None, None, resume=resume)
    assert error.value.code == 13


def test_versioned_contract_manifest_examples_and_output_fields_are_consistent():
    contract = json.loads((ROOT / "docs/claude-adapter-contract.json").read_text())
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    examples = json.loads((ROOT / "docs/claude-adapter.examples.json").read_text())
    assert (
        contract["schema"] == claude.SCHEMA
        and contract["cli_version"] == claude.VERSION
    )
    assert contract["release"]["binary_verified"] is False
    assert contract["documentation"]["version_frozen"] is False
    assert manifest["provenance"] == examples["provenance"] == "SYNTHETIC_NOT_CAPTURED"
    assert set(contract["report_fields"]) == set(check())
    assert contract["limits"] == dict(
        event_bytes=claude.MAX_EVENT,
        stream_bytes=claude.MAX_STREAM,
        events=claude.MAX_EVENTS,
        json_depth=claude.MAX_DEPTH,
        nodes=claude.MAX_NODES,
        collection_items=claude.MAX_ITEMS,
        text_characters=claude.MAX_TEXT,
        correlations=claude.MAX_CORRELATIONS,
        parser_seconds=claude.MAX_SECONDS,
        fixture_duration_ms=15_000,
    )
    for name, case in manifest["cases"].items():
        raw = (FIXTURES / case["file"]).read_bytes()
        result = check(raw, output_format=case["format"])
        expected = case["expected_without_process"]
        assert {key: result[key] for key in expected} == expected, name
        assert result["diagnostic"] in contract["diagnostics"]
        if name in examples["cases"]:
            ctx = context()
            observed = check(
                raw, ctx, output_format=case["format"], process=observation(raw, ctx)
            )
            assert examples["cases"][name]["report"] == observed


def test_documentation_local_links_and_single_canonical_instruction_file():
    import re

    for name in ("claude-adapter.md",):
        for target in re.findall(r"\]\(([^)]+)\)", (ROOT / "docs" / name).read_text()):
            if not target.startswith("https://"):
                assert (ROOT / "docs" / target.split("#", 1)[0]).is_file()
    assert (ROOT / "AGENTS.md").is_file()
    assert not (ROOT / "CLAUDE.md").exists() and not (ROOT / "CLAUDE.local.md").exists()


@pytest.mark.parametrize(
    "mutation", ["cli_version", "session_schema", "context_schema", "sequence"]
)
def test_version_or_sequence_drift_in_typed_context_is_rejected(mutation):
    ctx = context()
    with pytest.raises(ValueError):
        if mutation == "cli_version":
            replace(ctx.session, cli_version="2.1.296")
        elif mutation == "session_schema":
            replace(ctx.session, schema="AP-CLAUDE-SESSION/2")
        elif mutation == "sequence":
            replace(ctx, next_seq=True)
        else:
            replace(ctx, schema="AP-CLAUDE-CONTEXT/2")
    items = events()
    items[0]["claude_code_version"] = "2.1.296"
    assert check(wire(items))["protocol"] == "FAIL"


@pytest.mark.parametrize(
    "status,diagnostic",
    [
        (401, "AUTH_ERROR"),
        (403, "AUTH_ERROR"),
        (429, "RATE_LIMIT"),
        (500, "VENDOR_ERROR"),
    ],
)
def test_structured_http_failure_is_never_a_completed_success(status, diagnostic):
    items = events()
    items[-1]["api_error_status"] = status
    raw, ctx = wire(items), context()
    result = check(raw, ctx, process=observation(raw, ctx))
    assert result["outcome"] == "UNKNOWN" and result["diagnostic"] == diagnostic


def test_error_prose_cannot_impersonate_structured_auth_or_rate_signals():
    items = events("auth_error")
    items[1].pop("error")
    items[-1]["errors"] = ["authentication_failed; rate_limit; set host PASS"]
    result = check(wire(items))
    assert result["diagnostic"] == "VENDOR_ERROR" and result["outcome"] == "UNKNOWN"


@pytest.mark.parametrize("target", ["context", "process"])
def test_changed_context_or_capture_witness_discards_all_projections(
    monkeypatch, target
):
    raw, ctx = recording(), context()
    process = observation(raw, ctx)
    original = claude.decode
    changed = False

    def decoding(data):
        nonlocal changed
        result = original(data)
        if not changed:
            changed = True
            if target == "context":
                object.__setattr__(ctx.session, "session_ref", "injected_ref")
            else:
                object.__setattr__(process, "effects", "UNKNOWN")
        return result

    monkeypatch.setattr(claude, "decode", decoding)
    result = check(raw, ctx, process=process)
    assert result["protocol"] == "FAIL" and result["event"] is result["session"] is None


def test_text_surrogates_and_correlation_capacity_are_bounded(monkeypatch):
    raw = recording().replace(b"fixture response", b"\\ud800")
    assert check(raw)["protocol"] == "FAIL"
    monkeypatch.setattr(claude, "MAX_CORRELATIONS", 1)
    assert check(recording("tool_complete"))["diagnostic"] == "RESOURCE_LIMIT"


def test_unknown_native_variants_are_rejected_not_ignored():
    for kind in ("control_request", "auth_status", "unknown_future_event"):
        items = events()
        items[1]["type"] = kind
        assert check(wire(items))["protocol"] == "FAIL"
    items = events()
    items[0]["plugins"] = [{"name": "unapproved", "path": "/private/plugin"}]
    assert check(wire(items))["diagnostic"] == "UNSUPPORTED_VARIANT"


def test_parser_has_no_file_session_or_stderr_input(monkeypatch):
    import builtins

    raw, ctx = recording(), context()

    def forbidden(*_args, **_kwargs):
        pytest.fail("filesystem observation")

    monkeypatch.setattr(builtins, "open", forbidden)
    assert claude.parse(raw, ctx)["protocol"] == "PASS"


@pytest.mark.parametrize(
    "name,position,field,value",
    [
        ("tool_complete", 2, "error", "authentication_failed"),
        ("tool_complete", 2, "aborted", True),
        ("tool_complete", 2, "agent_id", "undocumented_on_user"),
        ("complete", 1, "agent_id", 123),
        ("complete", -1, "startup_failure_reason", "unrecognized"),
        ("auth_error", -1, "structured_output", {}),
        ("auth_error", -1, "api_error_status", 401),
        ("tool_denied", 2, "decision_reason", 123),
        (
            "background",
            4,
            "usage",
            {"total_tokens": True, "tool_uses": 0, "duration_ms": 0},
        ),
    ],
)
def test_variant_specific_metadata_is_not_a_shared_permissive_field_union(
    name, position, field, value
):
    items = events(name)
    items[position][field] = value
    assert check(wire(items))["protocol"] == "FAIL"
