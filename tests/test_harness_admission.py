"""HAR-02 fabricated offline pins only; no CLI, host or credential evidence."""

import copy
import json
import socket
import subprocess
from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path

import pytest
from test_codex_assignment import case as case
from test_harness_design_contract import matches as design_matches
from test_prepare import task as task

from agent_platform import codex_assignment as ca
from agent_platform import harness_admission as har
from agent_platform import native_codex
from agent_platform.state import PrepareError

DOCS = Path(__file__).resolve().parents[1] / "docs"
EXAMPLES = json.loads((DOCS / "harness-contract.examples.json").read_text())
NOW = 1000


def fixture(harness="codex"):
    raw = copy.deepcopy(EXAMPLES[harness]["selection"])
    binding = raw.pop("binding")
    binding["harness_id"] = har.HarnessId(binding["harness_id"])
    binding = har.Binding(**binding)
    raw.pop("launch_allowed")
    selection = har.WorkerSelection(binding=binding, **raw)
    caps = har.CapabilitySnapshot(binding, har.capability_row(binding.harness_id))
    approval = har.SelectionApproval(
        selection.digest,
        caps.digest,
        selection.issuer_ref,
        selection.approval_sha256,
        selection.continuity_witness_sha256,
        NOW,
        NOW + 300,
    )
    auth = har.TaskAuthorization(
        assignment_ref="attempt_fixture",
        task_authorization_sha256="8" * 64,
        task_identity_sha256="e" * 64,
        worker_ref=binding.worker_ref,
        enrollment_ref=binding.enrollment_ref,
        selection_sha256=selection.digest,
        agent_id="agent_fixture",
        model_policy_sha256="9" * 64,
        account_policy_ref=harness + "_account_fixture",
        required_capabilities=(),
        issued_at=NOW,
        expires_at=NOW + 300,
    )
    assignment = har.bind(selection, auth)
    inventory = har.Inventory(
        binding.worker_ref,
        binding.enrollment_ref,
        (selection,),
        caps,
        approval,
        (),
        "d" * 64,
        NOW,
        True,
    )
    return dict(
        assignment=assignment,
        authorization=auth,
        inventory=inventory,
        expected_worker=binding.worker_ref,
        expected_selection_sha256=selection.digest,
        expected_generation_sha256=inventory.generation_sha256,
        now=NOW,
    )


def checked(**args):
    result = har.advise(**args)
    assert all(
        result[key] is False
        for key in (
            "reserved",
            "prepare_authorized",
            "launch_allowed",
            "resume_authorized",
            "publish_authorized",
        )
    )
    assert result["host_evidence"] == "HOST_NOT_RUN"
    assert result["runtime_exit_code"] == 13
    assert result["runtime"] == "LIVE_NO_GO" and result["gate_73"] == "BLOCKED"
    assert result["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    return result


def retained(**changes):
    values = dict(
        assignment_ref="prior_attempt",
        assignment_sha256="a" * 64,
        task_authorization_sha256="b" * 64,
        task_identity_sha256="c" * 64,
        worker_ref="worker_fixture",
        enrollment_ref="old_boot",
        selection_sha256="f" * 64,
        selection_epoch=1,
        state="FINISHED",
        recorded_at=NOW - 1,
    )
    return har.RetainedAttempt(**(values | changes))


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_exact_pinned_binding_matches_but_grants_no_authority(harness):
    args = fixture(harness)
    first = checked(**args)
    assert first["status"] == "OFFLINE_BINDING_MATCH"
    assert first == checked(**args)
    assert first["assignment_sha256"] == args["assignment"].digest
    assert first["selection_sha256"] == args["expected_selection_sha256"]
    assert args["assignment"].record() == EXAMPLES[harness]["assignment"]
    assert design_matches(args["assignment"].record(), {"$ref": "#/$defs/assignment"})
    selection = args["inventory"].selections[0]
    assert design_matches(selection.record(), {"$ref": "#/$defs/selection"})


def test_matrix_is_exact_reviewed_har01_revision():
    matrix = json.loads((DOCS / "harness-capabilities.json").read_text())
    assert har.capability_matrix() == matrix
    assert har.MATRIX_SHA256 == har.digest(matrix)


@pytest.mark.parametrize(
    "value",
    [
        "Codex",
        "claude",
        "auto",
        "openai",
        "gpt",
        None,
        ["codex", "claude_code"],
        "codex",
    ],
)
def test_strings_unknown_models_or_multivalued_ids_do_not_become_typed_selection(value):
    original = fixture()["assignment"].binding
    with pytest.raises(ValueError):
        replace(original, harness_id=value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("selection_epoch", True),
        ("selection_epoch", 1.0),
        ("selection_epoch", 0),
        ("selection_epoch", 2**63),
        ("capability_revision", "AP-HCAP/2"),
        ("capability_matrix_sha256", "a" * 64),
        ("worker_ref", "../host"),
        ("enrollment_ref", ""),
        ("configuration_sha256", "secret"),
        ("executable_manifest_sha256", "latest"),
        ("parser_sha256", None),
    ],
)
def test_invalid_binding_pins_rejected(field, value):
    with pytest.raises(ValueError):
        replace(fixture()["assignment"].binding, **{field: value})


@pytest.mark.parametrize("name", ["assignment", "authorization", "inventory"])
def test_untrusted_dicts_subclasses_unknown_versions_and_extra_fields_rejected(name):
    args = fixture()
    original = args[name]
    args[name] = asdict(original)
    assert checked(**args)["status"] == "BLOCKED"
    with pytest.raises(ValueError):
        replace(original, schema="FUTURE/2")
    with pytest.raises(TypeError):
        replace(original, runtime="claude_code")
    with pytest.raises((FrozenInstanceError, AttributeError)):
        original.schema = "other"

    class Subclass(type(original)):
        pass

    args[name] = Subclass(
        **{field.name: getattr(original, field.name) for field in fields(original)}
    )
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize("name", ["selection", "caps", "approval", "retained"])
def test_nested_contract_versions_and_provenance_are_closed(name):
    args = fixture()
    inventory = args["inventory"]
    original = dict(
        selection=inventory.selections[0],
        caps=inventory.capabilities,
        approval=inventory.approval,
        retained=retained(),
    )[name]
    with pytest.raises(ValueError):
        replace(original, schema="UNKNOWN/2")
    if name == "approval":
        with pytest.raises(ValueError):
            replace(original, provenance="live_operator")


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
@pytest.mark.parametrize("field", [field.name for field in fields(har.Binding)])
def test_every_changed_worker_binding_blocks_existing_assignment(harness, field):
    args = fixture(harness)
    binding = args["assignment"].binding
    changes = {field: "f" * 64}
    if field == "harness_id":
        changes[field] = (
            har.HarnessId.CLAUDE_CODE if harness == "codex" else har.HarnessId.CODEX
        )
    elif field == "selection_epoch":
        changes[field] = 2
    elif field in {"worker_ref", "enrollment_ref"}:
        changes[field] = "different_fixture"
    elif field in {"capability_revision", "capability_matrix_sha256"}:
        with pytest.raises(ValueError):
            replace(binding, **changes)
        return
    args["assignment"] = replace(
        args["assignment"], binding=replace(binding, **changes)
    )
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "field",
    [
        "assignment_ref",
        "task_authorization_sha256",
        "model_policy_sha256",
        "account_policy_ref",
    ],
)
def test_task_cannot_replace_approved_assignment_fields(field):
    args = fixture()
    value = "f" * 64 if field.endswith("sha256") else "different_fixture"
    args["assignment"] = replace(args["assignment"], **{field: value})
    assert checked(**args)["reason"] == "authorization_mismatch"


def test_no_task_harness_selector_no_automatic_fallback():
    args = fixture()
    selection = args["inventory"].selections[0]
    with pytest.raises(TypeError):
        har.bind(selection, args["authorization"], harness_id=har.HarnessId.CLAUDE_CODE)
    other = fixture("claude_code")["inventory"].selections[0]
    with pytest.raises(har.Blocked):
        har.bind(other, args["authorization"])
    args["authorization"] = replace(
        args["authorization"], required_capabilities=("native_account_eligibility",)
    )
    assert checked(**args)["reason"] == "capability_unverified"
    assert args["inventory"].selections == (selection,)


@pytest.mark.parametrize(
    "field",
    [
        "selection_sha256",
        "capabilities_sha256",
        "issuer_ref",
        "approval_sha256",
        "continuity_witness_sha256",
    ],
)
def test_worker_cannot_self_approve_selection_or_capabilities(field):
    args = fixture()
    inventory = args["inventory"]
    value = "other_issuer" if field == "issuer_ref" else "a" * 64
    approval = replace(inventory.approval, **{field: value})
    args["inventory"] = replace(inventory, approval=approval)
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "field", ["expected_selection_sha256", "expected_generation_sha256"]
)
def test_old_view_does_not_override_independent_current_fencing_pins(field):
    args = fixture()
    args[field] = "f" * 64
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("complete", False),
        ("observed_at", NOW - 301),
        ("observed_at", NOW + 1),
        ("worker_ref", "other_worker"),
        ("enrollment_ref", "other_boot"),
        ("generation_sha256", "a" * 64),
    ],
)
def test_incomplete_stale_foreign_inventory_blocks(field, value):
    args = fixture()
    args["inventory"] = replace(args["inventory"], **{field: value})
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize("selections", [(), "two"])
def test_missing_or_dual_selection_is_invalid(selections):
    inventory = fixture()["inventory"]
    if selections == "two":
        selections = (
            inventory.selections[0],
            fixture("claude_code")["inventory"].selections[0],
        )
    with pytest.raises(ValueError):
        replace(inventory, selections=selections)


@pytest.mark.parametrize("state", ["QUIESCING", "RECONCILING", "BLOCKED"])
def test_operator_drain_does_not_release_existing_assignment(state):
    args = fixture()
    inventory = args["inventory"]
    args["inventory"] = replace(
        inventory, selections=(replace(inventory.selections[0], state=state),)
    )
    assert checked(**args)["status"] == "BLOCKED"


@pytest.mark.parametrize("state", ["RESERVED", "PREPARED", "RUNNING", "UNKNOWN"])
def test_one_active_attempt_even_if_old_boot_or_expired_lease(state):
    args = fixture()
    args["inventory"] = replace(args["inventory"], retained=(retained(state=state),))
    assert checked(**args)["reason"] == "worker_busy_or_unknown"


@pytest.mark.parametrize(
    "field",
    [
        "assignment_ref",
        "assignment_sha256",
        "task_authorization_sha256",
        "task_identity_sha256",
    ],
)
@pytest.mark.parametrize("worker", ["worker_fixture", "other_worker"])
def test_replay_including_finished_and_cross_worker_history_is_rejected(field, worker):
    args = fixture()
    value = (
        args["assignment"].digest
        if field == "assignment_sha256"
        else getattr(args["authorization"], field)
    )
    old = retained(worker_ref=worker, **{field: value})
    args["inventory"] = replace(args["inventory"], retained=(old,))
    assert checked(**args)["reason"] == "assignment_replayed"


def test_unrelated_finished_attempt_is_not_an_implicit_cleanup_or_retry():
    args = fixture()
    old = retained()
    args["inventory"] = replace(args["inventory"], retained=(old,))
    assert checked(**args)["status"] == "OFFLINE_BINDING_MATCH"
    assert args["inventory"].retained == (old,)
    args["inventory"] = replace(
        args["inventory"], retained=(replace(old, recorded_at=NOW + 1),)
    )
    assert checked(**args)["reason"] == "inventory_inconsistent"


def test_duplicate_history_or_capacity_overflow_is_never_collapsed_or_evicted():
    inventory = fixture()["inventory"]
    old = retained()
    with pytest.raises(ValueError):
        replace(inventory, retained=(old, old))
    with pytest.raises(ValueError):
        replace(inventory, retained=(old,) * (har.MAX_ENTRIES + 1))


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_capability_snapshot_cannot_claim_unknown_support_or_drop_columns(harness):
    caps = fixture(harness)["inventory"].capabilities
    for values in (
        caps.values[:-1],
        tuple(reversed(caps.values)),
        caps.values + (("automatic_fallback", "OFFLINE_CONTRACT"),),
        (("native_event_parser", "SUPPORTED"),) + caps.values[1:],
    ):
        with pytest.raises(ValueError):
            replace(caps, values=values)
    with pytest.raises(ValueError):
        replace(
            caps,
            binding=fixture("claude_code" if harness == "codex" else "codex")[
                "assignment"
            ].binding,
        )


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_required_unverified_isolation_never_becomes_eligible(harness):
    args = fixture(harness)
    args["authorization"] = replace(
        args["authorization"], required_capabilities=("complete_tool_auth_isolation",)
    )
    assert checked(**args)["reason"] == "capability_unverified"


def test_existing_offline_codex_parser_evidence_is_not_claude_parser_evidence():
    for harness in ("codex", "claude_code"):
        args = fixture(harness)
        args["authorization"] = replace(
            args["authorization"], required_capabilities=("native_event_parser",)
        )
        result = checked(**args)
        assert result["status"] == (
            "OFFLINE_BINDING_MATCH" if harness == "codex" else "BLOCKED"
        )


@pytest.mark.parametrize(
    "required",
    [
        ("unknown",),
        ("native_event_parser",) * 2,
        ["native_event_parser"],
        ("product_execution", "native_event_parser"),
    ],
)
def test_required_capabilities_are_closed_unique_canonical_tuple(required):
    with pytest.raises(ValueError):
        replace(fixture()["authorization"], required_capabilities=required)


@pytest.mark.parametrize("name", ["authorization", "approval"])
@pytest.mark.parametrize("time", [NOW - 1, NOW + 300])
def test_expired_or_not_yet_valid_grants_block(name, time):
    args = fixture()
    args["now"] = time
    assert checked(**args)["status"] == "BLOCKED"


def legacy_args(case):
    legacy = case["value"]
    args = fixture()
    authorization = replace(
        args["authorization"],
        origin_schema="AP-CA/1",
        task_authorization_sha256=legacy.digest,
        task_identity_sha256=har.digest(
            {"repo_id": legacy.admission.repo_id, "issue_id": legacy.admission.issue_id}
        ),
        agent_id=legacy.agent_id,
        issued_at=legacy.issued_at,
        expires_at=legacy.expires_at,
    )
    selection = args["inventory"].selections[0]
    args.update(authorization=authorization, legacy=legacy, now=legacy.issued_at)
    args["assignment"] = har.bind_codex(legacy, selection, authorization)
    approval = replace(
        args["inventory"].approval,
        issued_at=legacy.issued_at,
        expires_at=legacy.expires_at,
    )
    args["inventory"] = replace(
        args["inventory"], approval=approval, observed_at=legacy.issued_at
    )
    return args


def test_codex_compatibility_binds_entire_original_and_keeps_legacy_behavior(case):
    args = legacy_args(case)
    original = case["value"]
    assert checked(**args)["status"] == "OFFLINE_BINDING_MATCH"
    assert args["assignment"].task_authorization_sha256 == original.digest
    assert original.runtime == "codex" and original.schema_version == 1
    assert replace(original) == original  # No rewriting legacy App/target/expiry pins.
    args.pop("legacy")
    assert checked(**args)["reason"] == "legacy_codex_only"


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "other_agent"),
        ("task_identity_sha256", "f" * 64),
        ("task_authorization_sha256", "f" * 64),
        ("expires_at", "shorter"),
    ],
)
def test_legacy_migration_must_not_strip_or_relabel_original_authority(
    case, field, value
):
    args = legacy_args(case)
    if value == "shorter":
        value = args["authorization"].expires_at - 1
    authorization = replace(args["authorization"], **{field: value})
    with pytest.raises(ValueError):
        har.bind_codex(case["value"], args["inventory"].selections[0], authorization)


@pytest.mark.parametrize(
    "field,value",
    [("schema_version", 2), ("schema_version", True), ("runtime", "claude_code")],
)
def test_legacy_unknown_versions_and_claude_runtime_stay_invalid(case, field, value):
    with pytest.raises(ValueError):
        replace(case["value"], **{field: value})


def test_codex_record_cannot_migrate_to_claude_or_future_assignment_schema(case):
    args = legacy_args(case)
    other = fixture("claude_code")["inventory"].selections[0]
    auth = replace(args["authorization"], selection_sha256=other.digest)
    with pytest.raises(ValueError):
        har.bind_codex(case["value"], other, auth)
    with pytest.raises(ValueError):
        har.bind_codex(replace(case["value"], runtime="claude_code"), other, auth)


def test_import_binding_and_advice_do_not_start_processes_network_or_native_adapter(
    monkeypatch,
):
    args = fixture()

    def forbidden(*_args, **_kwargs):
        pytest.fail("effect attempted")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(native_codex, "arguments", forbidden)
    monkeypatch.setattr(native_codex, "execute", forbidden)
    monkeypatch.setattr(ca, "advise", forbidden)
    assert checked(**args)["status"] == "OFFLINE_BINDING_MATCH"
    har.bind(args["inventory"].selections[0], args["authorization"])


@pytest.mark.parametrize("resume", [False, True])
def test_native_gate_still_refuses_before_any_inspection(resume):
    with pytest.raises(PrepareError) as error:
        native_codex.execute(None, None, None, resume=resume)
    assert error.value.code == 13


def test_normalized_result_contains_no_native_output_paths_or_freeform_errors(
    monkeypatch,
):
    args = fixture()

    def fail(_value):
        raise OSError("secret /private/home credentials")

    monkeypatch.setattr(har, "digest", fail)
    result = checked(**args)
    assert result["status"] == "BLOCKED"
    raw = har.encoded(result)
    for value in (
        b"secret",
        b"/private",
        b"credentials",
        b"agent_fixture",
        b"account_fixture",
    ):
        assert value not in raw


def test_published_normalized_assignment_and_result_fixtures_match_closed_contracts():
    schema = json.loads((DOCS / "harness-admission.schema.json").read_text())
    examples = json.loads((DOCS / "harness-admission.examples.json").read_text())
    assert set(examples) == {"schema", "evidence", "cases"}
    assert examples["schema"] == "AP-HAR-FIXTURES/1"
    assert examples["evidence"] == "EXAMPLE_ONLY"
    assert set(examples["cases"]) == {
        "codex",
        "claude_code",
        "claude_parser_unverified",
        "stale_continuity",
    }
    for harness in ("codex", "claude_code"):
        example = examples["cases"][harness]
        args = fixture(harness)
        assert example["assignment"] == args["assignment"].record()
        assert example["selection"] == args["inventory"].selections[0].record()
        assert example["result"] == checked(**args)
    for example in examples["cases"].values():
        assert design_matches(example["result"], schema)
    assert set(schema["properties"]["reason"]["enum"]) == har.REASONS | {
        "binding_snapshot_only"
    }
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"launch_allowed": True},
        {"reserved": True},
        {"runtime_exit_code": 0},
        {"host_evidence": "HOST_PASS"},
        {"reason": "untrusted error text"},
        {"native_output": "secret"},
        {"status": "READY"},
    ],
)
def test_result_schema_rejects_authority_promotions_or_unredacted_output(change):
    schema = json.loads((DOCS / "harness-admission.schema.json").read_text())
    assert not design_matches(checked(**fixture()) | change, schema)


def test_unrecognized_internal_blocked_exception_is_redacted(monkeypatch):
    args = fixture()

    def fail(_value):
        raise har.Blocked("secret /private/path")

    monkeypatch.setattr(har, "digest", fail)
    result = checked(**args)
    assert result["reason"] == "invalid_contract"
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("target", ["inventory", "assignment", "authorization"])
def test_input_digest_bracketing_detects_mid_check_drift(monkeypatch, target):
    args = fixture()
    original = har.digest
    calls = 0

    def changing(value):
        nonlocal calls
        calls += 1
        result = original(value)
        # Drift after the initial snapshots, while checking the approval.
        if calls == 5:
            if target == "inventory":
                object.__setattr__(args[target], "generation_sha256", "f" * 64)
            elif target == "assignment":
                object.__setattr__(args[target], "assignment_ref", "other_attempt")
            else:
                object.__setattr__(args[target], "task_identity_sha256", "f" * 64)
        return result

    monkeypatch.setattr(har, "digest", changing)
    assert checked(**args)["status"] == "BLOCKED"


def test_document_links_resolve_without_network_and_typed_api_has_no_harness_override():
    import inspect
    import re

    document = (DOCS / "harness-admission.md").read_text()
    for link in re.findall(r"\]\(([^)]+)\)", document):
        if not link.startswith("https://"):
            assert (DOCS / link.split("#", 1)[0]).is_file()
    assert "harness_id" not in inspect.signature(har.bind).parameters
    assert "harness_id" not in {field.name for field in fields(har.TaskAuthorization)}


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_new_approved_operator_epoch_invalidates_old_assignment_instead_of_migrating(
    harness,
):
    args = fixture(harness)
    inventory = args["inventory"]
    old = inventory.selections[0]
    next_selection = replace(
        old,
        binding=replace(old.binding, selection_epoch=2),
        previous_selection_sha256=old.digest,
    )
    caps = replace(inventory.capabilities, binding=next_selection.binding)
    approval = replace(
        inventory.approval,
        selection_sha256=next_selection.digest,
        capabilities_sha256=caps.digest,
    )
    args["inventory"] = replace(
        inventory,
        selections=(next_selection,),
        capabilities=caps,
        approval=approval,
        generation_sha256="f" * 64,
    )
    args["expected_generation_sha256"] = "f" * 64
    args["expected_selection_sha256"] = next_selection.digest
    assert checked(**args)["reason"] == "binding_mismatch"
    assert args["assignment"].binding.selection_epoch == 1


def test_import_has_no_process_network_or_adapter_effect(monkeypatch):
    import importlib.util
    import sys

    def forbidden(*_args, **_kwargs):
        pytest.fail("import effect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(native_codex, "execute", forbidden)
    monkeypatch.setattr(ca, "advise", forbidden)
    # Execute a private copy of the module. Reloading `har` would rebind its enum
    # classes in the shared module and break every test module that already holds
    # the original HarnessId (order-dependent failures).
    name = "agent_platform._harness_admission_import_probe"
    spec = importlib.util.spec_from_file_location(name, har.__file__)
    probe = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, probe)
    spec.loader.exec_module(probe)
    assert probe.HarnessId is not har.HarnessId
    assert har.HarnessId.__module__ == "agent_platform.harness_admission"
    assert checked(**fixture())["status"] == "OFFLINE_BINDING_MATCH"
