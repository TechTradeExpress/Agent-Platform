"""HAR-01 document fixtures only: no runtime validator or authenticated admission.

The deliberately small schema interpreter below accepts only the keywords used
by the checked-in schema. It is test infrastructure, not a general JSON Schema
implementation. Unknown keywords fail the test instead of being ignored.
"""

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
SCHEMA = json.loads((DOCS / "harness-contract.schema.json").read_text())
MATRIX = json.loads((DOCS / "harness-capabilities.json").read_text())
EXAMPLES = json.loads((DOCS / "harness-contract.examples.json").read_text())
ZERO = "0" * 64


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def matches(value, schema):
    """Strict subset interpreter, including JSON integer != bool and closed keys."""
    supported = {
        "$ref",
        "$schema",
        "$id",
        "title",
        "$defs",
        "oneOf",
        "not",
        "const",
        "enum",
        "type",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
        "properties",
        "required",
        "additionalProperties",
    }
    assert not set(schema) - supported
    if "$ref" in schema:
        assert set(schema) == {"$ref"}
        return matches(value, SCHEMA["$defs"][schema["$ref"].removeprefix("#/$defs/")])
    if "oneOf" in schema:
        if sum(matches(value, option) for option in schema["oneOf"]) != 1:
            return False
    if "not" in schema and matches(value, schema["not"]):
        return False
    if "const" in schema:
        if type(value) is not type(schema["const"]) or value != schema["const"]:
            return False
    if "enum" in schema:
        if not any(
            type(value) is type(item) and value == item for item in schema["enum"]
        ):
            return False
    types = {"object": dict, "integer": int, "string": str}
    if "type" in schema and type(value) is not types[schema["type"]]:
        return False
    if type(value) is dict:
        if not set(schema.get("required", ())) <= set(value):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        if any(
            not matches(value[key], sub)
            for key, sub in properties.items()
            if key in value
        ):
            return False
    if type(value) is str:
        if (
            not schema.get("minLength", 0)
            <= len(value)
            <= schema.get("maxLength", len(value))
        ):
            return False
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            return False
    if type(value) is int:
        if not schema.get("minimum", value) <= value <= schema.get("maximum", value):
            return False
    return True


def check_record(value):
    assert matches(value, SCHEMA)
    assert len(encoded(value)) <= 16 * 1024


def rehash(chain):
    """Repair only fixture hash correlations, never mismatch fields."""
    chain["assignment"]["selection_sha256"] = digest(chain["selection"])
    for record in [chain["session"], *chain["events"]]:
        record["assignment_sha256"] = digest(chain["assignment"])


def check_fixture_chain(chain, previous=None):
    """Cross-record design invariants, not trust/provenance/launch validation."""
    selection, assignment, session = (
        chain[key] for key in ("selection", "assignment", "session")
    )
    binding = selection["binding"]
    for record in [MATRIX, selection, assignment, session, *chain["events"]]:
        check_record(record)
    assert selection["state"] == "SELECTED"
    assert binding["capability_matrix_sha256"] == digest(MATRIX)
    epoch = binding["selection_epoch"]
    if previous is None:
        assert epoch == 1 and selection["previous_selection_sha256"] == ZERO
    else:
        check_record(previous)
        assert epoch == previous["binding"]["selection_epoch"] + 1
        assert selection["previous_selection_sha256"] == digest(previous)
        assert binding["worker_ref"] == previous["binding"]["worker_ref"]
    assert assignment["selection_sha256"] == digest(selection)
    assert session["assignment_sha256"] == digest(assignment)
    assert all(
        record["binding"] == binding
        for record in [assignment, session, *chain["events"]]
    )
    events = chain["events"]
    assert 0 < len(events) <= 10_000
    assert sum(len(encoded(event)) for event in events) <= 1024 * 1024
    allowed = {
        None: {"STARTING", "BLOCKED"},
        "STARTING": {"RUNNING", "NEEDS_HUMAN"},
        "RUNNING": {"COMPLETED", "PAUSED", "NEEDS_HUMAN"},
    }
    state = None
    for seq, event in enumerate(events, 1):
        assert event["seq"] == seq
        assert event["session_ref"] == session["session_ref"]
        assert event["assignment_sha256"] == digest(assignment)
        assert event["state"] in allowed.get(state, set())
        state = event["state"]
    return state


def check_resume_fixture(chain, parent, checkpoint_digest):
    check_fixture_chain(chain)
    assert check_fixture_chain(parent) == "PAUSED"
    assert chain["session"]["mode"] == "RESUME"
    assert chain["session"]["parent_checkpoint_sha256"] == checkpoint_digest != ZERO
    assert (
        chain["session"]["native_session_sha256"]
        == parent["session"]["native_session_sha256"]
    )
    for key in (
        "binding",
        "task_authorization_sha256",
        "model_policy_sha256",
        "account_policy_ref",
    ):
        assert chain["assignment"][key] == parent["assignment"][key]
    assert (
        chain["assignment"]["assignment_ref"] != parent["assignment"]["assignment_ref"]
    )


@pytest.mark.parametrize("harness", ["codex", "claude_code"])
def test_fabricated_bindings_are_closed_correlated_and_never_grant_execution(harness):
    chain = EXAMPLES[harness]
    assert check_fixture_chain(chain) == "BLOCKED"
    assert encoded(chain) == encoded(json.loads(encoded(chain)))
    assert all(
        record["launch_allowed"] is False
        for record in [
            chain["selection"],
            chain["assignment"],
            chain["session"],
            *chain["events"],
            MATRIX,
        ]
    )


def test_every_object_is_closed_and_all_properties_required():
    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(SCHEMA)
    assert SCHEMA["$defs"]["HarnessId"] == {"enum": ["codex", "claude_code"]}


@pytest.mark.parametrize(
    "value", ["Codex", "claude", "auto", "gpt", "", None, ["codex", "claude_code"]]
)
def test_unknown_alias_model_or_multiple_harness_ids_rejected(value):
    record = copy.deepcopy(EXAMPLES["codex"]["selection"])
    record["binding"]["harness_id"] = value
    assert not matches(record, SCHEMA)


@pytest.mark.parametrize("record_name", ["selection", "assignment", "session"])
def test_missing_extra_unknown_schema_and_execution_authority_rejected(record_name):
    original = EXAMPLES["codex"][record_name]
    for mutation in (
        lambda r: r.pop("binding"),
        lambda r: r.update(schema="AP-UNKNOWN/2"),
        lambda r: r.update(launch_allowed=True),
        lambda r: r.update(credentials="forbidden"),
    ):
        record = copy.deepcopy(original)
        mutation(record)
        assert not matches(record, SCHEMA)


@pytest.mark.parametrize("value", [True, 1.0, 0, -1, 2**63, "1"])
def test_selection_epoch_is_bounded_exact_integer(value):
    record = copy.deepcopy(EXAMPLES["codex"]["selection"])
    record["binding"]["selection_epoch"] = value
    assert not matches(record, SCHEMA)


@pytest.mark.parametrize("key", list(SCHEMA["$defs"]["binding"]["properties"]))
def test_each_assignment_binding_drift_is_rejected_even_with_recomputed_hashes(key):
    chain = copy.deepcopy(EXAMPLES["codex"])
    other = chain["assignment"]["binding"]
    if key == "selection_epoch":
        other[key] = 2
    elif key.endswith("sha256"):
        other[key] = ZERO
    elif key == "harness_id":
        other[key] = "claude_code"
    else:
        other[key] += "_changed"
    rehash(chain)
    with pytest.raises(AssertionError):
        check_fixture_chain(chain)


@pytest.mark.parametrize("state", ["QUIESCING", "RECONCILING", "BLOCKED"])
def test_nonselected_workers_cannot_have_eligible_assignment_snapshot(state):
    chain = copy.deepcopy(EXAMPLES["codex"])
    chain["selection"]["state"] = state
    rehash(chain)
    with pytest.raises(AssertionError):
        check_fixture_chain(chain)


def test_next_selection_requires_previous_digest_and_exact_increment():
    chain = copy.deepcopy(EXAMPLES["claude_code"])
    previous = EXAMPLES["codex"]["selection"]
    for record in [
        chain["selection"],
        chain["assignment"],
        chain["session"],
        *chain["events"],
    ]:
        record["binding"]["selection_epoch"] = 2
    chain["selection"]["previous_selection_sha256"] = digest(previous)
    rehash(chain)
    check_fixture_chain(chain, previous)
    for bad in (0, 1, 3):
        broken = copy.deepcopy(chain)
        for record in [
            broken["selection"],
            broken["assignment"],
            broken["session"],
            *broken["events"],
        ]:
            record["binding"]["selection_epoch"] = bad
        rehash(broken)
        with pytest.raises(AssertionError):
            check_fixture_chain(broken, previous)
    chain["selection"]["previous_selection_sha256"] = ZERO
    rehash(chain)
    with pytest.raises(AssertionError):
        check_fixture_chain(chain, previous)


@pytest.mark.parametrize(
    "field",
    ["schema", "native_event_parser", "product_execution", "unknown_capability"],
)
def test_capability_matrix_is_closed_and_cannot_promote_evidence(field):
    matrix = copy.deepcopy(MATRIX)
    if field == "schema":
        matrix[field] = "AP-HCAP/2"
    else:
        matrix["claude_code"][field] = "SUPPORTED"
    assert not matches(matrix, SCHEMA)


@pytest.mark.parametrize(
    "state,reason",
    [
        ("COMPLETED", "OUTCOME_UNKNOWN"),
        ("PAUSED", "NONE"),
        ("NEEDS_HUMAN", "NONE"),
        ("BLOCKED", "NATIVE_TURN_FAILED"),
        ("RUNNING", "AUTH_UNVERIFIED"),
        ("SUCCESS", "NONE"),
    ],
)
def test_events_reject_ambiguous_or_unknown_state_reason_pairs(state, reason):
    event = copy.deepcopy(EXAMPLES["codex"]["events"][0])
    event.update(state=state, reason=reason)
    assert not matches(event, SCHEMA)


@pytest.mark.parametrize(
    "field,value",
    [
        ("seq", True),
        ("seq", 0),
        ("seq", 2**63),
        ("usage", 0),
        ("stderr", "sensitive"),
        ("native_session_id", "private"),
        ("message", "account data"),
        ("home", "/private"),
        ("launch_allowed", True),
    ],
)
def test_event_redaction_and_bounds_are_closed(field, value):
    event = copy.deepcopy(EXAMPLES["codex"]["events"][0])
    event[field] = value
    assert not matches(event, SCHEMA)


@pytest.mark.parametrize(
    "mutation", ["duplicate", "gap", "session", "post_terminal", "truncated_success"]
)
def test_invalid_event_correlation_order_and_terminal_replay(mutation):
    chain = copy.deepcopy(EXAMPLES["codex"])
    event = chain["events"][0]
    if mutation == "duplicate":
        chain["events"].append(copy.deepcopy(event))
    elif mutation == "gap":
        event["seq"] = 2
    elif mutation == "session":
        event["session_ref"] = "other_session"
    elif mutation == "post_terminal":
        chain["events"].append(dict(event, seq=2))
    else:
        event.update(state="COMPLETED", reason="NONE")
    with pytest.raises(AssertionError):
        check_fixture_chain(chain)


def paused_fixture():
    chain = copy.deepcopy(EXAMPLES["codex"])
    base = chain["events"][0]
    chain["events"] = [
        dict(base, seq=seq, state=state, reason=reason)
        for seq, state, reason in (
            (1, "STARTING", "NONE"),
            (2, "RUNNING", "NONE"),
            (3, "PAUSED", "NATIVE_TURN_FAILED"),
        )
    ]
    return chain


def resume_fixture(parent):
    chain = copy.deepcopy(parent)
    chain["assignment"]["assignment_ref"] = "fresh_attempt_fixture"
    chain["session"].update(mode="RESUME", parent_checkpoint_sha256="b" * 64)
    rehash(chain)
    return chain


def test_explicit_same_namespace_resume_fixture_preserves_all_policy_pins():
    parent = paused_fixture()
    check_resume_fixture(resume_fixture(parent), parent, "b" * 64)


@pytest.mark.parametrize(
    "key",
    [
        "harness_id",
        "worker_ref",
        "enrollment_ref",
        "selection_epoch",
        "configuration_sha256",
        "executable_manifest_sha256",
        "parser_sha256",
        "instructions_sha256",
        "isolation_profile_sha256",
    ],
)
def test_cross_harness_worker_epoch_or_configuration_resume_rejected(key):
    parent = paused_fixture()
    chain = resume_fixture(parent)
    replacement = 2 if key == "selection_epoch" else "f" * 64
    if key == "harness_id":
        replacement = "claude_code"
    if key in {"worker_ref", "enrollment_ref"}:
        replacement = "other_fixture"
    for record in [
        chain["selection"],
        chain["assignment"],
        chain["session"],
        *chain["events"],
    ]:
        record["binding"][key] = replacement
    rehash(chain)
    with pytest.raises(AssertionError):
        check_resume_fixture(chain, parent, "b" * 64)


@pytest.mark.parametrize(
    "field", ["task_authorization_sha256", "model_policy_sha256", "account_policy_ref"]
)
def test_resume_cannot_switch_task_model_or_native_account_policy(field):
    parent = paused_fixture()
    chain = resume_fixture(parent)
    chain["assignment"][field] = (
        "c" * 64 if field.endswith("sha256") else "other_account"
    )
    rehash(chain)
    with pytest.raises(AssertionError):
        check_resume_fixture(chain, parent, "b" * 64)


def test_unknown_parent_outcome_and_missing_resume_checkpoint_are_rejected():
    parent = paused_fixture()
    chain = resume_fixture(parent)
    parent["events"][-1].update(state="NEEDS_HUMAN", reason="OUTCOME_UNKNOWN")
    with pytest.raises(AssertionError):
        check_resume_fixture(chain, parent, "b" * 64)
    chain["session"]["parent_checkpoint_sha256"] = ZERO
    assert not matches(chain["session"], SCHEMA)


def test_document_links_are_local_valid_and_no_competing_instruction_file_added():
    adr = (DOCS / "multi-harness-architecture.md").read_text()
    for link in re.findall(r"\]\(([^)]+)\)", adr):
        if not link.startswith("https://"):
            assert (DOCS / link.split("#", 1)[0]).is_file()
    assert "--ignore-rules" in adr and "UNVERIFIED" in adr
    for name in ("CLAUDE.md", "CLAUDE.local.md"):
        assert not (DOCS.parent / name).exists()
    assert (DOCS.parent / "AGENTS.md").is_file()


def decode_document_record(raw):
    """Exercise the proposed strict JSON boundary on synthetic bytes only."""
    assert type(raw) is bytes and len(raw) <= 16 * 1024

    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("nonfinite_json")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    pending = [(value, 1)]
    while pending:
        node, depth = pending.pop()
        assert depth <= 8
        children = (
            node.values() if type(node) is dict else node if type(node) is list else ()
        )
        pending.extend((child, depth + 1) for child in children)
    check_record(value)
    return value


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"AP-HSEL/1","schema":"AP-HSEL/1"}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b"[" * 9 + b"0" + b"]" * 9,
        b" " * (16 * 1024 + 1),
        b"\xff",
        b'{"incomplete":',
    ],
)
def test_duplicate_nonfinite_deep_oversized_invalid_json_rejected(raw):
    with pytest.raises((AssertionError, ValueError, UnicodeError)):
        decode_document_record(raw)


def test_example_json_records_round_trip_through_strict_document_boundary():
    for chain in EXAMPLES.values():
        for record in [
            chain["selection"],
            chain["assignment"],
            chain["session"],
            *chain["events"],
            MATRIX,
        ]:
            assert decode_document_record(encoded(record)) == record
