"""HAR-07 / ADR 010 contract: offline documents, a closed schema and synthetic models.

Nothing here touches a provider CLI, network, credential or host. The reference
evaluator and the lifecycle model are test infrastructure that restate the documented
rules; they are not shipped code and prove nothing about a real host. The mini schema
interpreter fails on any keyword it does not know, so none can be silently ignored.
"""

import hashlib
import itertools
import json
import re
import subprocess
from pathlib import Path

import pytest

from agent_platform import instruction_sources

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ADR_PATH = DOCS / "trusted-harness-invocation-no-go.md"
ADR = ADR_PATH.read_text()
FLAT = " ".join(ADR.split()).replace("**", "")
SCHEMA = json.loads((DOCS / "harness-invocation-evidence.schema.json").read_text())
EXAMPLES = json.loads((DOCS / "harness-invocation-evidence.examples.json").read_text())
FIXTURE = json.loads((DOCS / "harness-invocation-scenarios.json").read_text())
AP_SM2_SHA256 = "1b3c2f8faa8fd4a2f89cd2c10bf01acfcadda3516231efb568f2c0d7833d3bd9"
SUPPORTED_KEYS = {
    "$schema",
    "$id",
    "title",
    "type",
    "const",
    "enum",
    "pattern",
    "minimum",
    "maximum",
    "maxItems",
    "minItems",
    "uniqueItems",
    "oneOf",
    "allOf",
    "contains",
    "minContains",
    "maxContains",
    "items",
    "properties",
    "required",
    "additionalProperties",
}


def matches(value, schema):
    assert not set(schema) - SUPPORTED_KEYS
    if "const" in schema and (
        type(value) is not type(schema["const"]) or value != schema["const"]
    ):
        return False
    if "enum" in schema and not any(
        type(value) is type(item) and value == item for item in schema["enum"]
    ):
        return False
    kind = schema.get("type")
    if kind:
        python = {"object": dict, "array": list, "string": str, "integer": int}[kind]
        if type(value) is not python:
            return False
    if "pattern" in schema and not re.search(schema["pattern"], value):
        return False
    if "oneOf" in schema and sum(matches(value, o) for o in schema["oneOf"]) != 1:
        return False
    if "allOf" in schema and not all(matches(value, a) for a in schema["allOf"]):
        return False
    assert "contains" in schema or not {"minContains", "maxContains"} & set(schema)
    if "contains" in schema:
        found = sum(matches(item, schema["contains"]) for item in value)
        if found < schema.get("minContains", 1):
            return False
        if found > schema.get("maxContains", len(value)):
            return False
    if "minItems" in schema and len(value) < schema["minItems"]:
        return False
    if schema.get("uniqueItems") and len({json.dumps(i) for i in value}) != len(value):
        return False
    if "minimum" in schema and value < schema["minimum"]:
        return False
    if "maximum" in schema and value > schema["maximum"]:
        return False
    if "maxItems" in schema and len(value) > schema["maxItems"]:
        return False
    if "items" in schema and not all(matches(item, schema["items"]) for item in value):
        return False
    if kind == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        if any(key not in value for key in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(matches(value[k], properties[k]) for k in value if k in properties)
    return True


def test_mini_interpreter_rejects_unknown_keywords_and_dangling_contains():
    for schema in ({"unknownKeyword": 1}, {"prefixItems": []}, {"$ref": "#"}):
        with pytest.raises(AssertionError):
            matches(1, schema)
    with pytest.raises(AssertionError):
        matches([1], {"minContains": 1})
    with pytest.raises(AssertionError):
        matches([1], {"maxContains": 1})
    once = {"contains": {"const": 1}, "minContains": 1, "maxContains": 1}
    assert (
        matches([1, 2], once) and not matches([2], once) and not matches([1, 1], once)
    )


def table_rows(heading, first_cell):
    """Rows of the first table after ``heading`` whose first cell matches the regex."""
    section = ADR.split(heading, 1)[1]
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if line.startswith("| ") and re.fullmatch(first_cell, cells[0]):
            rows.append(cells)
        elif rows and not line.startswith("|"):
            break
    return rows


CHECK_IDS = SCHEMA["properties"]["checks"]["items"]["properties"]["check_id"]["enum"]


# --------------------------------------------------------------------------- schema


def test_valid_examples_pass_and_invalid_examples_fail():
    assert set(EXAMPLES["valid"]) >= {
        "worker01_codex_current",
        "worker02_claude_current",
        "synthetic_fixture_still_no_go",
        "operator_attested_still_no_go",
        "all_independently_verified_future_shape_still_no_go",
    }
    for name, record in EXAMPLES["valid"].items():
        assert matches(record, SCHEMA), name
    assert len(EXAMPLES["invalid"]) >= 40
    for name, record in EXAMPLES["invalid"].items():
        assert not matches(record, SCHEMA), name


def test_schema_is_closed_and_defines_no_go_state():
    props = SCHEMA["properties"]
    assert SCHEMA["additionalProperties"] is False
    assert props["overall"] == {"const": "NO_GO"}
    assert props["launch_allowed"] == {"const": False}
    assert props["production_go"] == {"const": False}
    assert props["inherited_approval"] == {"const": False}
    assert props["worker_ref"]["enum"] == ["worker01", "worker02"]
    assert props["harness_id"]["enum"] == ["codex", "claude_code"]
    gates = props["gates"]["properties"]
    assert set(gates) == {"vendor_permission_a", "isolation_b", "operator_approval_c"}
    for gate in gates.values():
        assert gate["additionalProperties"] is False
        assert not {"GO", "SATISFIED", "PASS", "READY"} & set(
            gate["properties"]["status"]["enum"]
        )
    check = props["checks"]["items"]
    assert check["additionalProperties"] is False
    assert set(check["required"]) == set(check["properties"])
    assert (
        len(CHECK_IDS)
        == 25
        == props["checks"]["minItems"]
        == props["checks"]["maxItems"]
    )
    assert CHECK_IDS == [f"HC-{n:02d}" for n in range(1, 26)]
    dump = json.dumps(SCHEMA).lower()
    for forbidden in ("token", "secret", "password", "email", "prompt", "transcript"):
        assert f'"{forbidden}' not in dump


def test_examples_cover_every_check_exactly_once_and_stay_no_go():
    for name, record in EXAMPLES["valid"].items():
        assert [c["check_id"] for c in record["checks"]] == CHECK_IDS, name
        assert record["overall"] == "NO_GO", name
        assert record["launch_allowed"] is False, name
        assert record["production_go"] is False, name
        assert record["inherited_approval"] is False, name
    workers = {r["worker_ref"] for r in EXAMPLES["valid"].values()}
    assert workers == {"worker01", "worker02"}


def valid_check_forms(cid):
    """Several different, individually valid check objects for one identifier."""
    evidence = ["a" * 64]
    return [
        {
            "check_id": cid,
            "status": status,
            "origin": origin,
            "evidence_sha256": ev,
            "observed_date": date,
            "verification_ref": ref,
        }
        for status, origin, ev, date, ref in (
            ("HOST_NOT_RUN", "NONE", [], "NONE", "NONE"),
            ("BLOCKED", "NONE", [], "NONE", "NONE"),
            ("SOURCE_ONLY", "SOURCE_REVIEW", evidence, "2026-11-17", "NONE"),
            ("DISPOSABLE_FIXTURE", "DISPOSABLE_VM", evidence, "2026-11-17", "NONE"),
        )
    ]


def test_every_check_id_is_enforced_exactly_once_by_the_schema():
    checks = SCHEMA["properties"]["checks"]
    assert [
        a["contains"]["properties"]["check_id"]["const"] for a in checks["allOf"]
    ] == (CHECK_IDS)
    for entry in checks["allOf"]:
        assert entry["minContains"] == entry["maxContains"] == 1
        assert entry["contains"]["required"] == ["check_id"]
    assert checks["minItems"] == checks["maxItems"] == len(CHECK_IDS)
    base = EXAMPLES["valid"]["worker02_claude_current"]
    for permuted in (
        list(reversed(base["checks"])),
        base["checks"][1:] + base["checks"][:1],
    ):
        # order is not part of the contract; only exact membership is
        assert matches({**base, "checks": permuted}, SCHEMA)


def test_duplicate_identifier_with_a_different_valid_status_is_rejected():
    base = EXAMPLES["valid"]["worker02_claude_current"]
    rejected = 0
    for position in range(25):
        for other in range(25):
            if other == position:
                continue
            for form in valid_check_forms(CHECK_IDS[other]):
                assert matches(form, SCHEMA["properties"]["checks"]["items"])
                checks = list(base["checks"])
                checks[position] = form
                record = {**base, "checks": checks}
                assert len(checks) == 25
                assert len({c["check_id"] for c in checks}) == 24
                assert not matches(record, SCHEMA), (position, other, form["status"])
                rejected += 1
    assert rejected == 25 * 24 * 4


def test_reviewer_scenario_hc_25_replaced_by_a_second_hc_01_is_rejected():
    base = EXAMPLES["valid"]["worker02_claude_current"]
    assert base["checks"][24]["check_id"] == "HC-25"
    for form in valid_check_forms("HC-01"):
        record = {**base, "checks": [*base["checks"][:24], form]}
        assert len(record["checks"]) == 25
        assert len({c["check_id"] for c in record["checks"]}) == 24
        assert not matches(record, SCHEMA)


def test_removing_any_single_check_or_adding_an_unknown_one_is_rejected():
    base = EXAMPLES["valid"]["worker02_claude_current"]
    for index in range(25):
        checks = [c for i, c in enumerate(base["checks"]) if i != index]
        assert not matches({**base, "checks": checks}, SCHEMA), CHECK_IDS[index]
        unknown = valid_check_forms("HC-26")[0]
        assert not matches({**base, "checks": [*checks, unknown]}, SCHEMA)
        restored = [*checks, base["checks"][index]]
        assert matches({**base, "checks": restored}, SCHEMA)  # exact set again
    assert not matches({**base, "checks": []}, SCHEMA)


def test_duplicate_examples_cover_the_identifier_gap():
    names = set(EXAMPLES["invalid"])
    assert {
        "duplicate_id_replaces_last_different_status",
        "duplicate_id_in_the_middle",
        "first_check_replaced_by_last",
        "missing_hc_13_with_extra_hc_14",
        "hc_26_replaces_hc_25",
    } <= names
    for name in names:
        record = EXAMPLES["invalid"][name]
        if name.startswith(("duplicate_id", "first_check", "missing_hc_13")):
            assert len(record["checks"]) == 25
            assert len({c["check_id"] for c in record["checks"]}) < 25


def reference_check_ok(status, origin, evidence, date, ref):
    """Independent restatement of the per-check status/origin matrix."""
    real_date = date != "NONE"
    if status in {"HOST_NOT_RUN", "NOT_PROVEN", "BLOCKED"} and origin == "NONE":
        return not evidence and not real_date and ref == "NONE"
    if status in {"NOT_PROVEN", "BLOCKED", "SOURCE_ONLY"}:
        return origin == "SOURCE_REVIEW" and evidence and real_date and ref == "NONE"
    if status == "DISPOSABLE_FIXTURE":
        return (
            origin in {"SYNTHETIC_FIXTURE", "DISPOSABLE_VM"}
            and evidence
            and real_date
            and ref == "NONE"
        )
    if status == "OPERATOR_ATTESTED_UNAUTHENTICATED":
        return (
            origin == "OPERATOR_STATEMENT" and evidence and real_date and ref == "NONE"
        )
    if status == "INDEPENDENTLY_VERIFIED":
        return (
            origin == "INDEPENDENT_HOST_OBSERVATION"
            and evidence
            and real_date
            and ref != "NONE"
        )
    return False


def test_every_status_origin_combination_matches_the_reference_matrix():
    check_schema = SCHEMA["properties"]["checks"]["items"]
    statuses = check_schema["properties"]["status"]["enum"]
    origins = check_schema["properties"]["origin"]["enum"]
    accepted = 0
    for status, origin, n_ev, date, ref in itertools.product(
        statuses, origins, (0, 1), ("NONE", "2026-11-17"), ("NONE", "review.2026-12.01")
    ):
        evidence = ["a" * 64] * n_ev
        record = {
            "check_id": "HC-01",
            "status": status,
            "origin": origin,
            "evidence_sha256": evidence,
            "observed_date": date,
            "verification_ref": ref,
        }
        expected = bool(reference_check_ok(status, origin, evidence, date, ref))
        assert matches(record, check_schema) is expected, record
        if expected:
            accepted += 1
            if origin in {
                "NONE",
                "SYNTHETIC_FIXTURE",
                "SOURCE_REVIEW",
                "DISPOSABLE_VM",
            }:
                assert status != "INDEPENDENTLY_VERIFIED"
    assert accepted == 10


@pytest.mark.parametrize(
    ("date", "ok"),
    [
        ("2026-11-17", True),
        ("2028-02-29", True),
        ("2000-02-29", True),
        ("2027-02-29", False),
        ("2026-02-30", False),
        ("2026-04-31", False),
        ("2026-13-01", False),
        ("2026-00-10", False),
        ("1999-12-31", False),
        ("2100-01-01", False),
        ("26-11-17", False),
        ("NONE", False),
    ],
)
def test_observed_dates_must_be_real_calendar_dates(date, ok):
    record = {
        "check_id": "HC-01",
        "status": "SOURCE_ONLY",
        "origin": "SOURCE_REVIEW",
        "evidence_sha256": ["a" * 64],
        "observed_date": date,
        "verification_ref": "NONE",
    }
    assert matches(record, SCHEMA["properties"]["checks"]["items"]) is ok


# ------------------------------------------------- document, schema and fixture parity

CHECK_DOC_ROWS = table_rows("Closed set of 25 readiness checks", r"HC-\d\d")
WORKER_ROWS = table_rows("### worker01 (considered first)", r"HC-\d\d")


def test_check_table_matches_schema_and_examples():
    assert [r[0] for r in CHECK_DOC_ROWS] == CHECK_IDS
    assert [r[0] for r in WORKER_ROWS] == CHECK_IDS
    current = {
        c["check_id"]: c["status"]
        for c in EXAMPLES["valid"]["worker02_claude_current"]["checks"]
    }
    other = {
        c["check_id"]: c["status"]
        for c in EXAMPLES["valid"]["worker01_codex_current"]["checks"]
    }
    assert current == other
    for row in CHECK_DOC_ROWS:
        assert row[1].strip("`") != "" and row[3] in {"A", "B", "C", "-"}
        assert row[5] == current[row[0]], row
    for row in WORKER_ROWS:
        assert row[2] == row[3] == current[row[0]], row
    statuses = set(current.values())
    assert statuses <= {"SOURCE_ONLY", "HOST_NOT_RUN", "NOT_PROVEN", "BLOCKED"}
    assert "INDEPENDENTLY_VERIFIED" not in statuses
    # decision A, C and the blocked items stay unproven for both workers
    for cid in ("HC-07", "HC-10", "HC-17"):
        assert current[cid] == "BLOCKED"
    for cid in ("HC-05", "HC-19"):
        assert current[cid] == "NOT_PROVEN"
    for cid in ("HC-06", "HC-14", "HC-20", "HC-24"):
        assert current[cid] == "HOST_NOT_RUN"


def test_every_check_has_an_existing_future_issue_owner():
    fi_rows = table_rows("## Order of future implementation Issues", r"FI-\d\d")
    fi_ids = [r[0] for r in fi_rows]
    assert fi_ids == [f"FI-{n:02d}" for n in range(1, 14)]
    for row in CHECK_DOC_ROWS:
        for owner in row[4].split(", "):
            assert owner in fi_ids, row
    # FI-01 (scanner correction) precedes every host-facing Issue
    assert fi_ids.index("FI-01") < fi_ids.index("FI-10") < fi_ids.index("FI-11")
    assert fi_rows[-1][1].startswith("GO-state ADR")
    for row in fi_rows:
        assert row[3] and row[4]


# ------------------------------------------------------------- reference evaluator

DECISIONS = {"STOP", "BLOCKED", "DENY", "NEEDS_HUMAN", "NO_GO"}
LAUNCH_ACTIONS = {"request_launch", "resume", "rotate_harness"}
DENIED_ACTIONS = {
    "task_selects_harness": ("DENY", "HARNESS_SWITCH_DENIED"),
    "switch_harness_on_failure": ("DENY", "HARNESS_SWITCH_DENIED"),
    "claim_ready": ("DENY", "READY_NOT_HARNESS"),
    "merge": ("DENY", "MERGE_HUMAN_ONLY"),
}
HARNESSES = {"codex", "claude_code"}


def decide(f):
    """Reference evaluator of ADR 010; it can never return a GO."""
    if f["action"] in DENIED_ACTIONS:
        return DENIED_ACTIONS[f["action"]]
    if f["publisher_reachable"]:
        return "BLOCKED", "PUBLISHER_REACHABLE"
    if f["action"] in {"cancel", "timeout"}:
        if not f["process_death_proven"]:
            return "NEEDS_HUMAN", "CANCEL_UNCONFIRMED"
        if not f["effects_reconciled"]:
            return "NEEDS_HUMAN", "OUTCOME_UNKNOWN"
        return "NO_GO", "LAUNCHER_NOT_IMPLEMENTED"
    if f["action"] not in LAUNCH_ACTIONS:
        return "DENY", "ACTION_UNKNOWN"
    if f["harness_selected"] is None:
        return "STOP", "HARNESS_UNSELECTED"
    if f["harness_selected"] not in HARNESSES:
        return "STOP", "HARNESS_AMBIGUOUS"
    ordered = (
        (
            f["assignment_harness"] != f["harness_selected"],
            "STOP",
            "ASSIGNMENT_HARNESS_MISMATCH",
        ),
        (not f["worker_match"], "STOP", "WORKER_MISMATCH"),
        (not f["epoch_match"], "STOP", "EPOCH_MISMATCH"),
        (not f["selection_issuer_verified"], "STOP", "SELECTION_UNAUTHENTICATED"),
        (not f["config_digest_match"], "STOP", "CONFIG_DIGEST_MISMATCH"),
        (f["exe_source"] != "pinned_absolute", "STOP", "EXEC_NOT_PINNED"),
        (f["exec_binding"] != "fd_pinned", "STOP", "EXEC_REOPEN_RACE"),
        (not f["exe_hash_match"], "STOP", "EXEC_HASH_MISMATCH"),
        (not f["release_verified"], "BLOCKED", "RELEASE_UNVERIFIED"),
        (not f["elf_verified"], "BLOCKED", "ELF_UNVERIFIED"),
        # user_level_claude_md is deliberately absent: it is never a conflict
        (f["project_instruction_conflict"], "STOP", "INSTRUCTION_CONFLICT"),
        (not f["agents_load_observed"], "BLOCKED", "LOAD_NOT_OBSERVED"),
        (
            f["harness_selected"] == "claude_code" and not f["scanner_corrected"],
            "BLOCKED",
            "SCANNER_UNCORRECTED",
        ),
        (not f["parser_wire_verified"], "BLOCKED", "PARSER_UNVERIFIED"),
        (f["decision_a"] != "recorded", "BLOCKED", "VENDOR_NOT_PROVEN"),
        (
            f["decision_b"] != "independently_verified",
            "BLOCKED",
            "ISOLATION_NOT_PROVEN",
        ),
        (f["decision_c"] == "inherited", "BLOCKED", "APPROVAL_INHERITED"),
        (f["decision_c"] != "this_worker_epoch", "BLOCKED", "OPERATOR_NOT_APPROVED"),
        (f["ambient_credential"], "BLOCKED", "AMBIENT_CREDENTIAL"),
        (f["api_fallback"], "BLOCKED", "API_FALLBACK_FORBIDDEN"),
        (f["oauth_relay"], "BLOCKED", "OAUTH_RELAY_FORBIDDEN"),
        (f["unsafe_flag"], "BLOCKED", "UNSAFE_FLAG"),
        (not f["mediation_complete"], "BLOCKED", "MEDIATION_INCOMPLETE"),
        (not f["hooks_plugins_mcp_denied"], "BLOCKED", "HOOKS_MCP_PLUGINS_ENABLED"),
        (f["enforcement"] != "active_enforcing", "BLOCKED", "ENFORCEMENT_INACTIVE"),
        (not f["doctor_fresh"], "BLOCKED", "HOST_EVIDENCE_STALE"),
    )
    for failed, decision, code in ordered:
        if failed:
            return decision, code
    if f["action"] == "rotate_harness":
        for failed, code in (
            (f["active_attempts"] > 0, "ROTATION_NOT_DRAINED"),
            (f["unknown_outcome_retained"], "ROTATION_UNRECONCILED"),
            (not f["process_death_proven"], "PROCESS_DEATH_UNPROVEN"),
            (not f["rotation_reattested"], "ROTATION_NOT_REATTESTED"),
            (not f["rotation_approved"], "ROTATION_NOT_APPROVED"),
        ):
            if failed:
                return "BLOCKED", code
        if f["evidence_origin"] != "independent_host":
            return "BLOCKED", "SYNTHETIC_NOT_PROOF"
        return "NO_GO", "ROTATION_NOT_IMPLEMENTED"
    for failed, code in (
        (f["active_attempts"] > 0, "ACTIVE_ATTEMPT_EXISTS"),
        (f["unknown_outcome_retained"], "UNKNOWN_OUTCOME_RETAINED"),
        (f["replay"], "REPLAY_DENIED"),
        (f["action"] == "resume" and f["resume_cross"], "CROSS_HARNESS_RESUME_DENIED"),
        (f["evidence_origin"] != "independent_host", "SYNTHETIC_NOT_PROOF"),
    ):
        if failed:
            return "BLOCKED", code
    return "NO_GO", "LAUNCHER_NOT_IMPLEMENTED"


def facts_of(scenario):
    return {**FIXTURE["defaults"], **scenario["facts"]}


def test_every_scenario_has_its_documented_outcome():
    assert FIXTURE["schema"] == "AP-HINV-SCENARIOS/1"
    ids = [s["id"] for s in FIXTURE["scenarios"]]
    assert ids == [f"S-{n:02d}" for n in range(1, len(ids) + 1)]
    assert len(ids) >= 55
    for s in FIXTURE["scenarios"]:
        assert set(s["facts"]) <= set(FIXTURE["defaults"]), s["id"]
        assert s["expected"]["decision"] in DECISIONS, s["id"]
        assert decide(facts_of(s)) == (
            s["expected"]["decision"],
            s["expected"]["code"],
        ), s["id"]


def test_doc_scenario_table_matches_fixture_exactly():
    rows = table_rows("| ID | Scenario | Decision | Code |", r"S-\d\d")
    fixture = [
        (s["id"], s["title"], s["expected"]["decision"], f"`{s['expected']['code']}`")
        for s in FIXTURE["scenarios"]
    ]
    assert [tuple(r) for r in rows] == fixture


def test_negative_matrix_references_resolve_to_consistent_scenarios():
    by_id = {s["id"]: s for s in FIXTURE["scenarios"]}
    refs = 0
    for row in table_rows("### Negative tests", r"NI-\d\d"):
        expected_cell, status = row[2], row[3]
        for first, last in re.findall(r"S-(\d\d)(?:\.\.S-(\d\d))?", status):
            low, high = int(first), int(last or first)
            for n in range(low, high + 1):
                scenario = by_id[f"S-{n:02d}"]
                refs += 1
                assert scenario["expected"]["decision"] in expected_cell, (
                    row[0],
                    scenario["id"],
                )
    assert refs >= 30


def test_evaluator_never_grants_go_and_only_no_go_when_everything_holds():
    defaults = FIXTURE["defaults"]
    gating = {
        k for k in defaults if k not in {"action", "host", "user_level_claude_md"}
    }
    for scenario in FIXTURE["scenarios"]:
        decision, _ = decide(facts_of(scenario))
        assert decision in DECISIONS and decision != "GO"
    # flipping any single gating fact away from the ideal never yields NO_GO
    flips = {
        "harness_selected": [None, "both", "other"],
        "assignment_harness": ["codex"],
        "worker_match": [False],
        "epoch_match": [False],
        "selection_issuer_verified": [False],
        "config_digest_match": [False],
        "exe_source": ["path_lookup", "alias", "env_override", "personal_install"],
        "exec_binding": ["path_reopen"],
        "exe_hash_match": [False],
        "release_verified": [False],
        "elf_verified": [False],
        "project_instruction_conflict": [True],
        "agents_load_observed": [False],
        "scanner_corrected": [False],
        "parser_wire_verified": [False],
        "decision_a": ["not_proven", "blocked", "none"],
        "decision_b": ["not_run", "disposable_fixture"],
        "decision_c": ["none", "inherited", "previous_epoch"],
        "ambient_credential": [True],
        "api_fallback": [True],
        "oauth_relay": [True],
        "unsafe_flag": [True],
        "mediation_complete": [False],
        "hooks_plugins_mcp_denied": [False],
        "enforcement": ["inactive", "unknown"],
        "doctor_fresh": [False],
        "active_attempts": [1, 2],
        "unknown_outcome_retained": [True],
        "replay": [True],
        "publisher_reachable": [True],
        "evidence_origin": ["synthetic", "disposable_fixture"],
    }
    assert set(flips) <= gating
    for key, values in flips.items():
        for value in values:
            for action in ("request_launch", "resume", "rotate_harness"):
                if action == "rotate_harness" and key == "replay":
                    continue  # replay concerns task attempts, not rotation
                facts = {**defaults, "action": action, key: value}
                decision, code = decide(facts)
                assert decision != "NO_GO", (key, value, action, code)


def test_pairwise_and_exhaustive_boolean_fault_injection_never_reaches_go():
    defaults = FIXTURE["defaults"]
    booleans = [
        k
        for k, v in defaults.items()
        if isinstance(v, bool) and k not in {"user_level_claude_md"}
    ]
    ideal = {k: defaults[k] for k in booleans}
    no_go = 0
    for combo in itertools.product((False, True), repeat=10):
        keys = booleans[: len(combo)]
        facts = {**defaults, **dict(zip(keys, combo, strict=True))}
        decision, _ = decide(facts)
        assert decision != "GO"
        if decision == "NO_GO":
            no_go += 1
            assert all(facts[k] == ideal[k] for k in keys)
    assert no_go == 1  # only the all-ideal combination of the swept facts


def test_user_level_claude_file_never_changes_the_decision():
    for scenario in FIXTURE["scenarios"]:
        base = facts_of(scenario)
        with_user = {**base, "user_level_claude_md": True}
        without_user = {**base, "user_level_claude_md": False}
        assert decide(with_user) == decide(without_user), scenario["id"]


def test_harness_identity_cannot_unlock_authority_or_switch():
    for harness in ("codex", "claude_code"):
        for action, expected in DENIED_ACTIONS.items():
            facts = {
                **FIXTURE["defaults"],
                "harness_selected": harness,
                "assignment_harness": harness,
                "action": action,
            }
            assert decide(facts) == expected
    # even with every other fact ideal, the other harness is never chosen as fallback
    facts = {**FIXTURE["defaults"], "action": "switch_harness_on_failure"}
    assert decide(facts) == ("DENY", "HARNESS_SWITCH_DENIED")


# ----------------------------------------------------------------- lifecycle model

TRANSITIONS = [
    (r[0], r[2])
    for r in table_rows("| From | Event | To | Notes |", r"[A-Za-z_]+")
    if r[0] != "From"
]


def test_lifecycle_table_has_the_required_safety_properties():
    edges = {(a, b) for a, b in TRANSITIONS}
    states = {s for e in edges for s in e} - {"any"}
    assert states == {
        "IDLE",
        "RESERVED",
        "PREPARED",
        "RUNNING",
        "QUIESCING",
        "FINISHED",
        "OUTCOME_UNKNOWN",
        "BLOCKED",
    }
    # RUNNING is entered only from PREPARED; RESERVED only from IDLE
    assert {a for a, b in edges if b == "RUNNING"} == {"PREPARED"}
    assert {a for a, b in edges if b == "RESERVED"} == {"IDLE"}
    # an UNKNOWN outcome leaves only through operator reconciliation to FINISHED
    assert {b for a, b in edges if a == "OUTCOME_UNKNOWN"} == {"FINISHED"}
    # FINISHED is terminal: no automatic retry edge back into the machine
    assert not {b for a, b in edges if a == "FINISHED"}
    # nothing leaves RUNNING except into QUIESCING or FINISHED (exact terminal)
    assert {b for a, b in edges if a == "RUNNING"} == {"QUIESCING", "FINISHED"}
    # reachability: every state is reachable from IDLE and BLOCKED from any
    reach = {"IDLE"}
    changed = True
    while changed:
        changed = False
        for a, b in edges:
            if (a in reach or a == "any") and b not in reach:
                reach.add(b)
                changed = True
    assert reach == states


# --------------------------------------------------------------------- documents


def test_adr_has_required_status_gates_and_no_go_language():
    for needle in (
        "ADR 010",
        "AP-HINV/1",
        "Verdict: NO-GO",
        "PROPOSED / NO-GO / DESIGN_ONLY / SOURCE_ONLY",
        "HOST_NOT_RUN",
        "`SUBSCRIPTION_ISOLATION_BLOCKED` / public exit 13",
        "`LIVE_NO_GO`",
        "Gate #73 BLOCKED",
        "Publisher #108 BLOCKED",
        "exactly two Debian role packages",
        "one selected harness per worker",
        "human-only merge",
        "defines **no GO state**".replace("**", ""),
        "`overall=NO_GO`",
        "`launch_allowed=false`",
        "`production_go=false`",
        "`inherited_approval` is the constant `false`",
        "does not rewrite",
        "Refs #137",
        "never `Closes`",
        "feature/issue-136-supervised-multi-harness-workflow",
        "2cff431ffba3632baa11061f266ef8b2b7925692",
        "630178b9c67c3a9f9f2b193e25585bebc7422ad8",
    ):
        assert needle in FLAT, needle
    assert "Closes #137" not in ADR
    assert not re.search(r"^\| .*\| GO \|", ADR, re.M)


def test_adr_covers_every_required_design_topic():
    for needle in (
        "BC-1",
        "BC-5",
        "descriptor-bound",
        "PATH, aliases, wrappers",
        "not the selected harness",
        "A supervised personal CLI session",
        "Complete mediation",
        "hooks",
        "MCP",
        "plugins",
        "subagents",
        "AC-2",
        "FS-3",
        "enforcement is measured active",
        "PC-1",
        "kill domain",
        "NF-1",
        "NF-3",
        "R1 Drain",
        "R7 Resume work",
        "epoch + 1",
        "AS-1",
        "AS-4",
        "CJ-1",
        "CJ-6",
        "No blind replay",
        "HA-1",
        "HA-3",
        "worker01 is considered first",
        "package proof only",
        "OPERATOR_ATTESTED_UNAUTHENTICATED",
        "DISPOSABLE_FIXTURE",
        "SOURCE_ONLY",
        "INDEPENDENTLY_VERIFIED",
        "NOT_PROVEN",
        "HOST_NOT_RUN",
        "Entry conditions",
        "STOP conditions",
        "Rollback",
        "Per-worker GO/NO-GO checklist",
        "each of HC-01..HC-25 occurs exactly once",
        "minContains = maxContains = 1",
    ):
        assert needle.replace("**", "").replace("`", "") in FLAT.replace("`", ""), (
            needle
        )


def test_unresolved_requirements_are_separate_and_unresolved():
    rows = {r[0]: r for r in table_rows("## Known unresolved requirements", r"U-\d+")}
    assert list(rows) == [f"U-{n}" for n in range(1, 11)]
    assert "HAR-04" in rows["U-1"][1] and "BLOCKED" in rows["U-1"][2]
    assert "FI-01" in rows["U-1"][3]
    assert (
        "HOST_NOT_RUN" in rows["U-2"][2]
        and "file presence is never evidence" in rows["U-2"][3]
    )
    assert "NOT_PROVEN" in rows["U-3"][2] and "SYNTHETIC_NOT_CAPTURED" in rows["U-3"][1]
    assert "NOT_PROVEN" in rows["U-4"][2]
    assert "NOT_PROVEN" in rows["U-5"][2]
    for key in ("U-1", "U-2", "U-3", "U-4", "U-5"):
        assert "resolved" not in rows[key][2].lower().replace("unresolved", "")
    for word in ("user_config_home", "user_level_file_present", "load_confirmed"):
        assert word in ADR
    assert "before any native-runtime readiness assessment" in FLAT


def test_vendor_recheck_is_dated_sourced_and_does_not_widen_adr_009():
    rows = table_rows("| ID | Source | Observed fact", r"V\d")
    assert [r[0] for r in rows] == [f"V{n}" for n in range(1, 7)]
    assert "observed 2026-11-17" in FLAT
    for url in (
        "https://code.claude.com/docs/en/legal-and-compliance",
        "https://code.claude.com/docs/en/sandboxing",
        "https://code.claude.com/docs/en/settings",
        "https://code.claude.com/docs/en/hooks",
        "https://learn.chatgpt.com/docs/agent-approvals-security",
    ):
        assert url in ADR, url
    for needle in (
        "decisions of ADR 009",
        "are unchanged",
        "The sandbox covers shell commands only",
        "MCP servers, and hooks run outside it",
        "does not filter",
        "NOT_RUN",
        "lacks",
    ):
        assert needle.replace("**", "") in FLAT, needle
    # the claude and codex columns of the mediation table stay separate
    assert "never reused for the other" in FLAT


def test_adr_009_decisions_are_still_the_stricter_text():
    adr9 = (DOCS / "harness-auth-terms-isolation.md").read_text()
    assert "defines **no GO\n   state**" in adr9 or "no GO" in adr9
    flat9 = " ".join(adr9.split())
    for needle in (
        "**A. Vendor permission**",
        "**B. Isolation",
        "**C. Operator approval**",
    ):
        assert needle in flat9
    assert "BLOCKED" in flat9 and "NOT_PROVEN" in flat9


def test_adr_is_linked_from_readme_and_number_is_unique():
    readme = (ROOT / "README.md").read_text()
    assert "docs/trusted-harness-invocation-no-go.md" in readme
    assert "ADR 010" in readme and "NO-GO" in readme
    holders = [
        p.name
        for p in DOCS.glob("*.md")
        if re.search(r"^# ADR 010\b", p.read_text(), re.M)
    ]
    assert holders == ["trusted-harness-invocation-no-go.md"]
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", ADR):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (DOCS / target).resolve().exists(), target
    for anchor in re.findall(r"\]\(#([^)\s]+)\)", ADR):
        slug_targets = {
            re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-")
            for h in re.findall(r"^#+ (.+)$", ADR, re.M)
        }
        assert anchor in slug_targets, anchor


def test_single_instruction_policy_and_no_competing_files():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    names = {Path(p).name for p in tracked}
    assert not {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.override.md"} & names
    assert [p for p in tracked if p.endswith("AGENTS.md")] == ["AGENTS.md"]
    assert not any(p.startswith(".claude/") for p in tracked)
    assert not (ROOT / "AGENTS.md").is_symlink()
    assert (
        hashlib.sha256((DOCS / "solo-maintainer-policy.md").read_bytes()).hexdigest()
        == AP_SM2_SHA256
    )


def test_change_adds_no_runtime_code_or_product_reference():
    for source in (ROOT / "src").rglob("*.py"):
        text = source.read_text()
        for marker in ("AP-HINV", "harness-invocation", "trusted-harness-invocation"):
            assert marker not in text, (source, marker)
    for path in (ROOT / "packaging").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".json", ".toml", ".txt"}:
            assert "AP-HINV" not in path.read_text(), path


# ----------------------------------------------- HAR-04 scanner known limitation


def make_tree(tmp_path, ancestor_file=None, project_file=None):
    home = tmp_path / "home"
    root = home / "projects" / "wt"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_text("# policy\n")
    if ancestor_file:
        target = home / ancestor_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n")
    if project_file:
        target = root / project_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n")
    return root


def test_scanner_false_positive_is_pinned_as_a_known_limitation(tmp_path):
    root = make_tree(tmp_path, ".claude/CLAUDE.md")
    report = instruction_sources.diagnose(root, "2.1.295")
    # Current frozen behaviour (HAR-04): conservative CONFLICT for the user-level file.
    assert report["result"] == "CONFLICT"
    assert "claude_md_in_ancestor" in report["reasons"]
    assert report["load_confirmed"] is False
    # Document says this is corrected only by FI-01 and blocks HC-07 meanwhile.
    assert "frozen module" in FLAT and "FI-01" in FLAT


@pytest.mark.parametrize(
    "project_file", ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md"]
)
def test_real_project_conflicts_remain_conflicts(tmp_path, project_file):
    root = make_tree(tmp_path, ".claude/CLAUDE.md", project_file)
    report = instruction_sources.diagnose(root, "2.1.295")
    assert report["result"] == "CONFLICT" and report["load_confirmed"] is False


def test_no_scanner_result_confirms_a_load(tmp_path):
    for index, ancestor in enumerate(
        (None, "CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md")
    ):
        base = tmp_path / f"case{index}"
        base.mkdir()
        report = instruction_sources.diagnose(make_tree(base, ancestor), "2.1.295")
        assert report["load_confirmed"] is False
