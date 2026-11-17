"""HAR-05 / ADR 009 document contract: offline, no provider access, no runtime code.

The mini schema interpreter accepts only the keywords used by the checked-in schema
and fails on anything else, so a new keyword cannot be silently ignored.
"""

import copy
import datetime
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
ADR = (DOCS / "harness-auth-terms-isolation.md").read_text()
FLAT = " ".join(ADR.split()).replace("**", "")
SCHEMA = json.loads((DOCS / "harness-auth-evidence.schema.json").read_text())
EXAMPLES = json.loads((DOCS / "harness-auth-evidence.examples.json").read_text())
STATUSES = {"SUPPORTED", "NOT_PROVEN", "BLOCKED", "OUT_OF_SCOPE"}
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


def matrix_rows():
    section = ADR.split("## Decision matrix", 1)[1].split("Reading rule:", 1)[0]
    rows = []
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split(" | ")]
        if line.startswith("| ") and cells[0].isdigit():
            rows.append(cells)
    return rows


def test_valid_examples_pass_and_invalid_examples_fail():
    assert set(EXAMPLES["valid"]) >= {"claude_unclarified", "all_attested_still_not_go"}
    for name, record in EXAMPLES["valid"].items():
        assert matches(record, SCHEMA), name
    assert len(EXAMPLES["invalid"]) >= 15
    for name, record in EXAMPLES["invalid"].items():
        assert not matches(record, SCHEMA), name


def test_schema_has_no_go_state_and_is_closed():
    props = SCHEMA["properties"]
    assert SCHEMA["additionalProperties"] is False
    assert props["launch_allowed"] == {"const": False}
    assert props["production_go"] == {"const": False}
    assert set(props["overall"]["enum"]) == {"BLOCKED", "NOT_PROVEN", "NOT_RUN"}
    assert props["harness_id"]["enum"] == ["codex", "claude_code"]
    decisions = props["decisions"]
    assert set(decisions["properties"]) == {
        "vendor_permission",
        "isolation",
        "operator_approval",
    }
    for entry in decisions["properties"].values():
        assert entry["additionalProperties"] is False
        assert "GO" not in entry["properties"]["status"]["enum"]
    names = json.dumps(SCHEMA["properties"]).lower()
    for forbidden in ("token", "secret", "password", "email", "cookie"):
        assert forbidden not in names, forbidden


def test_examples_cannot_smuggle_secrets():
    blob = json.dumps(EXAMPLES["valid"])
    for pattern in (
        r"sk-[A-Za-z0-9]",
        r"eyJ[A-Za-z0-9]",
        r"/home/",
        r"@[a-z]+\.",
        r"Bearer ",
    ):
        assert not re.search(pattern, blob), pattern


def test_attested_record_still_cannot_launch():
    record = EXAMPLES["valid"]["all_attested_still_not_go"]
    assert all(
        v["status"] == "ATTESTED_UNAUTHENTICATED" for v in record["decisions"].values()
    )
    assert record["launch_allowed"] is False and record["production_go"] is False
    mutated = copy.deepcopy(record)
    mutated["overall"] = "GO"
    assert not matches(mutated, SCHEMA)


def test_decision_matrix_covers_requested_scenarios_with_closed_statuses():
    rows = matrix_rows()
    assert [row[0] for row in rows] == [str(n) for n in range(1, 11)]
    overall = {row[0]: row[5] for row in rows}
    for row in rows:
        for cell in row[2:5]:
            assert cell.split(" ")[0] in STATUSES | {
                "n/a",
                "per-session,",
                "NOT_RUN",
            }, cell
        assert re.match(r"\*\*(SUPPORTED|NOT_PROVEN|BLOCKED|OUT_OF_SCOPE)\b", row[5]), (
            row
        )
    assert overall["1"].startswith("**SUPPORTED")
    assert overall["2"].startswith("**SUPPORTED")
    assert overall["3"].startswith("**SUPPORTED as supervised")
    assert overall["4"] == "**NOT_PROVEN**"
    for unattended in ("5", "6", "7", "8"):
        assert overall[unattended] == "**BLOCKED**", unattended
    assert overall["9"] == "**OUT_OF_SCOPE**"
    assert overall["10"] == "**NOT_PROVEN**"
    assert not any(
        overall[n].startswith("**SUPPORTED")
        for n in ("4", "5", "6", "7", "8", "9", "10")
    )


def test_independent_decisions_and_preserved_gates_are_stated():
    for needle in (
        "A. Vendor permission",
        "B. Isolation and process safety",
        "C. Operator approval",
        "SUBSCRIPTION_ISOLATION_BLOCKED",
        "exit 13",
        "LIVE_NO_GO",
        "HOST_NOT_RUN",
        "Gate #73",
        "human-only merge",
        "one operator-selected harness per worker",
        "never a default GO",
        "not legal advice",
        "not a vendor approval",
        "provider authentication is never GitHub authority",
        "`--bare` is not a workaround",
        "never an OS boundary",
        "private ownership of the host does not",
    ):
        assert needle.lower() in FLAT.lower(), needle


def test_official_sources_are_listed_with_observation_date():
    assert "Observed **2026-11-16**" in ADR
    for url in (
        "https://code.claude.com/docs/en/legal-and-compliance",
        "https://code.claude.com/docs/en/cli-reference",
        "https://code.claude.com/docs/en/headless",
        "https://code.claude.com/docs/en/settings",
        "https://code.claude.com/docs/en/memory",
        "https://learn.chatgpt.com/docs/auth",
    ):
        assert url in ADR, url
    assert "Uncertainty bounds" in ADR and "NOT_PROVEN" in ADR


def test_negative_plan_ids_are_contiguous_and_referenced():
    ids = re.findall(r"^\| (NT-\d\d) \|", ADR, re.M)
    assert ids == [f"NT-{n:02d}" for n in range(1, 28)]
    threat = ADR.split("## Threat model", 1)[1].split("## Required evidence", 1)[0]
    referenced = set(re.findall(r"NT-\d\d", threat))
    assert {"NT-01", "NT-13", "NT-19", "NT-22"} <= referenced


def test_adr_number_is_unique_and_no_competing_instruction_files():
    heading = ADR.splitlines()[0]
    assert heading.startswith("# ADR 009:")
    numbers = {}
    for path in DOCS.glob("*.md"):
        match = re.match(r"# ADR (\d+):", path.read_text().splitlines()[0])
        if match:
            numbers.setdefault(match.group(1), []).append(path.name)
    assert numbers["009"] == ["harness-auth-terms-isolation.md"]
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    assert not [
        p for p in tracked if p.lower().endswith(("claude.md", "claude.local.md"))
    ]
    assert (ROOT / "AGENTS.md").is_file()


def test_change_adds_no_executable_or_runtime_code():
    adr_files = {
        "docs/harness-auth-terms-isolation.md",
        "docs/harness-auth-evidence.schema.json",
        "docs/harness-auth-evidence.examples.json",
        "tests/test_harness_auth_terms_contract.py",
    }
    assert all((ROOT / name).is_file() for name in adr_files)
    for source in (ROOT / "src").rglob("*.py"):
        text = source.read_text()
        assert "AP-HAUTH-EVIDENCE" not in text, source


@pytest.mark.parametrize("name", sorted(EXAMPLES["invalid"]))
def test_each_invalid_example_is_rejected(name):
    assert not matches(EXAMPLES["invalid"][name], SCHEMA)


def decision_schema():
    return SCHEMA["properties"]["decisions"]["properties"]["vendor_permission"]


def test_attested_requires_evidence_real_date_and_no_blocking_reasons():
    record = EXAMPLES["valid"]["all_attested_still_not_go"]
    for name in ("vendor_permission", "isolation", "operator_approval"):
        entry = record["decisions"][name]
        assert entry["evidence_sha256"] and entry["reasons"] == []
        datetime.date.fromisoformat(entry["observed_date"])
    for name, record in EXAMPLES["invalid"].items():
        if name.startswith(("attested_", "not_run_", "blocked_", "evidence_", "date_")):
            assert not matches(record, SCHEMA), name
    assert matches(EXAMPLES["valid"]["attested_leap_day"], SCHEMA)


def test_date_pattern_equals_real_calendar_for_every_day_2000_2099():
    pattern = decision_schema()["oneOf"][3]["properties"]["observed_date"]["pattern"]
    day = datetime.date(1999, 12, 25)
    end = datetime.date(2101, 1, 5)
    while day <= end:
        expected = 2000 <= day.year <= 2099
        assert bool(re.search(pattern, day.isoformat())) is expected, day
        day += datetime.timedelta(days=1)
    for bogus in (
        "2026-02-30",
        "2026-13-01",
        "2026-00-10",
        "2026-04-31",
        "2027-02-29",
        "2100-02-29",
        "2026-11-00",
        "2026-1-1",
        "2026-11-16T00:00:00Z",
        "NONE",
        "",
    ):
        assert not re.search(pattern, bogus), bogus
    for good in ("2000-02-29", "2024-02-29", "2026-11-16", "2099-12-31"):
        assert re.search(pattern, good), good


def test_status_branches_accept_only_the_four_defined_shapes():
    assert len(decision_schema()["oneOf"]) == 4
    sample = {
        "status": "NOT_RUN",
        "reasons": ["host_not_run"],
        "evidence_sha256": [],
        "observed_date": "NONE",
    }
    entry_schema = SCHEMA["properties"]["decisions"]["properties"]["isolation"]
    assert matches(sample, entry_schema)
    for status in ("NOT_PROVEN", "BLOCKED"):
        assert matches(dict(sample, status=status), entry_schema)
    assert not matches(dict(sample, status="GO"), entry_schema)


def test_jsonschema_library_agrees_when_available():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(SCHEMA)
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    for name, record in EXAMPLES["valid"].items():
        assert validator.is_valid(record), name
    for name, record in EXAMPLES["invalid"].items():
        assert not validator.is_valid(record), name


def test_scenario_three_matrix_is_logically_consistent():
    rows = {row[0]: row for row in matrix_rows()}
    for number in ("1", "2", "3"):
        _, _, a, b, c, overall, *_ = rows[number]
        assert a == "SUPPORTED"
        assert b.startswith("n/a") and c.startswith("n/a"), number
        assert overall.startswith("**SUPPORTED")
    row3 = " ".join(rows["3"])
    assert "NOT_PROVEN" in row3 and "says nothing about isolation" in row3
    for number, row in rows.items():
        cells = [cell.split(" ")[0] for cell in row[2:5]]
        unresolved = {"NOT_PROVEN", "NOT_RUN", "BLOCKED"} & set(cells)
        if row[5].startswith("**SUPPORTED"):
            assert not unresolved, number
        if number in {"4", "5", "6", "7", "8"}:
            assert "n/a" not in cells[1:], number
    reading = FLAT.split("Reading rule:", 1)[1].split("## Three independent", 1)[0]
    for needle in (
        "does not establish Agent Platform isolation",
        "B and C are `n/a` in rows 1-3",
        "not allowed",
    ):
        assert needle in reading, needle
    assert "`n/a` means the decision does not apply" in FLAT
    assert "any `NOT_PROVEN`, `NOT_RUN` or `BLOCKED` cell prevents SUPPORTED" in FLAT


def test_har07_does_not_require_har05_merge():
    section = FLAT.split("## Criteria for HAR-07 to proceed", 1)[1].split(
        "## Validation boundary", 1
    )[0]
    assert "No merge of HAR-05 is required" in section
    assert "exact published HEAD" in section and "positive hosted CI" in section
    assert "merged by the human into the series" not in FLAT
    assert "unmerged into `main` until every review and CI run has finished" in section
