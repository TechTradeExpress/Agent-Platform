"""RM-02: offline model tests with fabricated fixtures only; VERIFIED_OFFLINE."""

import ast
import builtins
import copy
import dataclasses
import importlib.util
import json
import re
import subprocess
import sys
import traceback
from dataclasses import fields
from pathlib import Path

import pytest

from agent_platform import repository_manager as rm

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "repository_manager"
MODULE = ROOT / "src/agent_platform/repository_manager.py"
DOC = ROOT / "docs/repository-manager-configuration.md"
C = rm.Control
R = rm.Result
SENTINEL = "SENTINEL-ghp_ABCDEF0123456789"

PARSERS = {
    "profile": rm.parse_profile,
    "manifest": rm.parse_manifest,
    "desired": rm.parse_desired,
    "actual": rm.parse_actual,
    "precreation": rm.parse_precreation,
    "existing": rm.parse_existing,
    "binding": rm.parse_binding,
    "enrollment": rm.parse_enrollment,
    "manifest-creation": rm.parse_manifest,
    "actual-compliant": rm.parse_actual,
    "actual-incomplete-identity": rm.parse_actual,
    "existing-origin": rm.parse_existing,
    "compliance": rm.parse_compliance,
    "result-compliant": rm.parse_result,
    "result-noncompliant": rm.parse_result,
    "result-unverified": rm.parse_result,
    "result-unsupported": rm.parse_result,
    "result-contradictory": rm.parse_result,
}
NAMES = sorted(PARSERS)
DISTINCT_PARSERS = {
    "profile": rm.parse_profile,
    "manifest": rm.parse_manifest,
    "desired": rm.parse_desired,
    "actual": rm.parse_actual,
    "precreation": rm.parse_precreation,
    "existing": rm.parse_existing,
    "binding": rm.parse_binding,
    "enrollment": rm.parse_enrollment,
    "compliance": rm.parse_compliance,
    "result": rm.parse_result,
}


def raw(name):
    return (FIXTURES / f"{name}.json").read_bytes()


def data(name):
    return json.loads(raw(name))


def enc(value):
    return json.dumps(value).encode()


def load(name):
    return PARSERS[name](raw(name))


def code(parser, payload):
    with pytest.raises(rm.RepositoryManagerError) as caught:
        parser(payload)
    assert caught.value.reason in rm.REASONS
    return caught.value.reason


def construct_code(factory):
    with pytest.raises(rm.RepositoryManagerError) as caught:
        factory()
    assert caught.value.reason in rm.REASONS
    return caught.value.reason


def edit(value, path, new):
    result = copy.deepcopy(value)
    node = result
    for key in path[:-1]:
        node = node[key]
    if new is DELETE:
        del node[path[-1]]
    elif path:
        node[path[-1]] = new
    else:
        result = new
    return result


DELETE = object()


def walk(node, path=()):
    yield path, node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, path + (key,))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, path + (index,))


def dict_paths(value):
    return [p for p, n in walk(value) if isinstance(n, dict)]


def leaf_paths(value):
    return [p for p, n in walk(value) if not isinstance(n, dict | list) and p]


def with_duplicate(value, target):
    def ser(node, path):
        if isinstance(node, dict):
            items = [(k, ser(v, path + (k,))) for k, v in node.items()]
            if path == target:
                items.append(items[0])
            return "{" + ",".join(f"{json.dumps(k)}:{v}" for k, v in items) + "}"
        if isinstance(node, list):
            return "[" + ",".join(ser(v, path + (i,)) for i, v in enumerate(node)) + "]"
        return json.dumps(node)

    return ser(value, ()).encode()


# --- fixtures: positive scenarios -------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_fixtures_parse_round_trip_and_are_deterministic(name):
    record = load(name)
    canonical = rm.dumps(record)
    assert canonical.isascii() and not canonical.endswith(b"\n")
    assert PARSERS[name](canonical) == record
    assert rm.dumps(PARSERS[name](canonical)) == canonical
    assert rm.digest(record) == rm.digest(PARSERS[name](canonical))
    assert len(rm.digest(record)) == 64


def test_fixture_set_is_exactly_the_documented_fabricated_set():
    assert sorted(p.stem for p in FIXTURES.glob("*.json")) == NAMES
    assert not [p for p in FIXTURES.iterdir() if p.suffix != ".json"]


def test_fixtures_contain_only_fictional_identifiers():
    for name in NAMES:
        text = raw(name).decode()
        for value in re.findall(r'"(?:ref|\w+_ref|source_ref)": "([^"]*)"', text):
            assert value.startswith("fixture-")
        for login in re.findall(r'"login": "([^"]*)"', text):
            assert login.startswith("fictional-")
        assert not re.search(
            r"https?://|@|ghp_|github_pat_|TechTradeExpress|su-17", text
        )


# --- generic strict parsing across every record ------------------------------------


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("bad", ["text", bytearray(b"{}"), None, 1, memoryview(b"{}")])
def test_parsers_require_exact_bytes(name, bad):
    assert code(PARSERS[name], bad) == "not_bytes"


@pytest.mark.parametrize("name", NAMES)
def test_size_utf8_and_json_boundaries(name):
    parser = PARSERS[name]
    assert code(parser, b" " * (rm.MAX_BYTES + 1)) == "too_large"
    assert code(parser, b"\xff\xfe{}") == "bad_utf8"
    assert code(parser, b"\xef\xbb\xbf" + raw(name)) == "bad_json"
    for text in (b"", b"{", b"{} {}", b"{'schema': 1}", b'{"a":1,}', b"nul"):
        assert code(parser, text) == "bad_json"
    for text in (b"[]", b'"x"', b"1", b"null", b"true"):
        assert code(parser, text) == "not_object"


@pytest.mark.parametrize("name", NAMES)
def test_nonfinite_float_and_huge_numbers_fail_closed(name):
    parser = PARSERS[name]
    for literal in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
        assert code(parser, b'{"schema": ' + literal + b"}") == "nonfinite_number"
        assert code(parser, b'{"x": [' + literal + b"]}") == "nonfinite_number"
    assert code(parser, b'{"schema": 1.5}') == "bad_type"
    assert code(parser, b'{"schema": 1e2}') == "bad_type"
    assert code(parser, b'{"schema": ' + b"9" * 400 + b"}") == "bad_range"


@pytest.mark.parametrize("name", NAMES)
def test_depth_limits(name):
    parser = PARSERS[name]
    deep = b"[" * (rm.MAX_DEPTH + 1) + b"]" * (rm.MAX_DEPTH + 1)
    assert code(parser, b'{"x": ' + deep + b"}") == "too_deep"
    assert code(parser, b"[" * 20000 + b"]" * 20000) == "too_deep"
    assert code(parser, b'{"a":' * 5000 + b"1" + b"}" * 5000) == "too_deep"
    assert code(parser, b'{"a":' * 5000) in {"too_deep", "bad_json"}


@pytest.mark.parametrize("name", NAMES)
def test_duplicate_keys_are_rejected_at_every_depth(name):
    value = data(name)
    for path in dict_paths(value):
        assert code(PARSERS[name], with_duplicate(value, path)) == "duplicate_key"


@pytest.mark.parametrize("name", NAMES)
def test_unknown_fields_are_rejected_at_every_nested_object(name):
    value = data(name)
    for path in dict_paths(value):
        mutated = copy.deepcopy(value)
        node = mutated
        for key in path:
            node = node[key]
        node["extra_field"] = 1
        assert code(PARSERS[name], enc(mutated)) == "unknown_field", path


@pytest.mark.parametrize("name", NAMES)
def test_missing_fields_are_rejected_for_every_key(name):
    value = data(name)
    for path, node in walk(value):
        if isinstance(node, dict):
            for key in node:
                reason = code(PARSERS[name], enc(edit(value, path + (key,), DELETE)))
                expected = (
                    "evidence_mismatch"
                    if path == ("evidence",) and key == "kind"
                    else "missing_field"
                )
                assert reason == expected, (path, key)


@pytest.mark.parametrize("name", NAMES)
def test_wrong_scalar_and_container_types_never_validate(name):
    value = data(name)
    accepted = []
    for path in leaf_paths(value) + [
        p for p, n in walk(value) if isinstance(n, dict | list) and p
    ]:
        node = value
        for key in path:
            node = node[key]
        if isinstance(node, bool):
            wrong = [None, 0, 1, "true", [], {}]
        elif isinstance(node, int):
            wrong = [None, True, False, 1.5, "1", [], {}]
        elif isinstance(node, str):
            wrong = [None, 0, True, [], {}]
        elif isinstance(node, list):
            wrong = [None, "x", 0, {}]
        else:
            wrong = [None, "x", 0, []]
        for replacement in wrong:
            if replacement == node and type(replacement) is type(node):
                continue  # identical value, e.g. the documented null placeholders
            if path == ("origin",) and replacement is None:
                continue  # null is the documented "no origin" value
            if (
                path == ("repository", "default_branch")
                and node is None
                and isinstance(replacement, str)
            ):
                continue  # a partially observed identity may name the branch alone
            try:
                PARSERS[name](enc(edit(value, path, replacement)))
            except rm.RepositoryManagerError:
                continue
            accepted.append((path, replacement))
    assert not accepted


@pytest.mark.parametrize("parser_name", sorted(DISTINCT_PARSERS))
def test_cross_record_confusion_is_wrong_record(parser_name):
    schema = {
        "profile": rm.PROFILE,
        "manifest": rm.MANIFEST,
        "desired": rm.DESIRED,
        "actual": rm.ACTUAL,
        "precreation": rm.PRECREATION,
        "existing": rm.EXISTING,
        "binding": rm.BINDING,
        "enrollment": rm.ENROLLMENT,
        "compliance": rm.COMPLIANCE,
        "result": rm.RESULT,
    }
    for name in NAMES:
        if data(name)["schema"] != schema[parser_name]:
            assert code(DISTINCT_PARSERS[parser_name], raw(name)) == "wrong_record"


@pytest.mark.parametrize("name", NAMES)
def test_schema_discriminator_and_version_are_exact(name):
    value = data(name)
    schema = value["schema"]
    for bad in (
        schema.replace("/1", "/2"),
        schema.replace("/1", "/01"),
        schema.lower(),
        "",
        schema + " ",
        "AP-RM-UNKNOWN/1",
    ):
        assert code(PARSERS[name], enc(edit(value, ("schema",), bad))) == (
            "unsupported_schema"
        )
    for bad in (None, 1, [], {}, True):
        assert code(PARSERS[name], enc(edit(value, ("schema",), bad))) == "bad_type"


@pytest.mark.parametrize("name", NAMES)
def test_diagnostics_never_echo_untrusted_input(name):
    value = data(name)
    payloads = [
        b'{"schema": "' + SENTINEL.encode() + b'"}',
        b'{"' + SENTINEL.encode() + b'": 1, "' + SENTINEL.encode() + b'": 2}',
        b"\xff" + SENTINEL.encode(),
        b"{" + SENTINEL.encode(),
        b'{"schema": ' + SENTINEL.encode() + b"}",
    ]
    for path in leaf_paths(value):
        payloads.append(enc(edit(value, path, SENTINEL)))
    for path in dict_paths(value):
        mutated = copy.deepcopy(value)
        node = mutated
        for key in path:
            node = node[key]
        node[SENTINEL] = SENTINEL
        payloads.append(enc(mutated))
    rejected = 0
    for payload in payloads:
        try:
            PARSERS[name](payload)
        except rm.RepositoryManagerError as error:
            rejected += 1
            rendered = "".join(traceback.format_exception(error))
            assert SENTINEL not in rendered and SENTINEL not in repr(error.__dict__)
            assert error.__cause__ is None
            assert error.__context__ is None
        # a free-form reference may legitimately contain the sentinel text
    assert rejected >= len(dict_paths(value)) + 5


def test_too_many_items_in_every_array():
    for name, paths in {
        "profile": ("controls",),
        "actual": ("observations",),
        "precreation": ("admin_scope",),
    }.items():
        for key in paths:
            big = edit(data(name), (key,), [0] * (rm.MAX_ITEMS + 1))
            assert code(PARSERS[name], enc(big)) == "too_many_items"


# --- identifier, range and timestamp boundaries ------------------------------------

BAD_FIELDS = [
    # (fixture, path, value, reason)
    ("precreation", ("owner", "id"), 0, "bad_range"),
    ("precreation", ("owner", "id"), -1, "bad_range"),
    ("precreation", ("owner", "id"), 2**53, "bad_range"),
    ("precreation", ("owner", "id"), True, "bad_type"),
    ("precreation", ("owner", "id"), "1", "bad_type"),
    ("precreation", ("owner", "login"), "", "bad_identifier"),
    ("precreation", ("owner", "login"), "-lead", "bad_identifier"),
    ("precreation", ("owner", "login"), "trail-", "bad_identifier"),
    ("precreation", ("owner", "login"), "dou--ble", "bad_identifier"),
    ("precreation", ("owner", "login"), "x" * 40, "bad_identifier"),
    ("precreation", ("owner", "login"), "has space", "bad_identifier"),
    ("precreation", ("owner", "login"), "uniçode", "bad_identifier"),
    ("precreation", ("owner", "login"), "line\n", "bad_identifier"),
    ("precreation", ("owner", "login"), "ghp_example", "bad_identifier"),
    ("precreation", ("owner", "type"), "Bot", "bad_value"),
    ("precreation", ("owner", "type"), "user", "bad_value"),
    ("precreation", ("provider",), "gitlab", "bad_value"),
    ("precreation", ("provider",), "GitHub", "bad_value"),
    ("precreation", ("repository", "name"), ".", "bad_identifier"),
    ("precreation", ("repository", "name"), "..", "bad_identifier"),
    ("precreation", ("repository", "name"), "a.git", "bad_identifier"),
    ("precreation", ("repository", "name"), "a/b", "bad_identifier"),
    ("precreation", ("repository", "name"), "x" * 101, "bad_identifier"),
    ("precreation", ("repository", "visibility"), "Public", "bad_value"),
    ("precreation", ("repository", "default_branch"), "..x", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "a//b", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "a.lock", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "a/b.lock/c", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "/a", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "a/", "bad_identifier"),
    ("precreation", ("repository", "default_branch"), "a b", "bad_identifier"),
    ("precreation", ("authorization_ref",), "", "bad_identifier"),
    ("precreation", ("authorization_ref",), "-x", "bad_identifier"),
    ("precreation", ("authorization_ref",), "ghp_" + "a" * 20, "bad_identifier"),
    ("precreation", ("authorization_ref",), "github_pat_" + "a" * 20, "bad_identifier"),
    ("precreation", ("authorization_ref",), "AKIA" + "A" * 16, "bad_identifier"),
    ("precreation", ("authorization_ref",), "x" * 129, "bad_identifier"),
    ("precreation", ("intent_id",), "A" * 32, "bad_identifier"),
    ("precreation", ("intent_id",), "a" * 31, "bad_identifier"),
    ("precreation", ("intent_id",), "g" * 32, "bad_identifier"),
    ("precreation", ("admin_scope",), [], "bad_range"),
    (
        "precreation",
        ("admin_scope",),
        ["create_repository", "create_repository"],
        "bad_value",
    ),
    (
        "precreation",
        ("admin_scope",),
        ["create_repository", "baseline_settings"],
        "not_sorted",
    ),
    ("precreation", ("admin_scope",), ["baseline_settings"], "bad_value"),
    (
        "precreation",
        ("admin_scope",),
        ["create_repository", "owner_admin"],
        "bad_value",
    ),
    ("precreation", ("admin_scope",), ["create_repository", 1], "bad_type"),
    ("existing", ("admin_scope",), ["create_repository"], "bad_value"),
    (
        "existing",
        ("repository", "full_name"),
        "fictional-owner/other",
        "identity_inconsistent",
    ),
    ("existing", ("repository", "full_name"), "bad name", "identity_inconsistent"),
    (
        "existing",
        ("repository", "full_name"),
        "Fictional-Owner/example-service",
        "identity_inconsistent",
    ),
    ("existing", ("repository", "id"), 0, "bad_range"),
    ("existing", ("repository", "id"), False, "bad_type"),
    ("actual", ("observed_at",), "2026-13-01T00:00:00Z", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-02-30T00:00:00Z", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-01-01 00:00:00Z", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-01-01T00:00:00+00:00", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-01-01T00:00:00.5Z", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-01-01T00:00:00Z\n", "bad_timestamp"),
    ("actual", ("observed_at",), "2026-01-01T24:00:00Z", "bad_timestamp"),
    ("actual", ("provenance",), "live", "bad_value"),
    ("actual", ("complete",), "false", "bad_type"),
    ("binding", ("precreation_sha256",), "A" * 64, "bad_digest"),
    ("binding", ("precreation_sha256",), "a" * 63, "bad_digest"),
    ("binding", ("observation", "observed_at"), "yesterday", "bad_timestamp"),
    ("enrollment", ("evidence", "sha256"), "z" * 64, "bad_digest"),
    ("enrollment", ("evidence", "sha256"), "a" * 65, "bad_digest"),
    ("enrollment", ("decision", "decided_at"), "2026-01-01", "bad_timestamp"),
    ("manifest", ("manifest_id",), "Upper", "bad_identifier"),
    ("manifest", ("profile_id",), "", "bad_identifier"),
    ("profile", ("profile_id",), "x" * 65, "bad_identifier"),
    ("result-unsupported", ("evidence", "endpoint"), "get /x", "bad_identifier"),
    ("result-unsupported", ("evidence", "endpoint"), "GET x", "bad_identifier"),
]


@pytest.mark.parametrize(
    "name,path,value,reason",
    BAD_FIELDS,
    ids=[
        f"{n}:{'/'.join(map(str, p))}:{i}"
        for i, (n, p, _v, _r) in enumerate(BAD_FIELDS)
    ],
)
def test_field_boundaries_fail_closed(name, path, value, reason):
    assert code(PARSERS[name], enc(edit(data(name), path, value))) == reason


# --- control vocabulary and profile/manifest/desired semantics -----------------------


def setting_wire(control, value, blocking=True):
    return {"control": control, "blocking": blocking, "value": value}


def profile_with(*settings):
    value = data("profile")
    value["controls"] = list(settings)
    return enc(value)


BAD_CONTROLS = [
    ([setting_wire("repo.delete_repository", True)], "unknown_control"),
    (
        [
            setting_wire("repo.allow_merge_commit", True),
            setting_wire("repo.allow_merge_commit", True),
        ],
        "duplicate_control",
    ),
    (
        [
            setting_wire("repo.allow_squash_merge", True),
            setting_wire("repo.allow_merge_commit", True),
        ],
        "not_sorted",
    ),
    ([setting_wire("repo.allow_merge_commit", "true")], "bad_type"),
    ([setting_wire("repo.allow_merge_commit", 1)], "bad_type"),
    ([setting_wire("repo.allow_merge_commit", None)], "bad_type"),
    ([setting_wire("actions.allowed_actions", "everything")], "bad_value"),
    ([setting_wire("actions.allowed_actions", True)], "bad_type"),
    ([setting_wire("actions.default_token_permissions", "admin")], "bad_value"),
    ([setting_wire("branch_protection.required_approvals", 7)], "bad_range"),
    ([setting_wire("branch_protection.required_approvals", -1)], "bad_range"),
    ([setting_wire("branch_protection.required_approvals", True)], "bad_type"),
    ([setting_wire("branch_protection.required_approvals", 1.0)], "bad_type"),
    ([setting_wire("observe.deploy_key_count", 1001)], "bad_range"),
    ([setting_wire("branch_protection.required_checks", [])], "bad_range"),
    ([setting_wire("branch_protection.required_checks", "checks")], "bad_type"),
    (
        [
            setting_wire(
                "branch_protection.required_checks", [{"name": "a", "app_id": 0}]
            )
        ],
        "bad_range",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks", [{"name": "a", "app_id": True}]
            )
        ],
        "bad_type",
    ),
    (
        [setting_wire("branch_protection.required_checks", [{"name": "a"}])],
        "missing_field",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks", [{"name": " a", "app_id": 1}]
            )
        ],
        "bad_identifier",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks", [{"name": "a ", "app_id": 1}]
            )
        ],
        "bad_identifier",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks",
                [{"name": "b", "app_id": 1}, {"name": "a", "app_id": 1}],
            )
        ],
        "not_sorted",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks",
                [{"name": "a", "app_id": 1}, {"name": "a", "app_id": 2}],
            )
        ],
        "duplicate_control",
    ),
    (
        [
            setting_wire(
                "branch_protection.required_checks",
                [{"name": f"c{i}", "app_id": 1} for i in range(9)],
            )
        ],
        "too_many_items",
    ),
    ([setting_wire("repo.allow_merge_commit", True, "yes")], "bad_type"),
    ([{"control": "repo.allow_merge_commit", "value": True}], "missing_field"),
    (
        [
            {
                "control": "repo.allow_merge_commit",
                "blocking": True,
                "value": True,
                "command": "x",
            }
        ],
        "unknown_field",
    ),
    (
        [
            {
                "control": "repo.allow_merge_commit",
                "blocking": True,
                "value": "${env.TOKEN}",
            }
        ],
        "bad_type",
    ),
    ([], "bad_range"),
]


@pytest.mark.parametrize("settings,reason", BAD_CONTROLS)
def test_profile_control_vocabulary_is_closed_and_typed(settings, reason):
    assert code(rm.parse_profile, profile_with(*settings)) == reason


def test_control_vocabulary_is_the_documented_finite_set():
    assert len(C) == 19
    assert {c.value.split(".")[0] for c in C} == {
        "repo",
        "actions",
        "branch_protection",
        "observe",
    }
    assert set(rm._SPECS) == set(C)
    with pytest.raises(ValueError):
        C("repo.arbitrary_setting")


# --- identity pins: pre-creation, post-creation, existing ----------------------------


@pytest.mark.parametrize(
    "path,value",
    [
        (("repository", "id"), 9100001),
        (("repository", "id"), None),
        (("repository", "repository_id"), 1),
        (("repository", "full_name"), "fictional-owner/example-service"),
        (("repository_id",), 9100001),
        (("repository_id",), None),
    ],
)
def test_precreation_never_carries_a_repository_id_even_as_null(path, value):
    assert (
        code(rm.parse_precreation, enc(edit(data("precreation"), path, value)))
        == "repository_id_in_precreation"
    )
    assert "id" not in {f.name for f in fields(rm.PreCreation)}
    assert "repository" not in {f.name for f in fields(rm.PreCreation)}


def test_existing_designation_requires_the_complete_pin_set():
    value = data("existing")
    for path in (
        ("repository", "id"),
        ("repository", "owner", "id"),
        ("repository", "owner", "login"),
        ("repository", "owner", "type"),
        ("repository", "name"),
        ("repository", "full_name"),
        ("repository", "visibility"),
        ("repository", "default_branch"),
        ("authorization_ref",),
        ("admin_scope",),
    ):
        assert code(rm.parse_existing, enc(edit(value, path, DELETE))) == (
            "missing_field"
        )
    assert code(rm.parse_existing, enc(edit(value, ("repository", "id"), None))) == (
        "bad_type"
    )


def variants_of(owner):
    return {
        "id": (rm.Owner(owner.id + 1, owner.login, owner.kind), "owner_mismatch"),
        "login": (rm.Owner(owner.id, "fictional-other", owner.kind), "owner_mismatch"),
        "type": (rm.Owner(owner.id, owner.login, "User"), "owner_mismatch"),
    }


def rebound(binding, **changes):
    repo = binding.repository
    ref = rm.RepositoryRef(
        changes.get("owner", repo.ref.owner),
        changes.get("id", repo.ref.id),
        changes.get("name", repo.ref.name),
        changes.get("full_name", None)
        or f"{changes.get('owner', repo.ref.owner).login}/"
        f"{changes.get('name', repo.ref.name)}",
    )
    repository = rm.Repository(
        ref,
        changes.get("visibility", repo.visibility),
        changes.get("default_branch", repo.default_branch),
    )
    return rm.Binding(
        changes.get("intent_id", binding.intent_id),
        changes.get("digest", binding.precreation_sha256),
        binding.creation_effect_ref,
        binding.observation_ref,
        binding.observed_at,
        repository,
    )


def test_post_creation_binding_detects_every_substitution():
    pre, binding = load("precreation"), load("binding")
    rm.verify_binding(pre, binding)
    for _label, (owner, reason) in variants_of(pre.owner).items():
        assert (
            construct_code(
                lambda owner=owner: rm.verify_binding(
                    pre, rebound(binding, owner=owner)
                )
            )
            == reason
        )
    cases = {
        "name_mismatch": {"name": "renamed-service"},
        "visibility_mismatch": {"visibility": "public"},
        "branch_mismatch": {"default_branch": "trunk"},
        "intent_mismatch": {"intent_id": "f" * 32},
        "digest_mismatch": {"digest": "e" * 64},
    }
    for reason, change in cases.items():
        assert (
            construct_code(
                lambda change=change: rm.verify_binding(pre, rebound(binding, **change))
            )
            == reason
        )
    other_pre = rm.PreCreation(
        pre.owner,
        pre.name,
        pre.visibility,
        pre.default_branch,
        pre.admin_scope,
        "fixture-authorization-9999",
        pre.intent_id,
    )
    assert construct_code(lambda: rm.verify_binding(other_pre, binding)) == (
        "digest_mismatch"
    )
    assert construct_code(lambda: rm.verify_binding(pre, None)) == "bad_type"
    assert construct_code(lambda: rm.verify_binding(binding, pre)) == "bad_type"


def test_name_only_transfer_and_rename_have_no_authority():
    pre, binding = load("precreation"), load("binding")
    stranger = rm.Owner(pre.owner.id + 7, pre.owner.login, pre.owner.kind)
    assert (
        construct_code(lambda: rm.verify_binding(pre, rebound(binding, owner=stranger)))
        == "owner_mismatch"
    )
    renamed_owner = rm.Owner(pre.owner.id, "fictional-renamed", pre.owner.kind)
    assert (
        construct_code(
            lambda: rm.verify_binding(pre, rebound(binding, owner=renamed_owner))
        )
        == "owner_mismatch"
    )
    same_full_name_other_id = rebound(binding, id=binding.repository.ref.id + 1)
    # the repository id is the post-creation pin: pins differ from the original
    assert same_full_name_other_id.repository.ref != binding.repository.ref
    assert rm.dumps(same_full_name_other_id) != rm.dumps(binding)


def test_binding_requires_independent_observation_not_a_create_response_echo():
    value = data("binding")
    same = edit(value, ("observation", "ref"), value["creation_effect_ref"])
    assert code(rm.parse_binding, enc(same)) == "binding_provenance"
    for kind in ("create_response", "write_response", "", None, 1):
        bad = edit(value, ("observation", "kind"), kind)
        assert code(rm.parse_binding, enc(bad)) == "binding_provenance"
    for key in ("creation_effect_ref",):
        assert code(rm.parse_binding, enc(edit(value, (key,), DELETE))) == (
            "missing_field"
        )
    bad_repo = edit(value, ("repository", "id"), 0)
    assert code(rm.parse_binding, enc(bad_repo)) == "bad_range"
    drop = edit(value, ("repository", "default_branch"), DELETE)
    assert code(rm.parse_binding, enc(drop)) == "missing_field"


def test_binding_is_never_created_or_adopted_automatically():
    public = {n for n in dir(rm) if not n.startswith("_")}
    assert not {
        n for n in public if re.search(r"adopt|auto|bind_|create_|apply|plan", n)
    }
    assert {f.name for f in fields(rm.Binding)} >= {"intent_id", "precreation_sha256"}


# --- actual state, per-control results, aggregation -----------------------------------


def test_unverified_reason_set_is_closed():
    value = data("result-unverified")
    for bad in (
        "unsupported",
        "not_supported",
        "provider_message",
        "",
        "HTTP_403",
        403,
        None,
    ):
        assert code(rm.parse_result, enc(edit(value, ("evidence", "reason"), bad))) in {
            "bad_value",
            "bad_type",
        }


def test_unsupported_requires_affirmative_independent_limitation_evidence():
    value = data("result-unsupported")
    for key in value["evidence"]:
        if key == "kind":
            continue
        assert code(rm.parse_result, enc(edit(value, ("evidence", key), DELETE))) == (
            "missing_field"
        )
    for key in ("provider_message", "http_status", "reason", "message"):
        assert code(rm.parse_result, enc(edit(value, ("evidence", key), "x"))) == (
            "unknown_field"
        )
    one = edit(value, ("evidence", "corroboration_refs"), ["fixture-corroboration-1"])
    assert code(rm.parse_result, enc(one)) == "bad_range"
    none = edit(value, ("evidence", "corroboration_refs"), [])
    assert code(rm.parse_result, enc(none)) == "bad_range"
    unsorted = edit(
        value, ("evidence", "corroboration_refs"), ["fixture-b", "fixture-a"]
    )
    assert code(rm.parse_result, enc(unsorted)) == "not_sorted"
    twice = edit(value, ("evidence", "corroboration_refs"), ["fixture-a", "fixture-a"])
    assert code(rm.parse_result, enc(twice)) == "not_sorted"
    for key in ("visibility_ref", "plan_ref", "documentation_ref"):
        shared = edit(
            value, ("evidence", key), value["evidence"]["corroboration_refs"][0]
        )
        assert code(rm.parse_result, enc(shared)) == "not_independent"
    same = edit(value, ("evidence", "plan_ref"), value["evidence"]["visibility_ref"])
    assert code(rm.parse_result, enc(same)) == "not_independent"
    stamp = edit(value, ("evidence", "observed_at"), "unknown")
    assert code(rm.parse_result, enc(stamp)) == "bad_timestamp"


def test_contradictory_requires_distinct_references_and_distinct_values():
    value = data("result-contradictory")
    assert rm.parse_result(enc(value)).result is R.CONTRADICTORY
    one = edit(
        value, ("evidence", "observations"), value["evidence"]["observations"][:1]
    )
    assert code(rm.parse_result, enc(one)) == "bad_range"
    same_value = edit(value, ("evidence", "observations", 1, "value"), False)
    assert code(rm.parse_result, enc(same_value)) == "evidence_mismatch"
    same_ref = edit(value, ("evidence", "observations", 1, "ref"), "fixture-read-0001")
    assert code(rm.parse_result, enc(same_ref)) == "not_sorted"
    typed = edit(value, ("evidence", "observations", 1, "value"), "yes")
    assert code(rm.parse_result, enc(typed)) == "bad_type"


def test_result_rejects_unknown_controls_and_blocking_type_errors():
    value = data("result-compliant")
    assert code(rm.parse_result, enc(edit(value, ("control",), "repo.nuke"))) == (
        "unknown_control"
    )
    assert code(rm.parse_result, enc(edit(value, ("blocking",), 1))) == "bad_type"
    assert code(rm.parse_result, enc(edit(value, ("control",), 5))) == "bad_type"


# --- enrollment and the evidence/authorization/admission separation -------------------


@pytest.mark.parametrize(
    "key",
    sorted(rm._AUTHORITY_KEYS),
)
def test_enrollment_rejects_authority_and_admission_fields_at_every_level(key):
    value = data("enrollment")
    for path in dict_paths(value):
        mutated = copy.deepcopy(value)
        node = mutated
        for step in path:
            node = node[step]
        node[key] = True
        assert code(rm.parse_enrollment, enc(mutated)) == "authority_field", path


# --- source and package boundaries -----------------------------------------

ALLOWED_IMPORTS = {"hashlib", "json", "math", "re", "dataclasses", "datetime", "enum"}
FORBIDDEN_NAMES = {
    "open",
    "exec",
    "eval",
    "compile",
    "__import__",
    "input",
    "print",
    "getattr",
    "setattr",
    "globals",
    "locals",
    "vars",
}
FORBIDDEN_TEXT = (
    "environ",
    "getenv",
    "expanduser",
    "Path(",
    "socket",
    "subprocess",
    "urllib",
    "http.",
    "http:",
    "https",
    "password",
    "os.",
    "sys.",
    "glob",
    "shutil",
    "tempfile",
)


def test_model_imports_only_the_standard_library_and_has_no_io_primitives():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Name):
            assert node.id not in FORBIDDEN_NAMES, node.id
        elif isinstance(node, ast.Attribute):
            assert not node.attr.startswith("__") or node.attr in {
                "__init__",
                "__post_init__",
            }
    assert imported == ALLOWED_IMPORTS
    for node in ast.walk(tree):  # docstrings may name what the model refuses to do
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            if isinstance(body[0].value, ast.Constant):
                body[0].value = ast.Constant("")
    code_only = ast.unparse(tree)
    for needle in FORBIDDEN_TEXT:
        assert needle not in code_only, needle


def test_model_paths_perform_no_io_network_subprocess_or_discovery(monkeypatch):
    import os
    import socket

    def boom(*_a, **_k):
        raise AssertionError("forbidden operation")

    inputs = {n: raw(n) for n in NAMES}
    failure = None
    with monkeypatch.context() as patch:  # undone before pytest formats any failure
        patch.setattr(builtins, "open", boom)
        patch.setattr(socket, "socket", boom)
        patch.setattr(socket, "create_connection", boom)
        patch.setattr(subprocess, "Popen", boom)
        patch.setattr(os, "system", boom)
        patch.setattr(os, "getenv", boom)
        patch.setattr(os, "listdir", boom)
        patch.setattr(os, "scandir", boom)
        for method in ("read_bytes", "read_text", "write_bytes", "write_text"):
            patch.setattr(Path, method, boom)
        patch.setattr(Path, "iterdir", boom)
        patch.setattr(Path, "exists", boom)
        try:
            records = {n: PARSERS[n](p) for n, p in inputs.items()}
            for record in records.values():
                rm.dumps(record)
                rm.digest(record)
            rm.compose_desired(
                records["profile"], records["manifest"], records["existing"]
            )
            rm.verify_binding(records["precreation"], records["binding"])
            rm.verify_origin(
                records["existing-origin"], records["precreation"], records["binding"]
            )
            desired = records["desired"]
            actual = records["actual-compliant"]
            results = derive_all(desired, actual)
            rm.verify_enrollment(
                records["enrollment"],
                records["compliance"],
                records["existing"],
                desired,
                actual,
                results,
            )
            rm.build_compliance(desired, actual, results, "fixture-evidence-0001")
            assert rm.summarize(desired, actual, results) is R.COMPLIANT
        except BaseException as error:  # noqa: BLE001 - reported after patches end
            failure = repr(error)
    assert failure is None, failure
    assert code(rm.parse_profile, b"{") == "bad_json"


def test_audit_events_during_parsing_contain_no_filesystem_network_or_process_calls():
    script = (
        "import sys, json\n"
        "from agent_platform import repository_manager as rm\n"
        "import datetime\n"
        "datetime.datetime.strptime('2026-01-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ')\n"
        "payloads = [(n, open(f'{sys.argv[1]}/{n}.json', 'rb').read())\n"
        "            for n in sys.argv[2:]]\n"
        "events = []\n"
        "sys.addaudithook(lambda e, a: events.append(e))\n"
        "for n, p in payloads:\n"
        "    parser = getattr(rm, 'parse_' + n.split('-')[0])\n"
        "    rm.digest(parser(p))\n"
        "bad = ('open', 'socket', 'subprocess', 'os.system', 'os.exec', 'os.fork',"
        " 'os.posix_spawn', 'os.listdir', 'os.scandir', 'os.mkdir', 'os.remove',"
        " 'os.rename', 'shutil', 'ctypes', 'urllib', 'http', 'ftplib', 'smtplib')\n"
        "print(json.dumps([e for e in events if e.startswith(bad)]))\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", script, str(FIXTURES), *NAMES],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
        check=False,
    )
    assert done.returncode == 0, done.stderr[-500:]
    assert json.loads(done.stdout) == []


def other_sources():
    for path in sorted((ROOT / "src/agent_platform").glob("*.py")):
        if path != MODULE:
            yield path


def test_no_runtime_worker_publisher_or_other_module_imports_or_names_the_model():
    for path in other_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all("repository_manager" not in a.name for a in node.names), path
            elif isinstance(node, ast.ImportFrom):
                assert "repository_manager" not in (node.module or ""), path
                assert all(a.name != "repository_manager" for a in node.names), path
        assert "repository_manager" not in path.read_text(), path


def test_model_is_source_only_and_absent_from_every_package_surface():
    spec = importlib.util.spec_from_file_location(
        "rm02_builder", ROOT / "packaging/build_deb.py"
    )
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    assert "repository_manager" in builder.SOURCE_ONLY
    assert all("repository_manager" not in m for m in builder.MODULES.values())
    assert "repository_manager" not in builder.PUBLISHER_MODULES
    assert not any(
        "repository_manager" in str(v) for v in builder.ENTRY_POINTS.values()
    )
    assert not any(
        "repository_manager" in v for v in builder.DEVELOPER_SCRIPTS.values()
    )
    builder.validate(ROOT)
    for relative in ("pyproject.toml", "uv.lock"):
        assert "repository_manager" not in (ROOT / relative).read_text()
    for folder in ("debian", ".github", "provisioning", "ci"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file():
                try:
                    text = path.read_text()
                except UnicodeDecodeError:
                    continue
                assert "repository_manager" not in text, path
    names = [p for p in (ROOT / "packaging").rglob("*.py") if p.name != "build_deb.py"]
    assert not any("repository_manager" in p.read_text() for p in names)
    build = (ROOT / "packaging/build_deb.py").read_text()
    assert build.count("repository_manager") == 1
    assert not list((ROOT / "src/agent_platform").glob("repository_manager/"))


def test_only_one_top_level_model_module_and_no_nested_or_glob_evasion():
    found = sorted(
        p.name
        for p in (ROOT / "src/agent_platform").rglob("*repository*")
        if "__pycache__" not in p.parts
    )
    assert found == ["repository_manager.py"]


# --- documentation contract ---------------------------------------------------


def test_configuration_document_matches_the_implemented_contract():
    text = DOC.read_text()
    for schema in rm.SCHEMAS:
        assert schema in text
    for control in C:
        assert f"`{control.value}`" in text
    for result in R:
        assert f"`{result.value}`" in text
    for reason in rm.UNAVAILABLE_REASONS:
        assert f"`{reason}`" in text
    for reason in rm.REASONS:
        assert f"`{reason}`" in text, reason
    for needle in (
        "VERIFIED_OFFLINE",
        "SOURCE_ONLY",
        "NO_LIVE",
        "HOST_NOT_RUN",
        "not authentication",
        "not authorization",
        "U2",
        "U9",
        "RM-04",
        "RM-05",
        "RM-08",
        "never admission",
    ):
        assert needle in text, needle
    assert "agent-platform-control" in text
    assert not re.search(r"https?://|ghp_|github_pat_|TechTradeExpress|su-17", text)


@pytest.mark.parametrize(
    "name,path",
    [
        ("actual", ("observed_at",)),
        ("binding", ("observation", "observed_at")),
        ("enrollment", ("decision", "decided_at")),
        ("result-unsupported", ("evidence", "observed_at")),
    ],
)
def test_impossible_dates_do_not_chain_or_echo_the_parser_error(name, path):
    impossible = "2026-13-45T25:61:61Z"
    payload = enc(edit(data(name), path, impossible))
    with pytest.raises(rm.RepositoryManagerError) as caught:
        PARSERS[name](payload)
    assert caught.value.reason == "bad_timestamp"
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert impossible not in "".join(traceback.format_exception(caught.value))


# --- RP-01: target binding, snapshot binding and enrollment context ---------------

PROFILE_R = load("profile")
MANIFEST_R = load("manifest")
MANIFEST_C = load("manifest-creation")
PRE = load("precreation")
BINDING = load("binding")
EXISTING = load("existing")
EXISTING_O = load("existing-origin")
DESIRED_R = load("desired")
MIXED = load("actual")
CLEAN = load("actual-compliant")
REPORT = load("compliance")
ENROLL = load("enrollment")
LIMIT = load("result-unsupported").evidence
BLOCKING = [s for s in DESIRED_R.controls if s.blocking]
SETTING = rm.ControlSetting


def other_value(setting):
    value = setting.value
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return "write" if value != "write" else "read"
    if isinstance(value, int):
        return value + 1
    return ()


def derive(desired, actual, control):
    setting = next(c for c in desired.controls if c.control == control)
    seen = actual.observation_of(control)
    if seen.observed:
        same = seen.value == setting.value
        result = R.COMPLIANT if same else R.NONCOMPLIANT
        evidence = (rm.Match if same else rm.Difference)(setting.value, seen.value)
    elif seen.limitation is not None:
        result, evidence = R.UNSUPPORTED, seen.limitation
    elif seen.reason == "conflicting_observations":
        result = R.CONTRADICTORY
        evidence = rm.Conflict(
            (
                rm.ConflictingObservation("fixture-read-1", setting.value),
                rm.ConflictingObservation("fixture-read-2", other_value(setting)),
            )
        )
    else:
        result, evidence = R.UNVERIFIED, rm.Unavailable(seen.reason)
    return rm.ControlResult(
        rm.digest(desired),
        rm.digest(actual),
        control,
        setting.blocking,
        result,
        evidence,
    )


def derive_all(desired, actual):
    return tuple(derive(desired, actual, s.control) for s in desired.controls)


def full_identity(desired):
    target = desired.target.repository
    return rm.ObservedIdentity(target.ref, target.visibility, target.default_branch)


def limit_for(control, repository_id=None):
    return dataclasses.replace(
        LIMIT,
        control=control,
        repository_id=repository_id or EXISTING.repository.ref.id,
    )


def snapshot(desired, observed, complete=None, scope=None, repository=None):
    obs = tuple(sorted(observed, key=lambda o: o.control.value))
    identity = repository or full_identity(desired)
    return rm.ActualState(
        identity,
        rm.digest(desired),
        "synthetic_fixture",
        "fixture-observation-1000",
        "2026-01-01T00:00:00Z",
        scope or tuple(o.control for o in obs),
        (identity.complete and all(o.observed for o in obs))
        if complete is None
        else complete,
        obs,
    )


CLEAN_RESULTS = tuple(derive(DESIRED_R, CLEAN, s.control) for s in DESIRED_R.controls)


def venroll(
    enrollment=None, report=None, pins=None, desired=None, actual=None, results=None
):
    """Full enrollment verification with the complete valid context by default."""
    return rm.verify_enrollment(
        enrollment or ENROLL,
        report or REPORT,
        pins or EXISTING,
        desired or DESIRED_R,
        actual or CLEAN,
        CLEAN_RESULTS if results is None else results,
    )


def alt_existing(**c):
    base = EXISTING.repository
    owner = c.get("owner", base.ref.owner)
    name = c.get("name", base.ref.name)
    ref = rm.RepositoryRef(
        owner, c.get("id", base.ref.id), name, f"{owner.login}/{name}"
    )
    repo = rm.Repository(
        ref, c.get("visibility", base.visibility), c.get("branch", base.default_branch)
    )
    return rm.ExistingPins(
        repo,
        EXISTING.admin_scope,
        c.get("auth", EXISTING.authorization_ref),
        c.get("origin", EXISTING.origin),
    )


def changed_owner(**c):
    o = EXISTING.repository.ref.owner
    return rm.Owner(c.get("id", o.id), c.get("login", o.login), c.get("kind", o.kind))


OTHER_PINS = alt_existing(id=9100002, name="other-service")


def desired_for(pins, manifest_id="fictional-manifest"):
    manifest = rm.Manifest(
        manifest_id, "fictional-profile", rm.existing_target(pins), MANIFEST_R.controls
    )
    return rm.compose_desired(PROFILE_R, manifest, pins)


def clean_snapshot(desired):
    return snapshot(
        desired,
        tuple(rm.Observation(s.control, True, s.value) for s in desired.controls),
    )


# F01: manifest and desired state are bound to a concrete target


def test_manifest_and_desired_state_carry_a_typed_target():
    assert type(MANIFEST_R.target) is rm.ExistingTarget
    assert type(MANIFEST_C.target) is rm.CreationTarget
    assert DESIRED_R.target == MANIFEST_R.target
    assert data("manifest")["target"]["mode"] == "existing"
    assert data("manifest-creation")["target"]["mode"] == "creation"
    assert data("desired")["target"] == data("manifest")["target"]
    assert "target" not in {f.name for f in fields(rm.Profile)}  # reusable policy


def test_review_finding_f01_manifest_substitution_between_repositories_is_detected():
    other = desired_for(OTHER_PINS, "fictional-manifest")
    assert other != DESIRED_R and rm.digest(other) != rm.digest(DESIRED_R)
    assert other.controls == DESIRED_R.controls  # only the target differs
    assert construct_code(
        lambda: rm.compose_desired(PROFILE_R, MANIFEST_R, OTHER_PINS)
    ) == ("repository_mismatch")
    assert construct_code(
        lambda: rm.verify_desired(other, PROFILE_R, MANIFEST_R, EXISTING)
    ) == ("desired_mismatch")
    assert construct_code(
        lambda: rm.verify_desired(DESIRED_R, PROFILE_R, MANIFEST_R, OTHER_PINS)
    ) == ("repository_mismatch")
    swapped = dataclasses.replace(DESIRED_R, target=other.target)
    assert construct_code(
        lambda: rm.verify_desired(swapped, PROFILE_R, MANIFEST_R, EXISTING)
    ) == ("desired_mismatch")


@pytest.mark.parametrize(
    "label,pins,reason",
    [
        ("owner id", alt_existing(owner=changed_owner(id=9000002)), "owner_mismatch"),
        (
            "owner login",
            alt_existing(owner=changed_owner(login="other-owner")),
            "owner_mismatch",
        ),
        (
            "owner type",
            alt_existing(owner=changed_owner(kind="User")),
            "owner_mismatch",
        ),
        ("repository id", alt_existing(id=9100002), "repository_mismatch"),
        ("name", alt_existing(name="renamed-service"), "repository_mismatch"),
        ("visibility", alt_existing(visibility="public"), "visibility_mismatch"),
        ("default branch", alt_existing(branch="trunk"), "branch_mismatch"),
        (
            "authorization",
            alt_existing(auth="fixture-authorization-9999"),
            "digest_mismatch",
        ),
        (
            "origin",
            alt_existing(origin=EXISTING_O.origin),
            "digest_mismatch",
        ),
    ],
)
def test_existing_manifest_target_must_equal_the_exact_complete_pins(
    label, pins, reason
):
    assert construct_code(lambda: rm.verify_target(MANIFEST_R.target, pins)) == reason
    assert (
        construct_code(lambda: rm.compose_desired(PROFILE_R, MANIFEST_R, pins))
        == reason
    )


@pytest.mark.parametrize(
    "label,pins,reason",
    [
        ("intent", dataclasses.replace(PRE, intent_id="f" * 32), "intent_mismatch"),
        (
            "owner id",
            dataclasses.replace(PRE, owner=changed_owner(id=9000002)),
            "owner_mismatch",
        ),
        (
            "owner type",
            dataclasses.replace(PRE, owner=changed_owner(kind="User")),
            "owner_mismatch",
        ),
        ("name", dataclasses.replace(PRE, name="renamed-service"), "name_mismatch"),
        (
            "visibility",
            dataclasses.replace(PRE, visibility="public"),
            "visibility_mismatch",
        ),
        ("branch", dataclasses.replace(PRE, default_branch="trunk"), "branch_mismatch"),
        (
            "authorization",
            dataclasses.replace(PRE, authorization_ref="fixture-authorization-9999"),
            "digest_mismatch",
        ),
        (
            "scope",
            dataclasses.replace(PRE, admin_scope=("create_repository",)),
            "digest_mismatch",
        ),
    ],
)
def test_creation_manifest_target_is_bound_to_the_exact_intent_and_pins(
    label, pins, reason
):
    assert construct_code(lambda: rm.verify_target(MANIFEST_C.target, pins)) == reason
    assert (
        construct_code(lambda: rm.compose_desired(PROFILE_R, MANIFEST_C, pins))
        == reason
    )


def test_creation_configuration_has_no_repository_id_and_composes_with_exact_pins():
    desired = rm.compose_desired(PROFILE_R, MANIFEST_C, PRE)
    assert desired.target == MANIFEST_C.target == rm.creation_target(PRE)
    assert desired.target.precreation_sha256 == rm.digest(PRE)
    assert "id" not in {f.name for f in fields(rm.CreationTarget)}
    wire = data("manifest-creation")["target"]
    assert "id" not in wire["repository"] and "repository_id" not in wire
    for path in (
        ("target", "repository", "id"),
        ("target", "repository_id"),
        ("target", "repository", "repository_id"),
        ("target", "repository", "full_name"),
    ):
        for value in (1, None, "x/y"):
            mutated = edit(data("manifest-creation"), path, value)
            assert (
                code(rm.parse_manifest, enc(mutated)) == "repository_id_in_precreation"
            )
    # an existing-repository manifest is not a creation intent, and vice versa
    assert construct_code(
        lambda: rm.compose_desired(PROFILE_R, MANIFEST_C, EXISTING)
    ) == ("target_mismatch")
    assert construct_code(lambda: rm.compose_desired(PROFILE_R, MANIFEST_R, PRE)) == (
        "target_mismatch"
    )
    for bad in (None, "x", PROFILE_R, rm.digest(PRE)):
        assert construct_code(
            lambda bad=bad: rm.compose_desired(PROFILE_R, MANIFEST_R, bad)
        ) == ("bad_type")
    with pytest.raises(TypeError):
        rm.compose_desired(PROFILE_R, MANIFEST_R)  # incomplete context


def test_existing_target_requires_the_complete_pin_set_and_digest():
    for key in ("id", "name", "full_name", "visibility", "default_branch", "owner"):
        bad = edit(data("manifest"), ("target", "repository", key), DELETE)
        assert code(rm.parse_manifest, enc(bad)) == "missing_field"
    for key in ("id", "login", "type"):
        bad = edit(data("manifest"), ("target", "repository", "owner", key), DELETE)
        assert code(rm.parse_manifest, enc(bad)) == "missing_field"
    assert code(
        rm.parse_manifest,
        enc(edit(data("manifest"), ("target", "pins_sha256"), DELETE)),
    ) == ("missing_field")
    assert code(
        rm.parse_manifest,
        enc(edit(data("manifest"), ("target", "pins_sha256"), "A" * 64)),
    ) == ("bad_digest")
    assert code(
        rm.parse_manifest, enc(edit(data("manifest"), ("target", "mode"), DELETE))
    ) == ("missing_field")
    for bad, reason in (
        ("other", "bad_value"),
        (None, "bad_type"),
        (1, "bad_type"),
        ("", "bad_value"),
    ):
        assert (
            code(
                rm.parse_manifest, enc(edit(data("manifest"), ("target", "mode"), bad))
            )
            == reason
        )
    # a mode switch keeps the other mode's fields and is rejected
    swapped = edit(data("manifest"), ("target", "mode"), "creation")
    assert code(rm.parse_manifest, enc(swapped)) in {"unknown_field", "missing_field"}
    assert (
        code(rm.parse_manifest, enc(edit(data("manifest"), ("target",), None)))
        == "not_object"
    )


def test_desired_state_preserves_the_target_and_digest_binds_it():
    desired = rm.compose_desired(PROFILE_R, MANIFEST_R, EXISTING)
    assert desired == DESIRED_R and desired.target is MANIFEST_R.target
    rm.verify_desired(desired, PROFILE_R, MANIFEST_R, EXISTING)
    assert code(rm.parse_desired, enc(edit(data("desired"), ("target",), DELETE))) == (
        "missing_field"
    )
    assert (
        construct_code(lambda: rm.DesiredState("p", "m", None, DESIRED_R.controls))
        == "bad_type"
    )
    assert construct_code(lambda: rm.Manifest("m", "p", "target", ())) == "bad_type"
    other_mode = rm.compose_desired(PROFILE_R, MANIFEST_C, PRE)
    assert rm.digest(other_mode) != rm.digest(desired)
    assert construct_code(
        lambda: rm.compose_desired(PROFILE_R, MANIFEST_R, EXISTING_O)
    ) == ("digest_mismatch")


def test_profile_and_manifest_composition_rules_still_apply():
    overlap = rm.Manifest(
        "other", PROFILE_R.profile_id, MANIFEST_R.target, (PROFILE_R.controls[0],)
    )
    assert construct_code(lambda: rm.compose_desired(PROFILE_R, overlap, EXISTING)) == (
        "overlapping_control"
    )
    other = rm.Manifest(
        "other", "different-profile", MANIFEST_R.target, MANIFEST_R.controls
    )
    assert construct_code(lambda: rm.compose_desired(PROFILE_R, other, EXISTING)) == (
        "unresolved_reference"
    )
    quiet_profile = rm.Profile(
        PROFILE_R.profile_id,
        tuple(SETTING(c.control, False, c.value) for c in PROFILE_R.controls),
    )
    quiet = rm.Manifest("quiet", PROFILE_R.profile_id, MANIFEST_R.target, ())
    assert construct_code(
        lambda: rm.compose_desired(quiet_profile, quiet, EXISTING)
    ) == ("no_blocking_control")
    assert construct_code(
        lambda: rm.compose_desired(load("actual"), MANIFEST_R, EXISTING)
    ) == ("bad_type")
    assert construct_code(
        lambda: rm.verify_desired(None, PROFILE_R, MANIFEST_R, EXISTING)
    ) == ("desired_mismatch")


def test_inconsistent_control_combinations_are_ambiguous_and_rejected():
    target = MANIFEST_R.target

    def desired(*settings):
        ordered = tuple(sorted(settings, key=lambda s: s.control.value))
        return rm.DesiredState("p", "m", target, ordered)

    none_allowed = (
        SETTING(C.REPO_ALLOW_MERGE_COMMIT, True, False),
        SETTING(C.REPO_ALLOW_REBASE_MERGE, True, False),
        SETTING(C.REPO_ALLOW_SQUASH_MERGE, True, False),
    )
    assert construct_code(lambda: desired(*none_allowed)) == "inconsistent_controls"
    assert desired(*none_allowed[:2]).controls
    assert (
        construct_code(
            lambda: desired(
                SETTING(C.BRANCH_REQUIRED_APPROVALS, True, 1),
                SETTING(C.BRANCH_REQUIRE_PULL_REQUEST, True, False),
            )
        )
        == "inconsistent_controls"
    )
    assert desired(
        SETTING(C.BRANCH_REQUIRED_APPROVALS, True, 0),
        SETTING(C.BRANCH_REQUIRE_PULL_REQUEST, True, False),
    ).controls
    wire = data("desired")
    wire["controls"] = []
    assert code(rm.parse_desired, enc(wire)) == "bad_range"


# Post-creation reconciliation keeps the relationship to the original intent


def test_existing_pins_after_creation_retain_the_exact_original_intent():
    rm.verify_origin(EXISTING_O, PRE, BINDING)
    assert EXISTING_O.origin == rm.Origin(
        PRE.intent_id, rm.digest(PRE), rm.digest(BINDING)
    )
    assert EXISTING.origin is None
    target = rm.existing_target(EXISTING_O)
    manifest = rm.Manifest(
        "fictional-manifest", "fictional-profile", target, MANIFEST_R.controls
    )
    desired = rm.compose_desired(PROFILE_R, manifest, EXISTING_O)
    assert desired.target.pins_sha256 == rm.digest(EXISTING_O)
    assert desired.target.pins_sha256 != rm.digest(EXISTING)
    assert construct_code(
        lambda: rm.compose_desired(PROFILE_R, manifest, EXISTING)
    ) == ("digest_mismatch")


def test_origin_verification_rejects_wrong_intent_binding_and_repository():
    other_pre = dataclasses.replace(PRE, intent_id="f" * 32)
    cases = {
        "no origin": (EXISTING, PRE, BINDING, "origin_mismatch"),
        "other pre-creation record": (
            EXISTING_O,
            other_pre,
            BINDING,
            "intent_mismatch",
        ),
        "binding for other intent": (
            EXISTING_O,
            PRE,
            dataclasses.replace(BINDING, intent_id="f" * 32),
            "intent_mismatch",
        ),
        "altered binding": (
            EXISTING_O,
            PRE,
            dataclasses.replace(BINDING, observation_ref="fixture-readback-9999"),
            "origin_mismatch",
        ),
        "digest of other pre-creation": (
            EXISTING_O,
            dataclasses.replace(PRE, authorization_ref="fixture-authorization-9999"),
            BINDING,
            "digest_mismatch",
        ),
        "other repository": (
            dataclasses.replace(
                EXISTING_O,
                repository=rm.Repository(EXISTING.repository.ref, "private", "trunk"),
            ),
            PRE,
            BINDING,
            "branch_mismatch",
        ),
        "other repository id": (
            dataclasses.replace(
                EXISTING_O, repository=alt_existing(id=9100002).repository
            ),
            PRE,
            BINDING,
            "repository_mismatch",
        ),
        "other origin intent": (
            dataclasses.replace(
                EXISTING_O,
                origin=dataclasses.replace(EXISTING_O.origin, intent_id="f" * 32),
            ),
            PRE,
            BINDING,
            "origin_mismatch",
        ),
    }
    for label, (pins, pre, binding, reason) in cases.items():
        assert (
            construct_code(lambda a=(pins, pre, binding): rm.verify_origin(*a))
            == reason
        ), label
    assert construct_code(lambda: rm.verify_origin(None, PRE, BINDING)) == "bad_type"
    assert (
        construct_code(lambda: rm.verify_origin(EXISTING_O, None, BINDING))
        == "bad_type"
    )
    assert construct_code(lambda: rm.verify_origin(EXISTING_O, PRE, None)) == "bad_type"
    assert (
        construct_code(lambda: rm.verify_origin(EXISTING_O, BINDING, PRE)) == "bad_type"
    )


def test_origin_wire_is_closed():
    value = data("existing-origin")
    assert (
        code(rm.parse_existing, enc(edit(value, ("origin",), DELETE)))
        == "missing_field"
    )
    assert code(rm.parse_existing, enc(edit(value, ("origin",), "x"))) == "not_object"
    for key in ("intent_id", "precreation_sha256", "binding_sha256"):
        assert (
            code(rm.parse_existing, enc(edit(value, ("origin", key), DELETE)))
            == "missing_field"
        )
    assert (
        code(
            rm.parse_existing, enc(edit(value, ("origin", "binding_sha256"), "g" * 64))
        )
        == "bad_digest"
    )
    assert code(
        rm.parse_existing, enc(edit(value, ("origin", "intent_id"), "A" * 32))
    ) == ("bad_identifier")
    assert construct_code(
        lambda: rm.ExistingPins(
            EXISTING.repository, EXISTING.admin_scope, "fixture-a-1", "x"
        )
    ) == ("bad_type")


# F02: observations and results are bound to the desired state, target and snapshot


def test_review_finding_f02_results_cannot_make_an_incomplete_snapshot_compliant():
    assert MIXED.complete is False
    assert MIXED.observation_of(C.BRANCH_REQUIRED_CHECKS).reason == "http_403_ambiguous"
    forged = tuple(
        rm.ControlResult(
            rm.digest(DESIRED_R),
            rm.digest(MIXED),
            s.control,
            s.blocking,
            R.COMPLIANT,
            rm.Match(s.value, s.value),
        )
        for s in DESIRED_R.controls
    )
    assert construct_code(lambda: rm.summarize(DESIRED_R, MIXED, forged)) == (
        "evidence_mismatch"
    )
    unavailable = [c for c in forged if not MIXED.observation_of(c.control).observed]
    assert unavailable
    for item in unavailable:
        assert construct_code(
            lambda item=item: rm.verify_result(item, DESIRED_R, MIXED)
        ) == ("evidence_mismatch")
    with pytest.raises(TypeError):
        rm.summarize(DESIRED_R, forged)  # a results-only conclusion no longer exists


def test_review_finding_f02_one_control_snapshot_is_not_the_desired_scope():
    one = snapshot(DESIRED_R, (rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, False),))
    assert one.complete is True and one.scope == (C.BRANCH_ALLOW_DELETIONS,)
    assert construct_code(lambda: rm.verify_actual(one, DESIRED_R)) == "scope_mismatch"
    assert (
        construct_code(
            lambda: rm.summarize(
                DESIRED_R, one, (derive(DESIRED_R, one, C.BRANCH_ALLOW_DELETIONS),)
            )
        )
        == "scope_mismatch"
    )
    assert (
        construct_code(
            lambda: rm.ActualState(
                MIXED.repository,
                MIXED.desired_sha256,
                "synthetic_fixture",
                "fixture-o-1",
                "2026-01-01T00:00:00Z",
                (C.BRANCH_ALLOW_DELETIONS, C.BRANCH_ALLOW_FORCE_PUSHES),
                True,
                (rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, False),),
            )
        )
        == "scope_mismatch"
    )


def test_completeness_is_explicit_and_exactly_verifiable():
    assert MIXED.complete is False and CLEAN.complete is True
    assert (
        construct_code(lambda: dataclasses.replace(MIXED, complete=True))
        == "completeness_mismatch"
    )
    assert (
        construct_code(lambda: dataclasses.replace(CLEAN, complete=False))
        == "completeness_mismatch"
    )
    assert (
        construct_code(lambda: dataclasses.replace(MIXED, complete="false"))
        == "bad_type"
    )
    for key, value in (("complete", True),):
        assert code(rm.parse_actual, enc(edit(data("actual"), (key,), value))) == (
            "completeness_mismatch"
        )
    assert code(
        rm.parse_actual, enc(edit(data("actual-compliant"), ("complete",), False))
    ) == ("completeness_mismatch")


def test_actual_scope_and_observations_are_closed_ordered_and_consistent():
    value = data("actual")
    assert value["scope"] == [o["control"] for o in value["observations"]]
    for mutated, reason in (
        (edit(value, ("scope",), value["scope"][:-1]), "scope_mismatch"),
        (edit(value, ("scope",), list(reversed(value["scope"]))), "not_sorted"),
        (edit(value, ("scope",), value["scope"] + [value["scope"][0]]), "not_sorted"),
        (edit(value, ("scope",), []), "bad_range"),
        (edit(value, ("scope", 0), "repo.delete_repository"), "unknown_control"),
        (edit(value, ("scope", 0), 5), "bad_type"),
    ):
        assert code(rm.parse_actual, enc(mutated)) == reason
    doubled = copy.deepcopy(value)
    doubled["observations"].insert(1, copy.deepcopy(doubled["observations"][0]))
    doubled["scope"].insert(1, doubled["scope"][0])
    assert code(rm.parse_actual, enc(doubled)) == "duplicate_control"
    assert (
        code(rm.parse_actual, enc(edit(value, ("desired_sha256",), "A" * 64)))
        == "bad_digest"
    )
    assert (
        code(rm.parse_actual, enc(edit(value, ("desired_sha256",), DELETE)))
        == "missing_field"
    )


def test_unavailable_observation_is_distinct_from_an_empty_observation():
    empty = rm.Observation(C.BRANCH_REQUIRED_CHECKS, True, ())
    missing = rm.Observation(C.BRANCH_REQUIRED_CHECKS, False, None, "not_observed")
    assert empty.wire()["value"] == [] and "value" not in missing.wire()
    assert empty != missing
    cases = [
        (
            lambda: rm.Observation(
                C.BRANCH_ALLOW_DELETIONS, False, False, "not_observed"
            ),
            "bad_value",
        ),
        (
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, False, None, None),
            "bad_type",
        ),
        (
            lambda: rm.Observation(
                C.BRANCH_ALLOW_DELETIONS, False, None, "unsupported"
            ),
            "bad_value",
        ),
        (
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, False, None, "not_found"),
            "bad_value",
        ),
        (
            lambda: rm.Observation(
                C.BRANCH_ALLOW_DELETIONS, True, False, "rate_limited"
            ),
            "bad_value",
        ),
        (lambda: rm.Observation(C.OBSERVE_DEPLOY_KEY_COUNT, True, None), "bad_type"),
        (lambda: rm.Observation(C.OBSERVE_DEPLOY_KEY_COUNT, True, ()), "bad_type"),
    ]
    for factory, reason in cases:
        assert construct_code(factory) == reason
    value = data("actual")
    index = next(
        i for i, o in enumerate(value["observations"]) if o["status"] == "unavailable"
    )
    assert code(
        rm.parse_actual, enc(edit(value, ("observations", index, "value"), []))
    ) == ("unknown_field")
    for reason in sorted(rm.UNAVAILABLE_REASONS):
        ok = edit(value, ("observations", index, "reason"), reason)
        assert rm.parse_actual(enc(ok)).observations[index].reason == reason
    bad = edit(value, ("observations", index, "reason"), "unsupported")
    assert code(rm.parse_actual, enc(bad)) == "bad_value"


def test_verify_actual_binds_snapshot_to_desired_state_and_repository():
    rm.verify_actual(MIXED, DESIRED_R)
    other_desired = desired_for(OTHER_PINS)
    assert (
        construct_code(lambda: rm.verify_actual(MIXED, other_desired))
        == "snapshot_mismatch"
    )
    bad_digest = dataclasses.replace(MIXED, desired_sha256="0" * 64)
    assert (
        construct_code(lambda: rm.verify_actual(bad_digest, DESIRED_R))
        == "snapshot_mismatch"
    )
    other_actual = snapshot(
        other_desired,
        tuple(rm.Observation(s.control, True, s.value) for s in other_desired.controls),
    )
    rm.verify_actual(other_actual, other_desired)
    redirected = dataclasses.replace(
        CLEAN,
        repository=rm.ObservedIdentity(OTHER_PINS.repository.ref, "private", "main"),
    )
    assert (
        construct_code(lambda: rm.verify_actual(redirected, DESIRED_R))
        == "repository_mismatch"
    )
    created = rm.compose_desired(PROFILE_R, MANIFEST_C, PRE)
    assert construct_code(lambda: rm.verify_actual(CLEAN, created)) == "target_mismatch"
    for bad in ((None, DESIRED_R), (MIXED, None), (DESIRED_R, MIXED)):
        assert construct_code(lambda bad=bad: rm.verify_actual(*bad)) == "bad_type"
    assert dataclasses.replace(MIXED).scope == tuple(
        c.control for c in DESIRED_R.controls
    )
    reduced = dataclasses.replace(DESIRED_R, controls=DESIRED_R.controls[:-1])
    assert construct_code(
        lambda: rm.verify_actual(
            dataclasses.replace(MIXED, desired_sha256=rm.digest(reduced)), reduced
        )
    ) == ("scope_mismatch")


def test_results_from_another_snapshot_desired_state_or_repository_are_rejected():
    result = derive(DESIRED_R, CLEAN, C.BRANCH_ALLOW_DELETIONS)
    rm.verify_result(result, DESIRED_R, CLEAN)
    # another observation snapshot of the same repository and desired state
    again = dataclasses.replace(CLEAN, source_ref="fixture-observation-7777")
    assert rm.digest(again) != rm.digest(CLEAN)
    assert (
        construct_code(lambda: rm.verify_result(result, DESIRED_R, again))
        == "snapshot_mismatch"
    )
    assert construct_code(
        lambda: rm.summarize(DESIRED_R, again, derive_all(DESIRED_R, CLEAN))
    ) == ("snapshot_mismatch")
    # each digest is checked on its own
    wrong_desired = dataclasses.replace(result, desired_sha256="0" * 64)
    wrong_actual = dataclasses.replace(result, actual_sha256="0" * 64)
    for forged in (wrong_desired, wrong_actual):
        assert (
            construct_code(lambda f=forged: rm.verify_result(f, DESIRED_R, CLEAN))
            == "snapshot_mismatch"
        )
    # another desired state
    changed = tuple(
        SETTING(s.control, s.blocking, True)
        if s.control is C.BRANCH_ALLOW_DELETIONS
        else s
        for s in DESIRED_R.controls
    )
    desired2 = dataclasses.replace(DESIRED_R, controls=changed)
    assert construct_code(
        lambda: rm.verify_result(result, desired2, clean_snapshot(desired2))
    ) == ("snapshot_mismatch")
    # another repository with otherwise identical configuration
    desired3 = desired_for(OTHER_PINS)
    actual3 = clean_snapshot(desired3)
    assert (
        construct_code(lambda: rm.verify_result(result, desired3, actual3))
        == "snapshot_mismatch"
    )
    foreign = derive_all(desired3, actual3)
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, CLEAN, foreign))
        == "snapshot_mismatch"
    )
    assert construct_code(
        lambda: rm.summarize(desired3, CLEAN, derive_all(DESIRED_R, CLEAN))
    ) == ("snapshot_mismatch")
    # digests are structural: malformed or missing ones never validate
    for bad in ("A" * 64, "a" * 63, 5, None):
        assert construct_code(
            lambda bad=bad: dataclasses.replace(result, actual_sha256=bad)
        ) in {
            "bad_digest",
            "bad_type",
        }
    for key in ("desired_sha256", "actual_sha256"):
        assert code(
            rm.parse_result, enc(edit(data("result-compliant"), (key,), DELETE))
        ) == ("missing_field")


def test_result_evidence_must_agree_with_the_corresponding_observation():
    good = derive(DESIRED_R, MIXED, C.BRANCH_ALLOW_FORCE_PUSHES)
    assert good.result is R.NONCOMPLIANT and good.evidence.observed is True
    rm.verify_result(good, DESIRED_R, MIXED)
    d, a = rm.digest(DESIRED_R), rm.digest(MIXED)

    def make(control, result, evidence, blocking=True):
        return rm.ControlResult(d, a, control, blocking, result, evidence)

    cases = {
        "observed value differs": make(
            C.BRANCH_ALLOW_DELETIONS, R.NONCOMPLIANT, rm.Difference(False, True)
        ),
        "claims match where observation differs": make(
            C.BRANCH_ALLOW_FORCE_PUSHES, R.COMPLIANT, rm.Match(False, False)
        ),
        "compliant for unavailable observation": make(
            C.BRANCH_REQUIRED_CHECKS,
            R.COMPLIANT,
            rm.Match(*(DESIRED_R.value_of(C.BRANCH_REQUIRED_CHECKS),) * 2),
        ),
        "unverified for an observed control": make(
            C.BRANCH_ALLOW_DELETIONS, R.UNVERIFIED, rm.Unavailable("rate_limited")
        ),
        "unverified with other reason": make(
            C.BRANCH_REQUIRED_CHECKS, R.UNVERIFIED, rm.Unavailable("rate_limited")
        ),
        "unsupported for an observed control": make(
            C.BRANCH_ALLOW_DELETIONS,
            R.UNSUPPORTED,
            limit_for(C.BRANCH_ALLOW_DELETIONS),
        ),
        "contradictory without conflicting observation": make(
            C.BRANCH_REQUIRED_CHECKS,
            R.CONTRADICTORY,
            rm.Conflict(
                (
                    rm.ConflictingObservation("fixture-read-1", ()),
                    rm.ConflictingObservation(
                        "fixture-read-2", DESIRED_R.value_of(C.BRANCH_REQUIRED_CHECKS)
                    ),
                )
            ),
        ),
        "desired value not the desired state's": make(
            C.BRANCH_ALLOW_DELETIONS, R.NONCOMPLIANT, rm.Difference(True, False)
        ),
    }
    for label, item in cases.items():
        assert construct_code(
            lambda item=item: rm.verify_result(item, DESIRED_R, MIXED)
        ) == ("evidence_mismatch"), label
    flipped = make(
        C.BRANCH_ALLOW_DELETIONS, R.COMPLIANT, rm.Match(False, False), blocking=False
    )
    assert (
        construct_code(lambda: rm.verify_result(flipped, DESIRED_R, MIXED))
        == "coverage_mismatch"
    )
    outside = make(C.REPO_ALLOW_REBASE_MERGE, R.COMPLIANT, rm.Match(False, False))
    assert (
        construct_code(lambda: rm.verify_result(outside, DESIRED_R, MIXED))
        == "coverage_mismatch"
    )
    assert (
        construct_code(lambda: rm.verify_result(None, DESIRED_R, MIXED)) == "bad_type"
    )


def test_result_fixtures_match_their_snapshot():
    for name in (n for n in NAMES if n.startswith("result-")):
        rm.verify_result(load(name), DESIRED_R, MIXED)
        assert construct_code(
            lambda n=name: rm.verify_result(load(n), DESIRED_R, CLEAN)
        ) == ("snapshot_mismatch")


def test_summary_requires_the_full_structural_context_and_all_blocking_coverage():
    assert rm.summarize(DESIRED_R, CLEAN, derive_all(DESIRED_R, CLEAN)) is R.COMPLIANT
    blocking_only = tuple(derive(DESIRED_R, CLEAN, s.control) for s in BLOCKING)
    assert rm.summarize(DESIRED_R, CLEAN, blocking_only) is R.COMPLIANT
    assert len(BLOCKING) == 7
    results = derive_all(DESIRED_R, CLEAN)
    for item in BLOCKING:
        missing = tuple(r for r in results if r.control is not item.control)
        assert construct_code(lambda m=missing: rm.summarize(DESIRED_R, CLEAN, m)) == (
            "coverage_mismatch"
        )
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, CLEAN, ()))
        == "coverage_mismatch"
    )
    # the snapshot is verified even when no result is supplied
    short = snapshot(
        DESIRED_R, (rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, False),)
    )
    assert construct_code(lambda: rm.summarize(DESIRED_R, short, ())) == (
        "scope_mismatch"
    )
    alien = dataclasses.replace(
        CLEAN,
        repository=rm.ObservedIdentity(OTHER_PINS.repository.ref, "private", "main"),
    )
    assert construct_code(lambda: rm.summarize(DESIRED_R, alien, ())) == (
        "repository_mismatch"
    )
    assert construct_code(
        lambda: rm.summarize(DESIRED_R, CLEAN, results + (results[0],))
    ) == ("duplicate_result")
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, CLEAN, list(results)))
        == "bad_type"
    )
    assert construct_code(lambda: rm.summarize(DESIRED_R, CLEAN, ("x",))) == "bad_type"
    assert construct_code(lambda: rm.summarize(None, CLEAN, results)) == "bad_type"
    assert construct_code(lambda: rm.summarize(DESIRED_R, None, results)) == "bad_type"
    assert construct_code(lambda: rm.summarize(DESIRED_R, results, CLEAN)) == "bad_type"


@pytest.mark.parametrize(
    "unavailable",
    [s.control.value for s in DESIRED_R.controls if s.blocking],
)
@pytest.mark.parametrize("reason", sorted(rm.UNAVAILABLE_REASONS))
def test_unavailable_blocking_observation_never_yields_compliant(unavailable, reason):
    control = C(unavailable)
    observed = tuple(
        rm.Observation(control, False, None, reason)
        if s.control is control
        else rm.Observation(s.control, True, s.value)
        for s in DESIRED_R.controls
    )
    actual = snapshot(DESIRED_R, observed)
    assert actual.complete is False
    results = derive_all(DESIRED_R, actual)
    overall = rm.summarize(DESIRED_R, actual, results)
    expected = R.CONTRADICTORY if reason == "conflicting_observations" else R.UNVERIFIED
    assert overall is expected and overall is not R.COMPLIANT
    forged = tuple(
        dataclasses.replace(
            r,
            result=R.COMPLIANT,
            evidence=rm.Match(*(DESIRED_R.value_of(control),) * 2),
        )
        if r.control is control
        else r
        for r in results
    )
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, actual, forged))
        == "evidence_mismatch"
    )


def test_incomplete_snapshot_is_never_compliant_even_for_non_blocking_gaps():
    nonblocking = next(s for s in DESIRED_R.controls if not s.blocking)
    observed = tuple(
        rm.Observation(s.control, False, None, "not_observed")
        if s.control is nonblocking.control
        else rm.Observation(s.control, True, s.value)
        for s in DESIRED_R.controls
    )
    actual = snapshot(DESIRED_R, observed)
    assert actual.complete is False
    assert (
        rm.summarize(DESIRED_R, actual, derive_all(DESIRED_R, actual)) is R.UNVERIFIED
    )


@pytest.mark.parametrize(
    "result", [R.NONCOMPLIANT, R.UNSUPPORTED, R.UNVERIFIED, R.CONTRADICTORY]
)
@pytest.mark.parametrize("control", [s.control.value for s in BLOCKING])
def test_any_non_compliant_blocking_control_blocks_overall_compliance(result, control):
    target = C(control)
    setting = next(s for s in DESIRED_R.controls if s.control is target)
    if result is R.NONCOMPLIANT:
        seen = rm.Observation(target, True, other_value(setting))
    elif result is R.CONTRADICTORY:
        seen = rm.Observation(target, False, None, "conflicting_observations")
    elif result is R.UNSUPPORTED:
        seen = rm.Observation(target, False, None, None, limit_for(target))
    else:
        seen = rm.Observation(target, False, None, "http_403_ambiguous")
    observed = tuple(
        seen if s.control is target else rm.Observation(s.control, True, s.value)
        for s in DESIRED_R.controls
    )
    actual = snapshot(DESIRED_R, observed)
    results = derive_all(DESIRED_R, actual)
    assert next(r for r in results if r.control is target).result is result
    assert rm.summarize(DESIRED_R, actual, results) is result


def test_summary_precedence_and_nonblocking_results():
    def overall(**observations):
        observed = []
        for s in DESIRED_R.controls:
            kind = observations.get(s.control.value)
            if kind == "differs":
                observed.append(rm.Observation(s.control, True, other_value(s)))
            elif kind:
                observed.append(rm.Observation(s.control, False, None, kind))
            else:
                observed.append(rm.Observation(s.control, True, s.value))
        actual = snapshot(DESIRED_R, tuple(observed))
        return rm.summarize(DESIRED_R, actual, derive_all(DESIRED_R, actual))

    deletions = C.BRANCH_ALLOW_DELETIONS.value
    assert overall(**{deletions: "differs"}) is R.NONCOMPLIANT
    assert (
        overall(**{deletions: "differs", C.REPO_ALLOW_AUTO_MERGE.value: "rate_limited"})
        is R.UNVERIFIED
    )
    worst = {
        deletions: "differs",
        C.REPO_ALLOW_AUTO_MERGE.value: "rate_limited",
        C.BRANCH_ALLOW_FORCE_PUSHES.value: "conflicting_observations",
    }
    assert overall(**worst) is R.CONTRADICTORY
    # a non-compliant, observed non-blocking control does not block (and is reported)
    nonblocking = next(
        s
        for s in DESIRED_R.controls
        if not s.blocking and isinstance(s.value, bool | int)
    )
    actual = snapshot(
        DESIRED_R,
        tuple(
            rm.Observation(
                s.control, True, other_value(s) if s is nonblocking else s.value
            )
            for s in DESIRED_R.controls
        ),
    )
    results = derive_all(DESIRED_R, actual)
    assert (
        next(r for r in results if r.control is nonblocking.control).result
        is R.NONCOMPLIANT
    )
    assert rm.summarize(DESIRED_R, actual, results) is R.COMPLIANT


def test_mixed_fixture_snapshot_is_never_compliant():
    results = derive_all(DESIRED_R, MIXED)
    assert {r.result for r in results} == set(R)
    assert rm.summarize(DESIRED_R, MIXED, results) is R.CONTRADICTORY


def test_result_set_is_exactly_the_five_documented_values():
    assert [r.value for r in R] == [
        "COMPLIANT",
        "NONCOMPLIANT",
        "UNSUPPORTED",
        "UNVERIFIED",
        "CONTRADICTORY",
    ]
    value = data("result-compliant")
    for bad in ("compliant", "PASS", "OK", "UNKNOWN", "UNSUPPORTED ", ""):
        assert code(rm.parse_result, enc(edit(value, ("result",), bad))) == "bad_value"


def test_each_result_requires_its_own_evidence_kind():
    wires = {n: data(n) for n in NAMES if n.startswith("result-")}
    for source, value in wires.items():
        for target, other in wires.items():
            if source == target:
                continue
            swapped = edit(value, ("result",), other["result"])
            assert code(rm.parse_result, enc(swapped)) == "evidence_mismatch"
            only_evidence = edit(value, ("evidence",), other["evidence"])
            assert code(rm.parse_result, enc(only_evidence)) == "evidence_mismatch"
    d, a = rm.digest(DESIRED_R), rm.digest(MIXED)
    evidences = {
        R.COMPLIANT: rm.Match(False, False),
        R.NONCOMPLIANT: rm.Difference(False, True),
        R.UNVERIFIED: rm.Unavailable("rate_limited"),
        R.UNSUPPORTED: LIMIT,
        R.CONTRADICTORY: load("result-contradictory").evidence,
    }
    for result in R:
        for evidence in evidences.values():
            if type(evidence) is not type(evidences[result]):
                assert (
                    construct_code(
                        lambda r=result, e=evidence: rm.ControlResult(
                            d, a, C.REPO_ALLOW_AUTO_MERGE, True, r, e
                        )
                    )
                    == "evidence_mismatch"
                )


def test_compliance_evidence_must_actually_match_or_differ():
    d, a = "1" * 64, "2" * 64

    def result(control, res, evidence):
        return lambda: rm.ControlResult(d, a, control, True, res, evidence)

    assert construct_code(
        result(C.BRANCH_ALLOW_DELETIONS, R.COMPLIANT, rm.Match(False, True))
    ) == ("evidence_mismatch")
    assert construct_code(
        result(C.BRANCH_ALLOW_DELETIONS, R.NONCOMPLIANT, rm.Difference(False, False))
    ) == ("evidence_mismatch")
    assert construct_code(
        result(C.BRANCH_ALLOW_DELETIONS, R.NONCOMPLIANT, rm.Difference(False, "no"))
    ) == ("bad_type")
    assert (
        construct_code(result(C.BRANCH_REQUIRED_CHECKS, R.COMPLIANT, rm.Match((), ())))
        == "bad_range"
    )
    desired = (rm.CheckPin("checks", 1),)
    assert (
        rm.ControlResult(
            d,
            a,
            C.BRANCH_REQUIRED_CHECKS,
            True,
            R.NONCOMPLIANT,
            rm.Difference(desired, ()),
        ).evidence.observed
        == ()
    )
    differing = edit(data("result-compliant"), ("evidence", "observed"), True)
    assert code(rm.parse_result, enc(differing)) == "evidence_mismatch"


@pytest.mark.parametrize("reason", sorted(rm.UNAVAILABLE_REASONS))
def test_ambiguous_or_failed_observations_are_unverified_never_unsupported(reason):
    value = data("result-unverified")
    ok = edit(value, ("evidence", "reason"), reason)
    assert rm.parse_result(enc(ok)).result is R.UNVERIFIED
    for other in ("UNSUPPORTED", "COMPLIANT"):
        assert (
            code(rm.parse_result, enc(edit(ok, ("result",), other)))
            == "evidence_mismatch"
        )
    assert (
        construct_code(
            lambda: rm.ControlResult(
                "1" * 64,
                "2" * 64,
                C.BRANCH_ALLOW_DELETIONS,
                True,
                R.UNSUPPORTED,
                rm.Unavailable(reason),
            )
        )
        == "evidence_mismatch"
    )


# F03: enrollment is verified against its compliance context and exact pins


def test_enrollment_verifies_against_the_complete_structural_context():
    assert venroll() is None
    assert ENROLL.evidence_sha256 == rm.digest(REPORT)
    assert ENROLL.evidence_ref == REPORT.evidence_ref
    assert ENROLL.repository == REPORT.repository == EXISTING.repository
    assert REPORT.overall is R.COMPLIANT and CLEAN.complete is True
    results = derive_all(DESIRED_R, CLEAN)
    assert results == CLEAN_RESULTS
    rm.verify_compliance(REPORT, DESIRED_R, CLEAN, results)
    assert (
        rm.build_compliance(DESIRED_R, CLEAN, results, "fixture-evidence-0001")
        == REPORT
    )
    assert REPORT.result_digests == tuple(sorted(rm.digest(r) for r in results))
    assert rm.verify_enrollment_linkage_only(ENROLL, REPORT, EXISTING) is None


def test_review_finding_f03_substituted_evidence_is_detected():
    swapped = dataclasses.replace(
        ENROLL, evidence_ref="fixture-unrelated-9999", evidence_sha256="0" * 64
    )
    only_ref = dataclasses.replace(ENROLL, evidence_ref="fixture-unrelated-9999")
    only_digest = dataclasses.replace(ENROLL, evidence_sha256="0" * 64)
    for enrollment, reason in (
        (swapped, "evidence_mismatch"),
        (only_ref, "evidence_mismatch"),
        (only_digest, "digest_mismatch"),
    ):
        assert construct_code(lambda e=enrollment: venroll(enrollment=e)) == reason
    other_report = dataclasses.replace(REPORT, evidence_ref="fixture-evidence-9999")
    assert construct_code(lambda: venroll(report=other_report)) == "evidence_mismatch"
    reseated = dataclasses.replace(
        ENROLL,
        evidence_ref=other_report.evidence_ref,
        evidence_sha256=rm.digest(other_report),
    )
    # the evidence reference is a label carried by the report; a re-seated enrollment
    # that names an otherwise exactly derived report is a consistent context
    venroll(enrollment=reseated, report=other_report)
    other_snapshot = dataclasses.replace(REPORT, actual_sha256="3" * 64)
    assert construct_code(lambda: venroll(report=other_snapshot)) == "evidence_mismatch"


def forged_report(**changes):
    base = dict(
        repository=EXISTING.repository,
        desired_sha256=rm.digest(DESIRED_R),
        actual_sha256=rm.digest(MIXED),
        overall=R.COMPLIANT,
        evidence_ref="fixture-evidence-9999",
        result_digests=("a" * 64,),
    )
    base.update(changes)
    return rm.ComplianceReport(**base)


def rebind_enrollment(report, **changes):
    return dataclasses.replace(
        ENROLL,
        evidence_ref=report.evidence_ref,
        evidence_sha256=rm.digest(report),
        **changes,
    )


def test_review_finding_rp02_f03_forged_compliant_report_is_rejected():
    forged = forged_report()
    enrollment = rebind_enrollment(forged)
    assert MIXED.complete is False
    # the RP-01 linkage check accepted exactly this; the full verification must not
    assert rm.verify_enrollment_linkage_only(enrollment, forged, EXISTING) is None
    mixed_results = derive_all(DESIRED_R, MIXED)
    for actual, results in (
        (MIXED, mixed_results),
        (MIXED, CLEAN_RESULTS),
        (CLEAN, CLEAN_RESULTS),
        (CLEAN, mixed_results),
    ):
        with pytest.raises(rm.RepositoryManagerError) as caught:
            venroll(
                enrollment=enrollment,
                report=forged,
                actual=actual,
                results=results,
            )
        assert caught.value.reason in {"evidence_mismatch", "snapshot_mismatch"}
    assert (
        construct_code(
            lambda: venroll(
                enrollment=enrollment,
                report=forged,
                actual=MIXED,
                results=mixed_results,
            )
        )
        == "evidence_mismatch"
    )


def test_arbitrary_result_digests_with_a_recomputed_enrollment_digest_are_rejected():
    count = len(REPORT.result_digests)
    arbitrary = tuple(f"{i:064x}" for i in range(1, count + 1))
    report = dataclasses.replace(REPORT, result_digests=arbitrary)
    assert (
        rm.verify_enrollment_linkage_only(rebind_enrollment(report), report, EXISTING)
        is None
    )
    assert (
        construct_code(
            lambda: venroll(enrollment=rebind_enrollment(report), report=report)
        )
        == "evidence_mismatch"
    )
    shorter = dataclasses.replace(REPORT, result_digests=REPORT.result_digests[:-1])
    assert (
        construct_code(
            lambda: venroll(enrollment=rebind_enrollment(shorter), report=shorter)
        )
        == "evidence_mismatch"
    )
    for field, value in (("desired_sha256", "b" * 64), ("actual_sha256", "c" * 64)):
        other = dataclasses.replace(REPORT, **{field: value})
        assert (
            construct_code(
                lambda o=other: venroll(enrollment=rebind_enrollment(o), report=o)
            )
            == "evidence_mismatch"
        )


@pytest.mark.parametrize(
    "label,pins,reason",
    [
        (
            "authorization",
            alt_existing(auth="fixture-authorization-9999"),
            "digest_mismatch",
        ),
        ("origin", alt_existing(origin=EXISTING_O.origin), "digest_mismatch"),
        (
            "scope",
            dataclasses.replace(
                EXISTING, admin_scope=("audit_read", "baseline_settings")
            ),
            "digest_mismatch",
        ),
        ("owner id", alt_existing(owner=changed_owner(id=9000002)), "owner_mismatch"),
        (
            "owner type",
            alt_existing(owner=changed_owner(kind="User")),
            "owner_mismatch",
        ),
        ("repository id", alt_existing(id=9100002), "repository_mismatch"),
        ("name", alt_existing(name="renamed-service"), "repository_mismatch"),
        ("visibility", alt_existing(visibility="public"), "visibility_mismatch"),
        ("default branch", alt_existing(branch="trunk"), "branch_mismatch"),
    ],
)
def test_enrollment_requires_the_exact_pins_of_the_desired_target(label, pins, reason):
    assert construct_code(lambda: venroll(pins=pins)) == reason
    # the same pins differ only in the authorization: identity alone is not the pins
    if label == "authorization":
        assert pins.repository == EXISTING.repository
        assert rm.verify_enrollment_linkage_only(ENROLL, REPORT, pins) is None


@pytest.mark.parametrize(
    "label,repo,reason",
    [
        (
            "default branch",
            rm.Repository(EXISTING.repository.ref, "private", "trunk"),
            "branch_mismatch",
        ),
        (
            "visibility",
            rm.Repository(EXISTING.repository.ref, "public", "main"),
            "visibility_mismatch",
        ),
        ("repository id", alt_existing(id=9100002).repository, "repository_mismatch"),
        (
            "name",
            alt_existing(name="renamed-service").repository,
            "repository_mismatch",
        ),
        (
            "owner id",
            alt_existing(owner=changed_owner(id=9000002)).repository,
            "owner_mismatch",
        ),
        (
            "owner login",
            alt_existing(owner=changed_owner(login="other-owner")).repository,
            "owner_mismatch",
        ),
        (
            "owner type",
            alt_existing(owner=changed_owner(kind="User")).repository,
            "owner_mismatch",
        ),
    ],
)
def test_enrollment_rejects_changed_identity_or_pins(label, repo, reason):
    enrolled = dataclasses.replace(ENROLL, repository=repo)
    assert construct_code(lambda: venroll(enrollment=enrolled)) == reason
    drifted_pins = dataclasses.replace(EXISTING, repository=repo)
    assert construct_code(lambda: venroll(pins=drifted_pins)) == reason
    drifted_report = dataclasses.replace(REPORT, repository=repo)
    assert construct_code(lambda: venroll(report=drifted_report)) == "evidence_mismatch"
    # a report that names another identity is also rejected by the linkage check
    bound = dataclasses.replace(ENROLL, evidence_sha256=rm.digest(drifted_report))
    assert (
        construct_code(
            lambda: rm.verify_enrollment_linkage_only(bound, drifted_report, EXISTING)
        )
        == reason
    )
    assert (
        construct_code(lambda: venroll(enrollment=bound, report=drifted_report))
        == "evidence_mismatch"
    )


def test_enrollment_rejects_a_substituted_desired_state_or_snapshot():
    other = desired_for(OTHER_PINS)
    assert construct_code(lambda: venroll(desired=other)) == "repository_mismatch"
    changed = tuple(
        SETTING(s.control, s.blocking, True)
        if s.control is C.BRANCH_ALLOW_DELETIONS
        else s
        for s in DESIRED_R.controls
    )
    desired2 = dataclasses.replace(DESIRED_R, controls=changed)
    assert construct_code(lambda: venroll(desired=desired2)) == "snapshot_mismatch"
    again = dataclasses.replace(CLEAN, source_ref="fixture-observation-7777")
    assert construct_code(lambda: venroll(actual=again)) == "snapshot_mismatch"
    created = rm.compose_desired(PROFILE_R, MANIFEST_C, PRE)
    assert construct_code(lambda: venroll(desired=created)) == "target_mismatch"
    assert construct_code(lambda: venroll(results=CLEAN_RESULTS[:-1])) == (
        "coverage_mismatch"
    )
    mixed_results = derive_all(DESIRED_R, MIXED)
    assert construct_code(lambda: venroll(results=mixed_results)) == "snapshot_mismatch"


def test_enrollment_cannot_rest_on_an_incomplete_snapshot_or_identity():
    INC = load("actual-incomplete-identity")
    assert INC.complete is False and INC.repository.complete is False
    assert all(o.observed for o in INC.observations)
    results = derive_all(DESIRED_R, INC)
    assert rm.summarize(DESIRED_R, INC, results) is R.UNVERIFIED
    honest = rm.build_compliance(DESIRED_R, INC, results, "fixture-evidence-0004")
    assert honest.overall is R.UNVERIFIED
    assert (
        construct_code(
            lambda: venroll(
                enrollment=rebind_enrollment(honest),
                report=honest,
                actual=INC,
                results=results,
            )
        )
        == "evidence_not_compliant"
    )
    forged = dataclasses.replace(honest, overall=R.COMPLIANT)
    assert (
        construct_code(
            lambda: venroll(
                enrollment=rebind_enrollment(forged),
                report=forged,
                actual=INC,
                results=results,
            )
        )
        == "evidence_mismatch"
    )
    # a snapshot that observed every control but only part of the identity
    partial = rm.ActualState(
        rm.ObservedIdentity(
            EXISTING.repository.ref, "private", None, "incomplete_observation"
        ),
        INC.desired_sha256,
        INC.provenance,
        INC.source_ref,
        INC.observed_at,
        INC.scope,
        False,
        INC.observations,
    )
    assert (
        rm.summarize(DESIRED_R, partial, derive_all(DESIRED_R, partial)) is R.UNVERIFIED
    )


def test_enrollment_requires_a_compliant_report_and_a_separate_decision():
    mixed_results = derive_all(DESIRED_R, MIXED)
    noncompliant = rm.build_compliance(
        DESIRED_R, MIXED, mixed_results, "fixture-evidence-0002"
    )
    assert noncompliant.overall is R.CONTRADICTORY
    bound = rebind_enrollment(noncompliant)
    assert (
        construct_code(
            lambda: venroll(
                enrollment=bound,
                report=noncompliant,
                actual=MIXED,
                results=mixed_results,
            )
        )
        == "evidence_not_compliant"
    )
    reused = dataclasses.replace(ENROLL, decision_ref=EXISTING.authorization_ref)
    assert construct_code(lambda: venroll(enrollment=reused)) == "not_independent"
    assert (
        construct_code(
            lambda: dataclasses.replace(ENROLL, decision_ref=ENROLL.evidence_ref)
        )
        == "not_independent"
    )


def test_enrollment_rejects_incomplete_structural_context():
    full = (ENROLL, REPORT, EXISTING, DESIRED_R, CLEAN, CLEAN_RESULTS)
    wrong = (None, None, None, None, None, None)
    for position in range(6):
        bad = list(full)
        bad[position] = wrong[position]
        reason = "bad_type"
        assert construct_code(lambda b=tuple(bad): rm.verify_enrollment(*b)) == reason
    for bad in (
        (ENROLL, REPORT, EXISTING.repository, DESIRED_R, CLEAN, CLEAN_RESULTS),
        (ENROLL, REPORT, EXISTING.repository.ref, DESIRED_R, CLEAN, CLEAN_RESULTS),
        (ENROLL, REPORT, PRE, DESIRED_R, CLEAN, CLEAN_RESULTS),
        (ENROLL, EXISTING, REPORT, DESIRED_R, CLEAN, CLEAN_RESULTS),
        (REPORT, ENROLL, EXISTING, DESIRED_R, CLEAN, CLEAN_RESULTS),
        (ENROLL, REPORT, EXISTING, CLEAN, DESIRED_R, CLEAN_RESULTS),
        (ENROLL, REPORT, EXISTING, DESIRED_R, CLEAN, list(CLEAN_RESULTS)),
        (ENROLL, REPORT, EXISTING, DESIRED_R, CLEAN, ("x",)),
    ):
        assert construct_code(lambda b=bad: rm.verify_enrollment(*b)) == "bad_type"
    for short in (
        (ENROLL, REPORT, EXISTING),
        (ENROLL, REPORT, EXISTING, DESIRED_R),
        (ENROLL, REPORT, EXISTING, DESIRED_R, CLEAN),
        (ENROLL, EXISTING.repository.ref),
    ):
        with pytest.raises(TypeError):
            rm.verify_enrollment(*short)  # the context cannot be omitted
    with pytest.raises(TypeError):
        rm.verify_enrollment_linkage_only(ENROLL, REPORT)


def test_linkage_only_helper_is_named_and_documented_as_insufficient():
    doc = rm.verify_enrollment_linkage_only.__doc__
    assert "LINKAGE ONLY" in doc and "not sufficient" in doc
    assert "can pass it" in doc
    assert "verify_enrollment" in doc
    assert (rm.verify_enrollment.__doc__ or "").count("not authentication") == 1


def test_compliance_report_is_derived_only_from_a_verified_context():
    results = derive_all(DESIRED_R, CLEAN)
    other_evidence = dataclasses.replace(REPORT, evidence_ref="fixture-evidence-0003")
    # the evidence reference is an operator-supplied label that the report carries; it
    # changes the report digest, which an enrollment must match exactly
    rm.verify_compliance(other_evidence, DESIRED_R, CLEAN, results)
    assert rm.digest(other_evidence) != rm.digest(REPORT)
    assert construct_code(lambda: venroll(report=other_evidence)) == "evidence_mismatch"
    assert construct_code(
        lambda: rm.verify_compliance(REPORT, DESIRED_R, CLEAN, results[:-1])
    ) == ("coverage_mismatch")
    nonblocking = [r for r in results if not r.blocking]
    trimmed = tuple(r for r in results if r is not nonblocking[0])
    assert rm.summarize(DESIRED_R, CLEAN, trimmed) is R.COMPLIANT
    assert construct_code(
        lambda: rm.verify_compliance(REPORT, DESIRED_R, CLEAN, trimmed)
    ) == ("evidence_mismatch")
    assert construct_code(
        lambda: rm.verify_compliance(REPORT, desired_for(OTHER_PINS), CLEAN, results)
    ) == ("snapshot_mismatch")
    assert construct_code(
        lambda: rm.verify_compliance(None, DESIRED_R, CLEAN, results)
    ) == ("evidence_mismatch")
    assert construct_code(
        lambda: rm.build_compliance(DESIRED_R, MIXED, results, "fixture-e-1")
    ) == ("snapshot_mismatch")
    wire = data("compliance")
    reversed_digests = list(reversed(wire["result_digests"]))
    assert (
        code(
            rm.parse_compliance, enc(edit(wire, ("result_digests",), reversed_digests))
        )
        == "not_sorted"
    )
    assert (
        code(rm.parse_compliance, enc(edit(wire, ("result_digests",), [])))
        == "bad_range"
    )
    assert (
        code(rm.parse_compliance, enc(edit(wire, ("overall",), "PASS"))) == "bad_value"
    )


def test_enrollment_is_data_only_and_not_a_capability():
    names = {f.name for f in fields(rm.Enrollment)}
    assert names == {
        "repository",
        "evidence_ref",
        "evidence_sha256",
        "decision_ref",
        "decided_at",
    }
    public = {n for n in dir(rm.Enrollment) if not n.startswith("_")}
    assert not {
        n
        for n in public
        if re.search(r"admit|admission|authoriz|approve|enroll|publish|merge", n)
    }
    assert not {
        n
        for n in dir(rm)
        if re.search(r"admit|admission|approve|enroll_|execute|apply", n)
    }
    assert rm.parse_enrollment(raw("enrollment")) == ENROLL
    assert {f.name for f in fields(rm.Repository)} == {
        "ref",
        "visibility",
        "default_branch",
    }


def test_direct_construction_is_validated_like_deserialization():
    owner = EXISTING.repository.ref.owner
    ref = EXISTING.repository.ref
    repo = EXISTING.repository
    checks = (rm.CheckPin("a", 1),)
    sha = "1" * 64
    identity = rm.ObservedIdentity(ref, "private", "main")
    cases = [
        (lambda: rm.Owner(True, "a", "User"), "bad_type"),
        (lambda: rm.Owner(1, "a", "Bot"), "bad_value"),
        (lambda: rm.Owner(1, "bad name", "User"), "bad_identifier"),
        (lambda: rm.RepositoryRef({}, 1, "n", "x/n"), "bad_type"),
        (lambda: rm.RepositoryRef(owner, 1, "n", "wrong/n"), "identity_inconsistent"),
        (lambda: rm.Repository(ref, "secret", "main"), "bad_value"),
        (lambda: rm.Repository(None, "public", "main"), "bad_type"),
        (lambda: rm.CheckPin("", 1), "bad_identifier"),
        (lambda: rm.ControlSetting("repo.allow_merge_commit", True, True), "bad_type"),
        (lambda: rm.ControlSetting(C.REPO_ALLOW_MERGE_COMMIT, 1, True), "bad_type"),
        (lambda: rm.ControlSetting(C.REPO_ALLOW_MERGE_COMMIT, True, 1), "bad_type"),
        (
            lambda: rm.ControlSetting(C.BRANCH_REQUIRED_CHECKS, True, [checks[0]]),
            "bad_type",
        ),
        (lambda: rm.ControlSetting(C.BRANCH_REQUIRED_CHECKS, True, ()), "bad_range"),
        (lambda: rm.ControlSetting(C.BRANCH_REQUIRED_CHECKS, True, ("a",)), "bad_type"),
        (
            lambda: rm.Profile(
                "p", [rm.ControlSetting(C.REPO_ALLOW_MERGE_COMMIT, True, True)]
            ),
            "bad_type",
        ),
        (lambda: rm.Profile("p", ()), "bad_range"),
        (lambda: rm.Profile("p", ("x",)), "bad_type"),
        (lambda: rm.Manifest("m", "p", MANIFEST_R.target, ({},)), "bad_type"),
        (lambda: rm.Manifest("m", "p", None, ()), "bad_type"),
        (
            lambda: rm.CreationTarget(ref, "n", "private", "main", "0" * 32, sha),
            "bad_type",
        ),
        (
            lambda: rm.CreationTarget(owner, "n", "private", "main", "g" * 32, sha),
            "bad_identifier",
        ),
        (
            lambda: rm.CreationTarget(owner, "n", "private", "main", "0" * 32, "x"),
            "bad_digest",
        ),
        (lambda: rm.ExistingTarget(ref, sha), "bad_type"),
        (lambda: rm.ExistingTarget(repo, "x"), "bad_digest"),
        (lambda: rm.Origin("0" * 32, sha, "short"), "bad_digest"),
        (lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, None), "bad_type"),
        (lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, "yes", False), "bad_type"),
        (
            lambda: rm.ControlResult(
                sha,
                sha,
                C.BRANCH_ALLOW_DELETIONS,
                True,
                "COMPLIANT",
                rm.Match(False, False),
            ),
            "bad_type",
        ),
        (
            lambda: rm.ControlResult(
                "bad",
                sha,
                C.BRANCH_ALLOW_DELETIONS,
                True,
                R.COMPLIANT,
                rm.Match(False, False),
            ),
            "bad_digest",
        ),
        (
            lambda: rm.PreCreation(
                owner, "n", "private", "main", ("create_repository",), "ref-1", "g" * 32
            ),
            "bad_identifier",
        ),
        (
            lambda: rm.PreCreation(
                ref, "n", "private", "main", ("create_repository",), "ref-1", "0" * 32
            ),
            "bad_type",
        ),
        (
            lambda: rm.PreCreation(
                owner, "n", "private", "main", ["create_repository"], "ref-1", "0" * 32
            ),
            "bad_type",
        ),
        (
            lambda: rm.Enrollment(ref, "e-1", sha, "d-1", "2026-01-01T00:00:00Z"),
            "bad_type",
        ),
        (
            lambda: rm.Enrollment(repo, "e-1", "x", "d-1", "2026-01-01T00:00:00Z"),
            "bad_digest",
        ),
        (
            lambda: rm.ComplianceReport(ref, sha, sha, R.COMPLIANT, "e-1", (sha,)),
            "bad_type",
        ),
        (
            lambda: rm.ComplianceReport(repo, sha, sha, "COMPLIANT", "e-1", (sha,)),
            "bad_type",
        ),
        (
            lambda: rm.ComplianceReport(repo, sha, sha, R.COMPLIANT, "e-1", ()),
            "bad_range",
        ),
        (
            lambda: rm.ActualState(
                identity,
                sha,
                "synthetic_fixture",
                "s-1",
                "2026-01-01T00:00:00Z",
                (),
                True,
                (),
            ),
            "bad_range",
        ),
        (
            lambda: rm.ActualState(
                identity,
                sha,
                "synthetic_fixture",
                "s-1",
                "2026-01-01T00:00:00Z",
                [C.BRANCH_ALLOW_DELETIONS],
                True,
                (),
            ),
            "bad_type",
        ),
        (
            lambda: rm.ActualState(
                identity,
                "x",
                "synthetic_fixture",
                "s-1",
                "2026-01-01T00:00:00Z",
                (C.BRANCH_ALLOW_DELETIONS,),
                True,
                (rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, False),),
            ),
            "bad_digest",
        ),
        (lambda: rm.ObservedIdentity(owner), "bad_type"),
        (
            lambda: rm.ObservedIdentity(ref, "private", "main", "rate_limited"),
            "bad_value",
        ),
        (lambda: rm.ObservedIdentity(ref, "private", None, None), "bad_type"),
        (lambda: rm.ObservedIdentity(ref, None, None, "not_found"), "bad_value"),
        (lambda: rm.ObservedIdentity(ref, "secret", "main"), "bad_value"),
        (lambda: rm.ObservedIdentity(ref, "private", "a..b"), "bad_identifier"),
        (
            lambda: rm.Observation(
                C.BRANCH_ALLOW_DELETIONS, False, None, "rate_limited", LIMIT
            ),
            "bad_value",
        ),
        (
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, False, False, None, LIMIT),
            "bad_value",
        ),
        (
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, True, False, None, LIMIT),
            "bad_value",
        ),
        (
            lambda: rm.Observation(
                C.BRANCH_ALLOW_DELETIONS, False, None, None, "limited"
            ),
            "bad_type",
        ),
        (
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, False, None, None, LIMIT),
            "evidence_mismatch",
        ),
        (lambda: dataclasses.replace(LIMIT, control="x"), "bad_type"),
        (lambda: dataclasses.replace(LIMIT, repository_id=True), "bad_type"),
        (lambda: dataclasses.replace(LIMIT, repository_id=0), "bad_range"),
    ]
    for factory, reason in cases:
        assert construct_code(factory) == reason
    record = rm.Owner(1, "a", "User")
    with pytest.raises((AttributeError, TypeError)):
        record.id = 2
    with pytest.raises((AttributeError, TypeError)):
        record.extra = 1


def test_creation_and_existing_scenarios_are_consistent():
    rm.verify_binding(PRE, BINDING)
    assert BINDING.precreation_sha256 == rm.digest(PRE)
    assert BINDING.repository.ref == ENROLL.repository.ref
    assert EXISTING.repository == BINDING.repository == EXISTING_O.repository
    assert "create_repository" in PRE.admin_scope
    assert "create_repository" not in EXISTING.admin_scope
    assert MANIFEST_C.target.intent_id == PRE.intent_id == BINDING.intent_id


# --- RP-02: UNSUPPORTED classification and full observed identity -------------------

UNSUPPORTED_CONTROL = C.BRANCH_REQUIRE_PULL_REQUEST


def snapshot_with(control, observation, **kwargs):
    observed = tuple(
        observation
        if s.control is control
        else rm.Observation(s.control, True, s.value)
        for s in DESIRED_R.controls
    )
    return snapshot(DESIRED_R, observed, **kwargs)


def unsupported_result(actual, evidence=None, control=UNSUPPORTED_CONTROL):
    return rm.ControlResult(
        rm.digest(DESIRED_R),
        rm.digest(actual),
        control,
        True,
        R.UNSUPPORTED,
        evidence or limit_for(control),
    )


def test_review_finding_rp02_f02_unsupported_fixtures_are_consistent():
    result = load("result-unsupported")
    seen = MIXED.observation_of(result.control)
    assert seen.status == "unsupported" and seen.limitation == result.evidence
    rm.verify_result(result, DESIRED_R, MIXED)
    # the observation no longer rests on an ambiguous 404
    assert seen.reason is None
    assert MIXED.observation_of(C.BRANCH_REQUIRED_CHECKS).reason == "http_403_ambiguous"


@pytest.mark.parametrize("reason", sorted(rm.UNAVAILABLE_REASONS))
def test_unsupported_is_rejected_for_every_ambiguous_or_failed_observation(
    reason,
):
    actual = snapshot_with(
        UNSUPPORTED_CONTROL,
        rm.Observation(UNSUPPORTED_CONTROL, False, None, reason),
    )
    assert actual.observation_of(UNSUPPORTED_CONTROL).status == "unavailable"
    forged = unsupported_result(actual)  # syntactically valid Limitation evidence
    assert (
        construct_code(lambda: rm.verify_result(forged, DESIRED_R, actual))
        == "evidence_mismatch"
    )
    results = tuple(
        forged if r.control is UNSUPPORTED_CONTROL else r
        for r in derive_all(DESIRED_R, actual)
    )
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, actual, results))
        == "evidence_mismatch"
    )
    honest = derive(DESIRED_R, actual, UNSUPPORTED_CONTROL)
    assert honest.result is (
        R.CONTRADICTORY if reason == "conflicting_observations" else R.UNVERIFIED
    )
    assert honest.result is not R.UNSUPPORTED


def test_unsupported_is_accepted_only_for_an_observation_that_carries_the_limitation():
    actual = snapshot_with(
        UNSUPPORTED_CONTROL,
        rm.Observation(
            UNSUPPORTED_CONTROL, False, None, None, limit_for(UNSUPPORTED_CONTROL)
        ),
    )
    result = derive(DESIRED_R, actual, UNSUPPORTED_CONTROL)
    assert result.result is R.UNSUPPORTED
    rm.verify_result(result, DESIRED_R, actual)
    results = derive_all(DESIRED_R, actual)
    assert rm.summarize(DESIRED_R, actual, results) is R.UNSUPPORTED
    assert actual.complete is False  # an unsupported control is never fully observed
    # other result kinds cannot be attached to an unsupported observation
    for other in (
        rm.ControlResult(
            rm.digest(DESIRED_R),
            rm.digest(actual),
            UNSUPPORTED_CONTROL,
            True,
            R.UNVERIFIED,
            rm.Unavailable("http_404_ambiguous"),
        ),
        rm.ControlResult(
            rm.digest(DESIRED_R),
            rm.digest(actual),
            UNSUPPORTED_CONTROL,
            True,
            R.COMPLIANT,
            rm.Match(True, True),
        ),
        rm.ControlResult(
            rm.digest(DESIRED_R),
            rm.digest(actual),
            UNSUPPORTED_CONTROL,
            True,
            R.CONTRADICTORY,
            rm.Conflict(
                (
                    rm.ConflictingObservation("fixture-read-1", True),
                    rm.ConflictingObservation("fixture-read-2", False),
                )
            ),
        ),
    ):
        assert (
            construct_code(lambda o=other: rm.verify_result(o, DESIRED_R, actual))
            == "evidence_mismatch"
        )


def test_limitation_evidence_cannot_move_between_controls_or_snapshots():
    good = limit_for(UNSUPPORTED_CONTROL)
    # another control
    assert (
        construct_code(
            lambda: rm.Observation(C.BRANCH_ALLOW_DELETIONS, False, None, None, good)
        )
        == "evidence_mismatch"
    )
    actual = snapshot_with(
        UNSUPPORTED_CONTROL,
        rm.Observation(UNSUPPORTED_CONTROL, False, None, None, good),
    )
    assert (
        construct_code(
            lambda: unsupported_result(actual, good, control=C.BRANCH_ALLOW_DELETIONS)
        )
        == "evidence_mismatch"
    )
    # another repository
    other_repo = limit_for(UNSUPPORTED_CONTROL, repository_id=9100002)
    assert (
        construct_code(
            lambda: snapshot_with(
                UNSUPPORTED_CONTROL,
                rm.Observation(UNSUPPORTED_CONTROL, False, None, None, other_repo),
            )
        )
        == "snapshot_mismatch"
    )
    # another snapshot: evidence that differs from the one the observation carries
    for changed in (
        dataclasses.replace(good, observed_at="2026-01-02T00:00:00Z"),
        dataclasses.replace(good, documentation_ref="fixture-doc-9999"),
        dataclasses.replace(
            good,
            corroboration_refs=(
                "fixture-corroboration-8001",
                "fixture-corroboration-8002",
            ),
        ),
        dataclasses.replace(good, endpoint="GET /repos/{owner}/{repo}/other"),
    ):
        assert (
            construct_code(
                lambda c=changed: rm.verify_result(
                    unsupported_result(actual, c), DESIRED_R, actual
                )
            )
            == "evidence_mismatch"
        )
    # a result built for another snapshot
    other_actual = snapshot_with(
        UNSUPPORTED_CONTROL,
        rm.Observation(UNSUPPORTED_CONTROL, False, None, None, good),
    )
    other_actual = dataclasses.replace(
        other_actual, source_ref="fixture-observation-7777"
    )
    assert (
        construct_code(
            lambda: rm.verify_result(
                unsupported_result(actual), DESIRED_R, other_actual
            )
        )
        == "snapshot_mismatch"
    )


def test_unsupported_still_requires_affirmative_independent_limitation_evidence():
    good = limit_for(UNSUPPORTED_CONTROL)
    cases = {
        "one corroboration": dict(corroboration_refs=("fixture-corroboration-1",)),
        "no corroboration": dict(corroboration_refs=()),
        "shared reference": dict(plan_ref=good.corroboration_refs[0]),
        "same visibility and plan read": dict(plan_ref=good.visibility_ref),
        "malformed endpoint": dict(endpoint="get everything"),
        "malformed time": dict(observed_at="unknown"),
    }
    for label, change in cases.items():
        assert construct_code(lambda c=change: dataclasses.replace(good, **c)) in {
            "bad_range",
            "not_independent",
            "bad_identifier",
            "bad_timestamp",
        }, label
    wire = data("actual")
    index = next(
        i for i, o in enumerate(wire["observations"]) if o["status"] == "unsupported"
    )
    base = ("observations", index)
    assert code(rm.parse_actual, enc(edit(wire, base + ("limitation",), DELETE))) == (
        "missing_field"
    )
    assert code(
        rm.parse_actual, enc(edit(wire, base + ("reason",), "rate_limited"))
    ) == ("unknown_field")
    assert code(rm.parse_actual, enc(edit(wire, base + ("value",), False))) == (
        "unknown_field"
    )
    for key in wire["observations"][index]["limitation"]:
        assert (
            code(rm.parse_actual, enc(edit(wire, base + ("limitation", key), DELETE)))
            == "missing_field"
        )
    assert (
        code(
            rm.parse_actual,
            enc(edit(wire, base + ("limitation", "control"), "repo.nuke")),
        )
        == "unknown_control"
    )
    assert (
        code(
            rm.parse_actual,
            enc(
                edit(wire, base + ("limitation", "control"), "repo.allow_squash_merge")
            ),
        )
        == "evidence_mismatch"
    )
    assert (
        code(
            rm.parse_actual,
            enc(edit(wire, base + ("limitation", "repository_id"), 9100002)),
        )
        == "snapshot_mismatch"
    )
    assert (
        code(rm.parse_actual, enc(edit(wire, base + ("status",), "limited")))
        == "bad_value"
    )


def test_unsupported_observation_wire_round_trips_and_is_incomplete():
    seen = MIXED.observation_of(UNSUPPORTED_CONTROL)
    assert seen.wire()["status"] == "unsupported"
    assert set(seen.wire()) == {"control", "status", "limitation"}
    assert rm.parse_actual(rm.dumps(MIXED)) == MIXED
    assert MIXED.complete is False
    assert (
        construct_code(lambda: dataclasses.replace(MIXED, complete=True))
        == "completeness_mismatch"
    )


# observed identity


def identity_variant(**changes):
    base = full_identity(DESIRED_R)
    return dataclasses.replace(base, **changes)


@pytest.mark.parametrize(
    "label,identity,reason",
    [
        (
            "visibility",
            lambda: identity_variant(visibility="public"),
            "visibility_mismatch",
        ),
        (
            "default branch",
            lambda: identity_variant(default_branch="trunk"),
            "branch_mismatch",
        ),
        (
            "owner id",
            lambda: rm.ObservedIdentity(
                alt_existing(owner=changed_owner(id=9000002)).repository.ref,
                "private",
                "main",
            ),
            "owner_mismatch",
        ),
        (
            "owner type",
            lambda: rm.ObservedIdentity(
                alt_existing(owner=changed_owner(kind="User")).repository.ref,
                "private",
                "main",
            ),
            "owner_mismatch",
        ),
        (
            "repository id",
            lambda: rm.ObservedIdentity(
                alt_existing(id=9100002).repository.ref, "private", "main"
            ),
            "repository_mismatch",
        ),
        (
            "name",
            lambda: rm.ObservedIdentity(
                alt_existing(name="renamed-service").repository.ref, "private", "main"
            ),
            "repository_mismatch",
        ),
    ],
)
def test_observed_identity_is_verified_against_the_exact_desired_target(
    label, identity, reason
):
    actual = snapshot(
        DESIRED_R,
        tuple(rm.Observation(s.control, True, s.value) for s in DESIRED_R.controls),
        repository=identity(),
    )
    assert construct_code(lambda: rm.verify_actual(actual, DESIRED_R)) == reason
    assert (
        construct_code(lambda: rm.summarize(DESIRED_R, actual, CLEAN_RESULTS)) == reason
    )
    assert construct_code(lambda: venroll(actual=actual)) == reason


def test_observed_identity_carries_visibility_and_default_branch():
    assert CLEAN.repository == full_identity(DESIRED_R)
    assert CLEAN.repository.visibility == DESIRED_R.target.repository.visibility
    assert CLEAN.repository.default_branch == DESIRED_R.target.repository.default_branch
    assert CLEAN.repository.complete is True
    wire = data("actual-compliant")["repository"]
    assert {"visibility", "default_branch", "unavailable_reason"} <= set(wire)
    assert wire["unavailable_reason"] is None


def test_missing_or_inconsistent_identity_information_is_rejected():
    wire = data("actual-compliant")
    for key in ("visibility", "default_branch", "unavailable_reason", "id", "owner"):
        assert code(rm.parse_actual, enc(edit(wire, ("repository", key), DELETE))) == (
            "missing_field"
        )
    assert code(
        rm.parse_actual, enc(edit(wire, ("repository", "visibility"), None))
    ) == ("bad_type")
    assert code(
        rm.parse_actual, enc(edit(wire, ("repository", "default_branch"), None))
    ) == ("bad_type")
    # a reason alongside a complete identity is contradictory
    assert (
        code(
            rm.parse_actual,
            enc(edit(wire, ("repository", "unavailable_reason"), "rate_limited")),
        )
        == "bad_value"
    )
    for bad in ("secret", "Public", "", 5):
        assert code(
            rm.parse_actual, enc(edit(wire, ("repository", "visibility"), bad))
        ) in {
            "bad_value",
            "bad_type",
        }
    assert (
        code(rm.parse_actual, enc(edit(wire, ("repository", "default_branch"), "a..b")))
        == "bad_identifier"
    )
    # a full-name that disagrees with owner and name
    assert (
        code(
            rm.parse_actual,
            enc(edit(wire, ("repository", "full_name"), "fictional-owner/x")),
        )
        == "identity_inconsistent"
    )


@pytest.mark.parametrize(
    "visibility,branch,reason",
    [
        (None, None, "http_403_ambiguous"),
        ("private", None, "incomplete_observation"),
        (None, "main", "permission_missing"),
        (None, None, "conflicting_observations"),
        (None, None, "not_observed"),
    ],
)
def test_incomplete_identity_never_supports_an_overall_compliant_report(
    visibility, branch, reason
):
    identity = rm.ObservedIdentity(EXISTING.repository.ref, visibility, branch, reason)
    assert identity.complete is False
    observed = tuple(
        rm.Observation(s.control, True, s.value) for s in DESIRED_R.controls
    )
    actual = snapshot(DESIRED_R, observed, repository=identity)
    assert actual.complete is False
    assert (
        construct_code(lambda: dataclasses.replace(actual, complete=True))
        == "completeness_mismatch"
    )
    results = derive_all(DESIRED_R, actual)
    assert rm.summarize(DESIRED_R, actual, results) is R.UNVERIFIED
    report = rm.build_compliance(DESIRED_R, actual, results, "fixture-evidence-0005")
    assert report.overall is R.UNVERIFIED
    forged = dataclasses.replace(report, overall=R.COMPLIANT)
    assert (
        construct_code(
            lambda: venroll(
                enrollment=rebind_enrollment(forged),
                report=forged,
                actual=actual,
                results=results,
            )
        )
        == "evidence_mismatch"
    )
    # whatever part of the identity was observed must still agree with the target
    if visibility is not None:
        wrong = rm.ObservedIdentity(EXISTING.repository.ref, "public", branch, reason)
        bad = snapshot(DESIRED_R, observed, repository=wrong)
        assert construct_code(lambda: rm.verify_actual(bad, DESIRED_R)) == (
            "visibility_mismatch"
        )
    if branch is not None:
        wrong = rm.ObservedIdentity(
            EXISTING.repository.ref, visibility, "trunk", reason
        )
        bad = snapshot(DESIRED_R, observed, repository=wrong)
        assert construct_code(lambda: rm.verify_actual(bad, DESIRED_R)) == (
            "branch_mismatch"
        )


def test_identity_fixture_is_incomplete_and_is_not_compliant():
    inc = load("actual-incomplete-identity")
    assert inc.repository.visibility is None and inc.repository.default_branch is None
    assert inc.repository.reason == "http_403_ambiguous"
    rm.verify_actual(inc, DESIRED_R)
    assert rm.summarize(DESIRED_R, inc, derive_all(DESIRED_R, inc)) is R.UNVERIFIED
