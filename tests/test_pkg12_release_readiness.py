"""Synthetic future-release metadata only; no final archives, authority or hosts."""

import ast
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location("pkg12_test", ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def facts():
    m = load("packaging/release_readiness.py")
    # Every identity, digest and future recipe below is fabricated. No such
    # final recipe or archive exists, and nothing is written by the assessor.
    recipe = "packaging/future_final_builder.py"
    common = {
        "packaging/build_deb.py": "3" * 64,
        recipe: "4" * 64,
        "debian/control": "5" * 64,
        "debian/changelog": "6" * 64,
        "pyproject.toml": "7" * 64,
        "uv.lock": "8" * 64,
    }
    inputs = {
        "control": common | {"src/agent_platform/cli.py": "9" * 64},
        "worker": common | {"src/agent_platform/native_artifact.py": "a" * 64},
    }
    source = m.SourcePin(
        "1" * 40,
        "2" * 40,
        1700000000,
        "3" * 64,
        recipe,
        "4" * 64,
        m.digest(inputs["control"]),
        m.digest(inputs["worker"]),
    )
    environment = m.EnvironmentPin(
        "debian-13/amd64",
        "sha256:" + "5" * 64,
        "3.13.5",
        "1.22.22",
        "5.8.1",
        "6" * 64,
    )
    plan = {
        "schema": "AP-PKG12-PLAN/1",
        "repository": m.REPOSITORY,
        "version": m.VERSION,
        "architecture": "amd64",
        "source": {key: getattr(source, key) for key in m.SOURCE_FIELDS},
        "environment": environment._asdict(),
        "roles": {},
    }
    for role, number in [("control", "b"), ("worker", "c")]:
        plan["roles"][role] = {
            "package": "agent-platform-" + role,
            "archive_sha256": number * 64,
            "archive_size": 100000,
            "manifest_sha256": "d" * 64,
            "embedded_build_sha256": "e" * 64,
            "provenance_sha256": "f" * 64,
            "rebuild_sha256": number * 64,
            "kind": "future-final",
            "ci_only": False,
            "inputs": inputs[role],
        }
    pins = dict(
        source_pin=source,
        environment_pin=environment,
        history_pin=m.HistoryPin("EMPTY", "a" * 64, None),
    )
    return m, plan, pins


def denied(report):
    assert report["observations_authenticated"] is False
    for key in (
        "final_generation_allowed",
        "release_authorized",
        "publication_allowed",
        "installation_allowed",
    ):
        assert report[key] is False


def test_consistent_fabricated_evidence_is_never_permission(facts):
    m, plan, pins = facts
    original = copy.deepcopy(plan)
    report = m.assess(plan, **pins)
    assert report["result"] == "CONSISTENT_UNVERIFIED"
    assert report["bundle_sha256"] == m.digest(plan)
    assert report == m.assess(json.loads(json.dumps(plan)), **pins)
    assert plan == original
    denied(report)
    assert m.assess(plan)["reason"] == "source_pin_unverified"


@pytest.mark.parametrize(
    "authority",
    [
        "release_authorized",
        "human_approved",
        "green_ci",
        "tag",
        "publish",
        "final_version",
        "reset_history",
    ],
)
def test_plan_cannot_supply_authority_or_reset_history(facts, authority):
    m, plan, pins = facts
    report = m.assess(plan | {authority: True}, **pins)
    assert report["result"] == "BLOCKED"
    denied(report)


@pytest.mark.parametrize(
    "field",
    [
        "commit",
        "tree",
        "epoch",
        "builder_sha256",
        "final_recipe_path",
        "final_recipe_sha256",
    ],
)
def test_stale_premerge_or_recipe_identity_blocks(facts, field):
    m, plan, pins = facts
    plan["source"][field] = 1700000001 if field == "epoch" else "stale"
    report = m.assess(plan, **pins)
    assert report["reason"] == "source_mismatch"
    denied(report)


@pytest.mark.parametrize(
    "field", ["platform", "image_digest", "python", "dpkg_deb", "xz", "packages_sha256"]
)
def test_environment_drift_blocks(facts, field):
    m, plan, pins = facts
    plan["environment"][field] = "unobserved"
    report = m.assess(plan, **pins)
    assert report["reason"] == "environment_mismatch"
    denied(report)


@pytest.mark.parametrize(
    "kind,ci",
    [
        ("candidate", False),
        ("ci-final-fixture", True),
        ("future-final", True),
        ("future-final", 0),
        ("future-final", "false"),
    ],
)
def test_candidate_or_renamed_ci_fixture_cannot_become_final(facts, kind, ci):
    m, plan, pins = facts
    plan["roles"]["worker"].update(kind=kind, ci_only=ci)
    report = m.assess(plan, **pins)
    assert report["reason"] == "artifact_not_future_final"
    denied(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_role",
        "third_role",
        "wrong_package",
        "same_archive",
        "rebuild",
        "zero_size",
        "boolean_size",
        "unknown_field",
        "bad_hash",
    ],
)
def test_role_artifact_or_rebuild_inconsistency_blocks(facts, mutation):
    m, plan, pins = facts
    worker = plan["roles"]["worker"]
    if mutation == "missing_role":
        del plan["roles"]["worker"]
    elif mutation == "third_role":
        plan["roles"]["codex"] = copy.deepcopy(worker)
    elif mutation == "wrong_package":
        worker["package"] = "agent-platform-control"
    elif mutation == "same_archive":
        worker.update(archive_sha256="b" * 64, rebuild_sha256="b" * 64)
    elif mutation == "rebuild":
        worker["rebuild_sha256"] = "a" * 64
    elif mutation == "zero_size":
        worker["archive_size"] = 0
    elif mutation == "boolean_size":
        worker["archive_size"] = True
    elif mutation == "unknown_field":
        worker["release_authorized"] = True
    else:
        worker["manifest_sha256"] = "UNKNOWN"
    report = m.assess(plan, **pins)
    assert report["result"] == "BLOCKED"
    denied(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "changed",
        "builder",
        "recipe",
        "private",
        "traversal",
        "limit",
    ],
)
def test_full_input_set_binding_and_no_private_paths(facts, mutation):
    m, plan, pins = facts
    inputs = plan["roles"]["worker"]["inputs"]
    if mutation == "missing":
        del inputs["debian/control"]
    elif mutation == "extra":
        inputs["docs/extra.md"] = "a" * 64
    elif mutation == "changed":
        inputs["debian/changelog"] = "a" * 64
    elif mutation == "builder":
        inputs["packaging/build_deb.py"] = "a" * 64
    elif mutation == "recipe":
        inputs[pins["source_pin"].final_recipe_path] = "a" * 64
    elif mutation == "private":
        inputs["/private/SECRET"] = "a" * 64
    elif mutation == "traversal":
        inputs["docs/../../SECRET"] = "a" * 64
    else:
        inputs.update({f"docs/f{i}": "a" * 64 for i in range(257)})
    report = m.assess(plan, **pins)
    assert report["result"] == "BLOCKED" and "SECRET" not in json.dumps(report)
    denied(report)


@pytest.mark.parametrize(
    "history",
    [
        None,
        "UNKNOWN",
        "invalid_continuity",
        "empty_with_bundle",
        "frozen_without_bundle",
        "serialized",
    ],
)
def test_missing_lost_or_unknown_history_is_not_a_new_empty_registry(facts, history):
    m, plan, pins = facts
    old = pins["history_pin"]
    if history is None:
        new = None
    elif history == "UNKNOWN":
        new = old._replace(state="UNKNOWN")
    elif history == "invalid_continuity":
        new = old._replace(continuity_sha256="UNKNOWN")
    elif history == "empty_with_bundle":
        new = old._replace(bundle_sha256=m.digest(plan))
    elif history == "frozen_without_bundle":
        new = old._replace(state="FROZEN")
    else:
        new = old._asdict()
    report = m.assess(plan, **(pins | {"history_pin": new}))
    assert report["reason"] == "history_unverified"
    denied(report)


@pytest.mark.parametrize(
    "change", ["archive", "manifest", "provenance", "source", "environment"]
)
def test_same_final_version_cannot_replace_any_frozen_identity(facts, change):
    m, plan, pins = facts
    pins["history_pin"] = m.HistoryPin("FROZEN", "a" * 64, m.digest(plan))
    if change == "archive":
        plan["roles"]["worker"].update(archive_sha256="a" * 64, rebuild_sha256="a" * 64)
    elif change == "manifest":
        plan["roles"]["control"]["manifest_sha256"] = "a" * 64
    elif change == "provenance":
        plan["roles"]["worker"]["provenance_sha256"] = "a" * 64
    elif change == "source":
        plan["source"]["commit"] = "3" * 40
        pins["source_pin"] = pins["source_pin"]._replace(commit="3" * 40)
    else:
        plan["environment"]["python"] = "3.13.6"
        pins["environment_pin"] = pins["environment_pin"]._replace(python="3.13.6")
    report = m.assess(plan, **pins)
    assert report["reason"] == "final_version_conflict"
    denied(report)


def test_identical_frozen_bundle_is_not_rebuild_resend_or_publish_permission(facts):
    m, plan, pins = facts
    pins["history_pin"] = m.HistoryPin("FROZEN", "a" * 64, m.digest(plan))
    report = m.assess(plan, **pins)
    assert report["history"] == "FROZEN" and report["result"] == "CONSISTENT_UNVERIFIED"
    denied(report)


def test_serialized_pins_and_boolean_epoch_do_not_create_trusted_identity(facts):
    m, plan, pins = facts
    assert (
        m.assess(plan, **(pins | {"source_pin": pins["source_pin"]._asdict()}))[
            "reason"
        ]
        == "source_pin_unverified"
    )
    plan["source"]["epoch"] = True
    pins["source_pin"] = pins["source_pin"]._replace(epoch=1)
    assert m.assess(plan, **pins)["result"] == "BLOCKED"


@pytest.mark.parametrize("value", [None, [], "SECRET", {"unknown": "SECRET"}])
def test_untrusted_shapes_are_closed_and_path_free(facts, value):
    m, _, pins = facts
    report = m.assess(value, **pins)
    assert report["result"] == "BLOCKED" and "SECRET" not in json.dumps(report)
    denied(report)


def test_nested_custom_objects_and_oversized_input_never_execute_or_leak(facts):
    m, plan, pins = facts

    class Untrusted:
        def __eq__(self, other):
            pytest.fail("untrusted equality executed")

    plan["source"] = Untrusted()
    assert m.assess(plan, **pins)["result"] == "BLOCKED"
    plan["source"] = {
        "nested": {"nested": {"nested": {"nested": {"nested": {"nested": "SECRET"}}}}}
    }
    assert m.assess(plan, **pins)["result"] == "BLOCKED"


def test_module_is_pure_and_direct_execution_is_inert(tmp_path):
    path = ROOT / "packaging/release_readiness.py"
    module = ast.parse(path.read_text())
    imports = {n.names[0].name for n in ast.walk(module) if isinstance(n, ast.Import)}
    assert imports == {"hashlib", "json", "re"}
    calls = {
        n.func.id
        for n in ast.walk(module)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert not calls & {"open", "eval", "exec", "__import__"}
    result = subprocess.run(
        [sys.executable, "-B", str(path)], cwd=tmp_path, capture_output=True, timeout=10
    )
    assert result.returncode == 0 and not result.stdout and not result.stderr
    assert list(tmp_path.iterdir()) == []


def test_normal_builder_final_flag_is_still_blocked_before_output(tmp_path):
    output = tmp_path / "must-not-exist"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "packaging/build_deb.py"),
            "--source-commit",
            "f8b447a716a410b8ebf2bd5f50e88167dc64d4b5",
            "--final-version",
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2 and not output.exists()


@pytest.mark.parametrize("ci", [False, True])
def test_actual_current_archives_remain_unreleased_and_assessor_is_not_shipped(
    facts,
    tmp_path,
    ci,
):
    import io
    import tarfile

    m, plan, pins = facts
    builder = load("packaging/build_deb.py")
    artifacts = builder.build(
        ROOT,
        tmp_path / "packages",
        8,
        "a" * 40,
        1700000000,
        source_tree="b" * 40,
        candidate=not ci,
        ci_final_fixture=ci,
    )
    for role, artifact in artifacts.items():
        raw = subprocess.check_output(
            ["dpkg-deb", "--fsys-tarfile", str(artifact)], timeout=15
        )
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            payload = {
                p.name.removeprefix("./"): archive.extractfile(p).read()
                for p in archive
                if p.isfile()
            }
        assert not any(p.endswith("/release_readiness.py") for p in payload)
        record = json.loads(
            payload["usr/share/doc/agent-platform-" + role + "/build.json"]
        )
        assert record["release_authorized"] is False
        assert record["ci_only"] is ci
        plan["roles"][role].update(kind=record["build_kind"], ci_only=record["ci_only"])
    report = m.assess(plan, **pins)
    assert report["reason"] == "artifact_not_future_final"
    denied(report)


def test_release_docs_links_host_scope_and_future_source_limits():
    import re

    docs = [
        ROOT / "docs/pkg12-release-readiness.md",
        ROOT / "docs/pkg12-host-upgrade-runbook.md",
    ]
    for path in docs:
        text = path.read_text()
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if not target.startswith(("http://", "https://", "mailto:")):
                assert (path.parent / target).resolve().is_file()
        for gate in (
            "HOST_NOT_RUN",
            "LIVE_NO_GO",
            "SUBSCRIPTION_ISOLATION_BLOCKED",
            "#73",
            "#108",
        ):
            assert gate in text
    runbook = docs[1].read_text()
    for host in ("control01", "worker01", "worker02"):
        assert f"| {host} |" in runbook
    readiness = docs[0].read_text()
    assert "not a release gate implementation" in readiness
    assert "no real" in readiness.lower() and "registry" in readiness
    assert "after the eventual human merge" in readiness


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "HEAD"),
        ("tree", "UNKNOWN"),
        ("epoch", True),
        ("final_recipe_path", "packaging/build_deb.py"),
        ("final_recipe_path", "packaging/release_readiness.py"),
        ("final_recipe_sha256", "UNKNOWN"),
        ("control_inputs_sha256", "0" * 63),
    ],
)
def test_incomplete_source_pins_cannot_admit_current_builder_or_assessor(
    facts, field, value
):
    m, plan, pins = facts
    pins["source_pin"] = pins["source_pin"]._replace(**{field: value})
    report = m.assess(plan, **pins)
    assert report["reason"] == "source_pin_unverified"
    denied(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("platform", "other"),
        ("image_digest", "latest"),
        ("python", "latest"),
        ("packages_sha256", "UNKNOWN"),
        ("dpkg_deb", "1.22.22\nSECRET"),
    ],
)
def test_unpinned_environment_cannot_establish_reproducibility(facts, field, value):
    m, plan, pins = facts
    pins["environment_pin"] = pins["environment_pin"]._replace(**{field: value})
    report = m.assess(plan, **pins)
    assert report["reason"] == "environment_pin_unverified"
    assert "SECRET" not in json.dumps(report)
    denied(report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "other/project"),
        ("version", "0.1.0-9"),
        ("architecture", "arm64"),
    ],
)
def test_freeze_scope_cannot_rotate_to_another_repository_or_version(
    facts, field, value
):
    m, plan, pins = facts
    report = m.assess(plan | {field: value}, **pins)
    assert report["reason"] == "plan_invalid"
    denied(report)
