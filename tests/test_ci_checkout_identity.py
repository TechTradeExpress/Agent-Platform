"""CI-01 contract: Debian package CI binds to the actual checkout (offline).

Real temporary Git repositories exercise ``ci/verify_checkout_identity.py``
and the unchanged package builder; no network, GitHub API, Docker or
credential is used. Here the workflow is checked as text; its step-gate
semantics are modelled in tests/test_ci_workflow_gate.py.
"""

import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / ".github/workflows/debian-package.yml").read_text()
# Package provenance fields: the checkout record must never claim any of them.
PACKAGE_FIELDS = {
    "build_kind",
    "ci_only",
    "release_authorized",
    "debian_version",
    "source_commit",
    "source_tree",
}


def load(relative):
    spec = importlib.util.spec_from_file_location(Path(relative).stem, ROOT / relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


module = load("ci/verify_checkout_identity.py")

GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(repo, *args):
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=GIT_ENV,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(repo, name, text):
    (repo / name).write_text(text)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def pr(tmp_path):
    """Base commit B, feature commit F on a branch, synthetic merge M(B, F)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    base = commit(repo, "a", "a\n")
    git(repo, "checkout", "-q", "-b", "feature")
    head = commit(repo, "b", "b\n")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "-m", "synthetic", "feature")
    merge = git(repo, "rev-parse", "HEAD")
    event = {
        "number": 7,
        "pull_request": {
            "base": {"sha": base, "ref": "feature/repository-manager"},
            "head": {"sha": head, "ref": "feature/issue-1-x"},
        },
    }
    return {
        "repo": repo,
        "base": base,
        "head": head,
        "merge": merge,
        "event": event,
    }


def facts(repo, event_name, ref, sha, event):
    git(repo, "checkout", "-q", "--detach", sha)
    fields = git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()
    return {
        "event_name": event_name,
        "ref": ref,
        "github_sha": sha,
        "event": event,
        "head": git(repo, "rev-parse", "HEAD"),
        "parents": fields[1:],
        "tree": git(repo, "rev-parse", "HEAD^{tree}"),
    }


def pull(pr, **override):
    data = facts(
        pr["repo"], "pull_request", "refs/pull/7/merge", pr["merge"], pr["event"]
    )
    data.update(override)
    return data


def test_pull_request_accepts_the_synthetic_merge_for_any_target(pr):
    record = module.verify(**pull(pr))
    assert record["mode"] == "synthetic_merge_result"
    assert record["checkout_sha"] == pr["merge"] != pr["head"]
    assert record["checkout_parents"] == [pr["base"], pr["head"]]
    assert record["event_base_sha"] == pr["base"]
    assert record["event_head_sha"] == pr["head"]
    # Non-default integration targets are recorded, not special-cased.
    assert record["base_ref"] == "feature/repository-manager"
    # CI_ONLY / NOT_RELEASED classify this workflow-level record only.
    assert record["scope"] == "checkout_identity_only"
    assert (record["status"], record["release"]) == ("CI_ONLY", "NOT_RELEASED")
    assert not PACKAGE_FIELDS & set(record)
    assert record["schema"] == "AP-CI-CHECKOUT-EVIDENCE/1"
    json.dumps(record)


def test_push_accepts_only_the_exact_pushed_head(pr):
    event = {"after": pr["head"]}
    data = facts(pr["repo"], "push", "refs/heads/feature", pr["head"], event)
    record = module.verify(**data)
    assert record["mode"] == "exact_head" and record["checkout_sha"] == pr["head"]
    for broken in (
        {"event": {"after": pr["base"]}},  # event names another commit
        {"event": {}},
        {"ref": "refs/pull/7/merge"},
        {"ref": ""},
        {"github_sha": pr["base"]},  # runner SHA is not the checkout
    ):
        with pytest.raises(module.Rejected):
            module.verify(**{**data, **broken})


@pytest.mark.parametrize("name", ["pull_request_target", "workflow_run", "", None])
def test_other_events_are_rejected(pr, name):
    with pytest.raises(module.Rejected):
        module.verify(**pull(pr, event_name=name))


def test_feature_head_checkout_is_not_merge_result_evidence(pr):
    """The former behavior: checking out the PR head must now be rejected."""
    data = facts(
        pr["repo"], "pull_request", "refs/pull/7/merge", pr["head"], pr["event"]
    )
    with pytest.raises(module.Rejected, match="two_parent"):
        module.verify(**data)


def test_tree_equality_never_substitutes_for_parent_binding(pr):
    repo = pr["repo"]
    git(repo, "checkout", "-q", "--detach", pr["merge"])
    # A different commit with the identical tree but the wrong parents.
    forged = git(
        repo,
        "commit-tree",
        pr["merge"] + "^{tree}",
        "-p",
        pr["head"],
        "-p",
        pr["base"],
        "-m",
        "forged",
    )
    assert git(repo, "rev-parse", forged + "^{tree}") == git(
        repo, "rev-parse", pr["merge"] + "^{tree}"
    )
    data = facts(repo, "pull_request", "refs/pull/7/merge", forged, pr["event"])
    with pytest.raises(module.Rejected, match="parents_differ"):
        module.verify(**data)
    single = git(
        repo, "commit-tree", pr["merge"] + "^{tree}", "-p", pr["base"], "-m", "single"
    )
    data = facts(repo, "pull_request", "refs/pull/7/merge", single, pr["event"])
    with pytest.raises(module.Rejected, match="two_parent"):
        module.verify(**data)


def test_stale_or_mismatched_event_identity_is_rejected(pr):
    def event(**changes):
        data = json.loads(json.dumps(pr["event"]))
        for key, value in changes.items():
            side, field = key.split("__")
            data["pull_request"][side][field] = value
        return data

    other = "f" * 40
    cases = [
        ({"event": event(base__sha=other)}, "parents_differ"),  # stale base
        ({"event": event(head__sha=other)}, "parents_differ"),  # stale head
        (
            {"event": event(base__sha=pr["head"], head__sha=pr["base"])},
            "parents_differ",
        ),  # swapped
        ({"ref": "refs/pull/8/merge"}, "merge_ref"),
        ({"ref": "refs/heads/feature"}, "merge_ref"),
        ({"github_sha": pr["head"]}, "differs_from_event_sha"),
        ({"head": pr["head"]}, "differs_from_event_sha"),
    ]
    for override, reason in cases:
        with pytest.raises(module.Rejected, match=reason):
            module.verify(**pull(pr, **override))


def test_missing_or_malformed_fields_are_rejected(pr):
    good = json.loads(json.dumps(pr["event"]))
    broken_events = []
    for drop in ("number", "pull_request"):
        data = dict(good)
        data.pop(drop)
        broken_events.append(data)
    for side in ("base", "head"):
        for field in ("sha", "ref"):
            data = json.loads(json.dumps(good))
            del data["pull_request"][side][field]
            broken_events.append(data)
    for value in ("ABC" * 14, "abc", 7, None, pr["base"].upper()):
        data = json.loads(json.dumps(good))
        data["pull_request"]["base"]["sha"] = value
        broken_events.append(data)
    broken_events.append({**good, "number": True})
    broken_events.append({**good, "number": "7"})
    for event in broken_events:
        with pytest.raises(module.Rejected):
            module.verify(**pull(pr, event=event))
    with pytest.raises(module.Rejected):
        module.verify(**pull(pr, parents=[]))
    with pytest.raises(module.Rejected):  # ambiguous octopus-like graph
        module.verify(**pull(pr, parents=[pr["base"], pr["head"], pr["base"]]))


def test_evidence_records_no_environment_or_secret_material(pr):
    text = json.dumps(module.verify(**pull(pr)))
    for token in ("GITHUB_TOKEN", "ghp_", "Bearer", "/home/", "secret"):
        assert token not in text


def test_cli_writes_evidence_and_the_binding_variable(pr, tmp_path, monkeypatch):
    repo = pr["repo"]
    git(repo, "checkout", "-q", "--detach", pr["merge"])
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(pr["event"]))
    out, env_file = tmp_path / "evidence.json", tmp_path / "github_env"
    monkeypatch.chdir(repo)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/7/merge")
    monkeypatch.setenv("GITHUB_SHA", pr["merge"])
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    monkeypatch.setattr(module.os, "environ", os.environ)
    assert module.main(["--output", str(out), "--github-env", str(env_file)]) == 0
    assert json.loads(out.read_text())["checkout_sha"] == pr["merge"]
    assert env_file.read_text() == f"AP_VERIFIED_CHECKOUT_SHA={pr['merge']}\n"
    # A stale event fails closed, writes nothing new and exports nothing.
    out.unlink()
    env_file.unlink()
    stale = json.loads(event_file.read_text())
    stale["pull_request"]["base"]["sha"] = "e" * 40
    event_file.write_text(json.dumps(stale))
    assert module.main(["--output", str(out), "--github-env", str(env_file)]) == 1
    assert not out.exists() and not env_file.exists()
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "missing.json"))
    assert module.main(["--output", str(out), "--github-env", str(env_file)]) == 1


def checkout_section():
    return WORKFLOW.split("steps:\n", 1)[1].split("      - name:", 1)[0]


def test_workflow_checks_out_the_default_ref_and_verifies_before_any_build():
    section = checkout_section()
    assert "ref:" not in section and "head.sha" not in WORKFLOW
    assert "fetch-depth: 0" in section and "persist-credentials: false" in section
    marker = "      - name: Verify actual checkout SHA and merge parents"
    verify = WORKFLOW.index(marker)
    assert verify < WORKFLOW.index("docker build") < WORKFLOW.index("docker run")
    step = WORKFLOW[verify:].split("      - name:", 2)[1]
    assert "\n        id: verify_checkout\n" in step and "if:" not in step
    assert "python3 -I ci/verify_checkout_identity.py" in step
    assert "ap-evidence/ci-checkout-evidence.json" in step
    assert "(checkout evidence CI_ONLY, NOT_RELEASED)" in step


def test_package_source_commit_must_equal_the_verified_checkout():
    assert WORKFLOW.count("source_sha=$(git rev-parse HEAD)") == 2
    assert WORKFLOW.count('test "$source_sha" = "$AP_VERIFIED_CHECKOUT_SHA"') == 2
    for line in re.findall(r"--source-commit \"?\$source_sha\"?", WORKFLOW):
        assert "source_sha" in line
    assert "--source-commit" in WORKFLOW and "--final-version" not in WORKFLOW


def test_workflow_authority_and_check_identity_are_unchanged():
    assert WORKFLOW.startswith("name: Debian package\non: [push, pull_request]\n")
    assert re.findall(r"^  ([\w-]+):$", WORKFLOW, re.M) == ["lifecycle"]
    assert "permissions:\n  contents: read\n" in WORKFLOW
    for forbidden in (
        "pull_request_target",
        "workflow_run",
        "secrets",
        "GITHUB_TOKEN",
        "write-all",
        "contents: write",
        "id-token",
        "continue-on-error",
        "--privileged",
        "docker.sock",
        "branches:",
    ):
        assert forbidden not in WORKFLOW
    pins = re.findall(r"uses: ([\w/-]+)@([0-9a-f]{40}) # (v[\d.]+)", WORKFLOW)
    assert {p[0] for p in pins} == {"actions/checkout", "actions/upload-artifact"}
    assert WORKFLOW.count("uses:") == len(pins)
    assert "name: debian-candidates-and-lifecycle-evidence" in WORKFLOW
    assert "${{ runner.temp }}/ap-evidence" in WORKFLOW


def documentation():
    text = " ".join((ROOT / "docs/debian-package.md").read_text().split())
    return text.replace("`", "")


def test_documentation_states_the_checkout_contract_and_step_gate():
    text = documentation()
    for needle in (
        "on push it checks out the exact pushed HEAD",
        "on pull_request it checks out the synthetic merge result",
        "including non-default integration targets",
        "ci/verify_checkout_identity.py",
        "tree equality, the event name or a run head_sha never count",
        "Every later step requires steps.verify_checkout.outcome == 'success'",
        "builds, upgrades and lifecycle keep success()",
        "the separate Codex lifecycle and the prior-manpage negative keep "
        "!cancelled(), and archive inspection and artifact upload keep always()",
        "A rejected, skipped or cancelled verification therefore builds, "
        "inspects, runs and uploads nothing",
        "CHECKOUT_EVIDENCE_REJECTED: <reason>",
        "After a verified checkout, a later failure or cancellation runs the same "
        "diagnostics and upload as before",
        "The gate reads outcome, not conclusion",
        "--source-commit equals the verified checkout",
    ):
        assert needle in text, needle


def test_documentation_separates_workflow_evidence_from_package_provenance():
    text = documentation()
    for needle in (
        "Checkout identity only: scope=checkout_identity_only",
        "status=CI_ONLY, release=NOT_RELEASED classify this workflow-level "
        "evidence, not package provenance",
        "never proof of a successful validation by itself",
        "Package provenance, unchanged by CI-01",
        "Ordinary candidates build_kind=candidate, ci_only=false, "
        "release_authorized=false",
        "embedded ci_only=false. They are not embedded CI_ONLY packages",
        "release_readiness.assess rejects candidate and ci-final-fixture kinds "
        "(artifact_not_future_final)",
        "is not the commit that a GitHub merge, squash or rebase creates",
        "Release custody (ProtectedCustody) is NOT_CONFIGURED",
        "no repository code consumes Actions artifacts",
    ):
        assert needle in text, needle
    lowered = text.lower()
    for claim in (
        "merge commit are ci_only",
        "merge-result packages are ci_only",
        "ci_only / not_released candidates",
    ):
        assert claim not in lowered, claim
    doc = " ".join(module.__doc__.split())
    assert "classify this workflow-level evidence, not any package" in doc
    assert "ci_only false" in doc and "built from it are CI_ONLY" not in doc


def test_merge_result_candidate_keeps_its_provenance_and_is_never_admitted(
    tmp_path,
):
    """CI_ONLY classifies workflow evidence; embedded provenance is unchanged.

    A real two-parent merge commit, verified like ``refs/pull/N/merge``, is
    built by the unchanged CLI as the workflow does (``--source-commit`` is the
    verified checkout). Both roles stay ordinary candidates with ci_only=false,
    and the release assessor rejects them by class even when that exact commit
    is pinned as the release source.
    """
    source = tmp_path / "source"
    source.mkdir()
    for directory in ("packaging", "debian", "docs", "src", "provisioning"):
        shutil.copytree(
            ROOT / directory,
            source / directory,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for name in ("pyproject.toml", "uv.lock", "LICENSE"):
        shutil.copyfile(ROOT / name, source / name)
    git(source, "init", "-q", "-b", "main")
    git(source, "add", "--", ".")
    git(source, "commit", "-q", "-m", "base")
    base = git(source, "rev-parse", "HEAD")
    git(source, "checkout", "-q", "-b", "feature/issue-1-x")
    head = commit(source, "feature.txt", "feature\n")
    git(source, "checkout", "-q", "main")
    git(source, "merge", "-q", "--no-ff", "-m", "synthetic", "feature/issue-1-x")
    merge = git(source, "rev-parse", "HEAD")
    event = {
        "number": 7,
        "pull_request": {
            "base": {"sha": base, "ref": "feature/repository-manager"},
            "head": {"sha": head, "ref": "feature/issue-1-x"},
        },
    }
    record = module.verify(
        **facts(source, "pull_request", "refs/pull/7/merge", merge, event)
    )
    assert record["checkout_parents"] == [base, head]
    assert record["scope"] == "checkout_identity_only"
    assert not PACKAGE_FIELDS & set(record)

    output = tmp_path / "packages"
    built = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(source / "packaging/build_deb.py"),
            "--source-commit",
            record["checkout_sha"],
            "--output",
            str(output),
        ],
        cwd=source,
        env={"PATH": os.defpath, "LC_ALL": "C"},
        capture_output=True,
        timeout=120,
    )
    assert built.returncode == 0, built.stderr.decode(errors="replace")[-2000:]
    roles = {}
    for role in ("control", "worker"):
        package = "agent-platform-" + role
        archive = output / f"{package}_0.1.0-8~git{merge}_amd64.deb"
        payload = subprocess.check_output(
            ["dpkg-deb", "--fsys-tarfile", str(archive)], timeout=30
        )
        with tarfile.open(fileobj=io.BytesIO(payload)) as members:
            raw = next(
                members.extractfile(member).read()
                for member in members
                if member.name.removeprefix("./")
                == f"usr/share/doc/{package}/build.json"
            )
        external = (output / f"{package}.provenance.json").read_bytes()
        embedded = json.loads(raw)
        for provenance in (embedded, json.loads(external)):
            assert provenance["source_commit"] == record["checkout_sha"] == merge
            assert provenance["source_tree"] == record["checkout_tree"]
            assert provenance["debian_version"] == "0.1.0-8~git" + merge
            assert (
                provenance["build_kind"],
                provenance["ci_only"],
                provenance["release_authorized"],
            ) == ("candidate", False, False)
            assert "CI_ONLY" not in provenance["status"]
            assert "NOT_RELEASED" in provenance["status"]
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        roles[role] = {
            "package": package,
            "archive_sha256": digest,
            "archive_size": archive.stat().st_size,
            "manifest_sha256": "d" * 64,
            "embedded_build_sha256": hashlib.sha256(raw).hexdigest(),
            "provenance_sha256": hashlib.sha256(external).hexdigest(),
            "rebuild_sha256": digest,
            "kind": embedded["build_kind"],
            "ci_only": embedded["ci_only"],
            "inputs": embedded["inputs"],
        }

    readiness = load("packaging/release_readiness.py")
    # Even the synthetic merge commit itself pinned as the release source.
    source_pin = readiness.SourcePin(
        merge,
        record["checkout_tree"],
        embedded["source_date_epoch"],
        "3" * 64,
        "packaging/future_final_builder.py",
        "4" * 64,
        "5" * 64,
        "6" * 64,
    )
    environment_pin = readiness.EnvironmentPin(
        "debian-13/amd64", "sha256:" + "7" * 64, "3.13.5", "1.22.22", "5.8.1", "8" * 64
    )
    pins = {
        "source_pin": source_pin,
        "environment_pin": environment_pin,
        "history_pin": readiness.HistoryPin("EMPTY", "a" * 64, None),
    }
    plan = {
        "schema": "AP-PKG12-PLAN/1",
        "repository": readiness.REPOSITORY,
        "version": readiness.VERSION,
        "architecture": "amd64",
        "source": {key: getattr(source_pin, key) for key in readiness.SOURCE_FIELDS},
        "environment": environment_pin._asdict(),
        "roles": roles,
    }
    report = readiness.assess(plan, **pins)
    assert report["reason"] == "artifact_not_future_final"
    for key in (
        "final_generation_allowed",
        "release_authorized",
        "publication_allowed",
        "installation_allowed",
    ):
        assert report[key] is False
    # The class gate is what blocks: a (forbidden) relabelled copy passes it.
    relabelled = copy.deepcopy(plan)
    for item in relabelled["roles"].values():
        item["kind"] = "future-final"
    assert readiness.assess(relabelled, **pins)["reason"] != report["reason"]
