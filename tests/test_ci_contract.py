"""Offline workflow security contracts, not a general YAML/Actions validator."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


def test_external_actions_have_reviewed_official_commit_pins():
    workflows = ROOT / ".github/workflows"
    assert sorted(
        p.name for p in workflows.iterdir() if p.suffix in {".yml", ".yaml"}
    ) == ["ci.yml", "debian-package.yml"]
    evidence = json.loads((ROOT / "docs/ci-action-pins.json").read_text())
    allowed = {
        "actions/checkout": 4,
        "actions/setup-python": 5,
        "astral-sh/setup-uv": 6,
    }
    pins = {v["repository"]: v for v in evidence["actions"]}
    assert set(pins) == set(allowed)
    uses = re.findall(r"uses:\s*(\S+)\s+# (v\d+\.\d+\.\d+)", WORKFLOW.read_text())
    assert len(uses) == 3
    assert WORKFLOW.read_text().count("uses:") == len(uses)
    for ref, version in uses:
        repository, sha = ref.split("@")
        assert repository in allowed and re.fullmatch(r"[0-9a-f]{40}", sha)
        assert version.startswith(f"v{allowed[repository]}.")
        assert (sha, version) == (
            pins[repository]["commit"],
            pins[repository]["version"],
        )
        assert pins[repository]["action_source_url"].startswith(
            f"https://github.com/{repository}/blob/{sha}/"
        )


def test_read_only_permissions_and_no_persisted_checkout_credentials():
    text = WORKFLOW.read_text()
    assert text.count("permissions:") == 1
    assert "\npermissions:\n  contents: read\njobs:\n" in text
    assert "\n          persist-credentials: false\n" in text
    for forbidden in [
        "write-all",
        "contents: write",
        "pull-requests:",
        "id-token:",
        "secrets.",
        "secrets:",
        "github.token",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "pull_request_target",
        "workflow_run",
        "schedule:",
        "workflow_dispatch",
        "continue-on-error",
        "if:",
        "environment:",
        "services:",
        "container:",
    ]:
        assert forbidden not in text


def test_only_offline_required_job_commands_and_bounded_runtime():
    text = WORKFLOW.read_text()
    assert "on: [push, pull_request]\n" in text
    jobs = text.split("\njobs:\n", 1)[1]
    assert re.findall(r"^  ([\w-]+):$", jobs, re.M) == ["checks"]
    assert re.findall(r"^      - run: (.+)$", jobs, re.M) == [
        "uv sync --locked",
        "uv run ruff check .",
        "uv run pytest",
        "git diff --check",
    ]
    assert jobs.count("run:") == 4
    assert re.findall(r"timeout-minutes: (\d+)", jobs) == ["20"]
    assert "    runs-on: ubuntu-latest\n" in jobs
    assert "          python-version: '3.12'\n" in jobs
    assert "          version: '0.13.6'\n" in jobs
