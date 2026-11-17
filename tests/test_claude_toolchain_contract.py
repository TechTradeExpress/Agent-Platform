"""HAR-04 contract: two packages, no vendor payload, docs equal the reviewed pin."""

import hashlib
import json
import re
from pathlib import Path

import pytest
from test_debian_package import builder, payload

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "provisioning/claude-release-lock.json").read_text())
PIN = LOCK["releases"][0]
DOC = (ROOT / "docs/claude-toolchain.md").read_text()
FORBIDDEN_PATH_PARTS = (
    "claude_upstream",
    "claude-release-lock",
    "claude-2.1",
    "claude-code-release-key",
    "instruction_sources",
)


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def test_lock_evidence_and_documented_digests_are_one_chain():
    evidence = "provisioning/evidence/"
    assert PIN["version"] == "2.1.295" and PIN["platform"] == "linux-x64"
    assert sha(evidence + "claude-2.1.295-manifest.json") == PIN["manifest_sha256"]
    assert sha(evidence + "claude-2.1.295-manifest.json.sig") == PIN["signature_sha256"]
    assert sha(evidence + "claude-code-release-key.asc") == PIN["key_sha256"]
    assert sha(evidence + "claude-2.1.295-provenance.json") == PIN["evidence_sha256"]
    assert sha("provisioning/claude-release-lock.json") in (
        (ROOT / "provisioning/claude_upstream.py").read_text()
    )
    proof = json.loads((ROOT / evidence / "claude-2.1.295-provenance.json").read_text())
    assert proof["schema"] == "AP-CLAUDE-PROVENANCE/1"
    assert proof["binary_sha256"] == PIN["binary_sha256"]
    assert proof["not_run"] and "NOT downloaded" in " ".join(proof["not_run"])
    for value in (
        PIN["binary_sha256"],
        PIN["manifest_sha256"],
        PIN["signature_sha256"],
        PIN["key_sha256"],
        PIN["key_fingerprint"],
        str(PIN["binary_size"]),
        PIN["version"],
    ):
        assert value in DOC


def test_manifest_listed_binary_matches_lock_and_is_glibc_linux_x64():
    manifest = json.loads(
        (ROOT / "provisioning/evidence/claude-2.1.295-manifest.json").read_text()
    )
    entry = manifest["platforms"]["linux-x64"]
    assert (entry["checksum"], entry["size"], entry["binary"]) == (
        PIN["binary_sha256"],
        PIN["binary_size"],
        "claude",
    )
    assert manifest["version"] == PIN["version"]


def test_pin_meets_agents_md_floor_and_equals_har03_profile():
    parts = tuple(map(int, PIN["version"].split(".")))
    assert parts >= (2, 1, 281)
    contract = (ROOT / "docs/claude-adapter.md").read_text()
    assert PIN["version"] in contract


@pytest.mark.parametrize("revision", [3, 4, 5, 6])
def test_exactly_two_role_packages_and_no_claude_payload(tmp_path, revision):
    artifacts = builder.build(
        ROOT, tmp_path / "packages", revision, "a" * 40, 1700000000
    )
    assert set(artifacts) == {"control", "worker"}
    assert sorted(p.name.split("_")[0] for p in artifacts.values()) == [
        "agent-platform-control",
        "agent-platform-worker",
    ]
    for role, artifact in artifacts.items():
        files = payload(artifact)
        for path in files:
            assert not any(part in path for part in FORBIDDEN_PATH_PARTS), path
        assert not any(re.search(r"(^|/)claude($|/|\.)", path) for path in files), role


@pytest.mark.parametrize("revision", [3, 4, 5, 6])
def test_no_vendor_binary_or_third_package_is_built(tmp_path, revision):
    artifacts = builder.build(
        ROOT, tmp_path / "packages", revision, "a" * 40, 1700000000
    )
    for artifact in artifacts.values():
        assert artifact.stat().st_size < 8 * 1024 * 1024  # No 256 MiB vendor binary.
    built = sorted(p.name for p in (tmp_path / "packages").rglob("*.deb"))
    assert len(built) == 2 and not any(
        "claude" in name or "codex" in name for name in built
    )
    control = (ROOT / "debian/control").read_text()
    assert "claude" not in control.lower()


def test_doctor_is_the_only_shipped_file_that_knows_claude():
    shipped_p1 = [
        p for p in (ROOT / "packaging/worker-provisioning").glob("*") if p.is_file()
    ]
    mentioning = sorted(
        p.name for p in shipped_p1 if "claude" in p.read_bytes().decode().lower()
    )
    assert mentioning == ["worker_doctor.py"]
    for name in ("provision.py", "worker_cli.py", "preinst"):
        assert (
            "claude"
            not in (ROOT / "packaging/worker-provisioning" / name).read_text().lower()
        )


def test_claude_modules_hold_no_launch_or_authentication_entrypoint():
    for path in (
        "provisioning/claude_upstream.py",
        "src/agent_platform/instruction_sources.py",
    ):
        text = (ROOT / path).read_text()
        for token in (
            "--dangerously",
            "--resume",
            "--print",
            "claude login",
            "ANTHROPIC_",
            "oauth",
        ):
            assert token not in text
    cli = (ROOT / "src/agent_platform/cli.py").read_text()
    assert "claude" not in cli.lower()


def test_documented_gates_are_preserved():
    for phrase in (
        "SUBSCRIPTION_ISOLATION_BLOCKED",
        "LIVE_NO_GO",
        "HOST_NOT_RUN",
        "Gate #73",
        "human-only merge",
        "PKG-09",
        "NOT_RUN",
        "INSTALL_INERT",
    ):
        assert phrase in DOC
    for forbidden in ("curl -fsSL", "| bash", "| sh -"):
        assert forbidden not in DOC.replace("`curl | sh`", "")


def test_agents_md_is_the_only_instruction_file_documented():
    assert "No `CLAUDE.md`, `CLAUDE.local.md`" in DOC
    assert not (ROOT / "CLAUDE.md").exists()
    assert not (ROOT / "CLAUDE.local.md").exists()
