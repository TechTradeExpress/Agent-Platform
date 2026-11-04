"""Offline decision-artifact contracts; never load a runtime or fetch upstream."""

import copy
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from agent_platform import native_security

DOCS = Path(__file__).resolve().parents[1] / "docs"
DECISION = DOCS / "native-runtime-decision.json"
SOURCE_COMMIT = "6ff1e1ca3b30fc8b914720681fcf5fe62e95f856"
CLASSES = {
    "OFFICIAL_SUPPORTED",
    "EXPERIMENTAL",
    "RECORDED_HISTORICAL",
    "UNKNOWN",
    "NOT_TESTED",
}


def bounded_record(raw):
    """Test-only static contract, deliberately absent from production dispatch."""
    assert len(raw) <= 64 * 1024

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result

    record = json.loads(raw, object_pairs_hook=unique_pairs)
    assert record["schema_version"] == 1
    assert record["specification"] == "AP-NF/1"
    assert record["activation_decision"] == "NO-GO"
    assert record["architecture_verdict"] == "ARCHITECTURE_REDESIGN_REQUIRED"
    assert record["runtime_status"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert record["runtime_exit_code"] == 13
    assert record["runtime_cap_bytes"] == 268435456
    assert record["selected_engine"] == "STOCK_CODEX_CHATGPT_SUBSCRIPTION"
    assert record["selected_candidate"] is None
    assert set(record["authority"]) == {
        "launch_allowed",
        "resume_authorized",
        "authentication_allowed",
        "kernel_run_allowed",
        "provisioning_allowed",
        "publish_authorized",
    }
    assert all(value is False for value in record["authority"].values())
    subject = record["subject"]
    assert subject["source_commit"] == SOURCE_COMMIT
    assert subject["release_tag"] == "rust-v0.166.0"
    assert subject["tag_object"] == "593389380740f7b4762771573c447ccfdc59742f"
    assert subject["artifact_bytes"] is subject["artifact_sha256"] is None
    assert subject["source_binary_equivalence"] == "UNKNOWN"
    assert subject["artifact_admission"] == "UNKNOWN_BLOCKING"
    assert subject["installed_build"] == "NOT_TESTED"
    assert subject["protocol_schema_generation"] == "NOT_TESTED"
    assert subject["user_plan_eligibility"] == "UNKNOWN"
    assert record["historical_subject"]["source_commit"] == (
        native_security.PIN.source_commit
    )
    assert record["historical_subject"]["version"] == native_security.PIN.version
    assert record["historical_subject"]["source_commit"] != SOURCE_COMMIT
    assert record["historical_subject"]["same_domain_result"] == (
        "FAIL_RECORDED_HISTORICAL"
    )
    assert record["unlisted_routes"] == "UNKNOWN_BLOCKING"
    sources = {row["id"]: row for row in record["sources"]}
    assert len(sources) == len(record["sources"])
    for source in sources.values():
        assert source["classification"] in CLASSES
        assert re.fullmatch("[0-9a-f]{64}", source["sha256"])
        assert 0 < source["bytes"] < 3_000_000
        url = urlsplit(source["url"])
        assert url.scheme == "https" and not url.username and not url.query
        if source["kind"] == "PINNED_PUBLIC_SOURCE":
            assert source["classification"] == "UNKNOWN"
            assert source["locator"]
            assert re.fullmatch("[0-9a-f]{40}", source["blob_sha1"])
            assert url.netloc == "raw.githubusercontent.com"
            assert url.path == f"/openai/codex/{SOURCE_COMMIT}/{source['path']}"
        else:
            assert source["kind"] == "MUTABLE_OFFICIAL_DOCUMENTATION"
            assert url.netloc == "learn.chatgpt.com"
    assert [r["route"] for r in record["routes"]] == [
        name for name, _, _ in native_security.ROUTES
    ]
    for row, (name, historical_dispatch, _) in zip(
        record["routes"], native_security.ROUTES, strict=True
    ):
        assert row["route"] == name
        assert row["historical_dispatch"] == historical_dispatch
        assert row["historical_boundary"] == row["enforced_boundary"] == "UNKNOWN"
        assert row["verified_mediated"] is False
        assert row["classification"] in CLASSES
        assert row["source_ids"] and set(row["source_ids"]) <= sources.keys()
        assert row["delta"] and row["required_proof"]
    assert [g["id"] for g in record["gates"]] == ["G0", "G1", "G2", "G3"]
    assert record["gates"][0]["status"] == "PARTIAL_STATIC_ONLY"
    assert all(g["status"] == "NOT_RUN" for g in record["gates"][1:])
    assert all(g["human_authorization"] and g["missing"] for g in record["gates"])
    assert record["blockers"] and record["follow_up"]["upstream_questions"]
    return record


def test_decision_is_bounded_pinned_and_never_launch_authority():
    record = bounded_record(DECISION.read_bytes())
    document = (DOCS / "native-runtime-feasibility.md").read_text()
    assert "```mermaid" in document
    for row in record["routes"]:
        assert f"| {row['route']} |" in document
    for source in record["sources"]:
        if source["kind"] == "PINNED_PUBLIC_SOURCE":
            assert source["url"] in document


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(activation_decision="GO"),
        lambda r: r.update(runtime_exit_code=0),
        lambda r: r.update(runtime_cap_bytes=384 * 1024 * 1024),
        lambda r: r["authority"].update(launch_allowed=True),
        lambda r: r["authority"].update(authentication_allowed=True),
        lambda r: r["authority"].update(publish_authorized=True),
        lambda r: r["subject"].update(source_commit=native_security.PIN.source_commit),
        lambda r: r["subject"].update(source_binary_equivalence="PASS"),
        lambda r: r["subject"].update(
            artifact_bytes=native_security.PIN.artifact_bytes
        ),
        lambda r: r["routes"].pop(),
        lambda r: r["routes"].append(copy.deepcopy(r["routes"][0])),
        lambda r: r["routes"][0].update(verified_mediated=True),
        lambda r: r["routes"][0].update(source_ids=["invented"]),
        lambda r: r["sources"][0].update(url="https://example.invalid/source"),
        lambda r: r["sources"][0].update(sha256="unverified"),
        lambda r: r["gates"][1].update(status="PASS"),
        lambda r: r["gates"][2].update(status="PASS"),
        lambda r: r["gates"][3].update(status="PASS"),
        lambda r: r.update(unlisted_routes="ALLOWED"),
    ],
)
def test_promoted_or_incomplete_static_evidence_cannot_satisfy_contract(change):
    record = json.loads(DECISION.read_bytes())
    change(record)
    with pytest.raises(AssertionError):
        bounded_record(json.dumps(record).encode())


def test_ambiguous_and_oversized_decision_records_fail():
    raw = DECISION.read_bytes()
    with pytest.raises(AssertionError):
        bounded_record(b'{"schema_version":1,' + raw[1:])
    with pytest.raises(AssertionError):
        bounded_record(raw + b" " * (64 * 1024))
