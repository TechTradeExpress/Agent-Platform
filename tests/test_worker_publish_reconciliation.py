"""PUB-05 fabricated snapshots, authorizations and remote observations."""

import fcntl
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_worker_publisher import artifact, homelab_job, job_for

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_reconciliation as rec
from agent_platform import worker_publisher as pub

NOW = 20000


def chain(records):
    previous = art.digest(b"")
    lines = []
    for record in records:
        line = art.encoded({"previous": previous, "record": record})
        lines.append(line + b"\n")
        previous = art.digest(line)
    return b"".join(lines), previous


@pytest.fixture
def case():
    data, head, tree, objects = artifact()
    old = homelab_job(job_for(data, head, tree))
    old.update(issue=169, ref="refs/heads/feature/issue-169-v4", expires=NOW - 1000)
    oid, blob = next(
        (oid, raw) for oid, (kind, raw) in objects.items() if kind == "blob"
    )
    claim = dict(phase="CLAIM", job=old["id"], ref=old["ref"], head=head, issue=169)

    def effect(phase, operation, payload):
        return dict(
            phase=phase, job=old["id"], operation=operation, digest=art.digest(payload)
        )

    publisher, p_tip = chain(
        [
            claim,
            effect(
                "UNKNOWN",
                "mint",
                art.encoded(
                    {
                        "repository_ids": [pub.REPO_ID],
                        "permissions": pub.PERMISSIONS,
                    }
                ),
            ),
            effect("CONFIRMED", "mint", b"token_issued"),
            effect("UNKNOWN", "object", bytes.fromhex(oid)),
            effect("UNKNOWN", "revoke", b"revoke"),
            effect("CONFIRMED", "revoke", b"revoked"),
        ]
    )
    signer, s_tip = chain(
        [
            claim,
            {"phase": "UNKNOWN", "job": old["id"], "operation": "sign"},
            dict(claim, phase="COMPLETE", operation="sign", pr=None),
        ]
    )
    snapshot = rec.Snapshot(art.encoded(old), data, publisher, signer)
    digest = rec.snapshot_digest(snapshot)
    fresh = "e" * 40
    proposed, head, tree, _ = artifact(fresh, b"new artifact\n")
    new = dict(
        old,
        id="b" * 32,
        head=head,
        tree=tree,
        parent=fresh,
        base=fresh,
        ref="refs/heads/feature/issue-169-fresh",
        expires=NOW + 120,
        artifact_sha256=art.digest(proposed),
        journal_sha256=art.digest(publisher),
        signer_journal_sha256=art.digest(signer),
    )
    candidate = {
        "job_sha256": art.digest(art.encoded(new)),
        "artifact_sha256": art.digest(proposed),
    }

    def observed(value, origin="github_read_only"):
        return dict(
            at=NOW - 20,
            origin=origin,
            status="observed",
            visibility="complete",
            value=value,
        )

    facts = {
        "repository": observed(
            dict(
                repo_id=pub.REPO_ID,
                full_name=pub.REPOSITORY,
                repo_node=old["repo_node"],
                owner_id=30,
                default_branch="main",
            )
        ),
        "main": observed({"head": fresh, "protected": True}),
        "issue": observed({"number": 169, "id": 500, "state": "open"}),
        "app_policy": observed(
            dict(
                worker="worker01",
                app_id=5748674,
                app_slug="tte-agent-worker01",
                app_owner_id=31,
                installation_id=181691110,
                bot_id=40,
                bot_login="tte-agent-worker01[bot]",
                permissions=pub.PERMISSIONS,
                repository_ids=[pub.REPO_ID],
                main_bypass="denied",
                events=[],
                selection="selected",
                suspended=False,
                account_id=30,
            )
        ),
        "blob": observed(
            {
                "oid": oid,
                "kind": "blob",
                "canonical_sha256": art.digest(art.canonical("blob", blob)),
            }
        ),
        "host": observed(
            {
                "retained_snapshot": digest,
                "publisher_allowlist": old["github_ipv4"] + "/32",
                "publisher": "failed_idle",
                "signer": "inactive_success",
                "jwt": "retained",
                "jwt_expiry_upper_bound": old["expires"],
            },
            "host_metadata",
        ),
        "token": observed(
            {"mint": "confirmed", "revoke": "confirmed"}, "journal_review"
        ),
        "candidate_review": observed(candidate, "independent_review"),
    }
    for key, subject in {
        "old_ref": old["ref"],
        "new_ref": new["ref"],
        "old_ref_prs_all_states": old["ref"],
        "new_ref_prs_all_states": new["ref"],
        "issue_linked_prs": 169,
        "old_tree": old["tree"],
        "old_commit": old["head"],
    }.items():
        facts[key] = dict(observed(subject), status="absent")
    proof = {
        "schema": "PUB-05/evidence/1",
        "candidate": candidate,
        "facts": facts,
        "history": {
            "snapshot": digest,
            "object": oid,
            "publisher_tip": p_tip,
            "signer_tip": s_tip,
            "object_sha256": facts["blob"]["value"]["canonical_sha256"],
        },
    }
    decision = {
        "schema": "PUB-05/decision/1",
        "intent": "PREVIEW_NEW_ATTEMPT_ONLY",
        "snapshot": digest,
        "evidence": art.digest(art.encoded(proof)),
        "candidate": dict(candidate),
        "issued": NOW - 10,
        "expires": NOW + 50,
    }

    def arguments():
        evidence = art.encoded(proof)
        approval = art.encoded(decision)
        return dict(
            pins=rec.PreviewPins(digest, art.digest(evidence), art.digest(approval)),
            object_id=oid,
            proposed_job=art.encoded(new),
            proposed_artifact=proposed,
            evidence=evidence,
            decision=approval,
            now=NOW,
        )

    return SimpleNamespace(
        snapshot=snapshot,
        old=old,
        new=new,
        proof=proof,
        decision=decision,
        args=arguments,
    )


def test_offline_case_reports_no_authority(case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("pure validator accessed I/O")

    monkeypatch.setattr(pub.HTTPS, "exchange", forbidden)
    monkeypatch.setattr(pub, "publish", forbidden)
    monkeypatch.setattr(rec.os, "open", forbidden)
    pins = case.args()["pins"]
    assert (
        rec.inspect(
            case.snapshot,
            expected_snapshot=pins.snapshot,
            object_id=case.args()["object_id"],
            now=NOW,
        )["status"]
        == "HISTORY_VERIFIED"
    )
    result = rec.preview(case.snapshot, **case.args())
    assert result == {
        "status": "PREVIEW_ONLY",
        "check": "production_admission_unavailable",
        "admission_allowed": False,
        "publish_allowed": False,
        "external_rollback_protection": "NOT_PROVIDED",
    }


@pytest.mark.parametrize(
    "fault", ["raw_change", "chain_change", "forged_complete", "object"]
)
def test_history_mismatch(case, fault):
    args = case.args()
    snap = case.snapshot
    if fault == "raw_change":
        snap = replace(snap, job=snap.job + b" ")
    elif fault == "object":
        args["object_id"] = "c" * 40
    else:
        events = [art.decode(x) for x in snap.publisher_journal.splitlines()]
        if fault == "chain_change":
            events[-1]["previous"] = "0" * 64
            raw = b"".join(art.encoded(event) + b"\n" for event in events)
        else:
            events[3]["record"]["phase"] = "COMPLETE"
            raw, _ = chain([event["record"] for event in events])
        snap = replace(snap, publisher_journal=raw)
        args["pins"] = replace(args["pins"], snapshot=rec.snapshot_digest(snap))
    assert rec.preview(snap, **args)["check"] == "history"


@pytest.mark.parametrize(
    "fact,field,value",
    [
        ("old_ref", "status", "observed"),
        ("new_ref", "status", "unknown"),
        ("old_ref_prs_all_states", "status", "observed"),
        ("issue_linked_prs", "visibility", "partial"),
        ("new_ref_prs_all_states", "status", "unknown"),
        ("blob", "value", {"oid": "f" * 40, "kind": "blob"}),
        ("blob", "origin", "operator"),
        ("token", "status", "unknown"),
        ("token", "value", {"mint": "confirmed"}),
        ("main", "value", {"head": "a" * 40, "protected": True}),
        ("main", "at", NOW - 301),
        ("main", "at", NOW + 1),
        ("host", "value", {"publisher": "running"}),
        ("app_policy", "value", True),
        ("candidate_review", "status", "unknown"),
    ],
)
def test_incomplete_conflicting_or_stale_evidence(case, fact, field, value):
    case.proof["facts"][fact][field] = value
    assert rec.preview(case.snapshot, **case.args())["check"] == "independent_evidence"


@pytest.mark.parametrize(
    "key",
    [
        "id",
        "ref",
        "head",
        "artifact_sha256",
        "parent",
        "journal_sha256",
        "signer_journal_sha256",
        "issue_id",
    ],
)
def test_proposed_candidate_cannot_replay_or_change_subject(case, key):
    case.new[key] = 501 if key == "issue_id" else case.old[key]
    assert rec.preview(case.snapshot, **case.args())["check"] == "new_candidate"


@pytest.mark.parametrize(
    "key,value",
    [
        ("intent", "APPROVE"),
        ("expires", NOW),
        ("issued", NOW - 21),
        ("evidence", "0" * 64),
        ("snapshot", "f" * 64),
    ],
)
def test_decision_must_bind_fresh_exact_inputs(case, key, value):
    case.decision[key] = value
    assert rec.preview(case.snapshot, **case.args())["check"] == "operator_decision"


@pytest.mark.parametrize("failure", ["missing", "partial", "different_pin"])
def test_unconfirmed_decision_boundary_refuses(case, failure):
    args = case.args()
    if failure == "missing":
        args["decision"] = b""
    elif failure == "partial":
        args["decision"] = args["decision"][:-1]
    else:
        args["pins"] = replace(args["pins"], decision="0" * 64)
    assert rec.preview(case.snapshot, **args)["check"] == "operator_decision"


@pytest.mark.parametrize(
    "fault", ["ok", "mode", "owner", "symlink", "hardlink", "lock"]
)
def test_snapshot_directory_envelope(case, tmp_path, monkeypatch, fault):
    directory = tmp_path / "case"
    directory.mkdir(mode=0o700)
    for filename, content in zip(
        ("job.json", "candidate.json", "publisher.jsonl", "signer.jsonl"),
        (
            case.snapshot.job,
            case.snapshot.artifact,
            case.snapshot.publisher_journal,
            case.snapshot.signer_journal,
        ),
        strict=True,
    ):
        leaf = directory / filename
        leaf.write_bytes(content)
        leaf.chmod(0o600)
    job = directory / "job.json"
    if fault == "mode":
        job.chmod(0o644)
    if fault in {"symlink", "hardlink"}:
        target = tmp_path / "outside"
        job.rename(target)
        if fault == "symlink":
            job.symlink_to(target)
        else:
            os.link(target, job)
    raw_stat, raw_fstat = os.stat, os.fstat

    def pretend(info):
        return SimpleNamespace(
            **{
                k: getattr(info, k)
                for k in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            },
            st_uid=123 if fault == "owner" else 0,
            st_gid=0,
        )

    monkeypatch.setattr(rec.os, "stat", lambda *a, **kw: pretend(raw_stat(*a, **kw)))
    monkeypatch.setattr(rec.os, "fstat", lambda fd: pretend(raw_fstat(fd)))
    first = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    other = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if fault == "lock":
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if fault == "ok":
            assert rec.read_snapshot(first) == case.snapshot
        else:
            with pytest.raises(art.Blocked):
                rec.read_snapshot(first)
    finally:
        os.close(other)
        os.close(first)
