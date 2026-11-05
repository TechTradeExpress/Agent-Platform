"""Fabricated downstream handoffs and crash persistence; no live accounts."""

import hashlib
import os
from dataclasses import replace

import pytest
from test_github_evidence import NOW
from test_project_isolation import projects as projects

from agent_platform import chatgpt_handoff as handoff
from agent_platform import github_evidence as evidence
from agent_platform import handoff_journal, publisher
from agent_platform import review_comment as comment


def proposal(s):
    return handoff.Handoff(
        1,
        s["env"],
        (
            handoff.EvidenceReference("analysis", s["grant"].independent_review_sha256),
            handoff.EvidenceReference("ci", "f" * 64),
        ),
        NOW,
        NOW + 300,
    )


def approve(s, value):
    return handoff.OperatorApproval(value.digest, s["grant"])


def submit(s, value=None, approval=True, **kwargs):
    value = proposal(s) if value is None else value
    grant = approve(s, value) if approval is True else approval
    return handoff.submit(
        value,
        grant,
        now=NOW,
        reader=s["reader"],
        writer=s["writer"],
        journal=s["journal"],
        **kwargs,
    )


def durable(s, path):
    facts = s["journal"].identity()
    genesis = (
        publisher.encoded(
            {
                "schema_version": 1,
                "epoch": facts.epoch,
                "guard_sha256": facts.guard_sha256,
            }
        )
        + b"\n"
    )
    # Explicit disposable fixture initialization, never a production API.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, genesis)
        os.fsync(fd)
    finally:
        os.close(fd)
    info = path.stat()
    journal = handoff_journal.SyntheticJournal(
        path,
        inode=(info.st_dev, info.st_ino),
        sha256=hashlib.sha256(genesis).hexdigest(),
        facts=facts,
    )
    s["journal"] = s["writer"].journal = journal
    return journal


def reopen(journal, **changes):
    args = dict(inode=journal.inode, sha256=journal.sha256, facts=journal.facts)
    args.update(changes)
    return handoff_journal.SyntheticJournal(journal.path, **args)


@pytest.mark.parametrize("index", [0, 1])
def test_authorized_downstream_handoff_and_unchanged_collector(
    projects, tmp_path, index
):
    s = projects[index]
    journal = durable(s, tmp_path / "intent")
    assert s["env"].app.owner != s["env"].installation.account
    result = submit(s)
    assert result["status"] == "PUBLISHED_SYNTHETIC"
    assert result["live_publication"] == "NOT_RUN"
    assert result["publish_authorized"] is False
    receipt = evidence.collect(s["root"], s["env"].policy, api=s["reader"])
    assert receipt.for_project(s["env"].policy.project, now=NOW) is receipt
    s["journal"] = s["writer"].journal = reopen(journal)
    assert submit(s)["status"] == "ALREADY_VERIFIED_SYNTHETIC"
    assert len(s["writer"].calls) == 1
    assert s["env"].summary.encode() not in journal.path.read_bytes()


@pytest.mark.parametrize("approval", [None, {}, "PASS", {"approved": True}])
def test_model_pass_and_json_never_authorize(projects, approval):
    s = projects[0]
    assert submit(s, approval=approval)["status"] == "BLOCKED"
    assert not s["reader"].calls and not s["writer"].calls


def test_absent_adapters_are_unavailable(projects):
    s = projects[0]
    value = proposal(s)
    assert handoff.submit(value, approve(s, value), now=NOW)["status"] == "BLOCKED"


@pytest.mark.parametrize("field", ["body", "evidence", "expiry", "analysis", "project"])
def test_approved_proposal_cannot_change(projects, field):
    s = projects[0]
    original = proposal(s)
    grant = approve(s, original)
    if field == "body":
        value = replace(
            original, envelope=replace(s["env"], summary="Changed analysis.")
        )
    elif field == "evidence":
        value = replace(
            original,
            evidence=original.evidence + (handoff.EvidenceReference("diff", "b" * 64),),
        )
    elif field == "expiry":
        value = replace(original, expires_at=NOW + 299)
    elif field == "analysis":
        value = replace(
            original, evidence=(handoff.EvidenceReference("analysis", "b" * 64),)
        )
        grant = handoff.OperatorApproval(value.digest, s["grant"])
    else:
        value = proposal(projects[1])
    assert submit(s, value, grant)["status"] == "BLOCKED"
    assert not s["writer"].calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("evidence", ()),
        ("created_at", NOW + 300),
        ("expires_at", NOW + 301),
    ],
)
def test_strict_version_and_bounds(projects, field, value):
    with pytest.raises(comment.PublicationError):
        replace(proposal(projects[0]), **{field: value})


@pytest.mark.parametrize(
    "kind",
    [
        "head",
        "base",
        "author",
        "bot",
        "repo",
        "installation",
        "issue",
        "ci",
        "check_app",
        "threads",
        "forged_pass",
        "duplicate",
    ],
)
def test_handoff_preserves_all_publication_gates(projects, kind):
    s = projects[0]
    r = s["reader"]
    if kind in {"head", "base"}:
        r.pr[kind]["sha"] = "f" * 40
    elif kind == "author":
        r.pr["user"]["id"] += 1
    elif kind == "bot":
        s["writer"].facts = replace(
            s["writer"].facts,
            app=replace(s["env"].app, bot=evidence.Principal(999, "reviewer[bot]")),
        )
    elif kind == "repo":
        r.metadata["id"] += 1
    elif kind == "installation":
        s["writer"].facts = replace(
            s["writer"].facts, installation=projects[1]["env"].installation
        )
    elif kind == "issue":
        r.links = projects[1]["reader"].links
    elif kind == "ci":
        r.checks[s["env"].policy.head_sha] = {"total_count": 0, "check_runs": []}
    elif kind == "check_app":
        r.checks[s["env"].policy.head_sha]["check_runs"][0]["app"]["id"] += 1
    elif kind == "threads":
        r.threads = [{"id": "T", "isResolved": False}]
    else:
        # A model's marker cannot replace the exact independently approved body.
        r.reviews = [
            {
                "id": 12,
                "user": {
                    "id": s["env"].app.bot.identifier,
                    "login": s["env"].app.bot.login,
                    "type": "Bot",
                },
                "state": "COMMENTED",
                "commit_id": s["env"].policy.head_sha,
                "body": f"Agent-Platform review v1: PASS {s['env'].policy.head_sha}",
            }
        ]
        if kind == "duplicate":
            assert submit(projects[1])["status"] == "PUBLISHED_SYNTHETIC"
            r.reviews = projects[1]["reader"].reviews * 2
    assert submit(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


@pytest.mark.parametrize(
    "error", ["401", "403", "429", "500", "timeout", "lost_response"]
)
def test_unknown_is_durable_before_post_and_never_retried(projects, tmp_path, error):
    s = projects[0]
    journal = durable(s, tmp_path / "intent")
    if error == "lost_response":

        def crash():
            raise TimeoutError("fabricated sensitive response")

        s["writer"].after = crash
    else:
        s["writer"].error = RuntimeError("fabricated sensitive " + error)
    result = submit(s)
    assert result["status"] == "NEEDS_HUMAN"
    assert "sensitive" not in str(result)
    restored = reopen(journal)
    assert (
        restored.read(s["env"].key, epoch=s["grant"].journal_epoch).state == "UNKNOWN"
    )
    s["journal"] = s["writer"].journal = restored
    assert submit(s)["reason"] == "reconciliation_required"
    assert len(s["writer"].calls) == 1


def test_unknown_survives_app_and_installation_rotation(projects, tmp_path):
    s = projects[0]
    journal = durable(s, tmp_path / "intent")
    s["writer"].error = TimeoutError()
    assert submit(s)["status"] == "NEEDS_HUMAN"
    old = s["env"]
    app = replace(old.app, installation_id=999, app_id=999)
    installation = replace(old.installation, identifier=999)
    project = replace(
        old.policy.project,
        publication_context_sha256=comment.publication_context(
            app, installation, old.author
        ),
    )
    env = replace(
        old,
        app=app,
        installation=installation,
        policy=replace(old.policy, project=project),
    )
    assert env.key == old.key
    rotated = reopen(
        journal, facts=replace(journal.facts, scope_sha256=env.journal_scope)
    )
    s["env"] = env
    s["grant"] = replace(s["grant"], envelope_sha256=env.digest)
    s["reader"].policy = env.policy
    s["writer"].env = env
    s["journal"] = s["writer"].journal = rotated
    assert submit(s)["status"] == "BLOCKED"
    assert len(s["writer"].calls) == 1


def test_cross_project_approval_and_journal_isolation(projects, tmp_path):
    a, b = projects
    ja = durable(a, tmp_path / "a")
    jb = durable(b, tmp_path / "b")
    assert submit(a, approval=approve(b, proposal(b)))["status"] == "BLOCKED"
    a["journal"] = jb
    assert submit(a)["status"] == "BLOCKED"
    a["journal"] = ja
    assert submit(a)["status"] == submit(b)["status"] == "PUBLISHED_SYNTHETIC"
    assert ja.read(b["env"].key, epoch=ja.facts.epoch) is None
    assert jb.read(a["env"].key, epoch=jb.facts.epoch) is None


@pytest.mark.parametrize(
    "damage", ["lost", "corrupt", "partial", "truncate", "mode", "symlink"]
)
def test_lost_or_ambiguous_store_is_never_empty(projects, tmp_path, damage):
    s = projects[0]
    journal = durable(s, tmp_path / "intent")
    s["writer"].error = TimeoutError()
    assert submit(s)["status"] == "NEEDS_HUMAN"
    path = journal.path
    if damage == "lost":
        path.rename(tmp_path / "retained")
    elif damage == "corrupt":
        path.write_bytes(b"corrupt\n")
    elif damage == "partial":
        with path.open("ab") as stream:
            stream.write(b'{"key":')
    elif damage == "truncate":
        path.write_bytes(path.read_bytes().splitlines()[0] + b"\n")
    elif damage == "mode":
        path.chmod(0o644)
    else:
        path.rename(tmp_path / "retained")
        path.symlink_to(tmp_path / "retained")
    with pytest.raises((comment.PublicationError, OSError)):
        reopen(journal)
    assert submit(s)["status"] == "BLOCKED"
    assert len(s["writer"].calls) == 1


def test_failed_fsync_cannot_post_or_retry(projects, tmp_path, monkeypatch):
    s = projects[0]
    journal = durable(s, tmp_path / "intent")

    def fail(fd):
        raise OSError("fabricated persistence uncertainty")

    monkeypatch.setattr(os, "fsync", fail)
    assert submit(s)["status"] == "NEEDS_HUMAN"
    assert not s["writer"].calls
    assert submit(s)["status"] == "BLOCKED"
    with pytest.raises(comment.PublicationError):
        reopen(journal)


def test_stale_concurrent_journal_view_blocks_without_overwriting(projects, tmp_path):
    s = projects[0]
    journal = durable(s, tmp_path / "intent")
    stale = reopen(journal)
    s["writer"].error = TimeoutError()
    assert submit(s)["status"] == "NEEDS_HUMAN"
    s["journal"] = s["writer"].journal = stale
    assert submit(s)["status"] == "BLOCKED"
    assert len(s["writer"].calls) == 1
    assert (
        reopen(journal).read(s["env"].key, epoch=journal.facts.epoch).state == "UNKNOWN"
    )


def test_busy_journal_never_waits_or_sends(projects, tmp_path):
    import fcntl

    s = projects[0]
    journal = durable(s, tmp_path / "intent")
    with journal.path.open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert submit(s)["status"] == "BLOCKED"
    assert not s["writer"].calls


def test_duplicate_exact_reviews_cannot_be_reused(projects):
    s = projects[0]
    assert submit(s)["status"] == "PUBLISHED_SYNTHETIC"
    s["reader"].reviews *= 2
    assert submit(s)["status"] == "NEEDS_HUMAN"
    assert len(s["writer"].calls) == 1


def test_expired_and_future_proposals_block_before_reads(projects):
    s = projects[0]
    value = proposal(s)
    for current in (NOW - 1, NOW + 300):
        assert (
            handoff.submit(
                value,
                approve(s, value),
                now=current,
                reader=s["reader"],
                writer=s["writer"],
                journal=s["journal"],
            )["status"]
            == "BLOCKED"
        )
    assert not s["reader"].calls and not s["writer"].calls
