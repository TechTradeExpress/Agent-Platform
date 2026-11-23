"""PUB-05 source-only validation of worker01 offline evidence. No host authority."""

import fcntl
import os
import stat
from dataclasses import dataclass

from . import worker_publish_artifact as art
from . import worker_publisher as pub

WINDOW = 300
RECORD_LIMIT = 16384
JOURNAL_LIMIT = 65536
SUBJECT = ("repo_node", "owner_id", "issue", "issue_id")
APP = (
    "worker",
    "app_id",
    "app_slug",
    "app_owner_id",
    "installation_id",
    "bot_id",
    "bot_login",
)
ACCOUNTS = ("publisher_uid", "publisher_gid", "signer_uid", "signer_gid", "worker_uid")


@dataclass(frozen=True)
class Snapshot:
    job: bytes
    artifact: bytes
    publisher_journal: bytes
    signer_journal: bytes


@dataclass(frozen=True)
class PreviewPins:
    snapshot: str
    evidence: str
    decision: str


def _bounded(raw, limit):
    art.need(type(raw) is bytes and 0 < len(raw) <= limit)
    return raw


def snapshot_digest(snapshot: Snapshot):
    """Fingerprint supplied bytes for comparison with independently held evidence."""
    return art.digest(
        art.encoded(
            {
                "job": art.digest(_bounded(snapshot.job, RECORD_LIMIT)),
                "artifact": art.digest(_bounded(snapshot.artifact, art.MAX_WIRE)),
                "publisher": art.digest(
                    _bounded(snapshot.publisher_journal, JOURNAL_LIMIT)
                ),
                "signer": art.digest(_bounded(snapshot.signer_journal, JOURNAL_LIMIT)),
                "schema": "PUB-05/snapshot/1",
            }
        )
    )


def read_snapshot(directory: int):
    """Copy fixed, private offline evidence files from a trusted open directory.

    The caller pins the directory and its ancestry before opening it and hands
    over a dedicated descriptor. No directory is searched, created or repaired.
    """

    def metadata(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def read(name, limit):
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(fd)
            art.need(
                stat.S_ISREG(before.st_mode)
                and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1
                and 0 < before.st_size <= limit
            )
            data = bytearray()
            while len(data) < before.st_size:
                chunk = os.read(fd, min(65536, before.st_size - len(data)))
                art.need(chunk)
                data.extend(chunk)
            art.need(metadata(os.fstat(fd)) == metadata(before))
            return bytes(data), metadata(before)
        finally:
            os.close(fd)

    try:
        root = os.fstat(directory)
        art.need(stat.S_ISDIR(root.st_mode) and stat.S_IMODE(root.st_mode) == 0o700)
        art.need(root.st_uid == root.st_gid == 0)
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            specs = (
                ("job.json", RECORD_LIMIT),
                ("candidate.json", art.MAX_WIRE),
                ("publisher.jsonl", JOURNAL_LIMIT),
                ("signer.jsonl", JOURNAL_LIMIT),
            )
            captured = [read(name, limit) for name, limit in specs]
            for (name, _), (_, pin) in zip(specs, captured, strict=True):
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                art.need(metadata(info) == pin)
            art.need(metadata(os.fstat(directory)) == metadata(root))
            return Snapshot(*(data for data, _ in captured))
        finally:
            fcntl.flock(directory, fcntl.LOCK_UN)
    except Exception:
        raise art.Blocked() from None


def _canonical(raw):
    value = art.decode(_bounded(raw, RECORD_LIMIT))
    art.need(type(value) is dict and art.encoded(value) == raw)
    return value


def _chain(raw, count):
    lines = raw.splitlines(keepends=True)
    art.need(len(lines) == count)
    tip = art.digest(b"")
    records = []
    for line in lines:
        value = _canonical(line[:-1])
        art.need(line.endswith(b"\n") and set(value) == {"previous", "record"})
        art.need(value["previous"] == tip)
        tip = art.digest(line[:-1])
        records.append(value["record"])
    return records, tip


def _history(snapshot, expected, oid, now):
    art.need(type(now) is int and now > 0)
    art.need(snapshot_digest(snapshot) == expected)
    job = _canonical(snapshot.job)
    expires = job["expires"]
    art.need(type(expires) is int and 1 < expires <= now)
    pub.validate_job(job, expires - 1)
    art.need(pub.homelab(job) and job["issue"] == 169 and art.sha(oid))
    art.need(job["journal_sha256"] == job["signer_journal_sha256"] == art.digest(b""))
    art.need(art.digest(snapshot.artifact) == job["artifact_sha256"])
    objects, _, _, _ = art.validate(
        snapshot.artifact, job["head"], job["tree"], job["parent"]
    )
    kind, payload = objects[oid]
    art.need(kind == "blob")
    publisher, publisher_tip = _chain(snapshot.publisher_journal, 6)
    signer, signer_tip = _chain(snapshot.signer_journal, 3)
    identity = {"job": job["id"]}
    claim = dict(identity, phase="CLAIM", ref=job["ref"], issue=169, head=job["head"])

    def effect(phase, operation, content):
        return dict(
            identity, phase=phase, operation=operation, digest=art.digest(content)
        )

    mint = art.encoded(
        {"repository_ids": [pub.REPO_ID], "permissions": pub.PERMISSIONS}
    )
    expected_publisher = [
        claim,
        effect("UNKNOWN", "mint", mint),
        effect("CONFIRMED", "mint", b"token_issued"),
        effect("UNKNOWN", "object", bytes.fromhex(oid)),
        effect("UNKNOWN", "revoke", b"revoke"),
        effect("CONFIRMED", "revoke", b"revoked"),
    ]
    expected_signer = [
        claim,
        dict(identity, phase="UNKNOWN", operation="sign"),
        dict(claim, phase="COMPLETE", operation="sign", pr=None),
    ]
    # Canonical-byte equality also rejects JSON bool/int aliases.
    art.need(art.encoded(publisher) == art.encoded(expected_publisher))
    art.need(art.encoded(signer) == art.encoded(expected_signer))
    return job, {
        "snapshot": expected,
        "object": oid,
        "publisher_tip": publisher_tip,
        "signer_tip": signer_tip,
        "object_sha256": art.digest(art.canonical(kind, payload)),
    }


def _report(status, check):
    return {
        "status": status,
        "check": check,
        "admission_allowed": False,
        "publish_allowed": False,
        "external_rollback_protection": "NOT_PROVIDED",
    }


def inspect(snapshot: Snapshot, *, expected_snapshot: str, object_id: str, now: int):
    """Check caller-supplied history without returning identifying data."""
    try:
        _history(snapshot, expected_snapshot, object_id, now)
    except Exception:
        return _report("STOP", "history")
    return _report("HISTORY_VERIFIED", "original_effect_unresolved")


def _proposed(snapshot, old, raw, artifact, now, *, fresh_generation=False):
    new = pub.validate_job(_canonical(raw), now)
    art.need(pub.homelab(new))
    art.need(all(new[k] == old[k] for k in SUBJECT + APP + ACCOUNTS))
    for key in ("id", "ref", "head", "artifact_sha256", "parent"):
        art.need(new[key] != old[key])
    publisher_log = b"" if fresh_generation else snapshot.publisher_journal
    signer_log = b"" if fresh_generation else snapshot.signer_journal
    art.need(new["journal_sha256"] == art.digest(publisher_log))
    art.need(new["signer_journal_sha256"] == art.digest(signer_log))
    digest = art.digest(_bounded(artifact, art.MAX_WIRE))
    art.need(new["artifact_sha256"] == digest)
    art.validate(artifact, new["head"], new["tree"], new["parent"])
    return new, {"job_sha256": art.digest(raw), "artifact_sha256": digest}


def _evidence(raw, pin, history, old, new, candidate, now):
    value = _canonical(raw)
    art.need(art.digest(raw) == pin)
    art.need(set(value) == {"schema", "history", "candidate", "facts"})
    art.need(value["schema"] == "PUB-05/evidence/1")
    art.need(value["history"] == history and value["candidate"] == candidate)
    facts = value["facts"]
    observed = {
        "repository": (
            "github_read_only",
            dict(
                repo_id=pub.REPO_ID,
                full_name=pub.REPOSITORY,
                repo_node=old["repo_node"],
                owner_id=old["owner_id"],
                default_branch="main",
            ),
        ),
        "main": ("github_read_only", {"head": new["parent"], "protected": True}),
        "issue": (
            "github_read_only",
            {"number": 169, "id": old["issue_id"], "state": "open"},
        ),
        "app_policy": (
            "github_read_only",
            dict(
                {k: old[k] for k in APP},
                repository_ids=[pub.REPO_ID],
                permissions=pub.PERMISSIONS,
                main_bypass="denied",
                events=[],
                selection="selected",
                suspended=False,
                account_id=old["owner_id"],
            ),
        ),
        "blob": (
            "github_read_only",
            {
                "oid": history["object"],
                "kind": "blob",
                "canonical_sha256": history["object_sha256"],
            },
        ),
        "host": (
            "host_metadata",
            {
                "retained_snapshot": history["snapshot"],
                "publisher_allowlist": old["github_ipv4"] + "/32",
                "publisher": "failed_idle",
                "signer": "inactive_success",
                "jwt": "retained",
                "jwt_expiry_upper_bound": old["expires"],
            },
        ),
        "token": ("journal_review", {"mint": "confirmed", "revoke": "confirmed"}),
        "candidate_review": ("independent_review", candidate),
    }
    # Absence is asserted for these exact subjects in complete read-only scope.
    absent = {
        "old_ref": old["ref"],
        "old_ref_prs_all_states": old["ref"],
        "new_ref": new["ref"],
        "new_ref_prs_all_states": new["ref"],
        "issue_linked_prs": 169,
        "old_tree": old["tree"],
        "old_commit": old["head"],
    }
    art.need(type(facts) is dict and set(facts) == set(observed) | set(absent))
    youngest = 0
    for name, fact in facts.items():
        at = fact["at"]
        art.need(type(at) is int and max(now - WINDOW, old["expires"]) <= at <= now)
        youngest = max(at, youngest)
        if name in observed:
            origin, expected = observed[name]
            status = "observed"
        else:
            origin, expected = "github_read_only", absent[name]
            status = "absent"
        art.need(
            art.encoded(fact)
            == art.encoded(
                {
                    "at": at,
                    "origin": origin,
                    "status": status,
                    "visibility": "complete",
                    "value": expected,
                }
            )
        )
    return youngest


def preview(
    snapshot: Snapshot,
    *,
    pins: PreviewPins,
    object_id: str,
    proposed_job: bytes,
    proposed_artifact: bytes,
    evidence: bytes,
    decision: bytes,
    now: int,
):
    """Validate exact pinned inputs for an inert preview. Performs no I/O."""
    check = "history"
    try:
        old, history = _history(snapshot, pins.snapshot, object_id, now)
        check = "new_candidate"
        new, candidate = _proposed(snapshot, old, proposed_job, proposed_artifact, now)
        check = "independent_evidence"
        observed_at = _evidence(
            evidence, pins.evidence, history, old, new, candidate, now
        )
        check = "operator_decision"
        value = _canonical(decision)
        art.need(art.digest(decision) == pins.decision)
        issued, expires = value["issued"], value["expires"]
        art.need(type(issued) is type(expires) is int)
        art.need(
            observed_at
            <= issued
            <= now
            < expires
            <= min(issued + WINDOW, new["expires"])
        )
        art.need(
            value
            == {
                "schema": "PUB-05/decision/1",
                "intent": "PREVIEW_NEW_ATTEMPT_ONLY",
                "snapshot": pins.snapshot,
                "evidence": pins.evidence,
                "candidate": candidate,
                "issued": issued,
                "expires": expires,
            }
        )
    except Exception:
        return _report("STOP", check)
    return _report("PREVIEW_ONLY", "production_admission_unavailable")
