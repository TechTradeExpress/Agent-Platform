"""Pinned filesystem and handoff contract for worker01/#169 recovery stage A."""

import os
import stat
from pathlib import Path

from . import worker_publish_artifact as art
from . import worker_publish_case as case
from . import worker_publish_reconciliation as reconciliation
from . import worker_publisher as pub
from .worker_publish_io import Journal, read_file

GENERATION = "worker01/169/v4/recovery-1"
REF = "refs/heads/feature/issue-169-worker01-draft-pilot-recovery"
INPUT = Path("/etc/ap-publisher-recovery-169")
JOB = INPUT / "job.json"
ARTIFACT = INPUT / "candidate.json"
SIGNER_JOURNAL = Path("/var/lib/ap-publisher-recovery-169-signer/journal")
PUBLISHER_JOURNAL = Path("/var/lib/ap-publisher-recovery-169-publisher/journal")
SIGNER_OUTPUT = Path("/run/ap-publisher-recovery-169-signer/app-jwt")
SIGNER_RESULT = SIGNER_OUTPUT.with_name("result.json")
PUBLISHER_RUNTIME = Path("/run/ap-publisher-recovery-169-publisher")
PUBLISHER_CREDENTIALS = Path("/run/credentials/ap-worker-publisher-recovery.service")
PUBLISHER_JWT = PUBLISHER_CREDENTIALS / "app-jwt"
PUBLISHER_RESULT = PUBLISHER_CREDENTIALS / "signer-result"


def check_job(job, old_job, now):
    """Check the fixed subject and freshness. This does not establish authority."""
    pub.validate_job(job, now)
    art.need(pub.homelab(job) and job["issue"] == 169 and job["ref"] == REF)
    for field in ("id", "ref", "head", "artifact_sha256"):
        art.need(job[field] != old_job[field])
    art.need(old_job["head"] == case.HEAD and old_job["ref"] == case.REF)
    art.need(old_job["artifact_sha256"] == case.ARTIFACT)
    art.need(
        all(
            job[key] == old_job[key]
            for key in (
                reconciliation.SUBJECT + reconciliation.APP + reconciliation.ACCOUNTS
            )
        )
    )
    for pin in ("journal_sha256", "signer_journal_sha256"):
        art.need(job[pin] == art.digest(b""))
    return job


def read_inputs(old_job, now):
    original = read_file(str(JOB), 0, 16384)
    job = check_job(art.decode(original), old_job, now)
    art.need(art.encoded(job) == original)
    artifact = read_file(str(ARTIFACT), 0, art.MAX_WIRE)
    art.need(art.digest(artifact) == job["artifact_sha256"])
    art.validate(artifact, job["head"], job["tree"], job["parent"])
    return original, artifact


def signer_payload(job_bytes, jwt):
    """Produce opaque handoff bytes, with no authority to issue an App JWT."""
    art.need(type(jwt) is str and 0 < len(jwt) <= 8192 and jwt.isascii())
    job = art.decode(job_bytes)
    jwt_bytes = art.encoded(
        {"generation": GENERATION, "job_sha256": art.digest(job_bytes), "jwt": jwt}
    )
    result = art.encoded(
        {
            "schema": "AP-worker01-recovery-signer-result/1",
            "generation": GENERATION,
            "id": job["id"],
            "job_sha256": art.digest(job_bytes),
            "artifact_sha256": job["artifact_sha256"],
            "jwt_sha256": art.digest(jwt_bytes),
        }
    )
    return jwt_bytes, result


def write_signer_handoff(job_bytes, jwt):
    """Commit the two envelopes without replacing any partial result."""
    jwt_bytes, result = signer_payload(job_bytes, jwt)
    directory = os.open(
        SIGNER_OUTPUT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        info = os.fstat(directory)
        art.need(info.st_uid == os.getuid() and info.st_gid == os.getgid())
        art.need(stat.S_IMODE(info.st_mode) == 0o700)
        for leaf in (SIGNER_OUTPUT.name, SIGNER_RESULT.name):
            try:
                os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise art.Blocked()
        for leaf, value in (
            (SIGNER_OUTPUT.name, jwt_bytes),
            (SIGNER_RESULT.name, result),
        ):
            fd = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
                dir_fd=directory,
            )
            try:
                art.need(os.write(fd, value) == len(value))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
    finally:
        os.close(directory)


def read_handoff(job_bytes):
    """Verify both systemd credential copies. Sender authorization is stage B."""
    jwt = read_file(str(PUBLISHER_JWT), os.getuid(), 16384, credential=True)
    result = read_file(str(PUBLISHER_RESULT), os.getuid(), 16384, credential=True)
    return verify_handoff(job_bytes, jwt, result)


def verify_handoff(job_bytes, jwt, result):
    value = art.decode(jwt)["jwt"]
    art.need((jwt, result) == signer_payload(job_bytes, value))
    return value


def stop(role):
    art.need(role in ("signer", "publisher"))
    # No stage A production path reads data, loads credentials or opens journals.
    print('{"status":"BLOCKED","code":"recovery_authorization_unavailable"}')
    return 1


def verify_signer_journal(job_bytes, launch_id, jwt, result, journal):
    """Require an exact launch-bound, hash-chained terminal Signer history."""
    job = reconciliation._canonical(job_bytes)
    verify_handoff(job_bytes, jwt, result)
    art.need(type(journal) is bytes and 0 < len(journal) <= 16384)
    records, _ = reconciliation._chain(journal, 3)
    operation = {"job": job["id"], "operation": "sign", "launch_id": launch_id}
    subject = {
        "job": job["id"],
        "ref": job["ref"],
        "issue": job["issue"],
        "head": job["head"],
    }
    art.need(
        records
        == [
            {"phase": "CLAIM", **subject},
            {"phase": "UNKNOWN", **operation},
            {
                "phase": "COMPLETE",
                **subject,
                **operation,
                "jwt_sha256": art.digest(jwt),
                "result_sha256": art.digest(result),
            },
        ]
    )


def inspect_signer_handoff(job_bytes, launch_id, journal_identity):
    """Read retained results as root under the Signer journal's flock."""
    job = reconciliation._canonical(job_bytes)
    signer = Journal(str(SIGNER_JOURNAL), None, inspect_owner=job["signer_uid"])
    try:
        art.need(signer.identity == journal_identity)
        art.need(0 < signer.size <= 16384)

        def identity(path):
            info = path.lstat()
            art.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            art.need(info.st_uid == job["signer_uid"])
            art.need(info.st_gid == job["signer_gid"])
            art.need(stat.S_IMODE(info.st_mode) == 0o400)
            return info

        before = [identity(path) for path in (SIGNER_OUTPUT, SIGNER_RESULT)]
        jwt, result = [
            read_file(
                str(path),
                job["signer_uid"],
                16384,
                writable_parent=True,
                private=True,
            )
            for path in (SIGNER_OUTPUT, SIGNER_RESULT)
        ]
        journal = os.pread(signer.fd, signer.size + 1, 0)
        art.need(len(journal) == signer.size and art.digest(journal) == signer.sha256)
        verify_signer_journal(job_bytes, launch_id, jwt, result, journal)
        after = [identity(path) for path in (SIGNER_OUTPUT, SIGNER_RESULT)]
        for first, last in zip(before, after, strict=True):
            art.need(
                os.path.samestat(first, last)
                and first.st_size == last.st_size
                and first.st_mtime_ns == last.st_mtime_ns
                and first.st_ctime_ns == last.st_ctime_ns
            )
        current = SIGNER_JOURNAL.lstat()
        art.need((current.st_dev, current.st_ino) == journal_identity)
        art.need(current.st_size == signer.size and current.st_nlink == 1)
        return jwt, result, journal
    finally:
        signer.close()


def verify_grant(
    role,
    raw,
    signature,
    *,
    public_key,
    key_pin,
    job_bytes,
    artifact,
    approval,
    pre_spend_receipt,
    observation,
    launch_id,
    now,
    handoff=None,
):
    """Verify bound role authority against independently obtained exact inputs.

    Callers supply the pinned key and evidence from trusted sources. This
    verifier performs no journal claim, unit launch or credential release.
    """
    from . import worker_publish_observer as observer

    art.need(role in ("signer", "publisher"))
    value = observer.verify(public_key, key_pin, "recovery-" + role, raw, signature)
    job = reconciliation._canonical(job_bytes)
    pub.validate_job(job, now)
    art.need(pub.homelab(job) and job["issue"] == 169 and job["ref"] == REF)
    art.need(job["head"] != case.HEAD and job["artifact_sha256"] != case.ARTIFACT)
    art.need(type(artifact) is bytes and art.digest(artifact) == job["artifact_sha256"])
    expires = value.get("expires")
    decision = reconciliation._canonical(approval)
    receipt = reconciliation._canonical(pre_spend_receipt)
    receipt_record = receipt["record"]
    art.need(set(receipt) == {"record", "signature"})
    art.need(type(receipt_record) is dict and observer._sha256(launch_id))
    art.need(type(receipt["signature"]) is str and len(receipt["signature"]) == 128)
    verified_receipt = observer.verify(
        public_key,
        key_pin,
        "pre-spend",
        art.encoded(receipt_record),
        bytes.fromhex(receipt["signature"]),
    )
    art.need(
        verified_receipt
        == {
            "schema": "AP-worker01-pre-spend/1",
            "generation": GENERATION,
            "case": case.CASE,
            "launch_id": launch_id,
            "approval_sha256": art.digest(approval),
            "expires": decision["expires"],
        }
    )
    bound = decision["binding"]
    art.need(
        decision["schema"] == "AP-worker01-create-draft/1"
        and decision["report_sha256"] == art.digest(observation)
        and bound["job"] == art.digest(job_bytes)
        and bound["artifact"] == job["artifact_sha256"]
        and bound["main"] == job["parent"]
    )
    art.need(
        type(expires) is int
        and now < expires <= min(job["expires"], decision["expires"])
    )
    expected = {
        "schema": "AP-worker01-recovery-grant/1",
        "case": case.CASE,
        "generation": GENERATION,
        "role": role,
        "audience": "ap-worker-publisher-recovery"
        + ("-signer" if role == "signer" else "")
        + ".service",
        "launch_id": launch_id,
        "job_sha256": art.digest(job_bytes),
        "artifact_sha256": job["artifact_sha256"],
        "approval_sha256": art.digest(approval),
        "pre_spend_sha256": art.digest(pre_spend_receipt),
        "observation_sha256": art.digest(observation),
        "main": job["parent"],
        "expires": expires,
    }
    if role == "publisher":
        art.need(type(handoff) is tuple and len(handoff) == 3)
        jwt, result, journal = handoff
        expected["signer_result_sha256"] = art.digest(result)
        expected["signer_journal_sha256"] = art.digest(journal)
    else:
        art.need(handoff is None)
    art.need(value == expected)
    if role == "publisher":
        verify_signer_journal(job_bytes, launch_id, jwt, result, journal)
    return job
