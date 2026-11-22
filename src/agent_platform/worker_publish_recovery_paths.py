"""Pinned filesystem and handoff contract for worker01/#169 recovery stage A."""

import os
import stat
from pathlib import Path

from . import worker_publish_artifact as art
from . import worker_publish_case as case
from . import worker_publish_reconciliation as reconciliation
from . import worker_publisher as pub
from .worker_publish_io import read_file

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
