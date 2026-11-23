"""Source-only custody primitive for a fresh worker01/#169 generation.

No runtime credential, systemd, Publisher, Signer or GitHub execution path.
The lease deliberately cannot be reconstructed after loss of its controller.
"""

import fcntl
import os
import secrets
import stat
from contextlib import contextmanager

from . import worker_publish_artifact as art
from . import worker_publish_case as case
from . import worker_publish_observer as observer
from . import worker_publish_pre_spend as pre_spend
from . import worker_publish_reconciliation as reconciliation
from . import worker_publish_recovery_paths as recovery

GENERATION = "generation-v4"
SPENT = "create-draft-spent.json"
SIGNER = "signer-claim.json"
PUBLISHER = "publisher-claim.json"
HANDOFF = "signer-handoff.json"
JOB = "generation-job.json"
ARTIFACT = "generation-candidate.json"
CONTINUITY = "spent-continuity.json"
PRE_SPEND = "pre-spend-receipt.json"


class _Lease:
    def __init__(
        self,
        directory,
        approval,
        job_sha256,
        artifact_sha256,
        expires,
        clock,
        continuity,
        pre_spend_receipt,
    ):
        self._directory = directory
        self._approval = approval
        self._job_sha256 = job_sha256
        self._artifact_sha256 = artifact_sha256
        self._expires = expires
        self._clock = clock
        self._phase = "spent"
        self._continuity = continuity
        self._receipt = None
        self._pre_spend_receipt = pre_spend_receipt

    def continuity_challenge(self):
        """Return the exact record an independent witness may acknowledge."""
        art.need(self._continuity is not None and self._phase == "spent")
        art.need(self._clock() < self._expires)
        return art.encoded(self._continuity[0])

    def confirm_continuity(self, signature):
        """Confirm continuity only in the process that received successful fsyncs."""
        phase = self._phase
        self._phase = "stopped"
        art.need(phase == "spent" and self._continuity is not None)
        expected, key, pin = self._continuity
        art.need(self._clock() < self._expires)
        raw = art.encoded(expected)
        art.need(
            observer.verify(key, pin, "spent-continuity", raw, signature) == expected
        )
        self._verify_inputs()
        receipt = art.encoded({"record": expected, "signature": signature.hex()})
        case._create(self._directory, CONTINUITY, receipt)
        self._receipt = receipt
        art.need(self._clock() < self._expires)
        self._phase = "continuity"
        return art.digest(raw)

    def _verify_inputs(self):
        art.need(
            case._read(self._directory, SPENT, reconciliation.RECORD_LIMIT)
            == self._approval
        )
        art.need(
            art.digest(case._read(self._directory, JOB, reconciliation.RECORD_LIMIT))
            == self._job_sha256
        )
        art.need(
            art.digest(case._read(self._directory, ARTIFACT, art.MAX_WIRE))
            == self._artifact_sha256
        )

        if self._pre_spend_receipt is not None:
            art.need(
                case._read(self._directory, PRE_SPEND, reconciliation.RECORD_LIMIT)
                == self._pre_spend_receipt
            )

    def _claim(self, expected, name, record):
        phase = self._phase
        self._phase = "stopped"
        art.need(phase == expected and self._clock() < self._expires)
        self._verify_inputs()
        if self._continuity is not None:
            art.need(self._receipt is not None)
            art.need(
                case._read(self._directory, CONTINUITY, reconciliation.RECORD_LIMIT)
                == self._receipt
            )
        case._create(self._directory, name, art.encoded(record))

    def signer_claim(self, job_sha256):
        if job_sha256 != self._job_sha256:
            self._phase = "stopped"
            raise art.Blocked()
        self._claim(
            "continuity" if self._continuity is not None else "spent",
            SIGNER,
            {"job_sha256": self._job_sha256},
        )
        self._phase = "signer"

    def signer_handoff(self, digest):
        """Bind an opaque result digest. This primitive never accepts JWT bytes."""
        if not observer._sha256(digest):
            self._phase = "stopped"
            raise art.Blocked()
        self._claim(
            "signer", HANDOFF, {"job_sha256": self._job_sha256, "result": digest}
        )
        self._phase = "handoff"

    def publisher_claim(self, job_sha256, result_digest):
        try:
            art.need(job_sha256 == self._job_sha256 and observer._sha256(result_digest))
            expected = art.encoded({"job_sha256": job_sha256, "result": result_digest})
            art.need(
                case._read(self._directory, HANDOFF, reconciliation.RECORD_LIMIT)
                == expected
            )
            self._claim("handoff", PUBLISHER, {"job_sha256": self._job_sha256})
        finally:
            self._phase = "stopped"


@contextmanager
def consume(
    directory,
    *,
    snapshot,
    snapshot_pin,
    object_id,
    archive_pin,
    archive_directory,
    challenge,
    job,
    artifact,
    observer_key,
    observer_pin,
    report,
    report_signature,
    selection,
    selection_signature,
    approval_key,
    approval_pin,
    approval,
    approval_signature,
    clock,
    witness_key=None,
    witness_pin=None,
    reserve_outside_worker=None,
):
    """Consume in a caller-pinned private directory while holding its exclusive lock.

    This is an uninstalled source primitive. The caller must use the fixed
    generation namespace and hold configuration and old-journal locks.
    """
    art.need(os.getuid() == os.geteuid() == 0)
    info = os.fstat(directory)
    art.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
    art.need(info.st_uid == info.st_gid == 0)
    entry = os.stat(GENERATION, dir_fd=archive_directory, follow_symlinks=False)
    art.need(stat.S_ISDIR(entry.st_mode))
    art.need((entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino))
    # Take a separate open file description. Two calls with the same supplied
    # descriptor must still contend, and cannot unlock each other's lease.
    locked = os.open(
        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
    )
    lease = None
    try:
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for filename in (
            SPENT,
            SIGNER,
            PUBLISHER,
            HANDOFF,
            JOB,
            ARTIFACT,
            CONTINUITY,
            PRE_SPEND,
        ):
            case._absent(locked, filename)
        case._confirm(archive_directory, archive_pin)
        intent = art.decode(
            case._read(archive_directory, case.INTENT, reconciliation.RECORD_LIMIT)
        )
        art.need(intent["snapshot"] == snapshot_pin)
        now = clock()
        old, history = reconciliation._history(snapshot, snapshot_pin, object_id, now)
        new, _ = reconciliation._proposed(
            snapshot,
            old,
            job,
            artifact,
            now,
            fresh_generation=True,
        )
        bound = observer.binding(snapshot_pin, job, archive_pin, challenge, now)
        observer.verify_report(
            observer_key,
            observer_pin,
            report,
            report_signature,
            bound=bound,
            selection_bytes=selection,
            selection_signature=selection_signature,
            blob_sha256=history["object_sha256"],
            now=now,
        )
        art.need(approval_pin != observer_pin)
        permission = observer.verify(
            approval_key, approval_pin, "create-draft", approval, approval_signature
        )
        issued, expires = permission["issued"], permission["expires"]
        art.need(type(issued) is type(expires) is int)
        art.need(art.decode(report)["at"] <= issued <= now < expires <= new["expires"])
        art.need(
            permission
            == {
                "schema": "AP-worker01-create-draft/1",
                "binding": bound,
                "report_sha256": art.digest(report),
                "issued": issued,
                "expires": expires,
            }
        )
        continuity = None
        if witness_key is not None or witness_pin is not None:
            art.need(type(witness_key) is bytes and len(witness_key) == 32)
            art.need(
                observer._sha256(witness_pin) and art.digest(witness_key) == witness_pin
            )
            art.need(witness_pin not in (approval_pin, observer_pin))
            continuity = (
                {
                    "schema": "AP-worker01-spent-continuity/1",
                    "case": case.CASE,
                    "generation": recovery.GENERATION,
                    "launch_id": secrets.token_hex(32),
                    "binding": bound,
                    "approval_sha256": art.digest(approval),
                    "approval_signature_sha256": art.digest(approval_signature),
                    "observer_key_sha256": observer_pin,
                    "witness_key_sha256": witness_pin,
                    "report_sha256": art.digest(report),
                    "expires": expires,
                },
                witness_key,
                witness_pin,
            )
        pre_spend_receipt = None
        if reserve_outside_worker is not None:
            art.need(new["ref"] == recovery.REF)
            art.need(continuity is None)
            request = pre_spend.challenge(
                art.digest(approval), secrets.token_hex(32), expires
            )
            raw = art.encoded(request)
            signature = reserve_outside_worker(raw)
            art.need(
                observer.verify(
                    approval_key, approval_pin, pre_spend.PURPOSE, raw, signature
                )
                == request
            )
            art.need(clock() < expires)
            # Archive continuity is independent of the external approval ledger.
            case._confirm(archive_directory, archive_pin)
            pre_spend_receipt = art.encoded(
                {"record": request, "signature": signature.hex()}
            )
            case._create(locked, PRE_SPEND, pre_spend_receipt)
        # Any partial write or lost acknowledgment leaves a blocker. Nothing
        # is handed to a role until all three writes have returned durably.
        case._create(locked, SPENT, approval)
        case._create(locked, JOB, job)
        case._create(locked, ARTIFACT, artifact)
        art.need(clock() < expires)
        lease = _Lease(
            locked,
            approval,
            bound["job"],
            bound["artifact"],
            expires,
            clock,
            continuity,
            pre_spend_receipt,
        )
        yield lease
    finally:
        if lease is not None:
            lease._phase = "stopped"
        os.close(locked)
