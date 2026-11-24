"""Operator-supervised custody and handoff for a fresh worker01/#169 generation.

A default handoff stays offline. The live role requires distinct signed
approval and policy evidence. A lost controller lease is never reconstructed.
"""

import fcntl
import os
import secrets
import stat
from contextlib import contextmanager

from . import worker_publish_artifact as art
from . import worker_publish_case as case
from . import worker_publish_observer as observer
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
    prepare_delivery=None,
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
            request = recovery.pre_spend_challenge(
                art.digest(approval), secrets.token_hex(32), expires
            )
            raw = art.encoded(request)
            if prepare_delivery is not None:
                prepare_delivery(new)
            art.need(clock() < expires)
            signature = reserve_outside_worker(raw)
            art.need(
                observer.verify(
                    approval_key,
                    approval_pin,
                    recovery.PRE_SPEND_PURPOSE,
                    raw,
                    signature,
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


def dispatch(
    lease,
    *,
    directory,
    job,
    artifact,
    observation,
    approval_key,
    approval_pin,
    sign,
    start,
    policy=None,
    preflight=None,
    artifact_identity,
):
    """Use the live lease for two create-only systemd credential sources.

    Sign is an operator-controlled exchange with the pinned approval key.
    Start synchronously starts the exact unit and returns only on success.
    """
    art.need(os.getuid() == os.geteuid() == 0)
    art.need(lease._pre_spend_receipt is not None)
    info = os.fstat(directory)
    art.need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
    art.need(info.st_uid == info.st_gid == 0)
    pinned = os.stat(recovery.GRANT_DIRECTORY, follow_symlinks=False)
    art.need(os.path.samestat(info, pinned))
    lease._verify_inputs()
    receipt = reconciliation._canonical(lease._pre_spend_receipt)
    launch_id = receipt["record"]["launch_id"]
    job_sha256 = art.digest(job)
    task = reconciliation._canonical(job)
    recovery.check_delivery_bounds(
        job, artifact, observation, approval_key, lease._approval, policy
    )
    art.need(recovery.read_role_artifact(task, artifact_identity) == artifact)
    if policy is not None:
        observer_key, observer_pin, policy_raw, policy_signature = policy
        art.need(observer_pin != approval_pin)
        verified_policy = recovery.verify_policy(
            job,
            observation,
            observer_key,
            observer_pin,
            policy_raw,
            policy_signature,
            lease._clock(),
        )
        art.need(lease._expires <= verified_policy["expires"])
        publisher_store = recovery.Journal(
            str(recovery.PUBLISHER_JOURNAL),
            task["journal_sha256"],
            inspect_owner=task["publisher_uid"],
        )
        try:
            publisher_identity = publisher_store.identity
            art.need(not publisher_store.events)
        finally:
            publisher_store.close()
    signer_store = recovery.Journal(
        str(recovery.SIGNER_JOURNAL),
        task["signer_journal_sha256"],
        inspect_owner=task["signer_uid"],
    )
    identity = signer_store.identity
    signer_store.close()

    def stage(role, handoff=None):
        unit = recovery.role_unit(role)
        fields = {
            "schema": "AP-worker01-recovery-grant/1",
            "case": case.CASE,
            "generation": recovery.GENERATION,
            "role": role,
            "audience": unit,
            "launch_id": launch_id,
            "job_sha256": job_sha256,
            "artifact_sha256": task["artifact_sha256"],
            "artifact_identity": artifact_identity,
            "approval_sha256": art.digest(lease._approval),
            "pre_spend_sha256": art.digest(lease._pre_spend_receipt),
            "observation_sha256": art.digest(observation),
            "main": task["parent"],
            "expires": lease._expires,
        }
        copies = {}
        if handoff is not None:
            copies = dict(
                zip(("jwt", "result", "signer_journal"), handoff, strict=True)
            )
            fields["signer_result_sha256"] = art.digest(copies["result"])
            fields["signer_journal_sha256"] = art.digest(copies["signer_journal"])
        live = role == "publisher" and policy is not None
        if live:
            unit = recovery.LIVE_UNIT
            fields.update(audience=unit, live=recovery.live_binding(task, policy_raw))
            copies.update(
                observer_key=observer_key,
                policy=policy_raw,
                policy_signature=policy_signature,
            )
        grant = art.encoded(fields)
        signature = sign("publisher-live" if live else role, grant)
        recovery.verify_grant(
            role,
            grant,
            signature,
            public_key=approval_key,
            key_pin=approval_pin,
            job_bytes=job,
            artifact=artifact,
            approval=lease._approval,
            pre_spend_receipt=lease._pre_spend_receipt,
            observation=observation,
            launch_id=launch_id,
            now=lease._clock(),
            handoff=handoff,
            policy=policy if live else None,
            artifact_identity=artifact_identity,
        )
        evidence = dict(
            grant=grant,
            signature=signature,
            public_key=approval_key,
            job=job,
            spent=lease._approval,
            pre_spend_receipt=lease._pre_spend_receipt,
            observation=observation,
            **copies,
        )
        payload = recovery.credential_packet(launch_id, evidence)
        case._create(directory, role + ".json", payload)
        art.need(lease._clock() < lease._expires)
        if not live:
            start(unit)
            return None
        art.need(preflight is not None)
        preflight()
        art.need(lease._clock() < lease._expires)
        try:
            exit_status = start(unit)
            journal = recovery.Journal(
                str(recovery.PUBLISHER_JOURNAL),
                None,
                inspect_owner=task["publisher_uid"],
            )
            try:
                art.need(journal.identity == publisher_identity)
                raw = os.pread(journal.fd, journal.size + 1, 0)
                art.need(len(raw) == journal.size and art.digest(raw) == journal.sha256)
                art.need(
                    raw
                    == b"".join(art.encoded(event) + b"\n" for event in journal.events)
                )
                return recovery.live_outcome(task, journal.events, exit_status)
            finally:
                journal.close()
        except Exception:
            # The unit start or the terminal readback may have taken effect.
            return {"status": "UNKNOWN"}

    live = os.open(
        recovery.LIVE_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
    )
    try:
        os.fchmod(live, 0o644)
        art.need(os.write(live, launch_id.encode("ascii")) == 64)
        fcntl.lockf(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease.signer_claim(job_sha256)
        stage("signer")
        handoff = recovery.inspect_signer_handoff(job, launch_id, identity)
        result_digest = art.digest(handoff[1])
        lease.signer_handoff(result_digest)
        lease.publisher_claim(job_sha256, result_digest)
        return stage("publisher", handoff)
    finally:
        os.close(live)


def operator_main(argv, operator):
    """One foreground root invocation. Only nonsecret signing requests cross stdio."""
    import argparse
    import select
    import time
    from contextlib import ExitStack

    from .worker_publish_io import read_file

    parser = argparse.ArgumentParser(description=operator_main.__doc__)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--continuity-sha256", required=True)
    parser.add_argument("--request-live", action="store_true")
    args = parser.parse_args(argv)

    def exchange(purpose, raw):
        print(
            art.encoded({"purpose": purpose, "request": art.decode(raw)}).decode(),
            flush=True,
        )
        deadline = time.monotonic() + 30
        response = bytearray()
        while len(response) < 129:
            remaining = deadline - time.monotonic()
            art.need(remaining > 0 and select.select([0], [], [], remaining)[0])
            part = os.read(0, 1)
            art.need(part)
            response += part
            if part == b"\n":
                break
        art.need(len(response) == 129 and response[-1:] == b"\n")
        signature = bytes.fromhex(response[:-1].decode("ascii"))
        art.need(signature.hex().encode("ascii") == response[:-1])
        return signature

    def start(unit):
        if unit == recovery.LIVE_UNIT:
            operator.systemctl("start", unit, timeout=320)
            return recovery.live_exit_status(operator.systemctl)
        directory = "/usr/lib/systemd/system/"
        output = operator.systemctl(
            "show",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--property=NeedDaemonReload",
            unit,
        ).splitlines()
        art.need(
            len(output) == 3
            and set(output)
            == {
                "FragmentPath=" + directory + unit,
                "DropInPaths=",
                "NeedDaemonReload=no",
            }
        )
        operator.systemctl("start", unit, timeout=25)

    try:
        art.need(os.getuid() == os.geteuid() == 0)
        with ExitStack() as locks:
            locks.callback(os.close, operator.exclusive_config())
            snapshot = case.frozen_snapshot(operator, locks)
            archive = locks.enter_context(case.case_directory())
            generation = os.open(
                GENERATION,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=archive,
            )
            locks.callback(os.close, generation)
            staging = os.open(
                recovery.GRANT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            locks.callback(os.close, staging)

            def record(name, limit=reconciliation.RECORD_LIMIT):
                return case._read(archive, name, limit)

            job = record("proposed-job.json")
            artifact = record("proposed-candidate.json", art.MAX_WIRE)
            observation = record("observer-report.json")
            approval_key = record("approval-public-key", 32)
            approval_pin = read_file(
                str(recovery.INPUT / "approval-pin"), 0, 64, private=True
            ).decode("ascii")
            observer_pin = read_file(
                "/etc/ap-publisher/observer-trust/key-pin", 0, 64, private=True
            ).decode("ascii")
            challenge = read_file(
                "/etc/ap-publisher/observer-trust/challenge", 0, 64, private=True
            ).decode("ascii")
            observer_key = record("observer-public-key", 32)
            policy = None
            preflight = None
            approval = record("create-draft-approval.json")
            if args.request_live:
                policy = (
                    observer_key,
                    observer_pin,
                    record("live-egress-policy.json"),
                    record("live-egress-policy.sig", 64),
                )
                verified_policy = recovery.verify_policy(
                    job, observation, *policy, int(time.time())
                )
                task = reconciliation._canonical(job)
                art.need(
                    reconciliation._canonical(approval)["expires"]
                    <= verified_policy["expires"]
                )

                def preflight():
                    recovery.check_live_unit(operator, verified_policy, task)

                preflight()
            recovery.check_delivery_bounds(
                job, artifact, observation, approval_key, approval, policy
            )
            artifact_identity = None

            def prepare_delivery(task):
                nonlocal artifact_identity
                artifact_identity = recovery.stage_artifact(task, artifact)

            with consume(
                generation,
                snapshot=snapshot,
                snapshot_pin=args.snapshot_sha256,
                object_id=case.OBJECT,
                archive_pin=args.continuity_sha256,
                archive_directory=archive,
                challenge=challenge,
                job=job,
                artifact=artifact,
                observer_key=observer_key,
                observer_pin=observer_pin,
                report=observation,
                report_signature=record("observer-report.sig", 64),
                selection=record("observer-selection.json"),
                selection_signature=record("observer-selection.sig", 64),
                approval_key=approval_key,
                approval_pin=approval_pin,
                approval=approval,
                approval_signature=record("create-draft-approval.sig", 64),
                clock=lambda: int(time.time()),
                reserve_outside_worker=lambda raw: exchange("pre-spend", raw),
                prepare_delivery=prepare_delivery,
            ) as lease:
                outcome = dispatch(
                    lease,
                    directory=staging,
                    job=job,
                    artifact=artifact,
                    observation=observation,
                    approval_key=approval_key,
                    approval_pin=approval_pin,
                    start=start,
                    sign=lambda role, raw: exchange("recovery-" + role, raw),
                    policy=policy,
                    preflight=preflight,
                    artifact_identity=artifact_identity,
                )
        if outcome is None:
            operator.report(
                "HANDOFF_VERIFIED", publication="DISABLED", publish_allowed=False
            )
            return 0
        status = outcome.pop("status")
        operator.report(status, publish_allowed=False, **outcome)
        return int(status != "DRAFT_VERIFIED")
    except Exception:
        operator.report("STOP", check="recovery_handoff", publish_allowed=False)
        return 1
