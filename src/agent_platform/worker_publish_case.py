"""Root-supervised, create-only evidence custody for the frozen worker01 case."""

import argparse
import fcntl
import os
import stat
import time
from contextlib import ExitStack, contextmanager

from . import worker_publish_artifact as art
from . import worker_publish_reconciliation as reconciliation
from . import worker_publisher as pub
from .worker_publish_io import read_file

CASE_DIRECTORY = "/var/lib/ap-publisher-recovery"
CASE = "worker01/169/v4"
HEAD = "9251405c797bbf48c2ec7bc62b1a9cdd6514353b"
PARENT = "73bb2d521347ec87fb2c584ada8ee86a0ab3eaba"
ARTIFACT = "739de194ef8eb14ba681637c026877add9b369bd8ac6e7d7c71b32491069ced7"
OBJECT = "dfa754b16bb4954371826191227dd3d594f50fcb"
REF = "refs/heads/feature/issue-169-worker01-draft-pilot-v4"
PUBLISHER_LOG = "e7628e3a105c103105b828bc1ce4c5bb81094fbd5471e7c4da2c8dc8fb3e8a6d"
SIGNER_LOG = "5fb0bdba2a9ecafb641856ca2428f81aa29b3e69ba5fd0e83404ffd1b2529bfe"
INTENT = "v4-intent.json"
RESOLUTION = "v4-resolution.json"


@contextmanager
def case_directory():
    parts = CASE_DIRECTORY.split("/")[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            art.need(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
        art.need(stat.S_IMODE(info.st_mode) == 0o700)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        first = os.fstat(fd)
        art.need(
            stat.S_ISREG(first.st_mode)
            and stat.S_IMODE(first.st_mode) == 0o600
            and first.st_uid == first.st_gid == 0
            and first.st_nlink == 1
            and 0 < first.st_size <= limit
        )
        data = bytearray()
        while len(data) < first.st_size:
            chunk = os.read(fd, min(65536, first.st_size - len(data)))
            art.need(chunk)
            data.extend(chunk)

        def identity(info):
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

        art.need(
            identity(first)
            == identity(os.fstat(fd))
            == identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
        )
        return bytes(data)
    finally:
        os.close(fd)


def _create(directory, name, data):
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    try:
        pending = memoryview(data)
        while pending:
            written = os.write(fd, pending)
            art.need(written > 0)
            pending = pending[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    art.need(_read(directory, name, len(data)) == data)
    os.fsync(directory)


def _absent(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise art.Blocked()


def frozen_snapshot(operator, locks):
    # Only the authorized root invocation reaches here. The caller holds
    # the existing config mutex. Both original journals stay read-only locked.
    identities = operator.host_identity()
    original = read_file(pub.JOB_PATH, 0, reconciliation.RECORD_LIMIT)
    job = art.decode(original)
    art.need(all(job[key] == value for key, value in identities.items()))
    art.need(
        job["issue"] == 169
        and job["head"] == HEAD
        and job["parent"] == PARENT
        and job["artifact_sha256"] == ARTIFACT
        and job["ref"] == REF
    )
    artifact = read_file(pub.HOMELAB_ARTIFACT, 0, art.MAX_WIRE)
    art.need(art.digest(artifact) == ARTIFACT)
    records = []
    for role, digest in (("publisher", PUBLISHER_LOG), ("signer", SIGNER_LOG)):
        journal = operator.journal(role, identities)
        locks.callback(journal.close)
        art.need(journal.size <= reconciliation.JOURNAL_LIMIT)
        data = os.pread(journal.fd, journal.size + 1, 0)
        art.need(
            len(data) == journal.size and art.digest(data) == journal.sha256 == digest
        )
        records.append(data)
    _frozen_host(operator, job)
    art.need(read_file(pub.JOB_PATH, 0, reconciliation.RECORD_LIMIT) == original)
    art.need(read_file(pub.HOMELAB_ARTIFACT, 0, art.MAX_WIRE) == artifact)
    return reconciliation.Snapshot(original, artifact, *records)


def _frozen_host(operator, job):
    fields = (
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
        "Job",
        "IPAddressAllow",
    )
    for role, state, substate, result, exit_status in (
        ("publisher", "failed", "failed", "exit-code", "1"),
        ("signer", "inactive", "dead", "success", "0"),
    ):
        output = operator.systemctl(
            "show", "--all", "--property=" + ",".join(fields), operator.unit(role)
        )
        rows = [line.split("=", 1) for line in output.splitlines()]
        actual = dict(rows)
        art.need(len(rows) == len(actual))
        art.need(
            actual
            == {
                "ActiveState": state,
                "SubState": substate,
                "Result": result,
                "ExecMainStatus": exit_status,
                "Job": "",
                "IPAddressAllow": job["github_ipv4"] + "/32"
                if role == "publisher"
                else "",
            }
        )
    # Verify retained JWT metadata only. Never open it or inspect its bytes.
    info = os.lstat(operator.SIGNER_OUTPUT)
    art.need(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == job["signer_uid"]
        and stat.S_IMODE(info.st_mode) == 0o400
        and 0 < info.st_size <= 16384
    )
    art.need(not os.path.lexists(operator.PENDING))


def _inputs(directory, snapshot, pins, now):
    candidate = _read(directory, "proposed-candidate.json", art.MAX_WIRE)
    parts = {
        "original-job.json": snapshot.job,
        "original-candidate.json": snapshot.artifact,
        "original-publisher.jsonl": snapshot.publisher_journal,
        "original-signer.jsonl": snapshot.signer_journal,
        "retained-proposed-candidate.json": candidate,
        "retained-proposed-job.json": _read(directory, "proposed-job.json", 16384),
        "retained-evidence.json": _read(directory, "evidence.json", 16384),
        "retained-decision.json": _read(directory, "decision.json", 16384),
    }
    result = reconciliation.preview(
        snapshot,
        pins=pins,
        object_id=OBJECT,
        proposed_job=parts["retained-proposed-job.json"],
        proposed_artifact=candidate,
        evidence=parts["retained-evidence.json"],
        decision=parts["retained-decision.json"],
        now=now,
    )
    art.need(result["status"] == "PREVIEW_ONLY")
    intent = art.encoded(
        {
            "schema": "PUB-06/intent/1",
            "case": CASE,
            "snapshot": pins.snapshot,
            "evidence": pins.evidence,
            "decision": pins.decision,
            "retained": {name: art.digest(data) for name, data in parts.items()},
        }
    )
    resolution = art.encoded(
        {
            "schema": "PUB-06/resolution/1",
            "case": CASE,
            "intent_sha256": art.digest(intent),
            "admission_allowed": False,
        }
    )
    return parts, intent, resolution


def _record(directory, parts, intent, resolution):
    for name in (INTENT, RESOLUTION, *parts):
        _absent(directory, name)
    _create(directory, INTENT, intent)
    for name, data in parts.items():
        _create(directory, name, data)
    # A continuity pin is returned only after the final fsync and readback.
    _create(directory, RESOLUTION, resolution)
    return art.digest(resolution)


def _confirm(directory, parts, intent, resolution, continuity_pin):
    art.need(type(continuity_pin) is str and continuity_pin == art.digest(resolution))
    art.need(_read(directory, INTENT, 16384) == intent)
    art.need(_read(directory, RESOLUTION, 16384) == resolution)
    for name, data in parts.items():
        art.need(_read(directory, name, len(data)) == data)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"status":"STOP","check":"invalid_arguments"}\n')


def main(argv, operator):
    parser = argparse.ArgumentParser(
        description="Root-only frozen worker01 case custody"
    )
    parser.add_argument("action", choices=("inspect", "preview", "record", "confirm"))
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--evidence-sha256")
    parser.add_argument("--decision-sha256")
    parser.add_argument("--continuity-sha256")
    parser.add_argument("--authorize-record", action="store_true")
    args = parser.parse_args(argv)
    status, check, details = "STOP", "root_required", {}
    try:
        art.need(os.getuid() == os.geteuid() == 0)
        check = "argument_scope"
        art.need(args.authorize_record == (args.action == "record"))
        art.need((args.continuity_sha256 is not None) == (args.action == "confirm"))
        check = "case_lock_or_history"
        with ExitStack() as locks:
            config = operator.exclusive_config()
            locks.callback(os.close, config)
            snapshot = frozen_snapshot(operator, locks)
            now = int(time.time())
            art.need(
                reconciliation.inspect(
                    snapshot,
                    expected_snapshot=args.snapshot_sha256,
                    object_id=OBJECT,
                    now=now,
                )["status"]
                == "HISTORY_VERIFIED"
            )
            status = "HISTORY_VERIFIED"
            if args.action != "inspect":
                status, check = "STOP", "case_inputs_or_continuity"
                directory = locks.enter_context(case_directory())
                pins = reconciliation.PreviewPins(
                    args.snapshot_sha256, args.evidence_sha256, args.decision_sha256
                )
                parts, intent, resolution = _inputs(directory, snapshot, pins, now)
                if args.action == "preview":
                    for name in (INTENT, RESOLUTION, *parts):
                        _absent(directory, name)
                    status = "PREVIEW_ONLY"
                elif args.action == "record":
                    art.need(args.authorize_record)
                    check = "record_requires_reconciliation_on_failure"
                    details["continuity_sha256"] = _record(
                        directory, parts, intent, resolution
                    )
                    status = "RESOLUTION_INTENT_RECORDED"
                else:
                    _confirm(
                        directory, parts, intent, resolution, args.continuity_sha256
                    )
                    status = "RESOLUTION_CONFIRMED"
            check = "production_admission_unavailable"
    except Exception:
        status, details = "STOP", {}
    operator.report(
        status, check=check, admission_allowed=False, publish_allowed=False, **details
    )
    return 1 if status == "STOP" else 0
