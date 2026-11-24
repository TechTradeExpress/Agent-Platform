"""Pinned filesystem and handoff contract for worker01/#169 recovery stage A."""

import fcntl
import os
import re
import stat
import struct
import time
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
LIVE_UNIT = "ap-worker-publisher-recovery-live.service"
LIVE_NAMESPACE = "/run/netns/ap-worker-publisher-recovery-live"
LIVE_PURPOSE = "recovery-publisher-live"
POLICY_PURPOSE = "recovery-egress-policy"
POLICY_PIN = "/etc/ap-publisher/observer-trust/key-pin"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"


def verify_policy(job_bytes, observation, key, pin, raw, signature, now):
    """Verify an independent, short-lived observation of kernel and PID 1 policy."""
    from . import worker_publish_observer as observer

    job = reconciliation._canonical(job_bytes)
    value = observer.verify(key, pin, POLICY_PURPOSE, raw, signature)
    at, expires = value["at"], value["expires"]
    art.need(type(at) is type(expires) is int)
    art.need(0 <= now - at < observer.WINDOW and now < expires <= at + observer.WINDOW)
    for field in ("netns_device", "netns_inode"):
        art.need(type(value[field]) is int and 0 < value[field] < 2**64)
    art.need(pub.homelab(job) and job["ref"] == REF and job["operation"] == "create")
    for field in ("pid1_sha256", "kernel_evidence_sha256"):
        art.need(observer._sha256(value[field]))
    art.need(
        type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        )
    )
    art.need(
        value
        == {
            "schema": "AP-worker01-recovery-egress/1",
            "unit": LIVE_UNIT,
            "generation": GENERATION,
            "job_sha256": art.digest(job_bytes),
            "observation_sha256": art.digest(observation),
            "github_ipv4": job["github_ipv4"],
            "port": 443,
            "transport": "tcp/ipv4",
            "signer_network": "denied",
            "boot_id": value["boot_id"],
            "netns_device": value["netns_device"],
            "netns_inode": value["netns_inode"],
            "pid1_sha256": value["pid1_sha256"],
            "kernel_evidence_sha256": value["kernel_evidence_sha256"],
            "at": at,
            "expires": expires,
        }
    )
    return value


def live_binding(job, policy_raw):
    art.need(job["operation"] == "create" and job["old"] == "ABSENT")
    return {
        "purpose": "create-draft-live",
        "policy_sha256": art.digest(policy_raw),
        "head": job["head"],
        "ref": job["ref"],
        "app": job["app_id"],
        "installation": job["installation_id"],
        "github_ipv4": job["github_ipv4"],
    }


def boot_id():
    with open(BOOT_ID_PATH, encoding="ascii") as stream:
        return stream.read(64).strip()


def check_live_namespace(policy, path, current_boot):
    art.need(current_boot == policy["boot_id"])
    namespace = os.stat(path)
    art.need(
        (namespace.st_dev, namespace.st_ino)
        == (policy["netns_device"], policy["netns_inode"])
    )


def _show(systemctl, unit, fields):
    output = systemctl("show", "--all", "--property=" + ",".join(fields), unit)
    rows = [line.split("=", 1) for line in output.splitlines()]
    art.need(len(rows) == len(fields) and all(len(row) == 2 for row in rows))
    values = dict(rows)
    art.need(set(values) == set(fields))
    return values


def check_live_unit(operator, policy, job):
    """Check PID 1's loaded values; the port restriction requires kernel evidence."""
    systemctl = operator.systemctl
    check_live_namespace(policy, LIVE_NAMESPACE, boot_id())
    host_namespace = os.stat("/proc/self/ns/net")
    art.need(host_namespace.st_dev == policy["netns_device"])
    art.need(host_namespace.st_ino != policy["netns_inode"])
    expected = {
        "Id": LIVE_UNIT,
        "LoadState": "loaded",
        "UnitFileState": "static",
        "FragmentPath": "/etc/systemd/system/" + LIVE_UNIT,
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "PrivateNetwork": "no",
        "NetworkNamespacePath": LIVE_NAMESPACE,
        "RestrictAddressFamilies": "AF_INET",
        "IPAddressAllow": job["github_ipv4"] + "/32",
        "IPAddressDeny": "0.0.0.0/0 ::/0",
        "AppArmorProfile": "ap-worker-publisher-recovery-live",
        "User": "ap-publisher",
        "Group": "ap-publisher",
        "Restart": "no",
        "Type": "oneshot",
        "NoNewPrivileges": "yes",
        "JoinsNamespaceOf": "",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateDevices": "yes",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "RestrictNamespaces": "yes",
        "SocketBindDeny": "any",
    }
    values = _show(systemctl, LIVE_UNIT, expected)
    art.need(set(values["IPAddressDeny"].split()) == {"0.0.0.0/0", "::/0"})
    art.need(
        all(
            values[key] == value
            for key, value in expected.items()
            if key != "IPAddressDeny"
        )
    )
    art.need(art.digest(art.encoded(values)) == policy["pid1_sha256"])
    executable = "/usr/libexec/" + LIVE_UNIT.removesuffix(".service")
    operator.verify_exec(
        LIVE_UNIT,
        executable,
        [executable],
        {
            "LoadCredential": (
                "a(ss)",
                [
                    ["handoff", GRANT_DIRECTORY + "/publisher.json"],
                    ["approval-pin", str(INPUT / "approval-pin")],
                    ["observer-pin", POLICY_PIN],
                    ["boot-id", BOOT_ID_PATH],
                ],
            ),
            "LoadCredentialEncrypted": ("a(ss)", []),
            "ImportCredentialEx": ("a(ss)", []),
            "SocketBindAllow": ("a(iiqq)", []),
            "SupplementaryGroups": ("as", []),
            "ReadWritePaths": ("as", [str(PUBLISHER_JOURNAL)]),
            "BindPaths": ("a(ssbt)", []),
            "BindReadOnlyPaths": ("a(ssbt)", []),
        },
    )
    signer = role_unit("signer")
    signer_expected = {
        "Id": signer,
        "LoadState": "loaded",
        "FragmentPath": "/usr/lib/systemd/system/" + signer,
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "PrivateNetwork": "yes",
        "RestrictAddressFamilies": "AF_UNIX",
        "IPAddressDeny": "0.0.0.0/0 ::/0",
        "IPAddressAllow": "",
        "NetworkNamespacePath": "",
        "AppArmorProfile": "ap-worker-publisher-recovery-signer",
        "Restart": "no",
    }
    signer_values = _show(systemctl, signer, signer_expected)
    art.need(set(signer_values.pop("IPAddressDeny").split()) == {"0.0.0.0/0", "::/0"})
    del signer_expected["IPAddressDeny"]
    art.need(signer_values == signer_expected)
    state = _show(systemctl, LIVE_UNIT, ("ActiveState", "SubState", "Job"))
    art.need(state == {"ActiveState": "inactive", "SubState": "dead", "Job": ""})


def live_exit_status(systemctl):
    values = _show(
        systemctl, LIVE_UNIT, ("ActiveState", "SubState", "Result", "ExecMainStatus")
    )
    code = values.pop("ExecMainStatus")
    art.need(
        values == {"ActiveState": "inactive", "SubState": "dead", "Result": "success"}
    )
    art.need(code in ("0", "2"))
    return int(code)


def live_outcome(job, events, exit_status):
    if exit_status == 2 and not events:
        return {"status": "STOP"}
    art.need(exit_status == 0 and len(events) >= 8)
    records = [event["record"] for event in events]
    subject = {key: job[key] for key in ("ref", "issue", "head")}
    art.need(records[0] == {"phase": "CLAIM", "job": job["id"], **subject})
    terminal = records[-1]
    pr = terminal.get("pr")
    art.need(type(pr) is int and 0 < pr < 2**31)
    art.need(terminal == {"phase": "COMPLETE", "job": job["id"], "pr": pr, **subject})
    effects = records[1:-1]
    art.need(len(effects) % 2 == 0)
    operations = []
    for unknown, confirmed in zip(effects[::2], effects[1::2], strict=True):
        operation = unknown["operation"]
        operations.append(operation)
        for expected_phase, record in (("UNKNOWN", unknown), ("CONFIRMED", confirmed)):
            art.need(
                record
                == {
                    "phase": expected_phase,
                    "job": job["id"],
                    "operation": operation,
                    "digest": record["digest"],
                }
            )
    art.need(
        operations
        == ["mint", *(["object"] * (len(operations) - 4)), "ref", "draft", "revoke"]
    )
    art.need(effects[-3]["digest"] == art.digest(art.encoded(pr)))
    return {"status": "DRAFT_VERIFIED", "pr": pr, "head": job["head"]}


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
    policy=None,
):
    """Verify bound role authority against independently obtained exact inputs.

    Callers supply the pinned key and evidence from trusted sources. This
    verifier performs no journal claim, unit launch or credential release.
    """
    from . import worker_publish_observer as observer

    art.need(role in ("signer", "publisher"))
    if policy is not None:
        art.need(role == "publisher")
    purpose = LIVE_PURPOSE if policy is not None else "recovery-" + role
    value = observer.verify(public_key, key_pin, purpose, raw, signature)
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
    if policy is not None:
        observer_key, observer_pin, policy_raw, policy_signature = policy
        art.need(observer_pin != key_pin)
        evidence = verify_policy(
            job_bytes,
            observation,
            observer_key,
            observer_pin,
            policy_raw,
            policy_signature,
            now,
        )
        art.need(expires <= evidence["expires"])
        expected.update(audience=LIVE_UNIT, live=live_binding(job, policy_raw))
    art.need(value == expected)
    if role == "publisher":
        verify_signer_journal(job_bytes, launch_id, jwt, result, journal)
    return job


# One bounded credential from the root operator. The artifact is embedded for
# this pilot so the unit never opens a separately writable input path.
CREDENTIAL_LIMIT = 512 * 1024
GRANT_DIRECTORY = "/run/ap-publisher-recovery-169-grants"
LIVE_PATH = "/run/ap-publisher-recovery-169-live"
# Linux amd64 struct flock. The Debian package and this pilot are amd64.
_FLOCK = struct.Struct("@hhqqi4x")


def require_live_controller(launch_id):
    art.need(os.uname().machine == "x86_64")
    raw = read_file(LIVE_PATH, 0, 64)
    art.need(raw == launch_id.encode("ascii"))
    fd = os.open(LIVE_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        art.need(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
        art.need(metadata.st_uid == metadata.st_gid == 0)
        art.need(stat.S_IMODE(metadata.st_mode) == 0o644)
        art.need(os.pread(fd, 65, 0) == raw)
        request = _FLOCK.pack(fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        status = fcntl.fcntl(fd, fcntl.F_GETLK, request)
        kind, _, _, _, owner = _FLOCK.unpack(status)
        art.need(kind == fcntl.F_WRLCK and owner > 0)
        art.need(os.path.samestat(metadata, os.stat(LIVE_PATH, follow_symlinks=False)))
    finally:
        os.close(fd)


PRE_SPEND_PURPOSE = "pre-spend"


def pre_spend_challenge(approval_sha256, launch_id, expires):
    from . import worker_publish_observer as observer

    art.need(observer._sha256(approval_sha256) and observer._sha256(launch_id))
    art.need(type(expires) is int)
    return {
        "schema": "AP-worker01-pre-spend/1",
        "case": case.CASE,
        "generation": GENERATION,
        "approval_sha256": approval_sha256,
        "launch_id": launch_id,
        "expires": expires,
    }


def role_unit(role):
    art.need(role in ("signer", "publisher"))
    return (
        "ap-worker-publisher-recovery"
        + ("-signer" if role == "signer" else "")
        + ".service"
    )


def read_role_credential(role, leaf, limit, *, live=False):
    art.need(role in ("signer", "publisher"))
    allowed = {"handoff", "approval-pin"}
    if role == "signer":
        allowed.add("app-key")
    if live:
        art.need(role == "publisher")
        allowed.update(("observer-pin", "boot-id"))
    art.need(leaf in allowed)
    directory = f"/run/credentials/{LIVE_UNIT if live else role_unit(role)}"
    art.need(os.environ.get("CREDENTIALS_DIRECTORY") == directory)
    return read_file(directory + "/" + leaf, os.getuid(), limit, credential=True)


def receive(role, now, *, live=False):
    import base64

    def credential(leaf, limit):
        if live:
            return read_role_credential(role, leaf, limit, live=True)
        return read_role_credential(role, leaf, limit)

    raw = credential("handoff", CREDENTIAL_LIMIT)
    data = art.decode(raw)
    art.need(type(data) is dict and art.encoded(data) == raw)
    fields = {
        "grant",
        "signature",
        "public_key",
        "job",
        "artifact",
        "spent",
        "pre_spend_receipt",
        "observation",
        "launch_id",
    }
    if role == "publisher":
        fields |= {"jwt", "result", "signer_journal"}
    if live:
        art.need(role == "publisher")
        fields |= {"observer_key", "policy", "policy_signature"}
    art.need(set(data) == fields)
    launch_id = data.pop("launch_id")
    parts = {
        name: base64.b64decode(value, validate=True) for name, value in data.items()
    }
    handoff = None
    if role == "publisher":
        handoff = tuple(parts[name] for name in ("jwt", "result", "signer_journal"))
    pin = credential("approval-pin", 64).decode("ascii")
    policy = None
    if live:
        policy = (
            parts["observer_key"],
            credential("observer-pin", 64).decode("ascii"),
            parts["policy"],
            parts["policy_signature"],
        )
    job = verify_grant(
        role,
        parts["grant"],
        parts["signature"],
        public_key=parts["public_key"],
        key_pin=pin,
        job_bytes=parts["job"],
        artifact=parts["artifact"],
        approval=parts["spent"],
        pre_spend_receipt=parts["pre_spend_receipt"],
        observation=parts["observation"],
        launch_id=launch_id,
        now=now,
        handoff=handoff,
        policy=policy,
    )
    art.validate(parts["artifact"], job["head"], job["tree"], job["parent"])
    decision = reconciliation._canonical(parts["grant"])
    art.need(int(time.time()) < decision["expires"])
    if live:
        pub.confinement(job, role, recovery=True, live=True)
        check_live_namespace(
            art.decode(parts["policy"]),
            "/proc/self/ns/net",
            credential("boot-id", 64).decode("ascii").strip(),
        )
    else:
        pub.confinement(job, role, recovery=True)
    require_live_controller(launch_id)
    return job, launch_id, parts


def run_publisher_handoff(*, transport_factory=None, live=False):
    """Keep injected fixture I/O disjoint from the authenticated live role."""
    art.need(not live or transport_factory is None)
    journal = None
    try:
        if live:
            job, launch_id, parts = receive("publisher", int(time.time()), live=True)
        else:
            job, launch_id, parts = receive("publisher", int(time.time()))
        journal = Journal(str(PUBLISHER_JOURNAL), job["journal_sha256"])
        art.need(not journal.events)
        if not live and transport_factory is None:
            journal.claim(job)
            journal.append(
                {"phase": "HANDOFF_VERIFIED", "job": job["id"], "launch_id": launch_id}
            )
            print('{"status":"HANDOFF_VERIFIED","publication":"DISABLED"}')
        else:
            expires = reconciliation._canonical(parts["grant"])["expires"]

            def authorize():
                art.need(int(time.time()) < expires)
                require_live_controller(launch_id)

            authorize()
            artifact = parts["artifact"]
            objects, _, _, _ = art.validate(
                artifact, job["head"], job["tree"], job["parent"]
            )
            jwt = verify_handoff(parts["job"], parts["jwt"], parts["result"])
            if live:
                wire = pub.transport(job, before_request=authorize)
            else:
                wire = transport_factory(journal, job, jwt)
            client = pub.Client(job, objects, wire)
            result = pub.publish(
                job, artifact, jwt, journal, client, authorize, before_effect=authorize
            )
            if live:
                art.need(result["status"] == "PUBLISHED")
                result["status"] = "DRAFT_VERIFIED"
            print(art.encoded(result).decode())
        return 0
    except Exception:
        if journal is not None and (journal.poisoned or journal.events):
            if live:
                print('{"status":"UNKNOWN"}')
            else:
                print('{"status":"UNKNOWN_NEEDS_HUMAN"}')
            return 1
        if live:
            print('{"status":"STOP"}')
            return 2
        return stop("publisher")
    finally:
        if journal is not None:
            journal.close()
