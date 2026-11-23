"""PUB-02 separately confined, one-shot signer; no INET or installation token."""

import base64
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import worker_publish_artifact as art
from .worker_publish_io import Journal, credential_path, read_file
from .worker_publisher import JOB_PATH, confinement, receipts, validate_job


def jwt_for(key, app_id, expires, now):
    art.need(isinstance(key, rsa.RSAPrivateKey) and 2048 <= key.key_size <= 4096)
    art.need(key.public_key().public_numbers().e == 65537)
    art.need(type(app_id) is int and app_id > 0 and now < expires <= now + 300)

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    prefix = b".".join(
        (
            b64(art.encoded({"alg": "RS256", "typ": "JWT"})),
            b64(art.encoded({"iat": now - 60, "exp": expires, "iss": str(app_id)})),
        )
    )
    return prefix + b"." + b64(key.sign(prefix, padding.PKCS1v15(), hashes.SHA256()))


OUTPUT_DIRECTORY = "/run/ap-publisher-signer"


def write_output(value):
    directory = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(
            "app-jwt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=directory,
        )
        try:
            art.need(os.write(fd, value) == len(value))
            os.fsync(fd)
        finally:
            os.close(fd)
        # A successful file fsync alone does not confirm the directory entry.
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    journal = None
    try:
        original = read_file(JOB_PATH, 0, 16384)
        job = validate_job(
            art.decode(original),
            int(time.time()),
        )
        confinement(job, "signer")
        receipts(job)
        source = credential_path("signer")
        # Retained output is evidence, never an overwrite/restart opportunity.
        art.need(not os.path.lexists(os.path.join(OUTPUT_DIRECTORY, "app-jwt")))
        journal = Journal(
            "/var/lib/ap-publisher-signer/journal", job["signer_journal_sha256"]
        )
        journal.claim(job, signer=True)
        journal.append({"phase": "UNKNOWN", "job": job["id"], "operation": "sign"})
        # Only this unit's credential mount is allowed by the separate AppArmor profile.
        raw = read_file(str(source), os.getuid(), 16384, credential=True)
        key = serialization.load_pem_private_key(raw, password=None)
        art.need(read_file(JOB_PATH, 0, 16384) == original)
        value = jwt_for(key, job["app_id"], job["expires"], int(time.time()))
        value = art.encoded(
            {"job_sha256": art.digest(original), "jwt": value.decode("ascii")}
        )
        write_output(value)
        journal.append(
            {
                "phase": "COMPLETE",
                "job": job["id"],
                "operation": "sign",
                "ref": job["ref"],
                "issue": job["issue"],
                "head": job["head"],
                "pr": job["pr"],
            }
        )
        return 0
    except Exception:
        print('{"status":"BLOCKED","code":"signer_stopped"}')
        return 1
    finally:
        if journal is not None:
            journal.close()


def recovery_main():
    from . import worker_publish_recovery_paths as recovery

    journal = None
    try:
        job, launch_id, parts = recovery.receive("signer", int(time.time()))
        journal = Journal(str(recovery.SIGNER_JOURNAL), job["signer_journal_sha256"])
        art.need(not journal.events)
        journal.claim(job, signer=True)
        operation = {"job": job["id"], "operation": "sign", "launch_id": launch_id}
        journal.append({"phase": "UNKNOWN", **operation})
        recovery.require_live_controller(launch_id)
        raw = recovery.read_role_credential("signer", "app-key", 16384)
        key = serialization.load_pem_private_key(raw, password=None)
        value = jwt_for(key, job["app_id"], job["expires"], int(time.time()))
        jwt = value.decode("ascii")
        recovery.write_signer_handoff(parts["job"], jwt)
        envelope, result = recovery.signer_payload(parts["job"], jwt)
        journal.append(
            {
                "phase": "COMPLETE",
                **operation,
                "ref": job["ref"],
                "issue": job["issue"],
                "head": job["head"],
                "jwt_sha256": art.digest(envelope),
                "result_sha256": art.digest(result),
            }
        )
        return 0
    except Exception:
        return recovery.stop("signer")
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
