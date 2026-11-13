"""PUB-02 separately confined, one-shot signer; no INET or installation token."""

import base64
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import worker_publish_artifact as art
from .worker_publish_io import Journal, read_file
from .worker_publisher import confinement, receipts, validate_job


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


def main():
    journal = None
    try:
        original = read_file("/etc/ap-publisher/job.json", 0, 16384)
        job = validate_job(
            art.decode(original),
            int(time.time()),
        )
        confinement(job, "signer")
        receipts(job)
        journal = Journal(
            "/var/lib/ap-publisher-signer/journal", job["signer_journal_sha256"]
        )
        journal.claim(job, signer=True)
        journal.append({"phase": "UNKNOWN", "job": job["id"], "operation": "sign"})
        # Only this unit's credential mount is allowed by the separate AppArmor profile.
        source = Path(os.environ.get("CREDENTIALS_DIRECTORY", "")) / "app-key"
        raw = read_file(
            str(source), os.getuid(), 16384, writable_parent=True, private=True
        )
        key = serialization.load_pem_private_key(raw, password=None)
        art.need(read_file("/etc/ap-publisher/job.json", 0, 16384) == original)
        value = jwt_for(key, job["app_id"], job["expires"], int(time.time()))
        value = art.encoded(
            {"job_sha256": art.digest(original), "jwt": value.decode("ascii")}
        )
        fd = os.open(
            "/run/ap-publisher-signer/app-jwt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
        )
        try:
            art.need(os.write(fd, value) == len(value))
            os.fsync(fd)
        finally:
            os.close(fd)
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


if __name__ == "__main__":
    raise SystemExit(main())
