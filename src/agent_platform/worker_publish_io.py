"""PUB-02 private file intake, append-only journal and fixed-peer HTTPS primitive."""

import errno
import fcntl
import http.client
import ipaddress
import os
import socket
import ssl
import stat
import threading
import time
from enum import StrEnum
from pathlib import Path

from .worker_publish_artifact import Blocked, decode, digest, encoded, need


def credential_path(role):
    """Only systemd's exact per-unit credential namespace, never caller paths."""
    need(role in ("publisher", "signer"))
    unit = "ap-worker-publisher" + ("-signer" if role == "signer" else "")
    directory = "/run/credentials/" + unit + ".service"
    need(os.environ.get("CREDENTIALS_DIRECTORY") == directory)
    return directory + ("/app-key" if role == "signer" else "/app-jwt")


ACL_XATTR = "system.posix_acl_access"
# Linux posix_acl_xattr tags (include/uapi/linux/posix_acl.h); perms r=4 w=2 x=1.
ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = (
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
)


def acl_entries(raw):
    """Decode one little-endian POSIX ACL xattr (version 2); no other format."""
    need(type(raw) is bytes and 4 <= len(raw) <= 4 + 8 * 32)
    need((len(raw) - 4) % 8 == 0 and int.from_bytes(raw[:4], "little") == 2)
    tags = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER}
    entries = []
    for offset in range(4, len(raw), 8):
        tag = int.from_bytes(raw[offset : offset + 2], "little")
        perm = int.from_bytes(raw[offset + 2 : offset + 4], "little")
        ident = int.from_bytes(raw[offset + 4 : offset + 8], "little")
        need(tag in tags and perm <= 7)
        entries.append((tag, perm, ident))
    return entries


def systemd_credential(fd, m, owner, *, directory):
    """Accept only systemd's two read-only per-unit credential layouts.

    systemd 257 (exec-credential.c) first grants the unit user an ACL on a
    root-owned 0400 file / 0500 directory; only where ACLs are unsupported
    (ramfs) does it chown them to that user instead. Either way nobody may
    write and no third principal may read. Anything else blocks.
    """
    need(stat.S_ISDIR(m.st_mode) if directory else stat.S_ISREG(m.st_mode))
    need(not stat.S_IMODE(m.st_mode) & 0o7222 and not m.st_mode & 0o007)
    try:
        raw = os.getxattr(fd, ACL_XATTR)
    except OSError as exc:
        need(exc.errno in (errno.ENODATA, errno.EOPNOTSUPP))
        raw = None
    if raw is None:
        need(m.st_uid == owner and not m.st_mode & 0o070)
        return
    granted = 0o5 if directory else 0o4
    need(m.st_uid == 0 and owner != 0 and (m.st_mode >> 3) & 0o7 == granted)
    entries = acl_entries(raw)
    tags = [tag for tag, _, _ in entries]
    need(sorted(tags) == [ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER])
    for tag, perm, ident in entries:
        if tag == ACL_USER:
            need(ident == owner and perm == granted)
        elif tag == ACL_MASK:
            need(perm == granted)
        elif tag == ACL_USER_OBJ:
            need(not perm & 0o2)
        else:  # GROUP_OBJ and OTHER: no access for root's group or anyone else
            need(perm == 0)


def read_file(
    path,
    owner,
    limit,
    *,
    writable_parent=False,
    allow_empty=False,
    private=False,
    credential=False,
):
    """Descriptor-walk every component; no symlinks/hardlinks/writable ancestors.

    credential=True is only for systemd's per-unit credential mount: its last
    directory and the leaf must match systemd_credential(), all other ancestors
    remain root-owned and not group/other writable.
    """
    need(not credential or not (writable_parent or allow_empty or private))
    p = Path(path)
    need(p.is_absolute() and ".." not in p.parts)
    need(not credential or len(p.parts) >= 3)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for i, part in enumerate(p.parts[1:-1]):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            m = os.fstat(fd)
            if credential and i == len(p.parts[1:-1]) - 1:
                systemd_credential(fd, m, owner, directory=True)
                continue
            need(m.st_uid == 0 or writable_parent and m.st_uid == owner)
            need(not m.st_mode & 0o022)
            if private and i == len(p.parts[1:-1]) - 1:
                need(not m.st_mode & 0o077)
        leaf = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
            if credential:
                systemd_credential(leaf, before, owner, directory=False)
            else:
                need(before.st_uid == owner and not before.st_mode & 0o6022)
            if private:
                need(not before.st_mode & 0o077)
            need((0 if allow_empty else 1) <= before.st_size <= limit)
            data = bytearray()
            while len(data) <= limit:
                b = os.read(leaf, min(65536, limit + 1 - len(data)))
                if not b:
                    break
                data.extend(b)
            after = os.fstat(leaf)

            def pin(m):
                return (
                    m.st_dev,
                    m.st_ino,
                    m.st_uid,
                    m.st_gid,
                    m.st_mode,
                    m.st_nlink,
                    m.st_size,
                    m.st_mtime_ns,
                    m.st_ctime_ns,
                )

            need(len(data) == before.st_size and pin(after) == pin(before))
            return bytes(data)
        finally:
            os.close(leaf)
    finally:
        os.close(fd)


class Journal:
    """Pre-provisioned append-only, full-lifetime nonblocking flock.

    A root-owned job must pin the exact prior file digest. No reset, truncate,
    repair, missing-file creation or uncertain append retry. Strict mode uses
    external continuity evidence; homelab mode trusts the root operator's local
    snapshot and does not protect against administrator rollback.
    """

    def __init__(self, path, previous, *, inspect_owner=None):
        # An explicitly trusted root observer can pin an existing store without
        # obtaining a writable descriptor or creating any state.
        need(inspect_owner is None or os.getuid() == os.geteuid() == 0)
        owner = os.getuid() if inspect_owner is None else inspect_owner
        self.read_only = inspect_owner is not None
        read_file(
            path,
            owner,
            4 * 1024 * 1024,
            writable_parent=True,
            allow_empty=True,
            private=True,
        )
        access = os.O_RDONLY if self.read_only else os.O_RDWR | os.O_APPEND
        self.fd = os.open(path, access | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.poisoned = False
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            m = os.fstat(self.fd)
            need(
                stat.S_ISREG(m.st_mode)
                and m.st_nlink == 1
                and m.st_size <= 4 * 1024 * 1024
            )
            need(m.st_uid == owner and stat.S_IMODE(m.st_mode) == 0o600)
            raw = os.pread(self.fd, m.st_size + 1, 0)
            self.sha256 = digest(raw)
            need(
                len(raw) == m.st_size
                and (previous is None and self.read_only or self.sha256 == previous)
            )
            self.events = [decode(line) for line in raw.splitlines()]
            need(len(self.events) <= 16384)
            head = digest(b"")
            for event in self.events:
                need(type(event) is dict and set(event) == {"previous", "record"})
                need(event["previous"] == head)
                head = digest(encoded(event))
            self.head = head
            self.identity = (m.st_dev, m.st_ino)
            self.size = m.st_size
            self.path = path
        except BaseException:
            os.close(self.fd)
            raise

    def append(self, record):
        need(
            not self.read_only
            and not self.poisoned
            and self.size < 4 * 1024 * 1024 - 8192
        )
        self.poisoned = True  # any uncertain write permanently stops this instance
        m = os.stat(self.path, follow_symlinks=False)
        need(
            (m.st_dev, m.st_ino) == self.identity
            and m.st_size == self.size
            and m.st_nlink == 1
        )
        event = {"previous": self.head, "record": record}
        data = encoded(event) + b"\n"
        need(len(data) <= 8192 and os.write(self.fd, data) == len(data))
        os.fsync(self.fd)
        need(os.pread(self.fd, len(data), self.size) == data)
        self.size += len(data)
        self.head = digest(encoded(event))
        self.events.append(event)
        self.poisoned = False

    def claim(self, job, *, signer=False):
        self.admissible(job, signer=signer)
        self.append(
            {
                "phase": "CLAIM",
                "job": job["id"],
                "ref": job["ref"],
                "issue": job["issue"],
                "head": job["head"],
            }
        )

    def admissible(self, job, *, signer=False):
        """Pure replay/continuity check under the held flock; appends nothing."""
        records = [e["record"] for e in self.events]
        # An unfinished attempt blocks the entire store across App/job rotation.
        if records:
            need(records[-1].get("phase") == "COMPLETE")
        need(not any(r.get("job") == job["id"] for r in records))
        related = [
            r
            for r in records
            if r.get("ref") == job["ref"] or r.get("issue") == job["issue"]
        ]
        if related and not signer:
            last = related[-1]
            need(job["operation"] == "update" and last.get("phase") == "COMPLETE")
            need(last.get("head") == job["old"] and last.get("pr") == job["pr"])
            need(last.get("ref") == job["ref"] and last.get("issue") == job["issue"])

    def close(self):
        os.close(self.fd)


class FailureReason(StrEnum):
    TIMEOUT = "timeout"
    TRANSPORT = "transport_error"
    RESPONSE = "invalid_response"
    STATUS = "unexpected_status"
    SHA = "object_sha_mismatch"
    CONTENT = "object_content_mismatch"
    UNCLASSIFIED = "unclassified_failure"


class ExchangeFailure(Blocked):
    def __init__(self, reason: FailureReason):
        super().__init__()
        self.reason = reason


class HTTPS:
    """One fixed verified origin and operator-pinned public IPv4/certificate.

    No proxies, DNS fallback, redirects, automatic retries or caller origin.
    The operation facade supplies the only allowed routes and payloads.
    """

    def __init__(self, ipv4, certificate, *, before_request=None):
        ip = ipaddress.ip_address(ipv4)
        need(
            ip.version == 4
            and ip.is_global
            and not ip.is_multicast
            and not ip.is_unspecified
            and type(certificate) is str
            and len(certificate) == 64
        )
        self.ip, self.certificate = str(ip), certificate
        self.before_request = before_request

    @classmethod
    def homelab(cls, ipv4, *, before_request=None):
        """Keep the selected egress IP for this job; authenticate via system CA/SNI."""
        wire = cls(ipv4, "0" * 64, before_request=before_request)
        wire.certificate = None
        return wire

    def exchange(self, method, path, payload, secret, limit=256 * 1024):
        # Private transport; the Client facade allowlists routes and exact payloads.
        deadline = time.monotonic() + 5

        def remaining():
            left = deadline - time.monotonic()
            if left <= 0:
                raise ExchangeFailure(FailureReason.TIMEOUT)
            return left

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        connection = http.client.HTTPSConnection(
            "api.github.com", timeout=5, context=context
        )
        timer = None
        watchdog = None
        response = None
        reason = FailureReason.TRANSPORT
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            try:
                raw.settimeout(remaining())
                raw.connect((self.ip, 443))
                need(raw.getpeername() == (self.ip, 443))
                # getresponse() can close the TLS socket while its response file
                # still reads from it. A separate descriptor keeps shutdown
                # usable through that handoff without touching the response file.
                watchdog = raw.dup()

                def interrupt():
                    try:
                        watchdog.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

                timer = threading.Timer(remaining(), interrupt)
                timer.start()
                raw.settimeout(remaining())
                connection.sock = context.wrap_socket(
                    raw, server_hostname="api.github.com"
                )
            except BaseException:
                raw.close()
                raise

            if self.certificate is not None:
                need(
                    digest(connection.sock.getpeercert(binary_form=True))
                    == self.certificate
                )
            body = None if payload is None else encoded(payload)
            need(body is None or len(body) <= 6 * 1024 * 1024)
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": "Agent-Platform-PUB-02",
                "X-GitHub-Api-Version": "2026-03-10",
                "Connection": "close",
            }
            if secret is not None:
                need(
                    type(secret) is str and 0 < len(secret) <= 8192 and secret.isascii()
                )
                need(not any(c.isspace() for c in secret))
                headers["Authorization"] = "Bearer " + secret
            if body is not None:
                headers["Content-Type"] = "application/json"
            # Cleanup must remain possible after expiry or controller loss.
            if self.before_request is not None and method != "DELETE":
                self.before_request()
            connection.sock.settimeout(remaining())
            connection.request(method, path, body=body, headers=headers)
            connection.sock.settimeout(remaining())
            response = connection.getresponse()
            reason = FailureReason.RESPONSE
            need(sum(len(k) + len(v) for k, v in response.getheaders()) <= 32768)
            need(
                response.getheader("Location") is None
                and response.getheader("Link") is None
            )
            length = response.getheader("Content-Length")
            encoding = response.getheader("Transfer-Encoding")
            if encoding is not None:
                need(encoding.lower() == "chunked" and length is None)
            if length is not None:
                length = length.strip(" \t")
                need(length.isascii() and length.isdecimal())
                length = int(length)
                need(length <= limit)
            chunks = bytearray()
            while True:
                remaining()
                part = response.read1(min(65536, limit + 1 - len(chunks)))
                remaining()
                if not part:
                    break
                chunks.extend(part)
                need(len(chunks) <= limit)
            # HTTPResponse.read1() can return EOF on a short fixed-length body.
            need(length is None or len(chunks) == length)
            if response.status not in (200, 201, 204, 404):
                raise ExchangeFailure(FailureReason.STATUS)
            try:
                value = None if not chunks else decode(bytes(chunks))
            except ValueError:
                raise ExchangeFailure(FailureReason.RESPONSE) from None
            remaining()
            return response.status, value
        except ExchangeFailure:
            raise
        except TimeoutError:
            raise ExchangeFailure(FailureReason.TIMEOUT) from None
        except OSError:
            raise ExchangeFailure(FailureReason.TRANSPORT) from None
        except http.client.HTTPException:
            raise ExchangeFailure(FailureReason.RESPONSE) from None
        except Blocked:
            raise ExchangeFailure(reason) from None
        except Exception:
            raise ExchangeFailure(FailureReason.UNCLASSIFIED) from None
        finally:
            if timer is not None:
                timer.cancel()
                timer.join(timeout=1)
            if watchdog is not None:
                watchdog.close()
            if response is not None:
                response.close()
            connection.close()
