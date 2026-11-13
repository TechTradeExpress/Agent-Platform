"""PUB-02 private file intake, append-only journal and fixed-peer HTTPS primitive."""

import fcntl
import http.client
import ipaddress
import os
import socket
import ssl
import stat
import threading
import time
from pathlib import Path

from .worker_publish_artifact import Blocked, decode, digest, encoded, need


def read_file(
    path, owner, limit, *, writable_parent=False, allow_empty=False, private=False
):
    """Descriptor-walk every component; no symlinks/hardlinks/writable ancestors."""
    p = Path(path)
    need(p.is_absolute() and ".." not in p.parts)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for i, part in enumerate(p.parts[1:-1]):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            m = os.fstat(fd)
            need(m.st_uid == 0 or writable_parent and m.st_uid == owner)
            need(not m.st_mode & 0o022)
            if private and i == len(p.parts[1:-1]) - 1:
                need(not m.st_mode & 0o077)
        leaf = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
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
    repair, missing-file creation or uncertain append retry. Root/external custody
    of that pin remains a separately verified anti-rollback prerequisite.
    """

    def __init__(self, path, previous):
        read_file(
            path,
            os.getuid(),
            4 * 1024 * 1024,
            writable_parent=True,
            allow_empty=True,
            private=True,
        )
        self.fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.poisoned = False
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            m = os.fstat(self.fd)
            need(
                stat.S_ISREG(m.st_mode)
                and m.st_nlink == 1
                and m.st_size <= 4 * 1024 * 1024
            )
            need(m.st_uid == os.getuid() and stat.S_IMODE(m.st_mode) == 0o600)
            raw = os.pread(self.fd, m.st_size + 1, 0)
            need(len(raw) == m.st_size and digest(raw) == previous)
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
        need(not self.poisoned and self.size < 4 * 1024 * 1024 - 8192)
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
        self.append(
            {
                "phase": "CLAIM",
                "job": job["id"],
                "ref": job["ref"],
                "issue": job["issue"],
                "head": job["head"],
            }
        )

    def close(self):
        os.close(self.fd)


class HTTPS:
    """One fixed verified origin and operator-pinned public IPv4/certificate.

    No proxies, DNS fallback, redirects, automatic retries or caller origin.
    The operation facade supplies the only allowed routes and payloads.
    """

    def __init__(self, ipv4, certificate):
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

    def exchange(self, method, path, payload, secret, limit=256 * 1024):
        # Private transport; the Client facade allowlists routes and exact payloads.
        started = time.monotonic()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        connection = http.client.HTTPSConnection(
            "api.github.com", timeout=5, context=context
        )
        timer = None
        response = None
        try:
            raw = socket.create_connection((self.ip, 443), timeout=5)
            try:
                need(raw.getpeername()[0] == self.ip)
                remaining = 5 - (time.monotonic() - started)
                need(remaining > 0)
                raw.settimeout(remaining)
                connection.sock = connection._context.wrap_socket(
                    raw, server_hostname="api.github.com"
                )
            except BaseException:
                raw.close()
                raise

            channel = connection.sock

            def interrupt():
                try:
                    channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(
                max(0.001, 5 - (time.monotonic() - started)), interrupt
            )
            timer.start()
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
            remaining = 5 - (time.monotonic() - started)
            need(remaining > 0)
            channel.settimeout(remaining)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            need(sum(len(k) + len(v) for k, v in response.getheaders()) <= 32768)
            need(
                response.getheader("Location") is None
                and response.getheader("Link") is None
            )
            remaining = 5 - (time.monotonic() - started)
            need(remaining > 0)
            channel.settimeout(remaining)
            chunks = bytearray()
            while True:
                left = 5 - (time.monotonic() - started)
                need(left > 0)
                channel.settimeout(left)
                part = response.read1(min(65536, limit + 1 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
                need(len(chunks) <= limit)
            data = bytes(chunks)
            need(len(data) <= limit and time.monotonic() - started <= 5)
            need(response.status in (200, 201, 204, 404))
            return response.status, None if not data else decode(data)
        except Exception:
            raise Blocked() from None
        finally:
            if timer is not None:
                timer.cancel()
                timer.join(timeout=1)
            if response is not None:
                response.close()
            connection.close()
