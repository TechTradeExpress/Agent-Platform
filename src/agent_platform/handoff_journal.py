"""Bounded durable *synthetic* journal for AP-CH/1 crash contract tests.

No initialization, recovery, migration, cleanup or live transport. The trusted
fixture/controller must retain the external full-file digest and inode pin.
Losing that continuity evidence blocks reopening, rather than creating a store.
Same-UID file modes are not production isolation or authenticated persistence.
"""

import fcntl
import hashlib
import json
import os
import stat
from dataclasses import asdict
from pathlib import Path

from . import publisher
from . import review_comment as comment

MAX_BYTES = 256 * 1024


class SyntheticJournal:
    provenance = "synthetic_journal"

    def __init__(self, path, *, inode, sha256, facts):
        comment.need(type(facts) is comment.JournalFacts and facts.complete is True)
        comment.need(publisher.hex_digest(facts.epoch))
        comment.need(publisher.hex_digest(facts.guard_sha256))
        comment.need(publisher.hex_digest(facts.scope_sha256))
        comment.need(publisher.hex_digest(sha256))
        self.path = Path(path)
        self.inode, self.sha256, self.facts = inode, sha256, facts
        self.identity()  # Existing, exact trusted snapshot only.

    def _open(self):
        comment.need(self.path.is_absolute())
        for parent in self.path.parents:
            info = parent.lstat()
            comment.need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
            # /tmp's sticky root-owned ancestor is allowed for disposable tests.
            comment.need(
                not info.st_mode & 0o022
                or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            )
        fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            comment.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            comment.need(
                info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
            )
            comment.need((info.st_dev, info.st_ino) == self.inode)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _read(self, fd):
        raw = os.read(fd, MAX_BYTES + 1)
        comment.need(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n"))
        comment.need(hashlib.sha256(raw).hexdigest() == self.sha256)
        lines = raw.splitlines()
        genesis = publisher.encoded(
            {
                "schema_version": 1,
                "epoch": self.facts.epoch,
                "guard_sha256": self.facts.guard_sha256,
            }
        )
        comment.need(lines[0] == genesis)
        cells = {}
        for line in lines[1:]:
            row = json.loads(line)
            comment.need(type(row) is dict and set(row) == {"key", "intent", "scope"})
            comment.need(publisher.encoded(row) == line)
            comment.need(
                publisher.hex_digest(row["key"]) and publisher.hex_digest(row["scope"])
            )
            value = row["intent"]
            comment.need(
                type(value) is dict
                and set(value)
                == {"envelope_sha256", "authorization_sha256", "state", "review_id"}
            )
            intent = comment.Intent(**value)
            self._valid(intent)
            previous = cells.get(row["key"])
            if previous is not None:
                old, scope = previous
                comment.need(scope == row["scope"] and old.state == "UNKNOWN")
                comment.need(intent.state == "VERIFIED")
                comment.need(old.envelope_sha256 == intent.envelope_sha256)
                comment.need(old.authorization_sha256 == intent.authorization_sha256)
            cells[row["key"]] = (intent, row["scope"])
        return cells, len(raw)

    @staticmethod
    def _valid(intent):
        comment.need(type(intent) is comment.Intent)
        comment.need(publisher.hex_digest(intent.envelope_sha256))
        comment.need(publisher.hex_digest(intent.authorization_sha256))
        comment.need(intent.state in {"UNKNOWN", "VERIFIED"})
        comment.need(
            intent.review_id is None
            if intent.state == "UNKNOWN"
            else (type(intent.review_id) is int and intent.review_id > 0)
        )

    def identity(self):
        fd = self._open()
        try:
            self._read(fd)
            return self.facts
        finally:
            os.close(fd)

    def read(self, key, *, epoch):
        comment.need(epoch == self.facts.epoch and publisher.hex_digest(key))
        fd = self._open()
        try:
            cells, _ = self._read(fd)
            previous = cells.get(key)
            if previous is None:
                return None
            # Global repo+PR guard spans installation/App/scope rotations.
            comment.need(previous[1] == self.facts.scope_sha256)
            return previous[0]
        finally:
            os.close(fd)

    def compare_and_swap(self, key, old, new, *, epoch):
        comment.need(epoch == self.facts.epoch and publisher.hex_digest(key))
        self._valid(new)
        fd = self._open()
        try:
            cells, length = self._read(fd)
            previous = cells.get(key)
            if previous is not None:
                comment.need(previous[1] == self.facts.scope_sha256)
            if (None if previous is None else previous[0]) != old:
                return False
            if old is not None:
                comment.need(old.state == "UNKNOWN" and new.state == "VERIFIED")
                comment.need(old.envelope_sha256 == new.envelope_sha256)
                comment.need(old.authorization_sha256 == new.authorization_sha256)
            row = (
                publisher.encoded(
                    {
                        "key": key,
                        "scope": self.facts.scope_sha256,
                        "intent": asdict(new),
                    }
                )
                + b"\n"
            )
            comment.need(length + len(row) <= MAX_BYTES)
            # Partial append/fsync failure poisons the external pin; no POST.
            comment.need(os.write(fd, row) == len(row))
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            self.sha256 = hashlib.sha256(os.read(fd, MAX_BYTES + 1)).hexdigest()
            return True
        finally:
            os.close(fd)
