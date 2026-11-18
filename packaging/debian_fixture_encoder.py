"""Pure byte encoder for verified PKG-13 synthetic rehearsal data only."""

import gzip
import hashlib
import io
import json
import tarfile

VERSION = "0.0.0-162"
ROLES = ("control", "worker")
LIMIT = 16 * 1024**2


def _json(record):
    return (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()


def _tar(files, modes, epoch):
    with io.BytesIO() as raw:
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo("./" + name)
                entry.size, entry.mode, entry.mtime = len(data), modes[name], epoch
                tar.addfile(entry, io.BytesIO(data))
        return gzip.compress(raw.getvalue(), mtime=0)


def _ar(name, data, epoch):
    header = f"{name:<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n"
    return header.encode("ascii") + data + (b"\n" if len(data) % 2 else b"")


def expected_members(files, role):
    """Derive a fresh test identity and rebind all changed metadata digests."""
    if role not in ROLES:
        raise ValueError("invalid_fixture_role")
    files = dict(files)
    doc = f"usr/share/doc/agent-platform-{role}/"
    record = json.loads(files[doc + "build.json"])
    if (
        record["rehearsal"]["class"] != "SYNTHETIC_ONLY_NONINSTALLABLE"
        or record["package"] != f"agent-platform-{role}"
        or record["build_kind"] != "final-unreleased"
        or record["ci_only"] is not False
        or record["release_authorized"] is not False
    ):
        raise ValueError("invalid_fixture_class")
    package = f"ap-pkg162-fixture-{role}"
    record.update(
        package=package,
        debian_version=VERSION,
        build_kind="test-encoding",
        ci_only=True,
        status="SYNTHETIC_ONLY / NOT_RELEASED",
    )
    files[doc + "build.json"] = _json(record)
    manifest = json.loads(files[doc + "manifest.json"])
    for item in manifest["files"]:
        name = item["path"][1:]
        if name != doc + "manifest.json":
            item["sha256"] = hashlib.sha256(files[name]).hexdigest()
    files[doc + "manifest.json"] = _json(manifest)
    files["DEBIAN/control"] = b"\n".join(
        f"Package: {package}".encode()
        if line.startswith(b"Package: ")
        else f"Version: {VERSION}".encode()
        if line.startswith(b"Version: ")
        else b"Description: Disposable PKG-162 encoding fixture"
        if line.startswith(b"Description: ")
        else line
        for line in files["DEBIAN/control"].split(b"\n")
    )
    files["DEBIAN/md5sums"] = "".join(
        hashlib.md5(data).hexdigest() + "  " + name + "\n"
        for name, data in sorted(files.items())
        if not name.startswith(("DEBIAN/", "etc/"))
    ).encode()
    return files


def encode(files, modes, epoch):
    """Pure Debian ar serialization. Paths come from checked rehearsal inventory."""
    members = [("debian-binary", b"2.0\n")]
    for area in ("control", "data"):
        selected = {
            name: name.removeprefix("DEBIAN/")
            for name in files
            if name.startswith("DEBIAN/") == (area == "control")
        }
        members.append(
            (
                area + ".tar.gz",
                _tar(
                    {v: files[k] for k, v in selected.items()},
                    {v: modes[k] for k, v in selected.items()},
                    epoch,
                ),
            )
        )
    result = b"!<arch>\n" + b"".join(_ar(name, data, epoch) for name, data in members)
    if len(result) > LIMIT:
        raise ValueError("fixture_archive_limit")
    return result


def verify(archive, files, modes, epoch):
    """Check ar framing, bounded decompression and every tar member."""
    if not archive.startswith(b"!<arch>\n") or len(archive) > LIMIT:
        raise ValueError("invalid_debian_archive")
    offset = 8
    for member in ("debian-binary", "control.tar.gz", "data.tar.gz"):
        header = archive[offset : offset + 60]
        size = int(header[48:58])
        start = offset + 60
        if not 0 <= size <= LIMIT or start + size > len(archive):
            raise ValueError("invalid_debian_member")
        body = archive[start : start + size]
        framing = _ar(member, body, epoch)
        if archive[offset : offset + len(framing)] != framing:
            raise ValueError("invalid_debian_framing")
        offset += len(framing)
        if member == "debian-binary":
            if body != b"2.0\n":
                raise ValueError("invalid_debian_version")
            continue
        control = member.startswith("control")
        expected = {
            "./" + name.removeprefix("DEBIAN/"): name
            for name in files
            if name.startswith("DEBIAN/") == control
        }
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
            raw = compressed.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("invalid_debian_member")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for item in tar:
                name = expected.pop(item.name, None)
                if (
                    name is None
                    or not item.isfile()
                    or (item.uid, item.gid, item.mode, item.mtime, item.size)
                    != (0, 0, modes[name], epoch, len(files[name]))
                    or tar.extractfile(item).read() != files[name]
                ):
                    raise ValueError("invalid_debian_payload")
        if expected:
            raise ValueError("incomplete_debian_payload")
    if offset != len(archive):
        raise ValueError("extra_debian_members")
