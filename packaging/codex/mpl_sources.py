"""Reproducible offline source-candidate bundle; never build/admit a binary."""

import argparse
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST_SHA256 = "7dc92081119f142918ab9c8b02ef512c2fd3505e5f2fd4f4d95b8d8ad6ec50f5"
NOTICE_SHA256 = "44904f89ec1bddf1a40d8c30d54e0910b60759eb95141e3d36032fb700794e25"
LIMIT = 16 * 1024 * 1024


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise ValueError("unsafe_source_input")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if (
            len(data) != before.st_size or len(data) > limit
            or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or os.lstat(path).st_ino != before.st_ino
        ):
            raise ValueError("source_input_changed")
        return data
    finally:
        os.close(fd)


def inputs():
    manifest = read_regular(ROOT / "mpl-source-candidates.json", 32_768)
    notice = read_regular(ROOT / "MPL-SOURCE-NOTICE.txt", 8192)
    if (
        hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA256
        or hashlib.sha256(notice).hexdigest() != NOTICE_SHA256
    ):
        raise ValueError("source_evidence_changed")
    return manifest, notice


def bundle(directory, output):
    manifest, notice = inputs()
    pin = json.loads(manifest)
    expected = {record["filename"] for record in pin["artifacts"]}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("source_inventory_mismatch")
    payload = {"manifest.json": manifest, "README-SOURCES.txt": notice}
    total = len(manifest) + len(notice)
    for record in pin["artifacts"]:
        name = record["filename"]
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("unsafe_source_name")
        data = read_regular(directory / name, 4 * 1024 * 1024)
        total += len(data)
        if (
            len(data) != record["size"] or total > LIMIT
            or hashlib.sha256(data).hexdigest() != record["sha256"]
        ):
            raise ValueError("source_digest_mismatch")
        payload["sources/" + name] = data
    # Validation completes before creating a new output. Uncertain partial output
    # is retained on I/O failure; no overwrite, repair or automatic cleanup.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        with tarfile.open(fileobj=stream, mode="w:xz", format=tarfile.USTAR_FORMAT,
                          preset=6) as archive:
            for name, data in sorted(payload.items()):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                item.mode = 0o644
                item.uid = item.gid = item.mtime = 0
                archive.addfile(item, io.BytesIO(data))
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "SOURCE_CANDIDATE_BUNDLE_ONLY", "artifacts": len(expected),
            "full_binary_mpl_set_verified": False, "redistribution_allowed": False,
            "package_built": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = bundle(args.sources, args.output)
    except (OSError, ValueError):
        print('{"code":"source_bundle_refused","status":"BLOCKED"}')
        return 13
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
