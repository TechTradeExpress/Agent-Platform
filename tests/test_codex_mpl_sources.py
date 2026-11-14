"""Source delivery tests do not establish binary membership or license clearance."""

import hashlib
import importlib.util
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mpl_sources", ROOT / "packaging/codex/mpl_sources.py"
)
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


@pytest.fixture
def candidates(tmp_path, monkeypatch):
    directory = tmp_path / "sources"
    directory.mkdir()
    data = b"fabricated source archive bytes, never executed"
    (directory / "fixture.crate").write_bytes(data)
    pin = {"artifacts": [{"filename": "fixture.crate", "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()}]}
    manifest = json.dumps(pin, sort_keys=True).encode()
    monkeypatch.setattr(sources, "inputs", lambda: (manifest, b"AUDIT ONLY\n"))
    return directory, data


def test_actual_source_candidate_pins_are_not_complete_binary_inventory():
    raw, notice = sources.inputs()
    pin = json.loads(raw)
    assert len(pin["components"]) == 11 and len(pin["artifacts"]) == 10
    assert not pin["full_binary_mpl_set_verified"]
    assert not pin["redistribution_allowed"]
    assert {c["license"] for c in pin["components"]} == {"MPL-2.0"}
    assert b"not a statement" in notice
    matcher = next(c for c in pin["components"] if c["name"] == "nucleo-matcher")
    assert matcher["license_path"] == "LICENSE"
    assert matcher["source_revision"] == "4253de9faabb4e5c6d81d946a5e35a90f87347ee"


def test_source_bundle_preserves_bytes_is_reproducible_and_never_admits_binary(
    candidates, tmp_path,
):
    directory, data = candidates
    a, b = tmp_path / "a.tar.xz", tmp_path / "b.tar.xz"
    report = sources.bundle(directory, a)
    assert sources.bundle(directory, b) == report
    assert a.read_bytes() == b.read_bytes()
    assert report["status"] == "SOURCE_CANDIDATE_BUNDLE_ONLY"
    assert not any(report[k] for k in (
        "full_binary_mpl_set_verified", "redistribution_allowed", "package_built",
    ))
    with tarfile.open(fileobj=io.BytesIO(a.read_bytes())) as archive:
        assert sorted(archive.getnames()) == [
            "README-SOURCES.txt", "manifest.json", "sources/fixture.crate",
        ]
        assert archive.extractfile("sources/fixture.crate").read() == data
        for member in archive:
            assert member.isfile() and member.mode == 0o644
            assert member.uid == member.gid == member.mtime == 0
    assert (directory / "fixture.crate").read_bytes() == data


def test_corrupt_source_refuses_before_output(candidates, tmp_path):
    directory, _ = candidates
    (directory / "fixture.crate").write_bytes(b"tampered")
    output = tmp_path / "new.tar.xz"
    with pytest.raises(ValueError, match="source_digest_mismatch"):
        sources.bundle(directory, output)
    assert not output.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "empty", "extra", "missing"])
def test_unsafe_or_incomplete_source_intake_refuses(candidates, tmp_path, kind):
    directory, data = candidates
    path = directory / "fixture.crate"
    if kind == "symlink":
        path.unlink()
        target = tmp_path / "target"
        target.write_bytes(data)
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(path, tmp_path / "alias")
    elif kind == "empty":
        path.write_bytes(b"")
    elif kind == "extra":
        (directory / "extra").write_bytes(b"unrequested")
    else:
        path.unlink()
    output = tmp_path / "new.tar.xz"
    with pytest.raises((OSError, ValueError)):
        sources.bundle(directory, output)
    assert not output.exists()


def test_existing_output_preserved(candidates, tmp_path):
    directory, _ = candidates
    output = tmp_path / "retained.tar.xz"
    output.write_bytes(b"retained evidence")
    with pytest.raises(FileExistsError):
        sources.bundle(directory, output)
    assert output.read_bytes() == b"retained evidence"


def test_changed_manifest_or_recipient_notice_refuses(tmp_path, monkeypatch):
    for name in ["mpl-source-candidates.json", "MPL-SOURCE-NOTICE.txt"]:
        (tmp_path / name).write_bytes((sources.ROOT / name).read_bytes())
    (tmp_path / "MPL-SOURCE-NOTICE.txt").write_bytes(b"CLEARANCE GRANTED")
    monkeypatch.setattr(sources, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="source_evidence_changed"):
        sources.inputs()
