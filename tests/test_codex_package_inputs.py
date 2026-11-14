"""Offline fabricated input checks; no Codex execution or package admission."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "codex_input_checks", ROOT / "packaging/codex/verify_inputs.py"
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def elf(ptype=2, tags=((0, 0),)):
    data = bytearray(512)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", data, 0,
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, ptype, 0, 128, 0, 0,
                     len(tags) * 16, len(tags) * 16, 8)
    for i, pair in enumerate(tags):
        struct.pack_into("<qQ", data, 128 + 16 * i, *pair)
    return bytes(data)


def fixture_archive(tmp_path, *, binary=None, member=None, extra=False):
    binary = elf() if binary is None else binary
    path = tmp_path / "fabricated.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        m = member or tarfile.TarInfo("codex-fixture")
        m.size = len(binary)
        m.mode = 0o755
        archive.addfile(m, io.BytesIO(binary))
        if extra:
            archive.addfile(tarfile.TarInfo("unexpected"), io.BytesIO())
    pin = {
        "archive": {"size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
        "binary": {"member": "codex-fixture", "size": len(binary),
                   "sha256": hashlib.sha256(binary).hexdigest(), "mode": 0o755},
    }
    return path, pin


def test_lock_is_exact_and_keeps_actual_release_blocked():
    pin = checks.read_lock()
    assert pin["version"] == "0.166.0"
    assert pin["draft"] is False and pin["prerelease"] is False
    assert pin["source_commit"] == "6ff1e1ca3b30fc8b914720681fcf5fe62e95f856"
    assert pin["archive"]["size"] == 121764138
    assert pin["license"]["redistribution_allowed"] is False
    assert pin["debian_dependencies"] is None
    assert pin["package_build"] == "BLOCKED"
    assert pin["runtime_authorized"] is False
    for name in ["LICENSE", "NOTICE"]:
        source = next(x for x in pin["sources"] if x["path"] == name)
        assert hashlib.sha256(
            (checks.ROOT / ("upstream-" + name)).read_bytes()
        ).hexdigest() == source["sha256"]


def test_valid_fabricated_archive_is_read_only_and_bounded(tmp_path):
    path, pin = fixture_archive(tmp_path)
    before = path.read_bytes(), path.stat()
    result = checks.inspect_archive(path, pin)
    assert result["binary_sha256"] == pin["binary"]["sha256"]
    assert result["elf"]["dt_needed"] == []
    assert path.read_bytes() == before[0]
    assert path.stat().st_mtime_ns == before[1].st_mtime_ns
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("field", ["archive", "binary"])
def test_digest_mismatch(tmp_path, field):
    path, pin = fixture_archive(tmp_path)
    pin[field]["sha256"] = "0" * 64
    with pytest.raises(checks.Blocked, match=field + "_digest_mismatch"):
        checks.inspect_archive(path, pin)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "empty"])
def test_unsafe_archive_files_refuse(tmp_path, kind):
    path, pin = fixture_archive(tmp_path)
    other = tmp_path / "alias"
    if kind == "symlink":
        other.symlink_to(path)
    elif kind == "hardlink":
        os.link(path, other)
    elif kind == "directory":
        other.mkdir()
    else:
        other.write_bytes(b"")
    with pytest.raises((checks.Blocked, OSError)):
        checks.inspect_archive(other, pin)


@pytest.mark.parametrize("field,value", [
    ("archive", checks.MAX_ARCHIVE + 1), ("binary", checks.MAX_BINARY + 1),
    ("archive", True), ("binary", -1),
])
def test_limits_before_open(tmp_path, field, value):
    path, pin = fixture_archive(tmp_path)
    pin[field]["size"] = value
    with pytest.raises(checks.Blocked, match="input_limit"):
        checks.inspect_archive(path, pin)


@pytest.mark.parametrize("name", ["../codex-fixture", "/codex-fixture", "foreign"])
def test_member_names_never_extracted(tmp_path, name):
    path, pin = fixture_archive(tmp_path, member=tarfile.TarInfo(name))
    with pytest.raises(checks.Blocked, match="archive_inventory_mismatch"):
        checks.inspect_archive(path, pin)
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_nonregular_member_refuses(tmp_path, kind):
    member = tarfile.TarInfo("codex-fixture")
    member.type = kind
    path, pin = fixture_archive(tmp_path, member=member)
    with pytest.raises(checks.Blocked, match="archive_inventory_mismatch"):
        checks.inspect_archive(path, pin)


def test_extra_member_refuses(tmp_path):
    path, pin = fixture_archive(tmp_path, extra=True)
    with pytest.raises(checks.Blocked, match="archive_inventory_mismatch"):
        checks.inspect_archive(path, pin)


@pytest.mark.parametrize("data,code", [
    (b"x" * 512, "unsupported_elf"),
    (elf(ptype=3), "unexpected_interpreter"),
    (elf(tags=((1, 42), (0, 0))), "unexpected_dynamic_dependency"),
    (elf(tags=((2, 42),)), "unsupported_elf"),
])
def test_elf_refusals(tmp_path, data, code):
    path, pin = fixture_archive(tmp_path, binary=data)
    with pytest.raises(checks.Blocked, match=code):
        checks.inspect_archive(path, pin)


def test_changed_input_refuses(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"input")
    with pytest.raises(checks.Blocked, match="input_changed"):
        with checks.regular(path, 10):
            path.write_bytes(b"other-size")


def test_replaced_same_content_input_refuses(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"input")
    with pytest.raises(checks.Blocked, match="input_changed"):
        with checks.regular(path, 10):
            other = tmp_path / "other"
            other.write_bytes(b"input")
            other.replace(path)


def test_lock_edit_cannot_authorize_package(tmp_path, monkeypatch):
    data = json.loads((checks.ROOT / "release-inputs.json").read_bytes())
    data["license"]["redistribution_allowed"] = True
    (tmp_path / "release-inputs.json").write_text(json.dumps(data))
    monkeypatch.setattr(checks, "ROOT", tmp_path)
    with pytest.raises(checks.Blocked, match="release_lock_changed"):
        checks.read_lock()


def test_license_investigation_edit_cannot_supply_clearance(tmp_path, monkeypatch):
    (tmp_path / "release-inputs.json").write_bytes(
        (checks.ROOT / "release-inputs.json").read_bytes()
    )
    (tmp_path / "license-investigation.json").write_bytes(
        b'{"redistribution_allowed":true}'
    )
    monkeypatch.setattr(checks, "ROOT", tmp_path)
    with pytest.raises(checks.Blocked, match="license_evidence_changed"):
        checks.read_lock()


def test_resolution_attempt_or_candidate_source_edit_refuses(tmp_path, monkeypatch):
    for name in (
        "release-inputs.json", "license-investigation.json", "resolution-attempts.json",
        "mpl-source-candidates.json", "MPL-SOURCE-NOTICE.txt",
    ):
        (tmp_path / name).write_bytes((checks.ROOT / name).read_bytes())
    (tmp_path / "resolution-attempts.json").write_bytes(b'{"all_gates":"PASS"}')
    monkeypatch.setattr(checks, "ROOT", tmp_path)
    with pytest.raises(checks.Blocked, match="license_evidence_changed"):
        checks.read_lock()


def test_large_fixture_result_edit_cannot_change_license_gate(tmp_path, monkeypatch):
    for name in (
        "release-inputs.json", "license-investigation.json", "resolution-attempts.json",
        "mpl-source-candidates.json", "MPL-SOURCE-NOTICE.txt",
        "large-fixture-observation.json", "resolution-job-inputs.json",
    ):
        (tmp_path / name).write_bytes((checks.ROOT / name).read_bytes())
    (tmp_path / "large-fixture-observation.json").write_bytes(b'{"status":"PASS"}')
    monkeypatch.setattr(checks, "ROOT", tmp_path)
    with pytest.raises(checks.Blocked, match="license_evidence_changed"):
        checks.read_lock()


def test_fabricated_complete_inputs_still_never_admit(tmp_path, monkeypatch):
    path, pin = fixture_archive(tmp_path)
    pin = copy.deepcopy(pin)
    pin.update(version="fabricated", sources=[])
    monkeypatch.setattr(checks, "read_lock", lambda: pin)
    report = checks.inspect(path, tmp_path)
    assert checks.inspect(path, tmp_path) == report
    assert report["inputs_verified"] is True
    assert report["status"] == "BLOCKED"
    assert not any(report[k] for k in (
        "redistribution_allowed", "package_built", "version_executed",
        "runtime_authorized",
    ))


def test_source_hash_and_size_are_checked(tmp_path):
    (tmp_path / "LICENSE").write_bytes(b"fabricated")
    pin = {"path": "LICENSE", "size": 10,
           "sha256": hashlib.sha256(b"fabricated").hexdigest()}
    checks.inspect_sources(tmp_path, [pin])
    (tmp_path / "LICENSE").write_bytes(b"substitute")
    with pytest.raises(checks.Blocked, match="source_digest_mismatch"):
        checks.inspect_sources(tmp_path, [pin])


def test_cli_fixed_redacted_refusal_and_no_outputs(tmp_path):
    private = tmp_path / "PRIVATE_SENTINEL"
    result = subprocess.run([
        sys.executable, "-I", str(ROOT / "packaging/build_codex_deb.py"),
        "--archive", str(private), "--sources", str(tmp_path),
    ], capture_output=True, timeout=10)
    assert result.returncode == 13
    report = json.loads(result.stdout)
    assert report["status"] == "BLOCKED" and not report["package_built"]
    assert b"PRIVATE_SENTINEL" not in result.stdout + result.stderr
    assert not result.stderr
    assert not list(tmp_path.iterdir())


def test_no_skip_license_or_alternate_pin_cli(tmp_path):
    result = subprocess.run([
        sys.executable, "-I", str(ROOT / "packaging/build_codex_deb.py"),
        "--archive", str(tmp_path / "missing"), "--sources", str(tmp_path),
        "--skip-license",
    ], capture_output=True, timeout=10)
    assert result.returncode == 2
    assert not list(tmp_path.iterdir())
