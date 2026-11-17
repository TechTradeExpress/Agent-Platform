"""HAR-04 synthetic provisioner tests. Never download, run or log in to Claude Code."""

import ast
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "provisioning/evidence"
VERSIONS = ("2.1.295", "2.1.296", "2.1.297", "2.1.298")


def module(path=ROOT / "provisioning/claude_upstream.py"):
    spec = importlib.util.spec_from_file_location("claude_upstream", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---- test-only OpenPGP construction (synthetic key, never a vendor key) ----


def mpi(value):
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return struct.pack(">H", value.bit_length()) + raw


def armor(kind, raw):
    body = base64.b64encode(raw).decode()
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return (
        f"-----BEGIN PGP {kind}-----\n\n{lines}\n=AAAA\n-----END PGP {kind}-----\n"
    ).encode()


def new_length(size):
    if size < 192:
        return bytes([size])
    size -= 192
    return bytes([(size >> 8) + 192, size & 255])


def public_key_armor(private):
    numbers = private.public_key().public_numbers()
    body = b"\x04" + struct.pack(">I", 1700000000) + b"\x01"
    body += mpi(numbers.n) + mpi(numbers.e)
    packet = b"\x99" + struct.pack(">H", len(body)) + body
    fingerprint = hashlib.sha1(packet).hexdigest().upper()
    return armor("PUBLIC KEY BLOCK", packet), fingerprint


def detached_signature(private, data, fingerprint, *, issuer=None):
    issuer = fingerprint if issuer is None else issuer
    hashed = b"\x05\x02" + struct.pack(">I", 1700000100)
    hashed += b"\x16\x21\x04" + bytes.fromhex(issuer)
    head = bytes([4, 0, 1, 8]) + struct.pack(">H", len(hashed)) + hashed
    message = data + head + b"\x04\xff" + struct.pack(">I", len(head))
    digest = hashlib.sha256(message).digest()
    signature = private.sign(message, padding.PKCS1v15(), hashes.SHA256())
    body = head + b"\x00\x00" + digest[:2] + mpi(int.from_bytes(signature, "big"))
    return armor("SIGNATURE", bytes([0xC2]) + new_length(len(body)) + body)


@pytest.fixture(scope="module")
def signer():
    def make():
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)

    private = make()
    key, fingerprint = public_key_armor(private)
    other = make()
    other_key, other_fingerprint = public_key_armor(other)
    return SimpleNamespace(
        private=private,
        key=key,
        fingerprint=fingerprint,
        other=other,
        other_key=other_key,
        other_fingerprint=other_fingerprint,
    )


# ---- synthetic vendor-like artifacts ----


def synthetic_elf(label="fixture", machine=62):
    data = bytearray(512)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        b"\x7fELF\x02\x01\x01" + bytes(9),
        2,
        machine,
        1,
        128,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 512, 512, 4096)
    data[128 : 128 + len(label)] = label.encode()
    return bytes(data)


def pin_for(m, signer, version, binary):
    manifest = (
        json.dumps(
            {
                "version": version,
                "platforms": {
                    "linux-x64": {
                        "binary": "claude",
                        "checksum": m.sha(binary),
                        "size": len(binary),
                    }
                },
            },
            sort_keys=True,
        )
        + "\n"
    ).encode()
    signature = detached_signature(signer.private, manifest, signer.fingerprint)
    pin = {
        "version": version,
        "platform": "linux-x64",
        "binary_name": "claude",
        "binary_sha256": m.sha(binary),
        "binary_size": len(binary),
        "manifest_sha256": m.sha(manifest),
        "signature_sha256": m.sha(signature),
        "key_sha256": m.sha(signer.key),
        "key_fingerprint": signer.fingerprint,
        "evidence": f"evidence/claude-{version}-provenance.json",
        "evidence_sha256": "e" * 64,
    }
    return pin, manifest, signature


def tree(path):
    """Complete byte/type snapshot of a tree; symlinks are not followed."""
    out = {}
    for item in sorted(Path(path).rglob("*")):
        rel = str(item.relative_to(path))
        if item.is_symlink():
            out[rel] = ("link", os.readlink(item))
        elif item.is_dir():
            out[rel] = ("dir", oct(item.stat().st_mode))
        else:
            out[rel] = ("file", oct(item.stat().st_mode), item.read_bytes())
    return out


@pytest.fixture
def env(tmp_path, monkeypatch, signer):
    m = module()
    opt, usrbin, localbin, pathbin = (
        tmp_path / n for n in ("opt", "usr-bin", "local-bin", "path-bin")
    )
    for path in (opt, usrbin, localbin, pathbin):
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    monkeypatch.setattr(m, "OWNER", os.getuid())
    monkeypatch.setattr(m, "BASE", str(opt / "claude-store"))
    monkeypatch.setattr(m, "SYSTEM_COMMANDS", (str(usrbin), str(localbin)))
    monkeypatch.setattr(m, "check_platform", lambda: None)
    monkeypatch.setattr(m, "FINGERPRINT", signer.fingerprint)

    @contextlib.contextmanager
    def fixture_directory(path):
        # Explicit test-only authority substitution; production has no UID flag.
        assert Path(path).is_relative_to(tmp_path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | m.NOFOLLOW)
        try:
            m.checked_meta(fd, True)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(m, "directory", fixture_directory)
    pins, files, manifests = {}, {}, {}
    for version in VERSIONS:
        binary = synthetic_elf(version)
        pin, manifest, signature = pin_for(m, signer, version, binary)
        path = tmp_path / ("claude-" + version)
        path.write_bytes(binary)
        path.chmod(0o755)
        pins[version], files[version] = pin, path
        manifests[version] = (manifest, signature)
    operator_path = f"{pathbin}:{tmp_path}/other"

    def run(version="2.1.295", **kwargs):
        selected = kwargs.pop("pins", {k: v for k, v in pins.items() if k != "2.1.298"})
        return m.operate(
            selected,
            version,
            path=kwargs.pop("path", files.get(version)),
            operator_path=kwargs.pop("operator_path", operator_path),
            **kwargs,
        )

    def inspect(selected=None):
        with m.directory(m.BASE) as fd:
            return m.inspect_store(fd, selected or pins)

    return SimpleNamespace(
        m=m,
        tmp=tmp_path,
        pins=pins,
        files=files,
        manifests=manifests,
        run=run,
        inspect=inspect,
        usrbin=usrbin,
        localbin=localbin,
        pathbin=pathbin,
        base=Path(m.BASE),
        signer=signer,
        monkeypatch=monkeypatch,
    )


# ---- official evidence and signature verification ----


@pytest.fixture
def real_copy(tmp_path):
    """Private mode-normalized copy of the reviewed code, lock and evidence."""
    target = tmp_path / "provisioning"
    shutil.copytree(
        ROOT / "provisioning",
        target,
        ignore=shutil.ignore_patterns("__pycache__", "codex*", "sigstore*"),
    )
    for item in [target, *target.rglob("*")]:
        item.chmod(0o755 if item.is_dir() else 0o644)
    return target


def patched(m, monkeypatch, tmp_path):
    monkeypatch.setattr(m, "OWNER", os.getuid())

    @contextlib.contextmanager
    def fixture_directory(path):
        assert Path(path).is_relative_to(tmp_path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | m.NOFOLLOW)
        try:
            m.checked_meta(fd, True)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(m, "directory", fixture_directory)


def test_real_release_lock_signature_and_manifest_verify(
    real_copy, tmp_path, monkeypatch
):
    m = module(real_copy / "claude_upstream.py")
    patched(m, monkeypatch, tmp_path)
    pins = m.load_lock()
    pin = pins["2.1.295"]
    assert (
        set(pins) == {"2.1.295"} and m.version_tuple(pin["version"]) >= m.MIN_AGENTS_MD
    )
    assert pin["platform"] == "linux-x64" and pin["binary_name"] == "claude"
    assert pin["key_fingerprint"] == "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
    assert m.sha((real_copy / "claude-release-lock.json").read_bytes()) == m.LOCK_SHA256
    assert m.source_urls("2.1.295")["binary"] == (
        "https://downloads.claude.ai/claude-code-releases/2.1.295/linux-x64/claude"
    )


def test_official_artifacts_are_the_pinned_bytes_and_key_is_documented_one():
    m = module()
    key = (EVIDENCE / "claude-code-release-key.asc").read_bytes()
    _, _, fingerprint = m.public_key(key)
    assert fingerprint == m.FINGERPRINT == "31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE"
    manifest = (EVIDENCE / "claude-2.1.295-manifest.json").read_bytes()
    signature = (EVIDENCE / "claude-2.1.295-manifest.json.sig").read_bytes()
    assert m.verify_detached(manifest, signature, key)
    entry = json.loads(manifest)["platforms"]["linux-x64"]
    lock = json.loads((ROOT / "provisioning/claude-release-lock.json").read_text())
    assert entry["checksum"] == lock["releases"][0]["binary_sha256"]
    assert entry["size"] == lock["releases"][0]["binary_size"]


@pytest.mark.parametrize("target", ["manifest", "signature", "key"])
def test_real_evidence_mutation_is_rejected(target):
    m = module()
    key = (EVIDENCE / "claude-code-release-key.asc").read_bytes()
    manifest = (EVIDENCE / "claude-2.1.295-manifest.json").read_bytes()
    signature = (EVIDENCE / "claude-2.1.295-manifest.json.sig").read_bytes()
    if target == "manifest":
        manifest = manifest.replace(b"4503bfe1", b"4503bfe2")
    elif target == "signature":
        text = bytearray(signature)
        index = text.index(b"\n\n") + 40
        text[index] = ord("A") if text[index] != ord("A") else ord("B")
        signature = bytes(text)
    else:
        key = key.replace(b"mQINBGnK", b"mQINBGnL", 1)
    with pytest.raises(m.Blocked):
        m.verify_detached(manifest, signature, key)


def test_lock_and_evidence_chain_is_pinned(real_copy, tmp_path, monkeypatch):
    m = module(real_copy / "claude_upstream.py")
    patched(m, monkeypatch, tmp_path)
    lock = real_copy / "claude-release-lock.json"
    original = lock.read_bytes()
    lock.write_bytes(original.replace(b"2.1.295", b"2.1.296", 1))
    with pytest.raises(m.Blocked, match="unreviewed_release_lock"):
        m.load_lock()
    lock.write_bytes(original)
    manifest = real_copy / "evidence/claude-2.1.295-manifest.json"
    manifest.write_bytes(manifest.read_bytes().replace(b"4503bfe1", b"4503bfe2"))
    with pytest.raises(m.Blocked, match="manifest_changed"):
        m.load_lock()


def test_compromised_manifest_with_rewritten_hash_chain_still_fails_signature(
    real_copy, tmp_path, monkeypatch
):
    """An attacker who also rewrites lock+evidence hashes cannot forge the signature."""
    m = module(real_copy / "claude_upstream.py")
    patched(m, monkeypatch, tmp_path)
    evidence = real_copy / "evidence"
    manifest = evidence / "claude-2.1.295-manifest.json"
    forged = manifest.read_bytes().replace(b"4503bfe1", b"4503bfe2")
    manifest.write_bytes(forged)
    proof = json.loads((evidence / "claude-2.1.295-provenance.json").read_text())
    proof["manifest_sha256"] = m.sha(forged)
    proof_bytes = (
        json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    (evidence / "claude-2.1.295-provenance.json").write_bytes(proof_bytes)
    lock = json.loads((real_copy / "claude-release-lock.json").read_text())
    lock["releases"][0]["manifest_sha256"] = m.sha(forged)
    lock["releases"][0]["evidence_sha256"] = m.sha(proof_bytes)
    lock_bytes = (json.dumps(lock, sort_keys=True, indent=1) + "\n").encode()
    (real_copy / "claude-release-lock.json").write_bytes(lock_bytes)
    monkeypatch.setattr(m, "LOCK_SHA256", m.sha(lock_bytes))  # simulate bad review
    with pytest.raises(m.Blocked, match="signature_digest_mismatch|bad_signature"):
        m.load_lock()


def test_substituted_signing_key_is_rejected_even_with_matching_hashes(
    real_copy, tmp_path, monkeypatch, signer
):
    m = module(real_copy / "claude_upstream.py")
    patched(m, monkeypatch, tmp_path)
    (real_copy / "evidence/claude-code-release-key.asc").write_bytes(signer.other_key)
    lock = json.loads((real_copy / "claude-release-lock.json").read_text())
    lock["releases"][0]["key_sha256"] = m.sha(signer.other_key)
    lock_bytes = (json.dumps(lock, sort_keys=True, indent=1) + "\n").encode()
    (real_copy / "claude-release-lock.json").write_bytes(lock_bytes)
    monkeypatch.setattr(m, "LOCK_SHA256", m.sha(lock_bytes))
    with pytest.raises(m.Blocked, match="key_fingerprint_mismatch"):
        m.load_lock()


# ---- synthetic signature and manifest semantics ----


def test_synthetic_signature_accepts_exact_key_and_rejects_everything_else(env):
    m, s = env.m, env.signer
    manifest, signature = env.manifests["2.1.295"]
    assert m.verify_detached(manifest, signature, s.key, s.fingerprint)
    with pytest.raises(m.Blocked, match="digest_mismatch"):
        m.verify_detached(manifest + b" ", signature, s.key, s.fingerprint)
    with pytest.raises(m.Blocked, match="key_fingerprint_mismatch"):
        m.verify_detached(manifest, signature, s.other_key, s.fingerprint)
    forged = detached_signature(s.other, manifest, s.fingerprint)  # lies about issuer
    with pytest.raises(m.Blocked, match="bad_signature"):
        m.verify_detached(manifest, forged, s.key, s.fingerprint)
    wrong_issuer = detached_signature(
        s.private, manifest, s.fingerprint, issuer="AB" * 20
    )
    with pytest.raises(m.Blocked, match="signature_issuer_mismatch"):
        m.verify_detached(manifest, wrong_issuer, s.key, s.fingerprint)


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda d: d.update(version="2.1.296"), "manifest_version_mismatch"),
        (lambda d: d["platforms"].pop("linux-x64"), "manifest_platform"),
        (
            lambda d: d["platforms"]["linux-x64"].update(checksum="0" * 64),
            "manifest_binary_mismatch",
        ),
        (
            lambda d: d["platforms"]["linux-x64"].update(size=1),
            "manifest_binary_mismatch",
        ),
        (
            lambda d: d["platforms"]["linux-x64"].update(binary="claude.exe"),
            "manifest_binary_mismatch",
        ),
        (
            # The musl entry must never satisfy the glibc linux-x64 pin.
            lambda d: d["platforms"].update(
                {"linux-x64-musl": d["platforms"].pop("linux-x64")}
            ),
            "manifest_platform",
        ),
    ],
)
def test_signed_but_inconsistent_manifest_is_rejected(env, mutate, reason):
    m, s = env.m, env.signer
    pin = dict(env.pins["2.1.295"])
    document = json.loads(env.manifests["2.1.295"][0])
    mutate(document)
    manifest = (json.dumps(document, sort_keys=True) + "\n").encode()
    signature = detached_signature(s.private, manifest, s.fingerprint)
    pin.update(manifest_sha256=m.sha(manifest), signature_sha256=m.sha(signature))
    with pytest.raises(m.Blocked, match=reason):
        m.verify_manifest(pin, manifest, signature, s.key)


def test_duplicate_json_keys_in_signed_manifest_are_rejected(env):
    m, s = env.m, env.signer
    pin = dict(env.pins["2.1.295"])
    manifest = b'{"version":"2.1.295","version":"2.1.295","platforms":{}}\n'
    signature = detached_signature(s.private, manifest, s.fingerprint)
    pin.update(manifest_sha256=m.sha(manifest), signature_sha256=m.sha(signature))
    with pytest.raises(m.Blocked, match="duplicate_json_key"):
        m.verify_manifest(pin, manifest, signature, s.key)


@pytest.mark.parametrize("version", ["2.1.276", "2.1.277", "2.1.280", "1.9.9"])
def test_versions_below_documented_agents_md_floor_are_refused(env, version):
    pin = dict(env.pins["2.1.295"], version=version)
    pin["evidence"] = f"evidence/claude-{version}-provenance.json"
    with pytest.raises(env.m.Blocked, match="agents_md_support_unverified"):
        env.m.validate_pin(pin)


@pytest.mark.parametrize(
    "field,value",
    [
        ("platform", "linux-x64-musl"),
        ("platform", "linux-arm64"),
        ("binary_name", "claude.exe"),
        ("key_fingerprint", "AB" * 20),
        ("binary_sha256", "A" * 64),
        ("binary_size", 0),
        ("version", "latest"),
        ("version", "stable"),
    ],
)
def test_pin_shape_rejects_unreviewed_values(env, field, value):
    with pytest.raises(env.m.Blocked):
        env.m.validate_pin(dict(env.pins["2.1.295"], **{field: value}))


# ---- install, upgrade, rollback ----


def test_install_places_unmodified_bytes_in_separate_namespace(env):
    before_outside = tree(env.tmp)
    result = env.run()
    assert result["outcome"] == "install" and result["launch_allowed"] is False
    assert result["runtime"] == "LIVE_NO_GO" and result["authentication"] == "NOT_RUN"
    assert result["harness_selection"] == "UNCHANGED"
    pin = env.pins["2.1.295"]
    binary = (
        env.base / "versions" / (pin["version"] + "-" + pin["binary_sha256"]) / "claude"
    )
    assert binary.read_bytes() == env.files["2.1.295"].read_bytes()
    assert os.stat(binary).st_mode & 0o7777 == 0o755
    assert result["executable"] == str(binary)
    # No command link, no selection, nothing outside the managed namespace.
    assert list(env.usrbin.iterdir()) == list(env.localbin.iterdir()) == []
    assert not (env.tmp / "harness.json").exists()
    after = tree(env.tmp)
    managed = {k: v for k, v in after.items() if not k.startswith("opt/claude-store")}
    assert managed == {k: v for k, v in before_outside.items() if k in managed}
    assert "/opt/agent-platform-codex" not in env.m.BASE
    assert env.m.BASE != "/opt/agent-platform-codex"
    assert sorted(os.listdir(env.base)) == ["current", "store.json", "versions"]


def test_install_is_idempotent_and_does_not_rewrite(env):
    env.run()
    snapshot = tree(env.base)
    assert env.run()["outcome"] == "already_installed"
    assert tree(env.base) == snapshot


def test_upgrade_requires_explicit_flag_and_never_downgrades(env):
    env.run()
    with pytest.raises(env.m.Blocked, match="explicit_upgrade_required"):
        env.run("2.1.296")
    assert env.run("2.1.296", upgrade=True)["outcome"] == "install"
    current, installed, transaction = env.inspect()
    assert (
        current.startswith("2.1.296-") and len(installed) == 2 and transaction is None
    )
    with pytest.raises(env.m.Blocked, match="downgrade_denied"):
        env.run("2.1.295", upgrade=True)


def test_rollback_selects_only_a_retained_older_version(env):
    env.run()
    env.run("2.1.296", upgrade=True)
    snapshot = {k: v for k, v in tree(env.base).items() if "versions/" in k}
    assert env.run("2.1.295", action="rollback", path=None)["outcome"] == "rollback"
    current, installed, _ = env.inspect()
    assert current.startswith("2.1.295-") and len(installed) == 2
    assert {k: v for k, v in tree(env.base).items() if "versions/" in k} == snapshot
    with pytest.raises(env.m.Blocked, match="rollback_not_older"):
        env.run("2.1.296", action="rollback", path=None)
    with pytest.raises(env.m.Blocked, match="rollback_not_retained"):
        env.run("2.1.297", action="rollback", path=None)
    env.run("2.1.296", upgrade=True)  # Retained version selected again explicitly.
    with pytest.raises(env.m.Blocked, match="rollback_takes_no_artifact"):
        env.run("2.1.295", action="rollback")


def test_retention_is_bounded_without_pruning(env):
    for version in ("2.1.295", "2.1.296", "2.1.297"):
        env.run(version, upgrade=version != "2.1.295")
    snapshot = tree(env.base)
    # A reviewed lock cannot name a fourth version, so no pruning is ever needed.
    with pytest.raises(env.m.Blocked, match="invalid_release_lock"):
        env.run("2.1.298", upgrade=True, pins=env.pins)
    assert tree(env.base) == snapshot


@pytest.mark.parametrize(
    "defect",
    [
        "wrong_bytes",
        "truncated",
        "symlink",
        "hardlink",
        "group_writable",
        "directory",
        "not_elf",
        "wrong_machine",
    ],
)
def test_bad_or_replaced_artifacts_refuse_before_any_write(env, defect):
    path = env.files["2.1.295"]
    pin = env.pins["2.1.295"]
    if defect == "wrong_bytes":
        path.write_bytes(path.read_bytes().replace(b"2.1.295", b"2.1.299"))
    elif defect == "truncated":
        path.write_bytes(path.read_bytes()[:-1])
    elif defect == "symlink":
        link = env.tmp / "link"
        link.symlink_to(path)
        path = link
    elif defect == "hardlink":
        os.link(path, env.tmp / "alias")
    elif defect == "group_writable":
        path.chmod(0o775)
    elif defect == "directory":
        path = env.tmp
    else:
        binary = (
            b"#!/bin/sh\n" + bytes(502)
            if defect == "not_elf"
            else synthetic_elf("2.1.295", machine=183)
        )
        path.write_bytes(binary)
        pin, _, _ = pin_for(env.m, env.signer, "2.1.295", binary)
        env.pins["2.1.295"] = pin
    with pytest.raises(env.m.Blocked):
        env.run(path=path)
    assert not env.base.exists()


def test_artifact_is_required_and_never_fetched(env):
    with pytest.raises(env.m.Blocked, match="artifact_required"):
        env.run(path=None)
    assert not env.base.exists()


@pytest.mark.parametrize("kind", ["file", "symlink"])
@pytest.mark.parametrize("where", ["usrbin", "localbin"])
def test_foreign_claude_commands_block_install(env, kind, where):
    folder = getattr(env, where)
    if kind == "file":
        (folder / "claude").write_bytes(b"personal")
    else:
        (folder / "claude").symlink_to("/nonexistent")
    with pytest.raises(env.m.Blocked, match="foreign_claude_command"):
        env.run()
    assert not env.base.exists()


def test_path_collision_blocks_and_personal_homes_are_never_read(env, monkeypatch):
    (env.pathbin / "claude").write_bytes(b"alternate")
    with pytest.raises(env.m.Blocked, match="path_collision"):
        env.run()
    assert not env.base.exists()
    opened = []
    real_open = os.open
    monkeypatch.setattr(
        os, "open", lambda p, *a, **k: opened.append(str(p)) or real_open(p, *a, **k)
    )
    (env.pathbin / "claude").unlink()
    env.run()
    assert not any(".claude" in p or "/home/" in p or ".codex" in p for p in opened)


@pytest.mark.parametrize("value", ["", "relative", "/a/../b", "x" * 5000, "/a:" * 40])
def test_operator_path_must_be_absolute_and_bounded(env, value):
    with pytest.raises(env.m.Blocked, match="invalid_operator_path"):
        env.run(operator_path=value)


# ---- interrupted provisioning ----

PHASES = [
    "store_created",
    "intent",
    "binary_staged",
    "record_staged",
    "version_published",
    "pointer_staged",
    "pointer_committed",
]


@pytest.mark.parametrize("phase", PHASES)
def test_interrupted_install_never_silently_repairs_or_replays(env, phase):
    def fault(seen):
        if seen == phase:
            raise RuntimeError("fault")

    env.monkeypatch.setattr(env.m, "checkpoint", fault)
    with pytest.raises(RuntimeError):
        env.run()
    env.monkeypatch.setattr(env.m, "checkpoint", lambda _phase: None)
    interrupted = tree(env.base)
    # Normal install and verify refuse; all bytes are retained for the operator.
    with pytest.raises(env.m.Blocked):
        env.run()
    with pytest.raises(env.m.Blocked):
        env.run(action="verify", path=None)
    assert tree(env.base) == interrupted
    if phase in ("version_published", "pointer_staged", "pointer_committed"):
        result = env.run(None, action="recover", path=None)
        assert result["outcome"] == "recovered"
        current, installed, transaction = env.inspect()
        assert current.startswith("2.1.295-") and transaction is None
        assert set(os.listdir(env.base)) == {"current", "store.json", "versions"}
    else:
        with pytest.raises(env.m.Blocked):
            env.run(None, action="recover", path=None)
        assert tree(env.base) == interrupted


def test_interrupted_upgrade_recovers_only_its_own_transaction(env):
    env.run()

    def fault(seen):
        if seen == "pointer_staged":
            raise RuntimeError("fault")

    env.monkeypatch.setattr(env.m, "checkpoint", fault)
    with pytest.raises(RuntimeError):
        env.run("2.1.296", upgrade=True)
    env.monkeypatch.setattr(env.m, "checkpoint", lambda _phase: None)
    with pytest.raises(env.m.Blocked, match="reconciliation_required"):
        env.run("2.1.297", upgrade=True)
    assert env.run(None, action="recover", path=None)["version"] == "2.1.296"
    assert env.inspect()[0].startswith("2.1.296-")


def test_recover_takes_no_selection_inputs_and_needs_pending_transaction(env):
    env.run()
    with pytest.raises(
        env.m.Blocked, match="no_recoverable_transaction|reconciliation"
    ):
        env.run(None, action="recover", path=None)


# ---- tampering and manipulation of an installed store ----


def key_dir(env, version="2.1.295"):
    pin = env.pins[version]
    return env.base / "versions" / (pin["version"] + "-" + pin["binary_sha256"])


@pytest.mark.parametrize(
    "defect",
    [
        "binary_flip",
        "binary_symlink",
        "binary_hardlink",
        "binary_mode",
        "record_changed",
        "extra_file",
        "version_dir_symlink",
        "current_foreign_link",
        "current_regular_file",
        "unknown_version_dir",
        "store_marker",
        "extra_top_level",
        "pending_next_link",
    ],
)
def test_store_tampering_or_symlink_manipulation_blocks_every_operation(env, defect):
    env.run()
    folder = key_dir(env)
    binary = folder / "claude"
    if defect == "binary_flip":
        data = bytearray(binary.read_bytes())
        data[200] ^= 1
        binary.chmod(0o755)
        binary.write_bytes(bytes(data))
    elif defect == "binary_symlink":
        data = binary.read_bytes()
        binary.unlink()
        (env.tmp / "elsewhere").write_bytes(data)
        binary.symlink_to(env.tmp / "elsewhere")
    elif defect == "binary_hardlink":
        os.link(binary, env.tmp / "alias")
    elif defect == "binary_mode":
        binary.chmod(0o775)
    elif defect == "record_changed":
        (folder / "record.json").write_bytes(b"{}\n")
    elif defect == "extra_file":
        (folder / "extra").write_bytes(b"x")
    elif defect == "version_dir_symlink":
        moved = env.tmp / "moved"
        folder.rename(moved)
        folder.symlink_to(moved)
    elif defect == "current_foreign_link":
        (env.base / "current").unlink()
        (env.base / "current").symlink_to("/opt/agent-platform-codex/current")
    elif defect == "current_regular_file":
        (env.base / "current").unlink()
        (env.base / "current").write_bytes(b"x")
    elif defect == "unknown_version_dir":
        (env.base / "versions" / "9.9.9-" / "x").parent.mkdir()
    elif defect == "store_marker":
        (env.base / "store.json").write_bytes(b"{}\n")
    elif defect == "extra_top_level":
        (env.base / "personal").write_bytes(b"x")
    else:
        (env.base / ".current.next").symlink_to("versions/x")
    snapshot = tree(env.base)
    with pytest.raises((env.m.Blocked, OSError)):
        env.inspect()
    for kwargs in (dict(), dict(action="verify", path=None)):
        with pytest.raises((env.m.Blocked, OSError)):
            env.run(**kwargs)
    assert tree(env.base) == snapshot  # Nothing repaired, deleted or rewritten.


def test_verify_is_read_only_and_checks_a_supplied_artifact(env):
    env.run()
    snapshot = tree(env.tmp)
    assert env.run(action="verify")["outcome"] == "verified"
    assert env.run(action="verify", path=None)["outcome"] == "verified"
    env.files["2.1.295"].write_bytes(env.files["2.1.295"].read_bytes() + b"x")
    with pytest.raises(env.m.Blocked):
        env.run(action="verify")
    assert {k: v for k, v in tree(env.tmp).items() if k.startswith("opt")} == {
        k: v for k, v in snapshot.items() if k.startswith("opt")
    }


# ---- hermetic: no network, no process, no execution, no vendor probes ----


def test_provisioner_cannot_reach_network_or_execute_anything(env, monkeypatch):
    tree_ = ast.parse((ROOT / "provisioning/claude_upstream.py").read_text())
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree_)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree_)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported <= {
        "argparse", "base64", "contextlib", "fcntl", "hashlib", "json", "os",
        "pathlib", "platform", "re", "resource", "stat", "struct", "sys",
    }  # fmt: skip
    attributes = {n.attr for n in ast.walk(tree_) if isinstance(n, ast.Attribute)}
    names = {n.id for n in ast.walk(tree_) if isinstance(n, ast.Name)}
    assert not attributes & {
        "system", "popen", "execv", "execve", "execvp", "spawnv", "fork",
        "environ", "getenv", "expanduser", "putenv",
    }  # fmt: skip
    assert not names & {"eval", "exec", "compile", "__import__"}
    strings = {n.value for n in ast.walk(tree_) if isinstance(n, ast.Constant)}
    assert not [
        x for x in strings if isinstance(x, str) and x.startswith(("~", "/home"))
    ]
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("process"))
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: pytest.fail("network"))
    monkeypatch.setattr(os, "execv", lambda *_a: pytest.fail("exec"))
    env.run()
    env.run("2.1.296", upgrade=True)
    env.run("2.1.295", action="rollback", path=None)


def test_installed_toolchain_is_inventory_only(env):
    env.run()
    result = env.run(action="verify", path=None)
    assert result["launch_allowed"] is False and result["authentication"] == "NOT_RUN"
    record = json.loads((key_dir(env) / "record.json").read_text())
    assert record["purpose"] == "toolchain_inventory_only"
    assert "harness_id" not in record and "selected" not in record


# ---- command line ----


@pytest.mark.parametrize(
    "argv",
    [
        [
            "install",
            "--version",
            "2.1.295",
            "--artifact",
            "/x",
            "--operator-path",
            "/usr/bin",
        ],
        ["install", "--version", "2.1.295", "--approve", "--operator-path", "/usr/bin"],
        ["install", "--approve", "--artifact", "/x", "--operator-path", "/usr/bin"],
        ["rollback", "--version", "2.1.295", "--operator-path", "/usr/bin"],
        ["recover", "--approve", "--version", "2.1.295", "--operator-path", "/usr/bin"],
        ["verify", "--approve", "--operator-path", "/usr/bin"],
        ["verify", "--upgrade", "--operator-path", "/usr/bin"],
        ["install", "--version", "2.1.295", "--approve", "--artifact", "/x"],
        ["install", "--url", "https://example.invalid/claude", "--approve"],
        ["download", "--approve", "--operator-path", "/usr/bin"],
    ],
)
def test_cli_requires_explicit_approval_and_has_no_fetch_interface(argv):
    with pytest.raises(SystemExit) as raised:
        module().main(argv)
    assert raised.value.code == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="needs an unprivileged caller")
def test_cli_refuses_untrusted_checkout_code(capsys):
    code = module().main(["verify", "--operator-path", "/usr/bin"])
    out = json.loads(capsys.readouterr().out)
    assert code == 13 and out["status"] == "BLOCKED" and out["launch_allowed"] is False
