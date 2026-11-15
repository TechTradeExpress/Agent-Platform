"""Synthetic-only source provisioner tests; never execute Codex or touch host paths."""

import contextlib
import copy
import gzip
import http.client
import importlib.util
import io
import json
import os
import stat
import struct
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location(
        "codex_upstream", ROOT / "provisioning/codex_upstream.py"
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def synthetic_elf(label="fixture"):
    data = bytearray(512)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3,
        62,
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


def archive_for(
    binary,
    *,
    name="codex-x86_64-unknown-linux-musl",
    kind=tarfile.REGTYPE,
    mode=0o755,
    extra=False,
):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        item = tarfile.TarInfo(name)
        item.mode = mode
        item.type = kind
        item.size = len(binary) if kind == tarfile.REGTYPE else 0
        if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            item.linkname = "/etc/fixture-secret"
        archive.addfile(item, io.BytesIO(binary) if item.size else None)
        if extra:
            item = tarfile.TarInfo("extra")
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
    return gzip.compress(output.getvalue(), mtime=0)


def release(m, version="1.0.0", binary=None, data=None):
    binary = binary or synthetic_elf(version)
    data = data or archive_for(binary)
    pin = {
        "version": version,
        "tag": "rust-v" + version,
        "release_id": 1,
        "asset_id": 1,
        "url": f"https://github.com/openai/codex/releases/download/rust-v{version}/codex-x86_64-unknown-linux-musl.tar.gz",
        "member": "codex-x86_64-unknown-linux-musl",
        "archive_size": len(data),
        "archive_sha256": m.sha(data),
        "binary_size": len(binary),
        "binary_sha256": m.sha(binary),
        "platform": "x86_64-unknown-linux-musl",
        "abi": "static-elf64-amd64-no-interpreter-no-needed",
        "provenance": {"evidence_sha256": "f" * 64},
    }
    return pin, data


@pytest.fixture
def env(tmp_path, monkeypatch):
    m = module()
    opt, bin_dir, system = (tmp_path / name for name in ("opt", "local-bin", "usr-bin"))
    for path in (opt, bin_dir, system):
        path.mkdir(mode=0o755)
        path.chmod(0o755)
    monkeypatch.setattr(m, "OWNER", os.getuid())
    monkeypatch.setattr(m, "BASE", str(opt / "store"))
    monkeypatch.setattr(m, "BIN", str(bin_dir))
    monkeypatch.setattr(m, "SYSTEM_BIN", str(system))
    monkeypatch.setattr(m, "check_platform", lambda: None)

    @contextlib.contextmanager
    def fixture_directory(path):
        # Explicit test-only authority substitution. Production has no root flag,
        # UID override or relaxed ancestor policy. Debian namespace tests use defaults.
        assert Path(path).is_relative_to(tmp_path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | m.NOFOLLOW)
        try:
            m.checked_meta(fd, True)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(m, "directory", fixture_directory)
    pins, paths = {}, {}
    for version in ("1.0.0", "2.0.0", "3.0.0", "4.0.0"):
        pin, data = release(m, version)
        pins[version] = pin
        path = tmp_path / (version + ".tar.gz")
        path.write_bytes(data)
        paths[version] = path

    def run(version="1.0.0", **kwargs):
        selected = {k: v for k, v in pins.items() if k != "4.0.0"}
        selected = kwargs.pop("pins", selected)
        if kwargs.get("action") in ("rollback", "recover"):
            kwargs.setdefault("archive", None)
        else:
            kwargs.setdefault("archive", paths.get(version))
        return m.operate(selected, version, operator_path=str(bin_dir), **kwargs)

    return m, run, pins, paths, tmp_path


def snapshot(path):
    result = {}
    for item in sorted(path.rglob("*")):
        meta = item.lstat()
        value = (
            os.readlink(item)
            if item.is_symlink()
            else item.read_bytes()
            if item.is_file()
            else None
        )
        result[str(item.relative_to(path))] = (stat.S_IMODE(meta.st_mode), value)
    return result


def test_offline_install_idempotence_upgrade_and_explicit_rollback(env):
    m, run, pins, _, temp = env
    report = run()
    assert report["launch_allowed"] is False and report["authentication"] == "NOT_RUN"
    assert Path(m.BASE, "current").readlink() == Path("versions") / m.key(pins["1.0.0"])
    before = snapshot(temp)
    assert run()["outcome"] == "already_installed"
    assert snapshot(temp) == before
    with pytest.raises(m.Blocked, match="explicit_upgrade_required"):
        run("2.0.0")
    assert snapshot(temp) == before
    run("2.0.0", upgrade=True)
    with pytest.raises(m.Blocked, match="downgrade_denied"):
        run("1.0.0", upgrade=True)
    assert run("1.0.0", action="rollback")["outcome"] == "rollback"
    assert len(list(Path(m.BASE, "versions").iterdir())) == 2


@pytest.mark.parametrize(
    "fault,recoverable",
    [
        ("store_created", False),
        ("intent", False),
        ("binary_staged", False),
        ("record_staged", False),
        ("version_published", True),
        ("command_link", True),
        ("pointer_staged", True),
        ("pointer_committed", True),
    ],
)
def test_interruption_retains_unknown_and_only_exact_published_state_recovers(
    env, monkeypatch, fault, recoverable
):
    m, run, _, _, temp = env

    def interrupt(phase):
        if phase == fault:
            raise OSError("synthetic power boundary")

    monkeypatch.setattr(m, "checkpoint", interrupt)
    with pytest.raises(OSError):
        run()
    monkeypatch.setattr(m, "checkpoint", lambda _: None)
    retained = snapshot(temp)
    with pytest.raises(m.Blocked):
        run()
    assert snapshot(temp) == retained
    if recoverable:
        assert run(action="recover")["outcome"] == "recovered"
        assert run()["outcome"] == "already_installed"
    else:
        with pytest.raises(m.Blocked):
            run(action="recover")
        assert snapshot(temp) == retained


@pytest.mark.parametrize(
    "kind",
    [
        "usr-bin",
        "command-file",
        "command-link",
        "base-link",
        "unsafe-parent",
        "unknown-store",
    ],
)
def test_foreign_files_permissions_links_and_state_are_preserved(env, kind):
    m, run, _, _, temp = env
    if kind == "usr-bin":
        Path(m.SYSTEM_BIN, "codex").write_text("foreign package executable")
    elif kind == "command-file":
        Path(m.BIN, "codex").write_text("foreign executable")
    elif kind == "command-link":
        Path(m.BIN, "codex").symlink_to("/missing-foreign")
    elif kind == "base-link":
        Path(m.BASE).symlink_to(temp / "foreign")
    elif kind == "unsafe-parent":
        Path(m.BASE).parent.chmod(0o777)
    else:
        Path(m.BASE).mkdir()
        Path(m.BASE, "unknown").write_text("retain")
    before = snapshot(temp)
    with pytest.raises((m.Blocked, OSError)):
        run()
    assert snapshot(temp) == before


def test_shadowing_and_user_auth_data_not_read_or_modified(env, monkeypatch):
    m, run, _, paths, temp = env
    home = temp / "home"
    (home / ".local/bin").mkdir(parents=True)
    codex = home / ".local/bin/codex"
    codex.write_bytes(b"foreign user tool")
    (home / ".codex").mkdir()
    credential = home / ".codex/auth.json"
    credential.write_text("synthetic credential sentinel")
    original_open = m.os.open

    def no_credential_open(path, *args, **kwargs):
        assert ".codex" not in str(path)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(m.os, "open", no_credential_open)
    before = snapshot(temp)
    with pytest.raises(m.Blocked, match="path_shadowing"):
        m.operate(
            {"1.0.0": release(m)[0]},
            "1.0.0",
            archive=paths["1.0.0"],
            operator_path=str(codex.parent) + ":" + m.BIN,
        )
    assert snapshot(temp) == before
    run()  # Explicit managed PATH; original user data remains intact.
    assert codex.read_bytes() == b"foreign user tool"
    assert credential.read_text() == "synthetic credential sentinel"


@pytest.mark.parametrize(
    "mutation", ["hash", "binary-hash", "version", "platform", "member", "url", "size"]
)
def test_bad_pin_or_archive_never_creates_store(env, mutation):
    m, run, pins, _, temp = env
    pin = copy.deepcopy(pins["1.0.0"])
    field, value = {
        "hash": ("archive_sha256", "0" * 64),
        "binary-hash": ("binary_sha256", "0" * 64),
        "version": ("tag", "rust-v99.0.0"),
        "platform": ("platform", "aarch64-unknown-linux-musl"),
        "member": ("member", "../codex"),
        "url": ("url", "https://example.invalid/file"),
        "size": ("binary_size", m.MAX_BINARY + 1),
    }[mutation]
    pin[field] = value
    before = snapshot(temp)
    with pytest.raises(m.Blocked):
        run(pins={"1.0.0": pin})
    assert snapshot(temp) == before


@pytest.mark.parametrize(
    "kind",
    [
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.DIRTYPE,
        tarfile.CHRTYPE,
        tarfile.FIFOTYPE,
    ],
)
def test_archive_links_directories_devices_and_fifos_are_refused(kind):
    m = module()
    data = archive_for(synthetic_elf(), kind=kind)
    pin, _ = release(m, data=data)
    with pytest.raises(m.Blocked):
        m.unpack(data, pin)


@pytest.mark.parametrize(
    "change",
    [
        "traversal",
        "absolute",
        "setuid",
        "writable",
        "extra",
        "corrupt",
        "bomb",
        "wrong-elf",
        "interpreter",
        "needed",
    ],
)
def test_malicious_or_broken_archive_refused_without_disk_extraction(change, tmp_path):
    m = module()
    binary = synthetic_elf()
    kwargs = {}
    if change == "traversal":
        kwargs["name"] = "../codex"
    if change == "absolute":
        kwargs["name"] = "/codex"
    if change == "setuid":
        kwargs["mode"] = 0o4755
    if change == "writable":
        kwargs["mode"] = 0o777
    if change == "extra":
        kwargs["extra"] = True
    if change == "wrong-elf":
        binary = b"not an ELF" * 52
    if change in ("interpreter", "needed"):
        binary = bytearray(binary)
        struct.pack_into("<I", binary, 64, 3 if change == "interpreter" else 2)
        if change == "needed":
            struct.pack_into("<Q", binary, 72, 128)
            struct.pack_into("<Q", binary, 96, 16)
            struct.pack_into("<qQ", binary, 128, 1, 1)
        binary = bytes(binary)
    data = archive_for(binary, **kwargs)
    if change == "corrupt":
        data = data[:-8]
    if change == "bomb":
        raw = gzip.decompress(data)
        data = gzip.compress(raw + bytes(2 * 1024**2), mtime=0)
    pin, _ = release(m, binary=binary, data=data)
    with pytest.raises(m.Blocked):
        m.unpack(data, pin)
    assert list(tmp_path.iterdir()) == []


@contextlib.contextmanager
def http_fixture(
    data, *, location=None, status=200, declared=None, truncate=False, delay=0
):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if delay:
                time.sleep(delay)
            if location:
                self.send_response(302)
                self.send_header("Location", location)
                self.end_headers()
                return
            self.send_response(status)
            self.send_header(
                "Content-Length", str(len(data) if declared is None else declared)
            )
            self.end_headers()
            try:
                self.wfile.write(data[:-1] if truncate else data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    def connector(host, timeout):
        assert host in ("github.com", "release-assets.githubusercontent.com")
        return http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=timeout
        )

    try:
        yield connector
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def test_controlled_http_fetch_and_install_uses_same_verifier(env):
    m, run, pins, paths, _ = env
    with http_fixture(paths["1.0.0"].read_bytes()) as connector:
        assert run(archive=None, connector=connector)["outcome"] == "install"
    assert run()["outcome"] == "already_installed"


@pytest.mark.parametrize(
    "location",
    [
        "http://github.com/unsafe",
        "https://evil.invalid/file",
        "https://user@release-assets.githubusercontent.com/github-production-release-asset/file",
        "https://release-assets.githubusercontent.com:444/github-production-release-asset/file",
        "file:///etc/passwd",
        "https://github.com/openai/other",
        "https://release-assets.githubusercontent.com/unknown/file",
    ],
)
def test_wrong_redirect_never_writes(env, location):
    m, run, _, paths, temp = env
    before = snapshot(temp)
    with http_fixture(paths["1.0.0"].read_bytes(), location=location) as connector:
        with pytest.raises(m.Blocked):
            run(archive=None, connector=connector)
    assert snapshot(temp) == before


@pytest.mark.parametrize("change", ["hash", "truncated", "oversized", "status", "loop"])
def test_http_failures_are_bounded_and_leave_no_state(env, change):
    m, run, _, paths, temp = env
    data = paths["1.0.0"].read_bytes()
    kwargs = {}
    if change == "hash":
        data = bytes(len(data))
    if change == "truncated":
        kwargs["truncate"] = True
    if change == "oversized":
        kwargs["declared"] = len(data) + 1
    if change == "status":
        kwargs["status"] = 503
    if change == "loop":
        kwargs["location"] = (
            "https://release-assets.githubusercontent.com/github-production-release-asset/loop"
        )
    before = snapshot(temp)
    with http_fixture(data, **kwargs) as connector:
        with pytest.raises((m.Blocked, http.client.HTTPException)):
            run(archive=None, connector=connector)
    assert snapshot(temp) == before


def test_production_lock_and_public_signature_evidence_bound_to_expected_bytes():
    m = module()
    lock = (ROOT / "provisioning/codex-release-lock.json").read_bytes()
    assert m.sha(lock) == m.LOCK_SHA256
    pin = json.loads(lock)["releases"][0]
    m.validate_pin(pin)
    evidence = (ROOT / "provisioning" / pin["provenance"]["evidence"]).read_bytes()
    assert m.sha(evidence) == pin["provenance"]["evidence_sha256"]
    record = json.loads(evidence)
    assert record["signature_verification"]["exit_code"] == 0
    assert record["signature_verification"]["candidate_executed"] is False
    assert (
        m.sha((ROOT / "provisioning/evidence/codex-0.166.0.sigstore").read_bytes())
        == record["sigstore_bundle_sha256"]
    )
    assert (
        m.sha(
            (
                ROOT
                / (
                    "provisioning/evidence/sigstore-trusted-root-"
                    + record["trusted_root_sha256"]
                    + ".json"
                )
            ).read_bytes()
        )
        == record["trusted_root_sha256"]
    )


def test_p0_closed_manifest_and_inert_worker_are_unchanged(tmp_path):
    # The source provisioner must never silently enter either P0 role payload.
    assert not list((ROOT / "src/agent_platform").glob("*provision*"))
    spec = importlib.util.spec_from_file_location(
        "p0_builder", ROOT / "packaging/build_deb.py"
    )
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    packages = builder.build(ROOT, tmp_path / "p0", 4, "a" * 40, 1700000000)
    import subprocess

    for package in packages.values():
        names = subprocess.check_output(
            ["dpkg-deb", "--contents", str(package)], text=True
        )
        assert "codex_upstream" not in names and "/provisioning/" not in names
    assert '"codex"' not in (ROOT / "packaging/debian/worker_inventory.py").read_text()


@pytest.mark.parametrize(
    "change",
    [
        "binary",
        "record",
        "hardlink",
        "mode",
        "version-link",
        "extra",
        "current",
        "missing-command",
    ],
)
def test_installed_state_tampering_never_repairs_or_overwrites(env, change):
    m, run, pins, _, temp = env
    run()
    version = Path(m.BASE, "versions", m.key(pins["1.0.0"]))
    if change == "binary":
        (version / "codex").write_bytes(b"tampered")
    if change == "record":
        (version / "record.json").write_text("{}\n")
    if change == "hardlink":
        os.link(version / "codex", temp / "aliased")
    if change == "mode":
        (version / "codex").chmod(0o777)
    if change == "version-link":
        (version / "record.json").unlink()
        (version / "record.json").symlink_to(temp / "foreign")
    if change == "extra":
        (version / "unknown").write_text("unknown")
    if change == "current":
        Path(m.BASE, "current").unlink()
        Path(m.BASE, "current").symlink_to("/foreign")
    if change == "missing-command":
        Path(m.BIN, "codex").unlink()
    before = snapshot(temp)
    with pytest.raises((m.Blocked, OSError)):
        run()
    assert snapshot(temp) == before


def test_update_interruption_keeps_previous_current_and_recover_requires_exact_intent(
    env, monkeypatch
):
    m, run, pins, _, temp = env
    run()

    def fail(phase):
        if phase == "version_published":
            raise OSError("fabricated")

    monkeypatch.setattr(m, "checkpoint", fail)
    with pytest.raises(OSError):
        run("2.0.0", upgrade=True)
    assert Path(m.BASE, "current").readlink() == Path("versions") / m.key(pins["1.0.0"])
    monkeypatch.setattr(m, "checkpoint", lambda _: None)
    journal = Path(m.BASE, "transaction.json")
    good = journal.read_bytes()
    journal.write_bytes(good.replace(b'"action":"install"', b'"action":"unknown"'))
    before = snapshot(temp)
    with pytest.raises(m.Blocked):
        run(action="recover")
    assert snapshot(temp) == before
    journal.write_bytes(good)  # Explicitly restore only fabricated test-owned bytes.
    assert run(action="recover")["version"] == "2.0.0"


def test_retention_bound_no_eviction_and_unknown_rollback(env):
    m, run, pins, _, temp = env
    with pytest.raises(m.Blocked, match="foreign_or_missing_store"):
        run("2.0.0", action="rollback")
    run()
    run("2.0.0", upgrade=True)
    run("3.0.0", upgrade=True)
    before = snapshot(temp)
    with pytest.raises(m.Blocked, match="invalid_release_lock"):
        run("4.0.0", pins=pins, upgrade=True)
    assert snapshot(temp) == before


def test_production_connector_ignores_proxy_ca_and_keylog_environment(
    monkeypatch, tmp_path
):
    m = module()
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "wrong-ca"))
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "must-not-exist"))
    connection = m.connect("github.com", 1)
    try:
        assert connection.host == "github.com" and connection.port == 443
        assert connection._context.check_hostname
        assert connection._context.verify_mode == m.ssl.CERT_REQUIRED
        assert connection._context.keylog_filename is None
        assert connection._context.minimum_version >= m.ssl.TLSVersion.TLSv1_2
    finally:
        connection.close()
    assert not list(tmp_path.iterdir())


def test_unreviewed_lock_is_refused_before_any_operations(env, monkeypatch):
    m, _, _, _, temp = env
    source = temp / "provisioner"
    source.mkdir(mode=0o755)
    (source / "codex-release-lock.json").write_text("{}\n")
    (source / "codex-release-lock.json").chmod(0o644)
    monkeypatch.setattr(m, "__file__", str(source / "codex_upstream.py"))
    with pytest.raises(m.Blocked, match="unreviewed_release_lock"):
        m.load_lock()


def test_kernel_lock_contention_refuses_without_creating_state(env):
    import fcntl

    m, run, _, _, temp = env
    fd = os.open(Path(m.BASE).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(temp)
        with pytest.raises(m.Blocked, match="provisioner_busy"):
            run()
        assert snapshot(temp) == before
    finally:
        os.close(fd)


def test_total_network_deadline_interrupts_slow_headers_without_writes(
    env, monkeypatch
):
    m, run, _, paths, temp = env
    monkeypatch.setattr(m, "NETWORK_SECONDS", 0.05)
    before = snapshot(temp)
    with http_fixture(paths["1.0.0"].read_bytes(), delay=0.2) as connector:
        with pytest.raises((m.Blocked, TimeoutError)):
            run(archive=None, connector=connector)
    assert snapshot(temp) == before


def test_valid_cdn_redirect_is_followed_only_to_pinned_bytes(env):
    m, run, _, paths, _ = env
    calls = []
    with http_fixture(paths["1.0.0"].read_bytes()) as final:
        with http_fixture(
            b"",
            location="https://release-assets.githubusercontent.com/github-production-release-asset/pinned",
        ) as first:

            def route(host, timeout):
                calls.append(host)
                return (first if host == "github.com" else final)(host, timeout)

            assert run(archive=None, connector=route)["outcome"] == "install"
    assert calls == ["github.com", "release-assets.githubusercontent.com"]


def test_noncanonical_recovery_intent_is_rejected_before_pointer_write(
    env, monkeypatch
):
    m, run, _, _, temp = env
    run()

    def stop(phase):
        if phase == "version_published":
            raise OSError("fabricated interruption")

    monkeypatch.setattr(m, "checkpoint", stop)
    with pytest.raises(OSError):
        run("2.0.0", upgrade=True)
    monkeypatch.setattr(m, "checkpoint", lambda _: None)
    intent = Path(m.BASE, "transaction.json")
    intent.write_text(json.dumps(json.loads(intent.read_bytes()), indent=2))
    before = snapshot(temp)
    with pytest.raises(m.Blocked, match="transaction_changed"):
        run(action="recover")
    assert snapshot(temp) == before


def test_recovery_rechecks_upgrade_versus_rollback_direction(env, monkeypatch):
    m, run, _, _, temp = env
    run()

    def stop(phase):
        if phase == "version_published":
            raise OSError("fabricated interruption")

    monkeypatch.setattr(m, "checkpoint", stop)
    with pytest.raises(OSError):
        run("2.0.0", upgrade=True)
    monkeypatch.setattr(m, "checkpoint", lambda _: None)
    intent = Path(m.BASE, "transaction.json")
    value = json.loads(intent.read_bytes())
    value["action"] = (
        "rollback"  # Canonical bytes, but inconsistent operation direction.
    )
    intent.write_bytes(m.encoded(value))
    before = snapshot(temp)
    with pytest.raises(m.Blocked, match="invalid_transaction_direction"):
        run(action="recover")
    assert snapshot(temp) == before
