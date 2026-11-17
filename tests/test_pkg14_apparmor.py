"""F-02 source contracts and fabricated descriptor mediation, never kernel proof."""

import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_platform import worker_publish_io as intake
from agent_platform.worker_publish_artifact import Blocked

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = "0fbc940ae94144f8cc29c9a0fd98afc704f58168"
COMMON = {
    "/",
    "/etc/",
    "/etc/ap-publisher/",
    "/run/",
    "/run/credentials/",
    "/usr/",
    "/usr/lib/",
    "/usr/lib/ap-worker-publisher/",
    "/usr/lib/ap-worker-publisher/agent_platform/",
    "/var/",
    "/var/lib/",
}
MODULES = (
    "worker_publisher",
    "worker_publish_io",
    "worker_publish_artifact",
    "worker_publish_signer",
    "worker_publish_export",
)


def unit(role):
    return "ap-worker-publisher" + ("-signer" if role == "signer" else "")


def directories(role):
    return COMMON | {
        f"/run/credentials/{unit(role)}.service/",
        "/var/lib/ap-publisher" + ("-signer" if role == "signer" else "") + "/",
    }


def leaves(role):
    result = {"/etc/ap-publisher/job.json", "/etc/ap-publisher/receipts.json"}
    result |= {f"/usr/lib/ap-worker-publisher/agent_platform/{m}.py" for m in MODULES}
    if role == "publisher":
        result |= {
            "/etc/ap-publisher/candidate.json",
            "/var/lib/ap-publisher/journal",
            "/run/credentials/ap-worker-publisher.service/app-jwt",
        }
    else:
        result |= {
            "/var/lib/ap-publisher-signer/journal",
            "/run/credentials/ap-worker-publisher-signer.service/app-key",
        }
    return result


def load_lifecycle():
    spec = importlib.util.spec_from_file_location(
        "pkg14_lifecycle", ROOT / "packaging/debian/worker_upgrade_lifecycle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profiles():
    return {
        unit(role): (
            ROOT / "packaging/worker-publisher" / (unit(role) + ".apparmor")
        ).read_bytes()
        for role in ("publisher", "signer")
    }


def historical_profiles():
    m = load_lifecycle()
    # Removing only the exact approved block reconstructs the unchanged historical
    # bytes, whose digests are independently pinned. No network/object fallback.
    anchor = b"  #include <abstractions/python>\n"
    return {
        name: data.replace(anchor + m.PROFILE_ADDITIONS[name].encode(), anchor, 1)
        for name, data in profiles().items()
    }


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_exact_profile_inventory_and_descriptor_ancestor_union(role):
    m = load_lifecycle()
    data = profiles()[unit(role)]
    old = historical_profiles()[unit(role)]
    assert hashlib.sha256(old).hexdigest() == m.HISTORICAL_PROFILES[unit(role)]
    block = m.PROFILE_ADDITIONS[unit(role)]
    allow = {
        line.strip().split()[0]
        for line in block.splitlines()
        if line.strip().endswith(" r,") and not line.strip().startswith("deny ")
    }
    assert allow == directories(role)
    required = {
        str(p) + ("/" if str(p) != "/" else "")
        for leaf in leaves(role)
        for p in Path(leaf).parents
    }
    assert required == allow
    # Exact old hash + insertion protects all existing includes, leaf rules,
    # denies, network/ptrace/signal policy and disallows injected rules/drop-ins.
    m.validate_profile_transition(historical_profiles(), profiles(), "pkg11")
    assert b"/** r," not in block.encode() and " w," not in block
    opposite = "publisher" if role == "signer" else "signer"
    assert f"/run/credentials/{unit(opposite)}.service/" not in allow
    assert "/etc/ap-publisher-keys/" not in allow
    assert "/run/ap-publisher-signer/" not in allow
    assert (
        "/var/lib/ap-publisher" + ("-signer" if opposite == "signer" else "") + "/"
        not in allow
    )
    for path in ("/home/**", "/root/**", "/proc/*/{mem,environ,fd/**,map_files/**}"):
        assert f"deny {path} rwklmx," in data.decode()


def fabricated_walk(monkeypatch, allowed_dirs, allowed_files):
    """Exercise actual intake control flow with synthetic denied/open descriptors.

    This is NOT an AppArmor evaluator, UID isolation or kernel-enforcement test.
    """
    fds, reads, opened = {}, {}, []

    def fake_open(path, flags, *args, dir_fd=None, **kwargs):
        absolute = path if dir_fd is None else str(Path(fds[dir_fd]) / path)
        isdir = bool(flags & os.O_DIRECTORY)
        name = absolute + ("/" if absolute != "/" and isdir else "")
        if name not in (allowed_dirs if isdir else allowed_files):
            raise PermissionError("synthetic mediation refusal")
        assert flags & os.O_NOFOLLOW
        fd = len(fds) + 10
        fds[fd], reads[fd] = absolute, False
        if isdir:
            opened.append(name)
        return fd

    def fake_stat(fd):
        directory = fds[fd] + ("/" if fds[fd] != "/" else "") in allowed_dirs
        return SimpleNamespace(
            st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o400),
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=1,
            st_dev=1,
            st_ino=fd,
            st_mtime_ns=1,
            st_ctime_ns=1,
        )

    def fake_read(fd, limit):
        value = b"" if reads[fd] else b"x"
        reads[fd] = True
        return value

    fake = SimpleNamespace(
        **{
            k: getattr(os, k)
            for k in ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
        },
        open=fake_open,
        fstat=fake_stat,
        close=lambda fd: None,
        read=fake_read,
    )
    monkeypatch.setattr(intake, "os", fake)
    return opened


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_actual_read_file_walk_uses_exact_allowed_ancestors(monkeypatch, role):
    opened = fabricated_walk(monkeypatch, directories(role), leaves(role))
    for path in leaves(role):
        assert intake.read_file(path, 0, 100) == b"x"
    assert set(opened) == directories(role)


@pytest.mark.parametrize(
    "role,missing",
    [(r, p) for r in ("publisher", "signer") for p in sorted(directories(r))],
)
def test_missing_each_directory_rule_blocks_actual_walk(monkeypatch, role, missing):
    fabricated_walk(monkeypatch, directories(role) - {missing}, leaves(role))
    path = next(
        p for p in sorted(leaves(role)) if missing == "/" or p.startswith(missing)
    )
    with pytest.raises(PermissionError):
        intake.read_file(path, 0, 100)


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_cross_role_private_paths_and_alternate_credential_units_block(
    monkeypatch, role
):
    opposite = "publisher" if role == "signer" else "signer"
    fabricated_walk(monkeypatch, directories(role), leaves(role))
    forbidden = leaves(opposite) - leaves(role)
    forbidden |= {
        "/etc/ap-publisher-keys/worker.pem",
        "/run/ap-publisher-signer/app-jwt",
        "/run/credentials/another.service/app-key",
        "/run/credentials/ap-worker-publisher@x.service/app-jwt",
    }
    for path in forbidden:
        with pytest.raises(PermissionError):
            intake.read_file(path, 0, 100)


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_credential_namespace_is_fixed_not_profile_claim(monkeypatch, role):
    expected = f"/run/credentials/{unit(role)}.service"
    for value in (
        expected + "/",
        expected + "/../other.service",
        "/tmp/credential",
        "/run/credentials/other.service",
    ):
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", value)
        with pytest.raises(Blocked):
            intake.credential_path(role)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", expected)
    assert intake.credential_path(role).startswith(expected + "/")


@pytest.mark.parametrize("name", ["ap-worker-publisher", "ap-worker-publisher-signer"])
@pytest.mark.parametrize(
    "fault",
    [
        "historical_edit",
        "missing_rule",
        "extra_rule",
        "dropin",
        "changed_deny",
        "admin_edit",
    ],
)
def test_only_exact_reviewed_historical_to_new_profile_delta(name, fault):
    m = load_lifecycle()
    old, new = historical_profiles(), profiles()
    if fault == "historical_edit":
        old[name] += b"# modified historical profile\n"
    elif fault == "missing_rule":
        new[name] = new[name].replace(b"  /run/ r,\n", b"")
    elif fault in ("extra_rule", "dropin"):
        new[name] += (
            b"  /** r,\n" if fault == "extra_rule" else b"#include <local/override>\n"
        )
    elif fault == "changed_deny":
        new[name] = new[name].replace(b"deny /home/** rwklmx,", b"/home/** r,")
    else:
        new[name] += b"# administrator override\n"
    with pytest.raises(AssertionError):
        m.validate_profile_transition(old, new, "pkg11")


def test_historical_upgrade_remains_exact_and_unknown_series_refused():
    m = load_lifecycle()
    old = historical_profiles()
    m.validate_profile_transition(old, old, "pkg09")
    with pytest.raises(AssertionError):
        m.validate_profile_transition(old, profiles(), "pkg09")
    with pytest.raises(AssertionError):
        m.validate_profile_transition(old, profiles(), "unknown")


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_profiles_parse_without_kernel_load_or_cache(role):
    parser = shutil.which("apparmor_parser")
    if parser is None:
        pytest.skip(
            "NOT_RUN: apparmor_parser unavailable; no installation or kernel fallback"
        )
    result = subprocess.run(
        [
            parser,
            "--skip-kernel-load",
            "--skip-cache",
            str(ROOT / "packaging/worker-publisher" / (unit(role) + ".apparmor")),
        ],
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0


def test_upgrade_keeps_conflict_continuity_and_no_activation_contract():
    source = (ROOT / "packaging/debian/worker_upgrade_lifecycle.py").read_text()
    assert source.index("validate_profile_transition(old_profiles") < source.index(
        "call(local_install_argv(old_control"
    )
    assert "assert edited_path.read_bytes() == edited_bytes" in source
    assert "edited_path.write_bytes(new_profiles[edited_name])" in source
    assert "assert snapshot() == before" in source
    assert '"profile_kernel_enforcement": "NOT_RUN"' in source
    assert "assert not marker.exists()" in source
    preinst = (ROOT / "packaging/worker-provisioning/preinst").read_text()
    assert '"/etc/systemd/system/$unit.service.d"' in preinst
    assert '"/run/systemd/system/$unit.service.d"' in preinst
    assert 'test -e "$path" || test -L "$path"' in preinst


def test_real_descriptor_walk_refuses_symlink_parent_without_reading_target(
    tmp_path, monkeypatch
):
    real = tmp_path / "real"
    real.mkdir()
    (real / "job.json").write_bytes(b"fabricated only")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    real_stat = intake.os.fstat

    def trusted_directory(fd):
        meta = real_stat(fd)
        # Synthetic ownership only; real O_NOFOLLOW opens still reject the alias.
        if stat.S_ISDIR(meta.st_mode):
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
        return meta

    monkeypatch.setattr(intake.os, "fstat", trusted_directory)
    with pytest.raises(OSError):
        intake.read_file(
            str(alias / "job.json"), os.getuid(), 100, writable_parent=True
        )
    assert (real / "job.json").read_bytes() == b"fabricated only"


def test_handoff_documents_policy_listing_and_unexecuted_gates():
    doc = (ROOT / "docs/pkg14-publisher-apparmor.md").read_text()
    for word in (
        "listing",
        "DAC",
        "conffile",
        "STOP",
        "HOST_NOT_RUN",
        "NOT_RUN",
        "Gate #73",
        "CI_ONLY",
        "0.1.0-8",
        "reboot",
        "#160",
    ):
        assert word in doc
