"""Static checks use the actual revision 9 archives and never start systemd."""

import io
import subprocess
import tarfile

import pytest
from test_pkg19_upgrade import archives  # noqa: F401
from test_worker_publish_recovery_paths import UNITS

from agent_platform import worker_publish_recovery_paths as recovery


@pytest.mark.parametrize("role", ["signer", "publisher"])
def test_exact_debian_recovery_unit_contract(archives, role):  # noqa: F811
    _, candidates = archives
    unit = recovery.role_unit(role)
    name = unit.removesuffix(".service")
    account = "ap-publisher" + ("-signer" if role == "signer" else "")
    opposite = "signer" if role == "publisher" else "publisher"
    raw = subprocess.check_output(
        ["dpkg-deb", "--fsys-tarfile", candidates["worker"]], timeout=15
    )
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:

        def read(path, source, mode):
            names = [entry for entry in archive if entry.name == "./" + path]
            (member,) = names
            assert member.isfile() and member.uid == member.gid == 0
            assert member.mode == mode
            data = archive.extractfile(member).read()
            assert data == (UNITS / source).read_bytes()
            return data.decode()

        service = read("usr/lib/systemd/system/" + unit, unit, 0o644)
        profile = read("etc/apparmor.d/" + name, name + ".apparmor", 0o644)
        executable = read("usr/libexec/" + name, name, 0o755)
    lines = service.splitlines()
    assert "[Install]" not in lines
    for directive in (
        "Type=oneshot",
        "Restart=no",
        "PrivateNetwork=yes",
        "IPAddressDeny=any",
        "RestrictAddressFamilies=AF_UNIX",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RuntimeDirectoryMode=0700",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SupplementaryGroups=",
        f"User={account}",
        f"Group={account}",
        f"AppArmorProfile={name}",
        f"ExecStart=/usr/libexec/{name}",
        f"RuntimeDirectory=ap-publisher-recovery-169-{role}",
    ):
        assert lines.count(directive) == 1
    assert not any(
        line.startswith(("IPAddressAllow=", "ExecStartPre=", "ExecStartPost="))
        for line in lines
    )
    credentials = [
        f"LoadCredential=handoff:/run/ap-publisher-recovery-169-grants/{role}.json",
        "LoadCredential=approval-pin:/etc/ap-publisher-recovery-169/approval-pin",
    ]
    if role == "signer":
        credentials.append("LoadCredential=app-key:/etc/ap-publisher-keys/worker.pem")
    assert [line for line in lines if line.startswith("LoadCredential")] == credentials
    assert [line for line in lines if line.startswith("ReadWritePaths=")] == [
        f"ReadWritePaths=/var/lib/ap-publisher-recovery-169-{role}/journal"
    ]
    assert f"-/var/lib/ap-publisher-recovery-169-{opposite}" in service
    assert f"-/run/ap-publisher-recovery-169-{opposite}" in service
    assert f"profile {name} /usr/libexec/{name} " in profile
    assert f"/run/credentials/{unit}/{{handoff,approval-pin}} r," in profile
    assert (
        f"deny /run/credentials/{recovery.role_unit(opposite)}/{{,**}} rwklmx,"
        in profile
    )
    assert (
        f"deny /var/lib/ap-publisher-recovery-169-{opposite}/{{,**}} rwklmx," in profile
    )
    assert f"deny /run/ap-publisher-recovery-169-{opposite}/{{,**}} rwklmx," in profile
    assert "deny /etc/ap-publisher{,-keys}/{,**} rwklmx," in profile
    assert "deny /run/ap-publisher-recovery-169-grants/{,**} rwklmx," in profile
    assert "deny network," in profile
    assert (f"/run/credentials/{unit}/app-key r," in profile) == (role == "signer")
    assert executable.rstrip().endswith("raise SystemExit(recovery_main())")
    assert "transport" not in executable
