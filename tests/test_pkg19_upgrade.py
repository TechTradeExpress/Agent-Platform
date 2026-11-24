"""Offline real dpkg unpack in an unprivileged, disconnected mount namespace."""

import io
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
from test_pkg09_versioning import ROOT, load

OLD = "73bb2d521347ec87fb2c584ada8ee86a0ab3eaba"
ARCHIVE = "3169158d734d7b4dd11e12e8c582bc992d81cf68"
FIELDS = (
    "ActiveState=inactive\nSubState=dead\nLoadState=loaded\nMainPID=0\n"
    "ControlPID=0\nJob=\nTransient=no\nType=oneshot\nRestart=no\nControlGroup=\n"
)
FROZEN = FIELDS.replace("ActiveState=inactive", "ActiveState=failed").replace(
    "SubState=dead", "SubState=failed"
)


@pytest.fixture(scope="module")
def archives(tmp_path_factory):
    root = tmp_path_factory.mktemp("pkg19")
    builder = load("pkg19_builder", "packaging/build_deb.py")
    with tarfile.open(
        fileobj=io.BytesIO(
            subprocess.check_output(["git", "archive", OLD], cwd=ROOT, timeout=15)
        )
    ) as source:
        source.extractall(root / "historical", filter="data")
    old_source = root / "historical"
    historical = load("pkg19_historical_builder", old_source / "packaging/build_deb.py")
    old_tree = subprocess.check_output(
        ["git", "rev-parse", OLD + "^{tree}"], cwd=ROOT, text=True, timeout=15
    ).strip()
    epoch = int(
        subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", OLD], cwd=ROOT, timeout=15
        )
    )
    old = historical.build(
        old_source,
        root / "old",
        8,
        OLD,
        epoch,
        source_tree=old_tree,
        candidate=True,
    )
    new = builder.build(
        ROOT,
        root / "next",
        9,
        ARCHIVE,
        1700000001,
        source_tree="b" * 40,
        candidate=True,
    )
    return old, new


def test_candidate_order_and_release_barriers(archives, tmp_path):
    old, new = archives
    for role in new:
        versions = [
            subprocess.check_output(
                ["dpkg-deb", "-f", str(packages[role]), "Version"], text=True
            ).strip()
            for packages in (old, new)
        ]
        assert versions == [f"0.1.0-8~git{OLD}", f"0.1.0-9~git{ARCHIVE}"]
        for previous in ("0.1.0-7", versions[0], "0.1.0-8"):
            subprocess.run(
                ["dpkg", "--compare-versions", versions[1], "gt", previous],
                check=True,
            )
    builder = load("pkg19_release_gate", "packaging/build_deb.py")
    for flags in (
        {},
        {"ci_final_fixture": True},
        {"ci_final_fixture": True, "candidate": True},
    ):
        with pytest.raises(ValueError):
            builder.build(
                ROOT,
                tmp_path / "forbidden",
                9,
                ARCHIVE,
                1700000001,
                source_tree="b" * 40,
                **flags,
            )


@pytest.fixture(scope="module")
def driver():
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        pytest.skip("bwrap unavailable")
    prefix = [
        bwrap,
        "--unshare-all",
        "--uid",
        "0",
        "--gid",
        "0",
        "--cap-add",
        "CAP_SYS_CHROOT",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
    ]
    check = subprocess.run([*prefix, "--", "/usr/bin/true"], capture_output=True)
    if check.returncode:
        pytest.skip("isolated namespace unavailable")
    return prefix


def provision(root):
    for directory in (
        "usr/libexec",
        "usr/lib/systemd/system",
        "etc/apparmor.d",
        "var/lib/dpkg",
        "usr/bin",
        "tmp",
    ):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "var/lib/dpkg/status").touch()
    commands = ("sh", "timeout", "stat", "find", "dpkg-query", "sort", "awk", "sed")
    for command in commands:
        binary = Path("/usr/bin") / command
        shutil.copyfile(binary, root / "usr/bin" / command)
        (root / "usr/bin" / command).chmod(0o755)
        libraries = subprocess.check_output(["ldd", str(binary)], text=True)
        for library in re.findall(r"(/[^\s]+)\s+\(", libraries):
            target = root / library.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(library, target)
            target.chmod(0o755)
    (root / "bin").symlink_to("usr/bin")
    for directory in root.rglob("*"):
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(0o755)


def unpack(driver, root, archive):
    return subprocess.run(
        [
            *driver,
            "--bind",
            str(root),
            "/fixture",
            "--ro-bind",
            str(archive),
            "/candidate.deb",
            "--dev",
            "/dev",
            "--dev",
            "/fixture/dev",
            "--",
            "/usr/bin/dpkg",
            "--root=/fixture",
            "--unpack",
            "/candidate.deb",
        ],
        env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"},
        capture_output=True,
        timeout=20,
    )


@pytest.mark.parametrize(
    "state",
    [
        "failed",
        "inactive",
        "active",
        "unknown",
        "missing",
        "transient",
        "pending",
        "control_pid",
        "main_pid",
        "duplicate",
        "restart",
        "changing",
        "populated",
    ],
)
def test_offline_worker_upgrade_preserves_frozen_v4(driver, archives, tmp_path, state):
    old, new = archives
    root = tmp_path / "root"
    provision(root)
    first = unpack(driver, root, old["worker"])
    assert first.returncode == 0, first.stderr
    (root / "run/systemd/system").mkdir(parents=True)
    frozen = [
        "var/lib/ap-publisher/journal",
        "var/lib/ap-publisher-signer/journal",
        "run/ap-publisher-signer/app-jwt",
        "etc/ap-publisher/job.json",
        "etc/ap-publisher/homelab-candidate.json",
        "run/systemd/system.control/ap-worker-publisher.service.d/50-IPAddressAllow.conf",
    ]
    for item in frozen:
        target = root / item
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("synthetic immutable " + item)
        target.chmod(0o400)

    facts = {
        "inactive": FIELDS,
        "active": FROZEN.replace("State=failed", "State=active"),
        "unknown": FROZEN.replace("MainPID=0\n", ""),
        "missing": FIELDS.replace("LoadState=loaded", "LoadState=not-found"),
        "transient": FROZEN.replace("Transient=no", "Transient=yes"),
        "pending": FROZEN.replace("Job=", "Job=12"),
        "control_pid": FROZEN.replace("ControlPID=0", "ControlPID=17"),
        "main_pid": FROZEN.replace("MainPID=0", "MainPID=23"),
        "duplicate": FROZEN + "MainPID=0\n",
        "restart": FROZEN.replace("Restart=no", "Restart=on-failure"),
    }.get(state, FROZEN)
    (root / "etc/publisher-state").write_text(facts)
    (root / "etc/signer-state").write_text(FIELDS)
    if state == "changing":
        (root / "etc/change-state").touch()
    if state == "populated":
        cgroup = root / "sys/fs/cgroup/system.slice/ap-worker-publisher.service"
        cgroup.mkdir(parents=True)
        (cgroup / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    stub = root / "usr/bin/systemctl"
    stub.write_text(
        "#!/bin/sh\n"
        'test "$#" = 4 && test "$1" = show && test "$2" = --all || exit 81\n'
        'case "$3" in --property=ActiveState,*) ;; *) exit 82;; esac\n'
        'case "$4" in\n'
        "ap-worker-publisher.service) state=/etc/publisher-state;;\n"
        "ap-worker-publisher-signer.service) state=/etc/signer-state;;\n"
        "*) exit 83;; esac\n"
        'if test -f /etc/change-state && test "$state" = /etc/publisher-state; then\n'
        '  if test -f /tmp/query; then printf "MainPID=1\\n"; fi; : >/tmp/query\n'
        "fi\n"
        'while IFS= read -r line; do printf "%s\\n" "$line"; done < "$state"\n'
    )
    stub.chmod(0o755)

    def snapshot():
        return [
            (
                (root / item).read_bytes(),
                (root / item).stat().st_ino,
                (root / item).stat().st_mode,
            )
            for item in frozen
        ]

    unit_paths = [
        root / f"usr/lib/systemd/system/ap-worker-publisher{suffix}.service"
        for suffix in ("", "-signer")
    ]
    old_units = [unit.read_bytes() for unit in unit_paths]
    before = snapshot()
    result = unpack(driver, root, new["worker"])
    status = (root / "var/lib/dpkg/status").read_text()
    if state in ("failed", "inactive"):
        assert result.returncode == 0, result.stderr
        assert f"Version: 0.1.0-9~git{ARCHIVE}" in status
    else:
        assert (
            result.returncode != 0 and b"worker_package_path_conflict" in result.stderr
        )
        assert f"Version: 0.1.0-8~git{OLD}" in status
    assert snapshot() == before
    assert [unit.read_bytes() for unit in unit_paths] == old_units
    assert (root / "etc/publisher-state").read_text() == facts
