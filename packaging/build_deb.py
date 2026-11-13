#!/usr/bin/python3
"""Stage a private Python application and build a real dpkg-deb candidate offline."""

import argparse
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = (
    "python3 (>= 3.12), python3-cryptography (>= 43.0.0), "
    "python3-cryptography (<< 51), git, gh"
)
PYTHON_DEPENDENCIES = ["cryptography>=43.0.0,<51"]

ENTRY_POINTS = {
    "agent-platform": "agent_platform.cli:main",
    "agent-platform-broker": "agent_platform.broker:main",
    "agent-platform-native-canary": "agent_platform.native_canary:main",
    "agent-platform-native-artifact": "agent_platform.native_artifact:main",
}


def checked_file(path):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
        raise ValueError("non_regular_input")
    return path.read_bytes()


def put(root, name, data, mode=0o644):
    dest = root / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(mode)


def build(source, output, revision, commit, epoch):
    if revision not in (1, 2) or not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("unsupported_candidate_identity")
    project = tomllib.loads(checked_file(source / "pyproject.toml").decode())["project"]
    if (
        project["version"] != "0.1.0"
        or project.get("dependencies") != PYTHON_DEPENDENCIES
        or project.get("optional-dependencies", {})
        or project["scripts"] != ENTRY_POINTS
    ):
        raise ValueError("review_version_or_dependencies")
    version = f"{project['version']}-{revision}"
    changelog_input = checked_file(source / "debian/changelog")
    if re.findall(rb"^agent-platform \(([^)]+)\)", changelog_input, re.M) != [
        b"0.1.0-2",
        b"0.1.0-1",
    ]:
        raise ValueError("review_changelog_version_mapping")
    if f"Depends: {DEPENDENCIES}\n".encode() not in checked_file(
        source / "debian/control"
    ):
        raise ValueError("review_debian_dependencies")
    if type(epoch) is not int or not 0 <= epoch <= 2**31 - 1:
        raise ValueError("unsupported_build_epoch")
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ap-deb-") as temp:
        stage = Path(temp) / "package"
        inputs = {
            p: hashlib.sha256(checked_file(source / p)).hexdigest()
            for p in (
                "pyproject.toml",
                "uv.lock",
                "LICENSE",
                "debian/control",
                "debian/changelog",
                "debian/copyright",
                "packaging/build_deb.py",
            )
        }

        def copy(path, destination, mode=0o644):
            data = checked_file(source / path)
            inputs[path] = hashlib.sha256(data).hexdigest()
            put(stage, destination, data, mode)

        for path in sorted((source / "src/agent_platform").glob("*.py")):
            # PUB-01 is source-only; no deployed handoff/activation component.
            if path.name == "publisher_handoff.py" or path.name.startswith(
                "worker_publish"
            ):
                # PUB-02 has an explicit separately reviewed operator installation.
                continue
            copy(
                str(path.relative_to(source)),
                "usr/lib/agent-platform/agent_platform/" + path.name,
            )
        private = "usr/lib/agent-platform/"
        metadata = private + "agent_platform-0.1.0.dist-info/"
        put(
            stage,
            metadata + "METADATA",
            b"Metadata-Version: 2.1\nName: agent-platform\n"
            b"Version: 0.1.0\nRequires-Python: >=3.12\n"
            b"Requires-Dist: cryptography>=43.0.0,<51\n",
        )
        put(stage, metadata + "INSTALLER", b"dpkg\n")
        entry_points = "[console_scripts]\n"
        for command, entry in project["scripts"].items():
            if not re.fullmatch(r"agent-platform(?:-[a-z-]+)?", command):
                raise ValueError("unsupported_entry_point")
            module, function = entry.split(":")
            if (
                not re.fullmatch(r"agent_platform\.[a-z_]+", module)
                or function != "main"
            ):
                raise ValueError("unsupported_entry_point")
            entry_points += f"{command} = {entry}\n"
            wrapper = f'''#!/usr/bin/python3 -I
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, "/usr/lib/agent-platform")
if sys.argv[1:] == ["--version"]:
    print("{command} 0.1.0 (Debian {version})")
    raise SystemExit(0)
from {module} import {function}
raise SystemExit({function}())
'''
            put(stage, "usr/bin/" + command, wrapper.encode(), 0o755)
            man = f""".TH {command.upper()} 1 "2026-11-04" "Agent Platform 0.1.0"
.SH NAME
{command} \\- supervised Agent Platform command
.SH SYNOPSIS
.B {command}
.RI [ options ]
.SH DESCRIPTION
Use --help for command syntax. No service is started by this package.
Native execution remains blocked. Historical helpers are not launch authority.
.SH OPTIONS
.TP
.B --version
Report the application and Debian candidate versions.
.TP
.B --help
Display command help.
"""
            put(
                stage,
                f"usr/share/man/man1/{command}.1.gz",
                gzip.compress(man.encode(), mtime=0),
            )
        put(stage, metadata + "entry_points.txt", entry_points.encode())
        if revision == 2:
            copy(
                "packaging/debian/migrate_example.py",
                private + "migrate-example",
                0o755,
            )
        put(
            stage,
            "etc/agent-platform/package.conf",
            (
                f"# Inert inventory, NOT runtime authorization.\n"
                f"package_schema={revision}\nexecution=blocked\n"
            ).encode(),
        )
        doc = "usr/share/doc/agent-platform/"
        copy("debian/copyright", doc + "copyright")
        changelog = checked_file(source / "debian/changelog")
        if revision == 1:
            changelog = changelog[changelog.index(b"agent-platform (0.1.0-1)") :]
        put(stage, doc + "changelog.Debian.gz", gzip.compress(changelog, mtime=0))
        put(
            stage,
            doc + "examples/schema-v1.json",
            b'{"format":"AP-PKG-SYNTHETIC","schema":1,"label":"offline demo"}\n',
        )
        copy("docs/debian-package.md", doc + "README.Debian")
        provenance = {
            "schema": 1,
            "application_version": "0.1.0",
            "debian_version": version,
            "source_commit": commit,
            "source_date_epoch": epoch,
            "inputs": inputs,
            "synthetic_baseline": revision == 1,
        }
        put(
            stage,
            doc + "build.json",
            (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode(),
        )
        control = (
            checked_file(source / "debian/control")
            .split(b"\n\n", 1)[1]
            .replace(b"@VERSION@", version.encode())
        )
        size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())
        put(
            stage,
            "DEBIAN/control",
            control + f"Installed-Size: {(size + 1023) // 1024}\n".encode(),
        )
        put(stage, "DEBIAN/conffiles", b"/etc/agent-platform/package.conf\n")
        sums = []
        for path in sorted(stage.rglob("*")):
            if (
                path.is_file()
                and "DEBIAN" not in path.relative_to(stage).parts
                and "etc" != path.relative_to(stage).parts[0]
            ):
                sums.append(
                    hashlib.md5(path.read_bytes()).hexdigest()
                    + "  "
                    + str(path.relative_to(stage))
                )
        put(stage, "DEBIAN/md5sums", ("\n".join(sums) + "\n").encode())
        for path in sorted(stage.rglob("*")) + [stage]:
            if path.is_dir():
                path.chmod(0o755)
            os.utime(path, (epoch, epoch))
        artifact = output / f"agent-platform_{version}_amd64.deb"
        subprocess.run(
            [
                "dpkg-deb",
                "--root-owner-group",
                "-Zxz",
                "-z6",
                "--uniform-compression",
                "--build",
                str(stage),
                str(artifact),
            ],
            check=True,
            env={"PATH": os.defpath, "LC_ALL": "C", "SOURCE_DATE_EPOCH": str(epoch)},
            timeout=60,
        )
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {artifact.name}\n")
    (output / "provenance.json").write_text(
        json.dumps(
            {
                **provenance,
                "artifact": artifact.name,
                "sha256": digest,
                "dpkg_deb": subprocess.check_output(
                    ["dpkg-deb", "--version"], text=True
                ).splitlines()[0],
            },
            indent=2,
        )
        + "\n"
    )
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = subprocess.check_output(
        [
            "git",
            "status",
            "--porcelain",
            "--",
            "src",
            "pyproject.toml",
            "packaging",
            "debian",
            "docs/debian-package.md",
        ],
        cwd=ROOT,
    )
    if dirty:
        parser.error("build inputs must be committed; no dirty source attestation")
    epoch = int(
        subprocess.check_output(["git", "show", "-s", "--format=%ct", commit], cwd=ROOT)
    )
    build(ROOT, args.output, args.revision, commit, epoch)


if __name__ == "__main__":
    main()
