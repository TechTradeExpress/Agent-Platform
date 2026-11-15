#!/usr/bin/python3
"""Build exactly two inert P0 Debian candidates from one committed source export."""

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = {
    "control": "python3 (>= 3.12), python3-cryptography (>= 43.0.0), "
    "python3-cryptography (<< 51), git, gh",
    "worker": "python3 (>= 3.12)",
}
P1_DEPENDENCIES = (
    "python3 (>= 3.12), python3-cryptography (>= 43.0.0), "
    "python3-cryptography (<< 51), git, ca-certificates, systemd (>= 257), "
    "apparmor (>= 4.1), apparmor-utils, acl, passwd"
)
PUBLISHER_MODULES = frozenset(
    """worker_publisher worker_publish_artifact worker_publish_io
    worker_publish_signer worker_publish_export""".split()
)

PYTHON_DEPENDENCIES = ["cryptography>=43.0.0,<51"]
MODULES = {
    "control": frozenset(
        """__init__ app_api_adapter app_api_wire app_metadata
    app_signer app_signer_ipc chatgpt_handoff cli codex codex_assignment
    coding_app_identity custody_journal draft_publisher execution github_evidence
    handoff_journal isolation issues prepare process publisher publisher_candidate
    queue recovery review_comment runtime_manifest state subscription
    subscription_hold supervisor task_status worker_review_handoff""".split()
    ),
    "worker": frozenset(
        "__init__ _native_elf native_artifact runtime_manifest".split()
    ),
}
SOURCE_ONLY = frozenset(
    """_native_canary_probe _sandbox broker broker_policy
control_plane_fixture control_plane_local_runner deployment doctor native_canary
native_codex native_security
notification_outbox notifications publisher_handoff telegram_console telegram_fake
tool_dispatch_probe worker_publisher worker_publish_artifact worker_publish_io
worker_publish_signer worker_publish_export""".split()
)
ENTRY_POINTS = {
    "control": {"agent-platform-control": "agent_platform.cli:main"},
    "worker": {
        "agent-platform-worker": None,
        "agent-platform-worker-native-artifact": "agent_platform.native_artifact:main",
    },
}
DEVELOPER_SCRIPTS = {
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


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def put(root, name, data, mode=0o644):
    dest = root / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    dest.chmod(mode)


def validate(source, revision=4):
    project = tomllib.loads(checked_file(source / "pyproject.toml").decode())["project"]
    if (
        project["version"] != "0.1.0"
        or project.get("dependencies") != PYTHON_DEPENDENCIES
        or project.get("optional-dependencies", {})
        or project["scripts"] != DEVELOPER_SCRIPTS
    ):
        raise ValueError("review_version_or_dependencies")
    expected = MODULES["control"] | MODULES["worker"] | SOURCE_ONLY
    directory = source / "src/agent_platform"
    if {p.name for p in directory.iterdir() if p.suffix == ".py"} != {
        name + ".py" for name in expected
    }:
        raise ValueError("review_module_classification")
    closures = dict(MODULES)
    if revision >= 5:
        closures["publisher"] = PUBLISHER_MODULES
    for role, modules in closures.items():
        for name in modules:
            tree = ast.parse(checked_file(directory / (name + ".py")))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(
                        n.name.split(".")[1]
                        for n in node.names
                        if n.name.startswith("agent_platform.")
                    )
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        if node.level != 1:
                            raise ValueError("review_relative_import")
                        if node.module:
                            imports.add(node.module.split(".")[0])
                        else:
                            imports.update(n.name for n in node.names)
                    if node.module == "agent_platform":
                        imports.update(n.name for n in node.names)
                    elif node.module and node.module.startswith("agent_platform."):
                        imports.add(node.module.split(".")[1])
            if not imports <= modules:
                raise ValueError("review_role_import_closure_" + role)
    stanzas = checked_file(source / "debian/control").decode().strip().split("\n\n")
    if len(stanzas) != 3:
        raise ValueError("review_debian_control")
    controls = {}
    for role, stanza in zip(DEPENDENCIES, stanzas[1:], strict=True):
        fields = dict(
            line.split(": ", 1)
            for line in stanza.splitlines()
            if line and not line.startswith(" ")
        )
        if (
            fields.get("Package") != "agent-platform-" + role
            or fields.get("Source") != "agent-platform"
            or fields.get("Depends")
            != ("@WORKER_DEPENDS@" if role == "worker" else DEPENDENCIES[role])
            or fields.get("Conflicts") != "agent-platform"
            or fields.get("Architecture") != "amd64"
            or fields.get("Version") != "@VERSION@"
            or any(
                key in fields
                for key in ("Replaces", "Breaks", "Provides", "Pre-Depends")
            )
        ):
            raise ValueError("review_debian_dependencies")
        controls[role] = (
            stanza.replace(
                "@WORKER_DEPENDS@",
                P1_DEPENDENCIES if revision >= 5 else DEPENDENCIES["worker"],
            )
            + "\n"
        )
    if re.findall(
        rb"^agent-platform \(([^)]+)\)", checked_file(source / "debian/changelog"), re.M
    ) != [b"0.1.0-6", b"0.1.0-5", b"0.1.0-4", b"0.1.0-3", b"0.1.0-2", b"0.1.0-1"]:
        raise ValueError("review_changelog_version_mapping")
    return controls


def build(source, output, revision, commit, epoch):
    """Low-level staging API; fabricated commit pins are permitted only in tests.

    Public CLI exports an exact clean committed tree before calling this API.
    """
    if revision not in (3, 4, 5, 6) or not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("unsupported_candidate_identity")
    if type(epoch) is not int or not 0 <= epoch <= 2**31 - 1:
        raise ValueError("unsupported_build_epoch")
    controls = validate(source, revision)
    version = f"0.1.0-{revision}"
    output.mkdir(parents=True, exist_ok=False)
    artifacts = {}
    for role in DEPENDENCIES:
        package = "agent-platform-" + role
        private = "usr/lib/" + package + "/"
        doc = "usr/share/doc/" + package + "/"
        with tempfile.TemporaryDirectory(prefix="ap-deb-") as temp:
            stage = Path(temp) / "package"
            inputs = {}

            def copy(path, destination=None, mode=0o644, *, inputs=inputs, stage=stage):
                data = checked_file(source / path)
                inputs[path] = hashlib.sha256(data).hexdigest()
                if destination:
                    put(stage, destination, data, mode)
                return data

            for path in (
                "pyproject.toml",
                "uv.lock",
                "LICENSE",
                "debian/control",
                "debian/changelog",
                "packaging/build_deb.py",
                "docs/debian-role-package-architecture.md",
                "docs/codex-upstream-provisioning-decision.md",
            ):
                copy(path)
            for name in sorted(MODULES[role]):
                copy(
                    "src/agent_platform/" + name + ".py",
                    private + "agent_platform/" + name + ".py",
                )
            metadata = private + "agent_platform-0.1.0.dist-info/"
            p1 = role == "worker" and revision >= 5
            requires = (
                "Requires-Dist: cryptography>=43.0.0,<51\n"
                if role == "control" or p1
                else ""
            )
            put(
                stage,
                metadata + "METADATA",
                (
                    "Metadata-Version: 2.1\nName: agent-platform\nVersion: 0.1.0\n"
                    "Requires-Python: >=3.12\n" + requires
                ).encode(),
            )
            put(stage, metadata + "INSTALLER", b"dpkg\n")
            entries = "[console_scripts]\n"
            for command, entry in ENTRY_POINTS[role].items():
                prefix = f'''#!/usr/bin/python3 -I
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, "/{private.rstrip("/")}")
if sys.argv[1:] == ["--version"]:
    print("{command} 0.1.0 (Debian {version})")
    raise SystemExit(0)
'''
                if entry is None:
                    # Standalone dispatcher is the wrapper itself, not a fifth W module.
                    wrapper = (
                        prefix
                        + copy(
                            "packaging/worker-provisioning/worker_cli.py"
                            if p1
                            else "packaging/debian/worker_inventory.py"
                        ).decode()
                    )
                else:
                    module, function = entry.split(":")
                    invocation = (
                        'main(prog="agent-platform-control")'
                        if role == "control"
                        else "main()"
                    )
                    wrapper = (
                        prefix
                        + f"from {module} import {function}\n"
                        + f"raise SystemExit({invocation})\n"
                    )
                    entries += f"{command} = {entry}\n"
                put(stage, "usr/bin/" + command, wrapper.encode(), 0o755)
                operator_help = (
                    "Explicit root-only provision and codex install/rollback/recover\n"
                    "require --approve. Bare doctor is read-only;\n"
                    "doctor --issue remains "
                    "quarantined at exit 13. See worker-doctor.md."
                    if p1
                    else "No provisioning commands are enabled in P0."
                )
                manual = f""".TH {command.upper()} 1 "2026-11-14" "Agent Platform 0.1.0"
.SH NAME
{command} \\- inert Agent Platform {role} candidate
.SH SYNOPSIS
.B {command}
.RI [ options ]
.SH DESCRIPTION
Use --help for syntax. CANDIDATE / NOT_RELEASED / NO_SERVICE / NO_LIVE_AUTHORITY.
No installation-time Codex acquisition or execution.
Native and legacy execution remain blocked.
{operator_help}
.SH OPTIONS
.TP
.B --version
Report application and Debian candidate versions.
.TP
.B --help
Display command help.
"""
                put(
                    stage,
                    f"usr/share/man/man1/{command}.1.gz",
                    gzip.compress(manual.encode(), mtime=0),
                )
            put(stage, metadata + "entry_points.txt", entries.encode())
            if revision in (4, 5, 6):
                copy(
                    "packaging/debian/migrate_example.py",
                    private + "migrate-example",
                    0o755,
                )
            put(
                stage,
                "etc/" + package + "/package.conf",
                (
                    "# Inert inventory, NOT runtime authorization.\n"
                    f"version={version}\npackage_schema={1 if revision == 3 else 2}\n"
                    "execution=blocked\n"
                ).encode(),
            )
            copy("debian/copyright", doc + "copyright")
            changelog = checked_file(source / "debian/changelog")
            start = changelog.index(f"agent-platform ({version})".encode())
            put(
                stage,
                doc + "changelog.Debian.gz",
                gzip.compress(changelog[start:], mtime=0),
            )
            put(
                stage,
                doc + "examples/schema-v1.json",
                b'{"format":"AP-PKG-SYNTHETIC","schema":1,"label":"offline demo"}\n',
            )
            copy("docs/debian-package.md", doc + "README.Debian")
            conffiles = [f"/etc/{package}/package.conf"]
            preinst_data = None
            if p1:
                publisher_root = "usr/lib/ap-worker-publisher/agent_platform/"
                put(stage, publisher_root + "__init__.py", b"")
                for name in sorted(PUBLISHER_MODULES):
                    copy(
                        "src/agent_platform/" + name + ".py",
                        publisher_root + name + ".py",
                    )
                for name in (
                    "ap-worker-publisher",
                    "ap-worker-publisher-export",
                    "ap-worker-publisher-signer",
                ):
                    copy(
                        "packaging/worker-publisher/" + name,
                        "usr/libexec/" + name,
                        0o755,
                    )
                for name in ("ap-worker-publisher", "ap-worker-publisher-signer"):
                    copy(
                        "packaging/worker-publisher/" + name + ".service",
                        "usr/lib/systemd/system/" + name + ".service",
                    )
                    copy(
                        "packaging/worker-publisher/" + name + ".apparmor",
                        "etc/apparmor.d/" + name,
                    )
                    conffiles.append("/etc/apparmor.d/" + name)
                for name in ("job.example.json", "receipts.example.json"):
                    copy("packaging/worker-publisher/" + name, doc + "examples/" + name)
                for document in (
                    "worker-doctor.md",
                    "worker-doctor.schema.json",
                    "worker-pilot-checklist.md",
                ):
                    copy("docs/" + document, doc + document)
                provision = private + "provisioning/"
                copy(
                    "packaging/worker-provisioning/provision.py",
                    provision + "provision.py",
                )
                copy(
                    "packaging/worker-provisioning/worker_doctor.py",
                    provision + "worker_doctor.py",
                )
                copy("provisioning/codex_upstream.py", provision + "codex_upstream.py")
                copy(
                    "provisioning/codex-release-lock.json",
                    provision + "codex-release-lock.json",
                )
                release = json.loads(
                    checked_file(source / "provisioning/codex-release-lock.json")
                )
                code = ast.parse(
                    checked_file(source / "provisioning/codex_upstream.py")
                )
                lock_digest = next(
                    ast.literal_eval(n.value)
                    for n in code.body
                    if isinstance(n, ast.Assign)
                    and any(
                        isinstance(t, ast.Name) and t.id == "LOCK_SHA256"
                        for t in n.targets
                    )
                )
                if (
                    hashlib.sha256(
                        checked_file(source / "provisioning/codex-release-lock.json")
                    ).hexdigest()
                    != lock_digest
                ):
                    raise ValueError("review_codex_release_lock")
                evidence = set()
                for pin in release["releases"]:
                    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pin["version"]):
                        raise ValueError("review_codex_version")
                    path = pin["provenance"]["evidence"]
                    if path != f"evidence/codex-{pin['version']}-provenance.json":
                        raise ValueError("review_provisioning_evidence")
                    proof = json.loads(checked_file(source / "provisioning" / path))
                    if (
                        not re.fullmatch("[0-9a-f]{64}", proof["trusted_root_sha256"])
                        or hashlib.sha256(
                            checked_file(source / "provisioning" / path)
                        ).hexdigest()
                        != pin["provenance"]["evidence_sha256"]
                    ):
                        raise ValueError("review_provisioning_evidence")
                    evidence.update(
                        (
                            path,
                            f"evidence/codex-{pin['version']}.sigstore",
                            "evidence/sigstore-trusted-root-"
                            + proof["trusted_root_sha256"]
                            + ".json",
                        )
                    )
                for path in sorted(evidence):
                    copy("provisioning/" + path, provision + path)
                copy("docs/worker-provisioning.md", doc + "worker-provisioning.md")
                # Pure pre-unpack collision guard; no configure/remove service hooks.
                preinst = copy("packaging/worker-provisioning/preinst")
                owned = sorted(
                    "/" + str(p.relative_to(stage))
                    for p in stage.rglob("*")
                    if p.is_file()
                    and str(p.relative_to(stage)).startswith(
                        (
                            "usr/lib/ap-worker-publisher/",
                            "usr/libexec/ap-worker-publisher",
                            "usr/lib/agent-platform-worker/provisioning/",
                            "usr/lib/systemd/system/ap-worker-publisher",
                            "etc/apparmor.d/ap-worker-publisher",
                        )
                    )
                )
                closed = set()
                for item in owned:
                    if item.startswith(
                        (
                            "/usr/lib/ap-worker-publisher/",
                            "/usr/lib/agent-platform-worker/provisioning/",
                        )
                    ):
                        closed.add(item)
                        for parent in Path(item).parents:
                            text = str(parent)
                            if text.startswith(
                                (
                                    "/usr/lib/ap-worker-publisher",
                                    "/usr/lib/agent-platform-worker/provisioning",
                                )
                            ):
                                closed.add(text)
                preinst_data = preinst.replace(
                    b"@OWNED_PATHS@", "\n".join(owned).encode()
                ).replace(
                    b"@CLOSED_ROOT_ENTRIES@",
                    " | ".join(shlex.quote(x) for x in sorted(closed)).encode(),
                )

            provenance = {
                "schema": 2,
                "package": package,
                "phase": "P1_INSTALL_INERT" if p1 else "P0",
                "status": "CANDIDATE / NOT_RELEASED / NO_SERVICE / NO_LIVE_AUTHORITY",
                "application_version": "0.1.0",
                "debian_version": version,
                "source_commit": commit,
                "source_date_epoch": epoch,
                "modules": sorted(MODULES[role]),
                "dependencies": P1_DEPENDENCIES if p1 else DEPENDENCIES[role],
                "inputs": inputs,
                "synthetic_baseline": revision == 3,
            }
            if p1:
                provenance["publisher_modules"] = sorted(PUBLISHER_MODULES)
                provenance["operator_tools"] = [
                    "provision.py",
                    "codex_upstream.py",
                    "worker_doctor.py",
                ]
            put(stage, doc + "build.json", encoded(provenance))
            manifest_path = doc + "manifest.json"
            inventory = [
                {
                    "path": "/" + str(p.relative_to(stage)),
                    "mode": stat.S_IMODE(p.stat().st_mode),
                    "uid": 0,
                    "gid": 0,
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                }
                for p in sorted(stage.rglob("*"))
                if p.is_file()
            ]
            inventory.append(
                {
                    "path": "/" + manifest_path,
                    "mode": 0o644,
                    "uid": 0,
                    "gid": 0,
                    "sha256": None,
                    "digest_location": "external provenance; self-reference excluded",
                }
            )
            put(
                stage,
                manifest_path,
                encoded(
                    {"schema": 1, "files": sorted(inventory, key=lambda x: x["path"])}
                ),
            )
            size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file())
            if preinst_data is not None:
                put(stage, "DEBIAN/preinst", preinst_data, 0o755)
            put(
                stage,
                "DEBIAN/control",
                (
                    controls[role].replace("@VERSION@", version)
                    + f"Installed-Size: {(size + 1023) // 1024}\n"
                ).encode(),
            )
            put(stage, "DEBIAN/conffiles", ("\n".join(conffiles) + "\n").encode())
            sums = [
                hashlib.md5(p.read_bytes()).hexdigest()
                + "  "
                + str(p.relative_to(stage))
                for p in sorted(stage.rglob("*"))
                if p.is_file()
                and p.relative_to(stage).parts[0] not in ("DEBIAN", "etc")
            ]
            put(stage, "DEBIAN/md5sums", ("\n".join(sums) + "\n").encode())
            manifest_hash = hashlib.sha256(
                (stage / manifest_path).read_bytes()
            ).hexdigest()
            for path in sorted(stage.rglob("*")) + [stage]:
                if path.is_dir():
                    path.chmod(0o755)
                os.utime(path, (epoch, epoch))
            artifact = output / f"{package}_{version}_amd64.deb"
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
                timeout=60,
                env={
                    "PATH": os.defpath,
                    "LC_ALL": "C",
                    "SOURCE_DATE_EPOCH": str(epoch),
                },
            )
        artifacts[role] = artifact
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        (output / (package + ".provenance.json")).write_bytes(
            encoded(
                {
                    **provenance,
                    "artifact": artifact.name,
                    "sha256": digest,
                    "size": artifact.stat().st_size,
                    "manifest_sha256": manifest_hash,
                    "dpkg_deb": subprocess.check_output(
                        ["dpkg-deb", "--version"], text=True, timeout=10
                    ).splitlines()[0],
                    "python": sys.version,
                    "xz": subprocess.check_output(
                        ["xz", "--version"], text=True, timeout=10
                    ).splitlines()[0],
                }
            )
        )
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
            for p in artifacts.values()
        )
    )
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", type=int, choices=(3, 4, 5, 6), default=6)
    parser.add_argument(
        "--source-commit", default="HEAD", help="Exact committed source (default HEAD)"
    )
    args = parser.parse_args()
    commit = subprocess.check_output(
        [
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            args.source_commit + "^{commit}",
        ],
        cwd=ROOT,
        text=True,
        timeout=10,
    ).strip()
    if subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, timeout=10
    ):
        parser.error("build inputs must be committed; no dirty source attestation")
    epoch = int(
        subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", commit], cwd=ROOT, timeout=10
        )
    )
    # Export, rather than attest mutable worktree bytes with an arbitrary SHA.
    data = subprocess.check_output(["git", "archive", commit], cwd=ROOT, timeout=30)
    with tempfile.TemporaryDirectory(prefix="ap-source-") as temp:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(temp, filter="data")
        if (
            checked_file(Path(temp) / "packaging/build_deb.py")
            != Path(__file__).read_bytes()
        ):
            parser.error("selected commit has a different build recipe")
        build(Path(temp), args.output, args.revision, commit, epoch)


if __name__ == "__main__":
    main()
