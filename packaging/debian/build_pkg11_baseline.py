"""Offline -7 reconstruction with the pinned original recipe; never a host artifact.

Only local immutable objects are read. Missing/drifting evidence is BLOCKED,
never a fallback to today's recipe or permission to fetch/install/repair.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = Path(__file__).with_name("pkg11-baseline.json")
PIN_SHA256 = "a34d89322d2578b5b251fdff9d03c10de8bede676d741d58d2d7bfba6d20cb06"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-c", "credential.helper=", *args],
        cwd=ROOT,
        timeout=30,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": os.defpath,
            "LC_ALL": "C",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )


def load_pin():
    raw = PIN.read_bytes()
    if sha(raw) != PIN_SHA256:
        raise ValueError("historical_pin_mismatch_STOP")
    return json.loads(raw)


def verify_archive(archive, record, pin, role):
    expected = pin["roles"][role]
    if (
        record.get("schema") != 2
        or record.get("package") != "agent-platform-" + role
        or record.get("source_commit") != pin["source_commit"]
        or record.get("source_tree") != pin["source_tree"]
        or record.get("source_date_epoch") != pin["source_date_epoch"]
        or record.get("debian_version") != pin["version"]
        or record.get("build_kind") != "final-version-unreleased"
        or record.get("manifest_sha256") != expected["manifest_sha256"]
        or record.get("sha256") != expected["archive_sha256"]
        or sha(archive.read_bytes()) != expected["archive_sha256"]
    ):
        raise ValueError("historical_provenance_mismatch_STOP")
    raw = subprocess.check_output(
        ["dpkg-deb", "--fsys-tarfile", str(archive)],
        timeout=30,
        stderr=subprocess.DEVNULL,
    )
    with tarfile.open(fileobj=io.BytesIO(raw)) as stream:
        members = {p.name.removeprefix("./"): p for p in stream if p.isfile()}
        doc = "usr/share/doc/agent-platform-" + role + "/"
        manifest_raw = stream.extractfile(members[doc + "manifest.json"]).read()
        embedded = json.loads(stream.extractfile(members[doc + "build.json"]).read())
        if sha(manifest_raw) != expected["manifest_sha256"] or any(
            embedded.get(key) != value
            for key, value in record.items()
            if key in embedded
        ):
            raise ValueError("historical_embedded_record_mismatch_STOP")
        manifest = json.loads(manifest_raw)
        if {p["path"].removeprefix("/") for p in manifest["files"]} != set(members):
            raise ValueError("historical_payload_mismatch_STOP")
        for item in manifest["files"]:
            member = members[item["path"].removeprefix("/")]
            if (
                (member.mode, member.uid, member.gid)
                != (item["mode"], item["uid"], item["gid"])
                or item["sha256"] is not None
                and sha(stream.extractfile(member).read()) != item["sha256"]
            ):
                raise ValueError("historical_payload_mismatch_STOP")
    return {
        "archive_sha256": expected["archive_sha256"],
        "manifest_sha256": expected["manifest_sha256"],
        "size": archive.stat().st_size,
    }


def build(output):
    pin = load_pin()
    commit = pin["source_commit"]
    if (
        git("rev-parse", commit + "^{tree}").decode().strip() != pin["source_tree"]
        or int(git("show", "-s", "--format=%ct", commit)) != pin["source_date_epoch"]
    ):
        raise ValueError("historical_source_mismatch_STOP")
    with tempfile.TemporaryDirectory(prefix="ap-pkg11-historical-") as temp:
        source = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(git("archive", commit))) as archive:
            archive.extractall(source, filter="data")
        recipe = source / "packaging/build_deb.py"
        if sha(recipe.read_bytes()) != pin["recipe_sha256"]:
            raise ValueError("historical_recipe_mismatch_STOP")
        spec = importlib.util.spec_from_file_location("pkg11_original_builder", recipe)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        original.build(
            source,
            output,
            7,
            commit,
            pin["source_date_epoch"],
            source_tree=pin["source_tree"],
        )
    roles = {}
    for role in ("control", "worker"):
        package = "agent-platform-" + role
        record = json.loads((output / (package + ".provenance.json")).read_text())
        roles[role] = verify_archive(
            output / (package + "_0.1.0-7_amd64.deb"),
            record,
            pin,
            role,
        )
    (output / "baseline-verification.json").write_text(
        json.dumps(
            {
                **pin,
                "schema": "AP-PKG11-BASELINE-VERIFIED/1",
                "roles": roles,
                "result": "RECONSTRUCTED_MATCHES_REPORTED_HASHES",
                "installed_artifact_verified": False,
                "original_archive_access": "NOT_RUN",
                "host": "HOST_NOT_RUN",
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.output)
    except (
        OSError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ):
        print('{"status":"BLOCKED","reason":"historical_baseline_unverified"}')
        raise SystemExit(1) from None
