"""Rebuild the immutable worker01 baseline using its OWN recipe, never current code.

Offline Git objects required. A matching installed manifest is mandatory. The
archive hash is recorded, not represented as the operator's unknown archive hash.
No downloads, installation, mutable ref selection or credential access.
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
PIN = Path(__file__).with_name("worker-baseline.json")


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


def verify_record(record, pin):
    if (
        record.get("schema") != 2
        or record.get("phase") != "P1_INSTALL_INERT"
        or record.get("source_commit") != pin["source_commit"]
        or record.get("source_date_epoch") != pin["source_date_epoch"]
        or record.get("debian_version") != pin["version"]
        or record.get("manifest_sha256") != pin["worker_manifest_sha256"]
    ):
        raise ValueError("historical_manifest_mismatch_STOP")


def build(output):
    pin = json.loads(PIN.read_text())
    commit = pin["source_commit"]
    if (
        commit != "938c5543757c4184635e08330115527f0108064a"
        or git("rev-parse", commit + "^{tree}").decode().strip() != pin["source_tree"]
        or int(git("show", "-s", "--format=%ct", commit)) != pin["source_date_epoch"]
    ):
        raise ValueError("historical_source_mismatch")
    with tempfile.TemporaryDirectory(prefix="ap-historical-") as temp:
        source = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(git("archive", commit))) as archive:
            archive.extractall(source, filter="data")
        recipe = source / "packaging/build_deb.py"
        if hashlib.sha256(recipe.read_bytes()).hexdigest() != pin["recipe_sha256"]:
            raise ValueError("historical_recipe_mismatch")
        spec = importlib.util.spec_from_file_location("historical_builder", recipe)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        original.build(source, output, 6, commit, pin["source_date_epoch"])
    record = json.loads((output / "agent-platform-worker.provenance.json").read_text())
    verify_record(record, pin)
    archive = output / "agent-platform-worker_0.1.0-6_amd64.deb"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError("historical_archive_mismatch_STOP")
    (output / "baseline-verification.json").write_text(
        json.dumps(
            {
                **pin,
                "schema": "AP-PKG-BASELINE-VERIFIED/1",
                "rebuilt_archive_sha256": record["sha256"],
                "operator_archive_sha256": "UNKNOWN",
                "result": "MATCHED_INSTALLED_MANIFEST",
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    build(parser.parse_args().output)
