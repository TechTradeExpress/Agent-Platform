"""Build historical experimental test artifacts with their original pinned recipe.

CI-only: never installs anything. Both old revisions are synthetic fixtures,
not new release candidates and not part of the current two-role builder output.
"""

import hashlib
import importlib.util
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

BASE = "2f6e7729badc772d40900ae02e2cdc86dc9bb591"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("one fresh output parent required")
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    # Fixed Git object; no checkout switch, fetch, network or target-supplied code.
    data = subprocess.check_output(["git", "archive", BASE], cwd=root, timeout=30)
    epoch = int(
        subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", BASE], cwd=root, timeout=10
        )
    )
    with tempfile.TemporaryDirectory(prefix="ap-legacy-fixture-") as temp:
        source = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(source, filter="data")
        recipe = source / "packaging/build_deb.py"
        expected = subprocess.check_output(
            ["git", "show", BASE + ":packaging/build_deb.py"], cwd=root, timeout=10
        )
        assert (
            hashlib.sha256(recipe.read_bytes()).digest()
            == hashlib.sha256(expected).digest()
        )
        spec = importlib.util.spec_from_file_location("legacy_deb_fixture", recipe)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for revision in (1, 2):
            module.build(source, output / f"legacy-{revision}", revision, BASE, epoch)


if __name__ == "__main__":
    main()
