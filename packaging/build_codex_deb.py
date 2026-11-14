#!/usr/bin/python3
"""PKG-03 preflight. Building is blocked pending exact-binary license clearance."""

import argparse
import importlib.util
import json
import tarfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "codex_input_checks", Path(__file__).resolve().parent / "codex/verify_inputs.py"
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = checks.inspect(args.archive, args.sources)
    except checks.Blocked as exc:
        result = {"status": "BLOCKED", "code": str(exc),
                  "inputs_verified": False, "package_built": False}
    except (OSError, ValueError, EOFError, tarfile.TarError):
        result = {"status": "BLOCKED", "code": "invalid_input",
                  "inputs_verified": False, "package_built": False}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
