"""Backend-independent, read-only static manifest and host-policy hints."""

import argparse
import json
import os
import re
from pathlib import Path

from agent_platform import isolation, process
from agent_platform import runtime_manifest as runtime

BWRAP = Path("/usr/bin/bwrap")
ENV = {"PATH": os.defpath, "LC_ALL": "C"}


def report(source_sha):
    return {
        "schema_version": 2,
        "scope": "static_diagnostics_only",
        "source_sha": source_sha,
        "source_sha_origin": "operator_assertion",
        "ownership_scope": "current_user_namespace_only",
        "catalog_sha256": None,
        "bubblewrap_version": None,
        "checks": {},
        "evidence": {
            key: "NOT_RUN"
            for key in (
                "offline_ci",
                "real_kernel",
                "authenticated_execution",
                "credential_isolation",
                "live_inference",
            )
        },
        "result": "E2E_BLOCKED",
    }


def record(result, key, action):
    try:
        value = action()
        result["checks"][key] = {"outcome": "PASS", "reason": "checks_passed"}
        return value
    except runtime.InvalidRuntime as exc:
        result["checks"][key] = {"outcome": "BLOCKED", "reason": exc.reason}
    except Exception:
        result["checks"][key] = {
            "outcome": "BLOCKED",
            "reason": "unavailable_or_unsafe",
        }
    return None


def manifest(root, path, source_sha):
    runtime.need(path is not None, "catalog_required")
    expected = runtime.catalog(path)
    runtime.need(expected["source_sha"] == source_sha, "source_sha_mismatch")
    return runtime.inspect_runtime(root, expected)


def scalar(path):
    with path.open("rb") as stream:
        raw = stream.read(129)
    runtime.need(len(raw) <= 128, "policy_limit")
    return raw.decode("ascii").strip()


def namespace_policy():
    runtime.need(
        os.name == "posix" and Path("/proc/self/ns/user").exists(), "linux_required"
    )
    runtime.need(
        int(scalar(Path("/proc/sys/kernel/yama/ptrace_scope"))) >= 1,
        "ptrace_policy_unavailable",
    )
    runtime.need(
        int(scalar(Path("/proc/sys/user/max_user_namespaces"))) > 0,
        "namespaces_unavailable",
    )
    knob = Path("/proc/sys/kernel/unprivileged_userns_clone")
    runtime.need(not knob.exists() or scalar(knob) == "1", "namespaces_unavailable")


def bubblewrap(result):
    isolation.trusted(BWRAP)
    runtime.need(BWRAP.stat().st_mode & 0o111, "bubblewrap_not_executable")
    runtime.bounded_file(BWRAP, runtime.BINARY_LIMIT)
    value = process.read_command(
        [str(BWRAP), "--version"],
        Path("/"),
        ENV,
        timeout=5,
        limit=128,
    )
    match = re.fullmatch(rb"bubblewrap ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\n?", value)
    runtime.need(match is not None, "bubblewrap_version_unavailable")
    result["bubblewrap_version"] = match[1].decode()


def audit(source_sha):
    result = report(source_sha)
    record(result, "namespace_policy_hint", namespace_policy)
    record(result, "bubblewrap", lambda: bubblewrap(result))
    result["host_status"] = (
        "host_hints_pass"
        if all(item["outcome"] == "PASS" for item in result["checks"].values())
        else "host_hints_blocked"
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("manifest", "audit"):
        command = commands.add_parser(name)
        command.add_argument("--source-sha", required=True)
        if name == "manifest":
            command.add_argument("--root", required=True, type=Path)
            command.add_argument("--catalog", required=True, type=Path)
    args = parser.parse_args()
    if re.fullmatch("[a-f0-9]{40}", args.source_sha) is None:
        parser.error("--source-sha must be a full lowercase Git SHA")
    if args.command == "audit":
        result = audit(args.source_sha)
    else:
        result = report(args.source_sha)
        value = record(
            result,
            "runtime_manifest",
            lambda: manifest(args.root, args.catalog, args.source_sha),
        )
        if value:
            result.update(value)
    print(json.dumps(result, sort_keys=True))
    return (
        0 if all(item["outcome"] == "PASS" for item in result["checks"].values()) else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
