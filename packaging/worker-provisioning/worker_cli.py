#!/usr/bin/python3 -IB
"""Worker P1 operator commands; native/legacy execution remains quarantined."""

import argparse
import json
import os


def main():
    parser = argparse.ArgumentParser(prog="agent-platform-worker", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "resume", "doctor"):
        command = commands.add_parser(name)
        command.add_argument("--issue", required=True, type=int)
        command.add_argument("--trusted-actor", action="append", default=[])
        if name == "doctor":
            command.add_argument("--resume", action="store_true")
    provisioning = commands.add_parser("provision")
    provisioning.add_argument("--approve", action="store_true", required=True)
    provisioning.add_argument("--initialize-journals", action="store_true")
    provisioning.add_argument("--recover", action="store_true")
    codex = commands.add_parser("codex")
    codex.add_argument("action", choices=("install", "rollback", "recover"))
    codex.add_argument("--approve", action="store_true", required=True)
    codex.add_argument("--version")
    codex.add_argument("--archive")
    codex.add_argument("--operator-path", required=True)
    codex.add_argument("--upgrade", action="store_true")
    args = parser.parse_args()
    if args.command in ("run", "resume", "doctor"):
        if args.issue <= 0:
            parser.error("positive Issue required")
        print(
            json.dumps(
                {
                    "reason": "legacy_execution_quarantined",
                    "launch_allowed": False,
                    "resume_authorized": False,
                    "subscription": "SUBSCRIPTION_ISOLATION_BLOCKED",
                    "runtime": "LIVE_NO_GO",
                },
                sort_keys=True,
            )
        )
        return 13
    if os.geteuid() != 0:
        print(
            '{"status":"BLOCKED","reason":"operator_root_required","launch_allowed":false}'
        )
        return 13
    prefix = "/usr/lib/agent-platform-worker/provisioning/"
    if args.command == "provision":
        argv = ["/usr/bin/python3", "-IB", prefix + "provision.py", "--approve"]
        if args.initialize_journals:
            argv.append("--initialize-journals")
        if args.recover:
            argv.append("--recover")
    else:
        argv = [
            "/usr/bin/python3",
            "-IB",
            prefix + "codex_upstream.py",
            args.action,
            "--approve",
            "--operator-path",
            args.operator_path,
        ]
        if args.version:
            argv += ["--version", args.version]
        if args.archive:
            argv += ["--archive", args.archive]
        if args.upgrade:
            argv.append("--upgrade")
    os.execv(argv[0], argv)  # Fixed interpreter/script, never shell or PATH discovery.
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
