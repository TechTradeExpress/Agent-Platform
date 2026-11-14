#!/usr/bin/python3 -I
"""Inert Worker P0 inventory. No agent, provisioning or authentication interface."""

import argparse
import json


def main():
    parser = argparse.ArgumentParser(prog="agent-platform-worker", description=__doc__)
    parser.add_argument(
        "--version", action="version", version="agent-platform-worker 0.1.0"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "resume", "doctor"):
        command = commands.add_parser(name, help="Report blocked execution; no I/O")
        command.add_argument("--issue", type=int, required=True)
        command.add_argument("--trusted-actor", action="append", default=[])
        if name == "doctor":
            command.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.issue <= 0:
        parser.error("--issue must be a positive Issue number")
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


if __name__ == "__main__":
    raise SystemExit(main())
