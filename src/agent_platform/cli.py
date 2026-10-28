"""Repository inspection, authorized preparation and guarded task execution."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from agent_platform.issues import LOGIN, AdmissionError, discover, positive_int
from agent_platform.process import CommandError, read_command

TIMEOUT = 5
OUTPUT_LIMIT = 8192


class InspectionError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        super().__init__(message)


def git(cwd: Path, *args: str, failure_code: int = 6) -> str:
    # Remove inherited Git routing/configuration and loader overrides. Git's
    # system/global config is unnecessary for these local queries.
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        raw = read_command(
            ["git", *args], cwd, env, timeout=TIMEOUT, limit=OUTPUT_LIMIT
        )
    except CommandError as exc:
        reason = str(exc)
        code, message = {
            "unavailable": (6, "Cannot execute Git; check the Git installation."),
            "timeout": (5, "Git inspection timed out (5 seconds)."),
            "output_limit": (6, "Git output exceeded the inspection limit."),
            "failed": (failure_code, "Git query failed; check repository and origin."),
        }[reason]
        raise InspectionError(code, message) from None
    try:
        value = raw.decode("utf-8").removesuffix("\n")
    except UnicodeError:
        raise InspectionError(
            7, "Git returned an unsupported path or value encoding."
        ) from None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InspectionError(7, "Git returned an unsafe path or value.")
    return value


def parse_origin(value: str) -> str:
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
        r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9_.-]+)",
        value,
    )
    if not match:
        raise InspectionError(
            4, "Origin must be a credential-free GitHub HTTPS or SSH URL."
        )
    owner, repo = match.groups()
    repo = repo.removesuffix(".git")
    if repo in {"", ".", ".."} or len(repo) > 100 or owner.endswith("-"):
        raise InspectionError(
            4, "Origin has an invalid GitHub owner or repository name."
        )
    return f"{owner}/{repo}"


def resolve_path(value: str, cwd: Path) -> Path:
    if not value:
        raise InspectionError(7, "Git returned an empty repository path.")
    try:
        return (cwd / value).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise InspectionError(7, "Cannot resolve repository paths safely.") from None


def inspect(cwd: Path) -> dict:
    try:
        cwd = cwd.resolve(strict=True)
    except (OSError, RuntimeError):
        raise InspectionError(
            7, "Cannot resolve the current directory safely."
        ) from None
    if any(ord(c) < 32 or ord(c) == 127 for c in str(cwd)):
        raise InspectionError(7, "Current directory contains unsafe characters.")
    root = resolve_path(git(cwd, "rev-parse", "--show-toplevel", failure_code=2), cwd)
    if cwd != root:
        raise InspectionError(3, "Run inspect from the repository working-tree root.")
    common = resolve_path(git(cwd, "rev-parse", "--git-common-dir"), cwd)
    git_dir = resolve_path(git(cwd, "rev-parse", "--absolute-git-dir"), cwd)
    origin = parse_origin(git(cwd, "remote", "get-url", "origin", failure_code=4))
    branch = git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    return {
        "repository": origin,
        "root": str(root),
        "linked_worktree": git_dir != common,
        "branch": None if branch == "HEAD" else branch,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inspect", help="Inspect the current Git working-tree root")
    issues = commands.add_parser(
        "issues", help="Report eligible GitHub Issues (read-only)"
    )
    issues.add_argument(
        "--issue", type=int, metavar="N", help="Validate this exact Issue"
    )
    issues.add_argument(
        "--trusted-actor",
        action="append",
        default=[],
        metavar="LOGIN",
        help="Operator-asserted trusted maintainer (repeatable)",
    )
    preparing = commands.add_parser(
        "prepare", help="Prepare one authorized task locally"
    )
    preparing.add_argument("--issue", required=True, type=int, metavar="N")
    preparing.add_argument(
        "--trusted-actor", action="append", default=[], metavar="LOGIN"
    )
    for command in ("run", "resume", "doctor"):
        execution = commands.add_parser(
            command,
            help=(
                "Check prepared task readiness"
                if command == "doctor"
                else "Explicit guarded Codex execution"
            ),
        )
        execution.add_argument("--issue", required=True, type=int, metavar="N")
        execution.add_argument(
            "--trusted-actor", action="append", default=[], metavar="LOGIN"
        )
        if command == "doctor":
            execution.add_argument(
                "--resume", action="store_true", help="Check PAUSED readiness"
            )
    args = parser.parse_args()
    if args.command in ("issues", "prepare", "run", "resume", "doctor"):
        if args.issue is not None and not positive_int(args.issue):
            parser.error("--issue must be a positive Issue number")
        if any(LOGIN.fullmatch(actor) is None for actor in args.trusted_actor):
            parser.error("--trusted-actor must be a GitHub user login")
    if args.command == "doctor":
        from agent_platform.doctor import diagnose

        result, code = diagnose(
            None, args.issue, args.trusted_actor, resume=args.resume
        )
        print(json.dumps(result, sort_keys=True))
        return code
    code = 0
    try:
        result = inspect(Path.cwd())
        if args.command in ("prepare", "run", "resume"):
            from agent_platform.prepare import prepare
            from agent_platform.state import PrepareError

            try:
                if args.command == "prepare":
                    result = prepare(result, args.issue, args.trusted_actor)
                else:
                    from agent_platform.execution import execute
                    from agent_platform.isolation import IsolationError

                    try:
                        result, code = execute(
                            result,
                            args.issue,
                            args.trusted_actor,
                            resume=args.command == "resume",
                        )
                    except IsolationError:
                        result = {"status": "isolation_unavailable", "state": None}
                        code = 13
            except PrepareError as exc:
                result = {
                    "status": exc.reason,
                    "state": "NEEDS_HUMAN" if exc.code == 12 else None,
                }
                code = exc.code
            except (AdmissionError, ValueError):
                result = {"status": "api_unavailable_or_ambiguous", "state": None}
                code = 8
            except (OSError, KeyboardInterrupt):
                result = {"status": "interrupted_transaction", "state": "NEEDS_HUMAN"}
                code = 12
        if args.command == "issues":
            repository = result["repository"]
            try:
                result, code = discover(repository, args.trusted_actor, args.issue)
            except (AdmissionError, ValueError) as exc:
                # ValueError also covers malformed pagination URLs. Never echo it.
                message = (
                    str(exc)
                    if isinstance(exc, AdmissionError)
                    else ("GitHub returned malformed pagination metadata.")
                )
                print(f"agent-platform: {message}", file=sys.stderr)
                result = {
                    "repository": repository,
                    "candidates": [],
                    "status": "unavailable",
                    "reason": "api_unavailable_or_ambiguous",
                }
                code = 8
    except InspectionError as exc:
        if args.command in ("prepare", "run", "resume"):
            print(
                json.dumps(
                    {
                        "status": "invalid_target",
                        "state": None,
                        "reason": {
                            2: "not_git",
                            3: "nested_invocation",
                            4: "untrusted_origin",
                            5: "git_timeout",
                            6: "git_failure",
                            7: "unsafe_path",
                        }[exc.code],
                    },
                    sort_keys=True,
                )
            )
            return exc.code
        print(f"agent-platform: {exc}", file=sys.stderr)
        return exc.code
    except OSError:
        if args.command in ("prepare", "run", "resume"):
            print(
                json.dumps({"status": "unsafe_target", "state": None}, sort_keys=True)
            )
            return 7
        print("agent-platform: Cannot access the current directory.", file=sys.stderr)
        return 7
    print(json.dumps(result, sort_keys=True))
    return code
