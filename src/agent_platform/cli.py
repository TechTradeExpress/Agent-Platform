"""Small CLI with fixed local Git queries and no network operations."""

import argparse
import json
import os
import re
import selectors
import subprocess
import sys
import time
from pathlib import Path

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
        process = subprocess.Popen(
            ["git", *args],
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        raise InspectionError(
            6, "Cannot execute Git; check the Git installation."
        ) from None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + TIMEOUT
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InspectionError(5, "Git inspection timed out (5 seconds).")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), OUTPUT_LIMIT + 1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(chunk)
                    if len(buffers[key.data]) > OUTPUT_LIMIT:
                        raise InspectionError(
                            6, "Git output exceeded the inspection limit."
                        )
            try:
                status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise InspectionError(
                    5, "Git inspection timed out (5 seconds)."
                ) from None
        if status:
            raise InspectionError(
                failure_code, "Git query failed; check repository and origin."
            )
        raw = buffers["stdout"]
        try:
            value = raw.decode("utf-8").removesuffix("\n")
        except UnicodeError:
            raise InspectionError(
                7, "Git returned an unsupported path or value encoding."
            ) from None
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise InspectionError(7, "Git returned an unsafe path or value.")
        return value
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


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
    parser.parse_args()
    try:
        result = inspect(Path.cwd())
    except InspectionError as exc:
        print(f"agent-platform: {exc}", file=sys.stderr)
        return exc.code
    except OSError:
        print("agent-platform: Cannot access the current directory.", file=sys.stderr)
        return 7
    print(json.dumps(result, sort_keys=True))
    return 0
