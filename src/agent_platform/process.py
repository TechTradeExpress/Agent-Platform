"""Bounded foreground command capture; callers supply fixed argv and environment."""

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path


class CommandError(Exception):
    """Only a safe reason code, never command output or environment values."""


def read_command(
    argv: list[str], cwd: Path, env: dict[str, str], *, timeout: float, limit: int
) -> bytes:
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            umask=0o077,
        )
    except OSError:
        raise CommandError("unavailable") from None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandError("timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), limit + 1)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(chunk)
                    if len(buffers[key.data]) > limit:
                        raise CommandError("output_limit")
            try:
                status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise CommandError("timeout") from None
        if status:
            raise CommandError("failed")
        completed = True
        return bytes(buffers["stdout"])
    finally:
        if not completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()
