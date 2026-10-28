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
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    *,
    timeout: float,
    limit: int,
    pass_fds: tuple[int, ...] = (),
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
            pass_fds=pass_fds,
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


def stream_jsonl(
    argv,
    cwd,
    env,
    prompt,
    accept,
    *,
    pass_fds=(),
    timeout=300,
    line_limit=65536,
    total_limit=8 * 1024 * 1024,
):
    """Bounded duplex stdin/JSONL capture; kill and reap the whole group on any exit."""
    import codecs

    if len(prompt) > 128 * 1024:
        raise CommandError("prompt_limit")
    try:
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
            start_new_session=True,
            umask=0o077,
        )
    except OSError:
        raise CommandError("unavailable") from None
    deadline = time.monotonic() + timeout
    pending = bytearray()
    sent = total = errors = 0
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with selectors.DefaultSelector() as selector:
            for stream, event, name in (
                (child.stdin, selectors.EVENT_WRITE, "stdin"),
                (child.stdout, selectors.EVENT_READ, "stdout"),
                (child.stderr, selectors.EVENT_READ, "stderr"),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandError("timeout")
                for key, _ in selector.select(remaining):
                    if key.data == "stdin":
                        if sent < len(prompt):
                            try:
                                sent += os.write(key.fd, prompt[sent : sent + 4096])
                            except BrokenPipeError:
                                raise CommandError("stdin_closed") from None
                        if sent == len(prompt):
                            selector.unregister(key.fileobj)
                            child.stdin.close()
                        continue
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > total_limit:
                        raise CommandError("stream_limit")
                    if key.data == "stderr":
                        errors += len(chunk)
                        decoder.decode(chunk)  # Validate, discard, never log stderr.
                        if errors > 65536:
                            raise CommandError("stderr_limit")
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending:
                        raw, _, rest = pending.partition(b"\n")
                        if not raw or len(raw) > line_limit:
                            raise CommandError("line_limit")
                        pending[:] = rest
                        accept(bytes(raw))
                    if len(pending) > line_limit:
                        raise CommandError("line_limit")
            decoder.decode(b"", final=True)
            if pending:
                raise CommandError("truncated_jsonl")
            # Leave the PID unreaped until group termination, preventing PID/PGID
            # reuse between observing exit and killing possible descendants.
            while True:
                status = os.waitid(
                    os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG
                )
                if status is not None:
                    return (
                        status.si_status
                        if status.si_code == os.CLD_EXITED
                        else -status.si_status
                    )
                if time.monotonic() >= deadline:
                    raise CommandError("timeout")
                time.sleep(0.005)
    except UnicodeError:
        raise CommandError("invalid_utf8") from None
    finally:
        # Also kill descendants after a reported terminal event. The isolation
        # supervisor independently holds the host flock and dies with its parent.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()
