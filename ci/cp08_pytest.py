"""Source-only CI entry: validate the fixed OS interpreter, then run pytest in-process.

No provisioning, executable selection, process creation, permission repair or
product-runtime admission. Import is inert. Ubuntu image drift fails closed.
"""

import json
import os
import platform
import sys

from agent_platform import control_plane_local_runner as lr

EXPECTED_BINARY = "/usr/bin/python3.12"
FORBIDDEN_BITS = (
    (0o4000, "setuid"),
    (0o2000, "setgid"),
    (0o020, "group_write"),
    (0o002, "other_write"),
)


def mode_categories():
    """Only fixed categories for our active real executable; no paths or raw mode."""
    try:
        meta = os.stat(os.path.realpath(sys.executable), follow_symlinks=False)
        return {
            name: "PRESENT" if meta.st_mode & bit else "ABSENT"
            for bit, name in FORBIDDEN_BITS
        }
    except Exception:
        return dict.fromkeys((name for _, name in FORBIDDEN_BITS), "UNKNOWN")


def snapshot():
    """Private correlation pin. Never serialized or converted to launch authority."""
    lr._require(
        sys.platform == "linux" and platform.python_implementation() == "CPython"
    )
    lr._require(sys.version_info[:2] == (3, 12))
    lr._require(os.getuid() != 0 and os.getuid() == os.geteuid())
    lr._require(os.getgid() == os.getegid())
    lr._require(len(set(os.getresuid())) == len(set(os.getresgid())) == 1)
    lr._no_capabilities()
    actual = lr._runtime()  # Original mode, owner and xattr requirements, unchanged.
    lr._require(actual == os.path.realpath(EXPECTED_BINARY))
    before = os.stat(actual, follow_symlinks=False)
    digest = lr._file_hash(actual, 64 * 1024 * 1024)
    after = os.stat(actual, follow_symlinks=False)

    def pin(meta):
        return (
            meta.st_dev,
            meta.st_ino,
            meta.st_mode,
            meta.st_uid,
            meta.st_gid,
            meta.st_size,
            meta.st_mtime_ns,
            meta.st_ctime_ns,
        )

    lr._require(pin(before) == pin(after))
    # Include the executing process, so the check cannot silently move to a child.
    return (os.getpid(), actual, pin(after), digest)


def _emit(code):
    print(
        json.dumps(
            {
                "code": code,
                "permission_bits": mode_categories(),
                "live": "LIVE_NO_GO",
                "host": "HOST_NOT_RUN",
                "launch_allowed": False,
            },
            sort_keys=True,
        )
    )


def main():
    try:
        expected = snapshot()
        import pytest

        lr._require(snapshot() == expected)
    except Exception:
        _emit("ci_interpreter_blocked")
        return 13
    _emit("ci_interpreter_verified_same_process")
    # No subprocess/exec: pytest and the validation above share one interpreter.
    result = pytest.main([])
    try:
        lr._require(snapshot() == expected)
    except Exception:
        _emit("ci_interpreter_changed")
        return 13
    return int(result)


if __name__ == "__main__":
    if len(sys.argv) != 1:
        _emit("ci_arguments_blocked")
        raise SystemExit(13)
    raise SystemExit(main())
