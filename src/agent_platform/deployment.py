"""Read-only deployment audit and explicit no-credential disposable rehearsal."""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from agent_platform import isolation, process
from agent_platform import runtime_manifest as runtime
from agent_platform.broker import private_read
from agent_platform.broker_policy import Policy, decode


def outcome(status, reason):
    return {"outcome": status, "reason": reason}


def report(source_sha):
    return {
        "schema_version": 1,
        "source_sha_origin": "operator_assertion",
        "ownership_scope": "current_user_namespace_only",
        "operator": {"uid": os.getuid(), "primary_gid": os.getgid()},
        "source_sha": source_sha,
        "codex_version": "0.164.0",
        "codex_sha256": None,
        "catalog_sha256": None,
        "profile_sha256": None,
        "broker_id": None,
        "bubblewrap_requirement": "unprivileged_namespaces_caps_drop_sync_fd",
        "bubblewrap_version": None,
        "checks": {},
        "evidence": {
            key: "NOT_RUN"
            for key in ("offline_ci", "real_kernel", "audited_broker", "live_inference")
        },
        "result": "E2E_BLOCKED",
    }


def record(result, key, action):
    try:
        value = action()
        result["checks"][key] = outcome("PASS", "checks_passed")
        return value
    except runtime.InvalidRuntime as exc:
        result["checks"][key] = outcome(
            "FAIL"
            if exc.reason
            in (
                "hash_mismatch",
                "kernel_probe_failed",
                "unsafe_mode_or_owner",
                "broker_socket_unsafe",
                "broker_health_invalid",
                "broker_endpoint_not_denied",
            )
            else "BLOCKED",
            exc.reason,
        )
    except Exception:
        result["checks"][key] = outcome("BLOCKED", "unavailable_or_unsafe")
    return None


def load_catalog(path, source_sha):
    runtime.need(path is not None, "catalog_required")
    expected = runtime.catalog(path)
    runtime.need(expected["source_sha"] == source_sha, "source_sha_mismatch")
    return expected


def manifest(result, root, expected, *, require_root=False):
    value = runtime.inspect_runtime(root, expected, require_root=require_root)
    result.update(value)
    result["broker_id"] = expected["broker_id"]
    return value


def scalar(path):
    with path.open("rb") as stream:
        raw = stream.read(129)
    runtime.need(len(raw) <= 128, "policy_limit")
    return raw.decode("ascii").strip()


def installed_profile():
    runtime.need(isolation.PROFILE.exists(), "runtime_profile_missing")
    isolation.trusted(isolation.PROFILE, True)
    isolation.trusted(isolation.PROFILE / "rootfs", True)


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
    isolation.trusted(isolation.BWRAP)
    runtime.need(isolation.BWRAP.stat().st_mode & 0o111, "bubblewrap_not_executable")
    runtime.bounded_file(isolation.BWRAP, runtime.BINARY_LIMIT)
    value = process.read_command(
        [str(isolation.BWRAP), "--version"],
        Path("/"),
        isolation.ENV,
        timeout=5,
        limit=128,
    )
    match = re.fullmatch(rb"bubblewrap ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\n?", value)
    runtime.need(match is not None, "bubblewrap_version_unavailable")
    result["bubblewrap_version"] = match[1].decode()


def profile_metadata(result, expected):
    isolation.trusted(isolation.PROFILE, True)
    path = isolation.PROFILE / "profile.json"
    isolation.trusted(path)
    raw = runtime.bounded_file(path, 4096)
    data = decode(raw)
    runtime.need(
        isinstance(data, dict)
        and data.keys() == {"version", "codex_version", "codex_sha256", "broker_id"},
        "profile_invalid",
    )
    runtime.need(
        type(data["version"]) is int
        and data["version"] == 1
        and data["codex_version"] == "0.164.0"
        and data["broker_id"] == expected["broker_id"]
        and data["codex_sha256"] == expected["files"]["usr/bin/codex"]["sha256"],
        "profile_mismatch",
    )
    result["profile_sha256"] = hashlib.sha256(raw).hexdigest()
    result["broker_id"] = data["broker_id"]


def socket_policy():
    runtime.need(
        isolation.BROKER.exists() or isolation.BROKER.is_symlink(),
        "broker_socket_missing",
    )
    isolation.trusted(isolation.BROKER.parent, True)
    info = isolation.BROKER.lstat()
    runtime.need(
        stat.S_ISSOCK(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and not info.st_mode & 7,
        "broker_socket_unsafe",
    )
    # Bubblewrap drops supplementary groups. Primary GID must suffice.
    runtime.need(os.getuid() != 0, "nonroot_operator_required")
    runtime.need(
        info.st_gid == os.getgid() and info.st_mode & 0o020,
        "broker_primary_gid_access_required",
    )


def broker_policy(path, expected):
    runtime.need(path is not None, "broker_policy_required")
    value = Policy.parse(decode(private_read(path, 16384)))
    runtime.need(value.broker_id == expected["broker_id"], "broker_identity_mismatch")
    runtime.need((os.getuid(), os.getgid()) in value.peers, "broker_peer_pair_mismatch")


def broker_health(expected):
    status, raw = isolation.broker_request("GET", "/agent-platform/health")
    runtime.need(status == 200, "broker_health_unavailable")
    value = decode(raw)
    runtime.need(
        value
        == {
            "protocol": 1,
            "broker_id": expected["broker_id"],
            "inference_only": True,
            "credentials_exposed": False,
            "network_tools": False,
        }
        and type(value.get("protocol")) is int
        and all(
            type(value.get(k)) is bool
            for k in ("inference_only", "credentials_exposed", "network_tools")
        ),
        "broker_health_invalid",
    )
    for method, endpoint in [
        ("GET", "/auth"),
        ("POST", "/v1/admin"),
        ("GET", "/v1/models"),
    ]:
        runtime.need(
            isolation.broker_request(method, endpoint)[0] == 403,
            "broker_endpoint_not_denied",
        )


def audit(source_sha, catalog_path=None, policy_path=None):
    result = report(source_sha)
    record(result, "namespace_policy_hint", namespace_policy)
    record(result, "installed_profile", installed_profile)
    record(result, "bubblewrap", lambda: bubblewrap(result))
    expected = record(result, "catalog", lambda: load_catalog(catalog_path, source_sha))
    if expected:
        record(
            result,
            "runtime_manifest",
            lambda: manifest(
                result, isolation.PROFILE / "rootfs", expected, require_root=True
            ),
        )
        record(result, "profile_metadata", lambda: profile_metadata(result, expected))
        record(result, "broker_policy", lambda: broker_policy(policy_path, expected))
    else:
        for key in ("runtime_manifest", "profile_metadata", "broker_policy"):
            result["checks"][key] = outcome("NOT_RUN", "catalog_required")
    record(result, "broker_socket", socket_policy)
    if expected and result["checks"]["broker_socket"]["outcome"] == "PASS":
        record(result, "broker_health_peer", lambda: broker_health(expected))
    else:
        result["checks"]["broker_health_peer"] = outcome(
            "NOT_RUN", "socket_and_catalog_required"
        )
    result["checks"]["codex_version_execution"] = outcome(
        "NOT_RUN", "isolated_rehearsal_required"
    )
    result["checks"]["launch_doctor"] = outcome(
        "NOT_RUN", "launch_specific_doctor_required"
    )
    static = [
        v
        for key, v in result["checks"].items()
        if key not in ("codex_version_execution", "launch_doctor")
    ]
    result["host_status"] = (
        "host_audit_pass"
        if all(v["outcome"] == "PASS" for v in static)
        else "host_audit_blocked"
    )
    return result


def probe_command(root, fd, command):
    # Match Profile.command(probe=True); parity is regression-tested. No host
    # /usr, /home, /run, task repository or production socket is mounted.
    return [
        str(isolation.BWRAP),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-cgroup",
        "--uid",
        "0",
        "--gid",
        "0",
        "--cap-drop",
        "ALL",
        "--sync-fd",
        str(fd),
        "--ro-bind",
        str(root),
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "HOME",
        "/codex-home",
        "--setenv",
        "CODEX_HOME",
        "/codex-home",
        "--setenv",
        "GIT_CONFIG_NOSYSTEM",
        "1",
        "--setenv",
        "GIT_CONFIG_GLOBAL",
        "/dev/null",
        "--ro-bind",
        str(isolation.HELPER),
        "/agent-platform-sandbox.py",
        "--tmpfs",
        "/workspace",
        "--tmpfs",
        "/codex-home",
        "--chdir",
        "/workspace",
        "--",
        *command,
    ]


def rehearse(root, scratch):
    namespace_policy()
    runtime.need(
        not scratch.is_relative_to(root) and not root.is_relative_to(scratch),
        "scratch_conflict",
    )
    runtime.safe_ancestors(scratch.parent)
    runtime.need(not scratch.exists() and not scratch.is_symlink(), "scratch_conflict")
    scratch.mkdir(mode=0o700)  # Explicit rehearsal only; never in audit/manifest.
    private = scratch / "synthetic-private"
    private.mkdir(mode=0o700)
    (private / "fabricated-canary").write_text("synthetic-no-credential-canary")
    fd = os.open(
        scratch / "synthetic-lock",
        os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    try:
        lock = os.fstat(fd)
        names = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
        data = {
            "namespaces": {n: os.readlink("/proc/self/ns/" + n) for n in names},
            "private": [str(private), str(scratch / "synthetic-state")],
            "lock_inode": [lock.st_dev, lock.st_ino],
        }
        probe = [
            "/usr/bin/python3",
            "-I",
            "/agent-platform-sandbox.py",
            "probe",
            json.dumps(data),
        ]
        for command, expected in [
            (probe, b"isolated\n"),
            (
                [
                    "/usr/bin/codex",
                    "--no-daemon",
                    "-c",
                    'sandbox_mode="workspace-write"',
                    "sandbox",
                    "--",
                    *probe,
                    "native",
                ],
                b"isolated\n",
            ),
            (["/usr/bin/codex", "--version"], b"codex-cli 0.164.0\n"),
        ]:
            raw = process.read_command(
                probe_command(root, fd, command),
                Path("/"),
                isolation.ENV,
                timeout=10,
                limit=4096,
                pass_fds=(fd,),
            )
            runtime.need(raw == expected, "kernel_probe_failed")
    finally:
        os.close(fd)
    # Keep only synthetic artifacts for explicit operator review, including on failure.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("manifest", "audit", "rehearse"):
        command = commands.add_parser(name)
        command.add_argument("--source-sha", required=True)
        command.add_argument("--catalog", type=Path)
        if name in ("manifest", "rehearse"):
            command.add_argument("--root", required=True, type=Path)
        if name == "audit":
            command.add_argument("--broker-policy", type=Path)
        if name == "rehearse":
            command.add_argument("--scratch", required=True, type=Path)
            command.add_argument(
                "--consent-kernel-probe", action="store_true", required=True
            )
    args = parser.parse_args()
    if re.fullmatch("[a-f0-9]{40}", args.source_sha) is None:
        parser.error("--source-sha must be a full lowercase Git SHA")
    if args.command == "audit":
        result = audit(args.source_sha, args.catalog, args.broker_policy)
        code = 0 if result["host_status"] == "host_audit_pass" else 2
    else:
        result = report(args.source_sha)
        if args.command == "rehearse":
            result["evidence"]["real_kernel"] = "BLOCKED"
        expected = record(
            result, "catalog", lambda: load_catalog(args.catalog, args.source_sha)
        )
        if expected:
            record(
                result,
                "runtime_manifest",
                lambda: manifest(result, args.root, expected),
            )
        if (
            args.command == "rehearse"
            and result["checks"].get("runtime_manifest", {}).get("outcome") == "PASS"
        ):
            record(result, "bubblewrap", lambda: bubblewrap(result))
            if result["checks"]["bubblewrap"]["outcome"] == "PASS":
                record(
                    result, "kernel_probe", lambda: rehearse(args.root, args.scratch)
                )
                result["evidence"]["real_kernel"] = result["checks"]["kernel_probe"][
                    "outcome"
                ]
        code = (
            0
            if result["checks"]
            and all(v["outcome"] == "PASS" for v in result["checks"].values())
            else 2
        )
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
