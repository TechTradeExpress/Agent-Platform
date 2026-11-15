#!/usr/bin/python3 -IB
"""Read-only PKG-05 observations. Never repairs, authenticates or grants authority."""

import contextlib
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

PREFIX = "/usr/lib/agent-platform-worker/provisioning"
DOC = "/usr/share/doc/agent-platform-worker"
ROLES = ("ap-publisher", "ap-publisher-signer")
UNITS = ("ap-worker-publisher", "ap-worker-publisher-signer")
BAD_ATTRS = {
    "system.posix_acl_access",
    "system.posix_acl_default",
    "system.nfs4_acl",
    "security.capability",
}
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
STATES = frozenset(
    ("INSTALLED", "CONFIGURED", "READY_FOR_SUPERVISED_PUBLISHING", "BLOCKED", "NOT_RUN")
)
REASONS = frozenset(
    """verified_local_package verified_managed_codex
verified_dependencies verified_local_identities verified_state_metadata
verified_effective_unit_settings verified_enforced_profiles
package_verification_required object_missing observation_denied observation_failed
unsafe_metadata unsafe_attributes
object_changed invalid_record package_record_invalid installed_payload_changed
package_version_mismatch codex_verification_failed path_shadowing path_invalid
codex_verification_required caller_path_only coding_identity_invalid
coding_environment_scope_unverified
home_codex_present dependencies_missing identity_invalid state_metadata_invalid
config_acl_invalid unit_missing unit_constraints_rejected profiles_not_enforcing
profile_attachment_evidence_missing bpf_attachment_evidence_missing
process_isolation_evidence_missing independent_continuity_evidence_missing
bpf_interface_missing bpf_egress_policy_missing
app_identity_not_authenticated operator_authorization_not_observed
account_lock_not_observed diagnostic_timeout""".split()
)
SCOPE_FAILURES = frozenset(
    """object_missing observation_denied observation_failed
unsafe_metadata unsafe_attributes object_changed invalid_record""".split()
)
SCOPE_REASONS = {
    "path": SCOPE_FAILURES
    | {
        "codex_verification_required",
        "coding_identity_invalid",
        "coding_environment_scope_unverified",
        "home_codex_present",
    },
    "caller_path": SCOPE_FAILURES
    | {"caller_path_only", "path_invalid", "path_shadowing"},
}

CHECKS = (
    "package",
    "codex",
    "path",
    "dependencies",
    "identities",
    "state",
    "units",
    "apparmor",
    "account_lock",
    "profile_attachment",
    "bpf",
    "process_isolation",
    "continuity",
    "app_identity",
    "operator_authorization",
    "caller_path",
)


class Blocked(Exception):
    pass


def need(value, reason):
    if not value:
        raise Blocked(reason)


def stamp(m):
    return (
        m.st_dev,
        m.st_ino,
        m.st_uid,
        m.st_gid,
        m.st_mode,
        m.st_nlink,
        m.st_size,
        m.st_mtime_ns,
        m.st_ctime_ns,
    )


def meta(fd, uid=0, gid=0, mode=None, directory=False, acl=False):
    m = os.fstat(fd)
    need((m.st_uid, m.st_gid) == (uid, gid), "unsafe_metadata")
    need(
        stat.S_ISDIR(m.st_mode)
        if directory
        else stat.S_ISREG(m.st_mode) and m.st_nlink == 1,
        "unsafe_metadata",
    )
    need(not m.st_mode & 0o7022, "unsafe_metadata")
    need(mode is None or stat.S_IMODE(m.st_mode) == mode, "unsafe_metadata")
    bad = BAD_ATTRS - ({"system.posix_acl_access"} if acl else set())
    need(not bad.intersection(os.listxattr(fd)), "unsafe_attributes")
    return m


@contextlib.contextmanager
def directory(path):
    need(
        path.startswith("/") and all(p not in (".", "..") for p in path.split("/")),
        "unsafe_metadata",
    )
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        meta(fd, directory=True)
        for part in path.split("/")[1:]:
            if part:
                nxt = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = nxt
                meta(fd, directory=True)
        yield fd
    finally:
        os.close(fd)


def read(path, limit=262144, mode=0o644):
    parent, name = path.rsplit("/", 1)
    with directory(parent) as fd:
        file = os.open(name, FLAGS, dir_fd=fd)
        try:
            before = meta(file, mode=mode)
            need(0 <= before.st_size <= limit, "invalid_record")
            data = os.read(file, limit + 1)
            need(
                len(data) == before.st_size
                and stamp(before) == stamp(os.fstat(file))
                and stamp(before)
                == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                "object_changed",
            )
            return data
        finally:
            os.close(file)


def parse(data):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "invalid_record")
            out[key] = value
        return out

    result = json.loads(data, object_pairs_hook=pairs)
    need(type(result) is dict, "invalid_record")
    return result


def sibling(name):
    # Fixed installed code only; no PYTHONPATH, checkout or plugin discovery.
    path = PREFIX + "/" + name + ".py"
    data = read(path)
    spec = importlib.util.spec_from_loader("doctor_" + name, loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = path
    exec(compile(data, path, "exec"), module.__dict__)
    return module


def query(argv):
    """Fixed read-only tools; bounded pipe consumption, no shell or stderr output."""
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "observation_failed")
    with subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env={
            "PATH": "/usr/sbin:/usr/bin",
            "LC_ALL": "C",
            "SYSTEMD_PAGER": "",
            "SYSTEMD_COLORS": "0",
        },
    ) as child:
        try:
            result = bytearray()
            end = time.monotonic() + 5
            with selectors.DefaultSelector() as poll:
                os.set_blocking(child.stdout.fileno(), False)
                poll.register(child.stdout, selectors.EVENT_READ)
                while True:
                    need(time.monotonic() < end, "observation_failed")
                    if not poll.select(min(0.1, max(0, end - time.monotonic()))):
                        continue
                    data = os.read(child.stdout.fileno(), 4096)
                    if not data:
                        break
                    result.extend(data)
                    need(len(result) <= 65536, "observation_failed")
            need(
                child.wait(timeout=max(0.01, end - time.monotonic())) == 0,
                "observation_failed",
            )
            return result.decode("ascii", "strict")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


class Observer:
    def __init__(self):
        self.accounts = None
        self.artifacts = None
        self._codex_identity = None

    def package(self):
        self.artifacts = None
        self._codex_identity = None
        build = parse(read(DOC + "/build.json"))
        inventory = parse(read(DOC + "/manifest.json"))
        need(
            build.get("schema") == 2
            and build.get("package") == "agent-platform-worker"
            and build.get("phase") == "P1_INSTALL_INERT"
            and re.fullmatch("[0-9a-f]{40}", build.get("source_commit", ""))
            and re.fullmatch(r"0\.1\.0-[5-9][0-9]*", build.get("debian_version", "")),
            "package_record_invalid",
        )
        version = query(
            [
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${Status}\n${Version}\n",
                "agent-platform-worker",
            ]
        )
        need(
            version == "install ok installed\n" + build["debian_version"] + "\n",
            "package_version_mismatch",
        )
        need(
            set(inventory) == {"schema", "files"}
            and inventory["schema"] == 1
            and type(inventory["files"]) is list
            and 20 <= len(inventory["files"]) <= 128,
            "package_record_invalid",
        )
        paths = set()
        for item in inventory["files"]:
            need(
                type(item) is dict and type(item.get("path")) is str,
                "package_record_invalid",
            )
            path = item["path"]
            need(
                path not in paths
                and all(p not in (".", "..", "") for p in path.split("/")[1:])
                and (
                    path.startswith(
                        (
                            "/usr/lib/agent-platform-worker/",
                            "/usr/lib/ap-worker-publisher/",
                            "/usr/libexec/ap-worker-publisher",
                            "/usr/share/doc/agent-platform-worker/",
                            "/usr/lib/systemd/system/ap-worker-publisher",
                            "/etc/apparmor.d/ap-worker-publisher",
                        )
                    )
                    or path
                    in (
                        "/usr/bin/agent-platform-worker",
                        "/usr/bin/agent-platform-worker-native-artifact",
                        "/etc/agent-platform-worker/package.conf",
                        "/usr/share/man/man1/agent-platform-worker.1.gz",
                        "/usr/share/man/man1/agent-platform-worker-native-artifact.1.gz",
                    )
                ),
                "package_record_invalid",
            )
            paths.add(path)
            if path == DOC + "/manifest.json":
                need(item.get("sha256") is None, "package_record_invalid")
                continue
            need(
                set(item) == {"path", "mode", "uid", "gid", "sha256"}
                and item["uid"] == item["gid"] == 0
                and item["mode"] in (0o644, 0o755)
                and re.fullmatch("[0-9a-f]{64}", item["sha256"]),
                "package_record_invalid",
            )
            need(
                hashlib.sha256(read(path, mode=item["mode"])).hexdigest()
                == item["sha256"],
                "installed_payload_changed",
            )
        need(
            {
                PREFIX + "/worker_doctor.py",
                PREFIX + "/provision.py",
                PREFIX + "/codex_upstream.py",
                DOC + "/build.json",
            }
            <= paths,
            "package_record_invalid",
        )
        self.artifacts = {
            "worker_version": build["debian_version"],
            "source_commit": build["source_commit"],
            "manifest_sha256": hashlib.sha256(read(DOC + "/manifest.json")).hexdigest(),
        }
        return "INSTALLED", "verified_local_package"

    def codex(self):
        self._codex_identity = None
        need(self.artifacts is not None, "package_verification_required")
        m = sibling("codex_upstream")
        try:
            m.check_platform()
            pins = m.load_lock()
            with m.directory(m.BASE) as root:
                current, installed, transaction = m.inspect_store(root, pins)
                need(transaction is None, "codex_verification_failed")
            with m.directory(m.BIN) as fd:
                m.link(fd, "codex", m.BASE + "/current/codex")
            with m.directory(m.SYSTEM_BIN) as fd:
                m.need(m.exists(fd, "codex") is None, "foreign_usr_bin_codex")
            pin = installed[current]
            if self.artifacts is not None:
                self.artifacts.update(
                    codex_version=pin["version"],
                    codex_release_url=pin["url"],
                    codex_release_tag=pin["tag"],
                    release_lock_sha256=m.LOCK_SHA256,
                    archive_sha256=pin["archive_sha256"],
                    binary_sha256=pin["binary_sha256"],
                    release_pin_sha256=m.sha(m.encoded(pin)),
                    effective_path=m.BASE + "/versions/" + current + "/codex",
                )
        except m.Blocked as exc:
            raise Blocked("codex_verification_failed") from exc
        self._codex_identity = tuple(
            self.artifacts[k]
            for k in ("effective_path", "binary_sha256", "release_pin_sha256")
        )
        return "INSTALLED", "verified_managed_codex"

    @staticmethod
    def exists_name(path):
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            return False

    def caller_path(self):
        """Caller PATH names only; never proof of any user's session environment."""
        value = os.environ.get("PATH", "")
        parts = value.split(":")
        need(
            0 < len(value) <= 4096
            and len(parts) <= 32
            and all(
                p.startswith("/") and not {".", ".."}.intersection(p.split("/"))
                for p in parts
            ),
            "path_invalid",
        )
        found = False
        for part in parts:
            if part == "/usr/local/bin":
                found = True
                break
            need(not self.exists_name(part.rstrip("/") + "/codex"), "path_shadowing")
        need(found, "path_invalid")
        return "NOT_RUN", "caller_path_only"

    def path(self):
        """Fail-closed coding-user scope, independent of caller HOME/PATH/UID."""
        need(
            self._codex_identity is not None
            and self.artifacts is not None
            and tuple(
                self.artifacts.get(k)
                for k in ("effective_path", "binary_sha256", "release_pin_sha256")
            )
            == self._codex_identity,
            "codex_verification_required",
        )
        # Fixed public local account metadata, never NSS plugins or shell files.
        # A matching local record is still not authenticated session/NSS proof.
        rows = [
            line.split(":")
            for line in read("/etc/passwd", 2 * 1024**2).decode().splitlines()
        ]
        need(
            len(rows) <= 10000 and all(len(row) == 7 for row in rows),
            "coding_identity_invalid",
        )
        matches = [row for row in rows if row[0] == "agentdev"]
        need(len(matches) == 1, "coding_identity_invalid")
        account = matches[0]
        need(
            re.fullmatch("[1-9][0-9]{0,9}", account[2])
            and int(account[2]) < 2**32 - 1
            and all(re.fullmatch("[0-9]{1,10}", row[2]) for row in rows)
            and sum(int(row[2]) == int(account[2]) for row in rows) == 1,
            "coding_identity_invalid",
        )
        home = account[5]
        need(
            home.startswith("/")
            and home not in ("/", "/root")
            and len(home) <= 4096
            and not {".", ".."}.intersection(home.split("/")),
            "coding_identity_invalid",
        )
        # Only lstat the named candidate. No home/binary/session contents read.
        need(
            not self.exists_name(home.rstrip("/") + "/.local/bin/codex"),
            "home_codex_present",
        )
        # No safe observation of the actual coding session PATH/aliases exists.
        # Root's clean PATH, or even a matching caller UID/HOME, cannot fill it.
        return "NOT_RUN", "coding_environment_scope_unverified"

    def dependencies(self):
        need(sys.version_info >= (3, 12), "dependencies_missing")
        text = query(["/usr/bin/git", "--version"])
        need(
            re.fullmatch(r"git version [0-9]+\.[0-9]+\.[0-9]+\n", text),
            "dependencies_missing",
        )
        return "INSTALLED", "verified_dependencies"

    def identities(self):
        need(self.artifacts is not None, "package_verification_required")
        # Local public databases only. Never NSS plugins, shadow or passwd -S.
        users = [
            line.split(":")
            for line in read("/etc/passwd", 2 * 1024**2).decode().splitlines()
        ]
        groups = [
            line.split(":")
            for line in read("/etc/group", 2 * 1024**2).decode().splitlines()
        ]
        need(len(users) <= 10000 and len(groups) <= 10000, "identity_invalid")
        m = sibling("provision")
        snapshot = {
            "users": [
                {
                    "name": p[0],
                    "uid": int(p[2]),
                    "gid": int(p[3]),
                    "home": p[5],
                    "shell": p[6],
                }
                for p in users
            ],
            "groups": [
                {
                    "name": g[0],
                    "gid": int(g[2]),
                    "members": g[3].split(",") if g[3] else [],
                }
                for g in groups
            ],
        }
        try:
            self.accounts = m.identities(snapshot)
        except m.Blocked as exc:
            raise Blocked("identity_invalid") from exc
        return "CONFIGURED", "verified_local_identities"

    def state(self):
        need(self.accounts is not None, "state_metadata_invalid")
        saved = parse(
            read(
                "/var/lib/agent-platform-worker-provisioning/receipt.json", 65536, 0o600
            )
        )
        need(
            set(saved) == {"schema", "accounts", "paths", "intent_sha256"}
            and saved["schema"] == "AP-WORKER-PROVISION/1"
            and saved["accounts"] == self.accounts
            and re.fullmatch("[0-9a-f]{64}", saved["intent_sha256"]),
            "state_metadata_invalid",
        )
        with directory("/var/lib/agent-platform-worker-provisioning") as ledger:
            meta(ledger, mode=0o700, directory=True)
            need(set(os.listdir(ledger)) == {"receipt.json"}, "state_metadata_invalid")
        records = {}
        with directory("/var/lib") as parent:
            for role in ROLES:
                ids = self.accounts[role]
                fd = os.open(role, FLAGS | os.O_DIRECTORY, dir_fd=parent)
                try:
                    m = meta(fd, **ids, mode=0o700, directory=True)
                    need(m.st_dev == os.fstat(parent).st_dev, "state_metadata_invalid")
                    records["/var/lib/" + role] = self.record(m)
                    # Journal content is NEVER read, even when invoked as root.
                    journal = os.open("journal", FLAGS, dir_fd=fd)
                    try:
                        m = meta(journal, **ids, mode=0o600)
                        records["/var/lib/" + role + "/journal"] = self.record(m)
                    finally:
                        os.close(journal)
                finally:
                    os.close(fd)
        with directory("/etc") as parent:
            fd = os.open("ap-publisher", FLAGS | os.O_DIRECTORY, dir_fd=parent)
            try:
                m = meta(fd, mode=0o750, directory=True, acl=True)
                records["/etc/ap-publisher"] = self.record(m)
            finally:
                os.close(fd)
        acl = query(
            [
                "/usr/bin/getfacl",
                "--absolute-names",
                "--numeric",
                "--omit-header",
                "/etc/ap-publisher",
            ]
        )
        expected = {"user::rwx", "group::r-x", "mask::r-x", "other::---"} | {
            f"user:{self.accounts[r]['uid']}:r-x" for r in ROLES
        }
        need(set(acl.split()) == expected, "config_acl_invalid")
        need(saved["paths"] == records, "state_metadata_invalid")
        return "CONFIGURED", "verified_state_metadata"

    @staticmethod
    def record(m):
        return {
            "uid": m.st_uid,
            "gid": m.st_gid,
            "mode": stat.S_IMODE(m.st_mode),
            "device": m.st_dev,
            "inode": m.st_ino,
        }

    def units(self):
        common = {
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "UnitFileState": "static",
            "NoNewPrivileges": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "yes",
            "ProtectProc": "invisible",
            "ProcSubset": "pid",
            "CapabilityBoundingSet": "",
            "AmbientCapabilities": "",
            "ProtectKernelTunables": "yes",
            "ProtectKernelModules": "yes",
            "ProtectKernelLogs": "yes",
            "ProtectControlGroups": "yes",
            "RestrictSUIDSGID": "yes",
            "RestrictRealtime": "yes",
            "LockPersonality": "yes",
            "RestrictNamespaces": "yes",
            "LimitCORE": "0",
            "LimitCORESoft": "0",
            "CPUQuotaPerSecUSec": "1s",
            "TimeoutStopUSec": "5s",
            "ReadOnlyPaths": "/etc/ap-publisher /usr/lib/ap-worker-publisher",
            "StandardOutput": "journal",
            "StandardError": "null",
            "UMask": "0077",
            "SupplementaryGroups": "",
            "DropInPaths": "",
            "KillMode": "control-group",
            "Restart": "no",
        }
        for unit, role in zip(UNITS, ROLES, strict=True):
            expected = common | {
                "User": role,
                "Group": role,
                "AppArmorProfile": unit,
                "TasksMax": "1" if role.endswith("signer") else "8",
                "LimitNOFILE": "32" if role.endswith("signer") else "64",
                "LimitNOFILESoft": "32" if role.endswith("signer") else "64",
                "MemoryMax": "134217728" if role.endswith("signer") else "268435456",
                "TimeoutStartUSec": "10s" if role.endswith("signer") else "5min 10s",
                "ReadWritePaths": "/var/lib/"
                + role
                + "/journal"
                + (" /run/ap-publisher-signer" if role.endswith("signer") else ""),
                "InaccessiblePaths": "/var/lib/ap-publisher"
                if role.endswith("signer")
                else "/etc/ap-publisher-keys /var/lib/ap-publisher-signer",
            }
            expected["FragmentPath"] = "/usr/lib/systemd/system/" + unit + ".service"
            if role.endswith("signer"):
                expected["PrivateNetwork"] = "yes"
            text = query(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--no-pager",
                    "--property=" + ",".join(sorted(expected)),
                    "--all",
                    "--no-ask-password",
                    unit + ".service",
                ]
            )
            rows = [line.split("=", 1) for line in text.splitlines()]
            need(
                all(len(r) == 2 for r in rows)
                and len({r[0] for r in rows}) == len(rows),
                "unit_constraints_rejected",
            )
            actual = dict(rows)
            need(actual.get("LoadState") == "loaded", "unit_missing")
            need(actual == expected, "unit_constraints_rejected")
        return "CONFIGURED", "verified_effective_unit_settings"

    def apparmor(self):
        # Kernel pseudo-file: bounded read, no profile attachment inference.
        fd = os.open("/sys/kernel/security/apparmor/profiles", FLAGS)
        try:
            data = os.read(fd, 65537)
            need(len(data) <= 65536, "profiles_not_enforcing")
        finally:
            os.close(fd)
        lines = data.decode("ascii", "strict").splitlines()
        need(
            all(unit + " (enforce)" in lines for unit in UNITS),
            "profiles_not_enforcing",
        )
        return "CONFIGURED", "verified_enforced_profiles"

    def bpf(self):
        # Interface presence and effective policy are prerequisites, not proof
        # of an attached BPF program. No bpftool/probe/privileged syscall.
        try:
            interface = os.lstat("/sys/fs/bpf")
        except FileNotFoundError as exc:
            raise Blocked("bpf_interface_missing") from exc
        need(stat.S_ISDIR(interface.st_mode), "bpf_interface_missing")
        text = query(
            [
                "/usr/bin/systemctl",
                "show",
                "--no-pager",
                "--property=IPAddressDeny,IPAddressAllow,SocketBindDeny,RestrictAddressFamilies",
                "--all",
                "--no-ask-password",
                "ap-worker-publisher.service",
            ]
        )
        rows = [line.split("=", 1) for line in text.splitlines()]
        need(
            all(len(r) == 2 for r in rows)
            and len(rows) == 4
            and len({r[0] for r in rows}) == 4,
            "bpf_egress_policy_missing",
        )
        props = dict(rows)
        need(
            set(props)
            == {
                "IPAddressDeny",
                "IPAddressAllow",
                "SocketBindDeny",
                "RestrictAddressFamilies",
            }
            and set(props["IPAddressDeny"].split()) == {"0.0.0.0/0", "::/0"}
            and props["SocketBindDeny"] == "any"
            and props["RestrictAddressFamilies"] == "AF_INET",
            "bpf_egress_policy_missing",
        )
        peers = props["IPAddressAllow"].split()
        need(0 < len(peers) <= 8, "bpf_egress_policy_missing")
        need(
            all(ipaddress.ip_network(p, strict=True).num_addresses == 1 for p in peers),
            "bpf_egress_policy_missing",
        )
        return "NOT_RUN", "bpf_attachment_evidence_missing"


def report(observer):
    checks = {}
    for name in (*CHECKS[:8], "bpf", "caller_path"):
        try:
            state, reason = getattr(observer, name)()
        except Blocked as exc:
            state, reason = (
                "BLOCKED",
                (str(exc) if str(exc) in REASONS else "observation_failed"),
            )
        except FileNotFoundError:
            state, reason = "BLOCKED", "object_missing"
        except PermissionError:
            state, reason = "NOT_RUN", "observation_denied"
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            IndexError,
            RecursionError,
            subprocess.SubprocessError,
        ):
            state, reason = "BLOCKED", "observation_failed"
        need(state in STATES and reason in REASONS, "invalid_record")
        if name in SCOPE_REASONS and (
            state not in ("BLOCKED", "NOT_RUN") or reason not in SCOPE_REASONS[name]
        ):
            state, reason = "BLOCKED", "observation_failed"
        checks[name] = {"state": state, "reason": reason}
    for name, reason in zip(
        CHECKS[8:-1],
        (
            "account_lock_not_observed",
            "profile_attachment_evidence_missing",
            "bpf_attachment_evidence_missing",
            "process_isolation_evidence_missing",
            "independent_continuity_evidence_missing",
            "app_identity_not_authenticated",
            "operator_authorization_not_observed",
        ),
        strict=True,
    ):
        if name != "bpf":
            checks[name] = {"state": "NOT_RUN", "reason": reason}
    return {
        "schema": "AP-WORKER-DOCTOR/1",
        "status": "BLOCKED",
        "checks": checks,
        "artifacts": observer.artifacts,
        "launch_allowed": False,
        "installation": checks["package"]["state"],
        "configuration": "CONFIGURED"
        if all(
            checks[n]["state"] == "CONFIGURED"
            for n in ("path", "identities", "state", "units", "apparmor")
        )
        else "BLOCKED",
        "host_evidence": "HOST_NOT_RUN",
        "runtime": "LIVE_NO_GO",
        "subscription": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "gate_73": "BLOCKED",
    }


def main():
    print(json.dumps(report(Observer()), sort_keys=True, separators=(",", ":")))
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
