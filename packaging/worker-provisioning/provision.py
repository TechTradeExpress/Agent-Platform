#!/usr/bin/python3 -IB
"""Explicit operator provisioning; never a maintainer script or service launcher."""

import argparse
import contextlib
import fcntl
import grp
import hashlib
import json
import os
import platform
import pwd
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

ROOT = 0
ROLES = ("ap-publisher", "ap-publisher-signer")
LEDGER = "/var/lib/agent-platform-worker-provisioning"
CONFIG = "/etc/ap-publisher"
PAYLOAD = "/usr/share/doc/agent-platform-worker/manifest.json"
BAD_ATTRS = {
    "system.posix_acl_access",
    "system.posix_acl_default",
    "system.nfs4_acl",
    "security.capability",
}
FLAGS = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


class Blocked(Exception):
    pass


def need(value, reason):
    if not value:
        raise Blocked(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def metadata(fd, uid, gid, mode, directory=False, acl=False):
    m = os.fstat(fd)
    need(
        (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode)) == (uid, gid, mode),
        "ownership_or_mode_conflict",
    )
    need(
        stat.S_ISDIR(m.st_mode)
        if directory
        else stat.S_ISREG(m.st_mode) and m.st_nlink == 1,
        "aliased_or_unsafe_object",
    )
    bad = BAD_ATTRS - ({"system.posix_acl_access"} if acl else set())
    need(not bad.intersection(os.listxattr(fd)), "unsafe_attributes")
    return {"uid": uid, "gid": gid, "mode": mode, "device": m.st_dev, "inode": m.st_ino}


@contextlib.contextmanager
def directory(path):
    need(path.startswith("/") and ".." not in path.split("/"), "invalid_fixed_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | FLAGS)
    try:
        metadata(fd, ROOT, ROOT, 0o755, True)
        for part in path.split("/")[1:]:
            if not part:
                continue
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
            metadata(fd, ROOT, ROOT, 0o755, True)
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def child(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | FLAGS, dir_fd=parent)
    try:
        need(os.fstat(fd).st_dev == os.fstat(parent).st_dev, "foreign_mount")
        yield fd
    finally:
        os.close(fd)


def exists(fd, name):
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def read(fd, name, limit=65536, mode=0o600):
    file = os.open(name, os.O_RDONLY | FLAGS, dir_fd=fd)
    try:
        metadata(file, ROOT, ROOT, mode)
        before = os.fstat(file)
        need(before.st_size <= limit, "oversize_state")
        with os.fdopen(file, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(file)
        need(
            len(data) == before.st_size
            and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "changing_state",
        )
        return data
    finally:
        os.close(file)


def parse(data):
    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, "duplicate_state_key")
            out[key] = value
        return out

    try:
        value = json.loads(data, object_pairs_hook=pairs)
        need(isinstance(value, dict), "invalid_state")
        need(encoded(value) == data, "noncanonical_state")
        return value
    except (ValueError, RecursionError) as exc:
        raise Blocked("invalid_state") from exc


def create(fd, name, data):
    file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | FLAGS, 0o600, dir_fd=fd)
    try:
        os.fchmod(file, 0o600)
        with os.fdopen(file, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(file)
    finally:
        os.close(file)
    os.fsync(fd)


def closed_tree(root, paths):
    """Reject unknown private code before any account/state writes."""
    allowed = set(paths)
    directories = {root}
    for path in allowed:
        for parent in Path(path).parents:
            if str(parent) == root or str(parent).startswith(root + "/"):
                directories.add(str(parent))
    need(len(allowed) <= 64 and len(directories) <= 16, "code_inventory_limit")
    for path in sorted(directories):
        expected = {
            str(Path(item).name)
            for item in allowed | directories
            if str(Path(item).parent) == path
        }
        with directory(path) as fd:
            need(set(os.listdir(fd)) == expected, "unknown_installed_code")


class System:
    """Production adapter: fixed tools, no shell, auth discovery or service writes."""

    def run(self, argv):
        need(
            signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
            and threading.active_count() == 1,
            "unsafe_child_lifecycle",
        )
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
                close_fds=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Blocked("system_tool_unavailable") from exc
        need(
            result.returncode == 0 and len(result.stdout) <= 32768,
            "system_tool_refused",
        )
        return result.stdout.decode("ascii", "strict")

    def accounts(self):
        with directory("/etc") as fd:
            policy = read(fd, "nsswitch.conf", 65536, 0o644).decode().splitlines()
        for database in ("passwd", "group"):
            entries = [
                line.split("#", 1)[0].split(":", 1)[1].split()
                for line in policy
                if line.startswith(database + ":")
            ]
            need(
                len(entries) == 1
                and "files" in entries[0]
                and set(entries[0]) <= {"files", "systemd"},
                "unsupported_nss_policy",
            )
        users = [
            {
                "name": x.pw_name,
                "uid": x.pw_uid,
                "gid": x.pw_gid,
                "home": x.pw_dir,
                "shell": x.pw_shell,
            }
            for x in pwd.getpwall()
        ]
        groups = [
            {"name": x.gr_name, "gid": x.gr_gid, "members": sorted(x.gr_mem)}
            for x in grp.getgrall()
        ]
        need(len(users) <= 10000 and len(groups) <= 10000, "nss_inventory_limit")
        # NSS and local files must agree for service principals. No shadow hashes read.
        with directory("/etc") as fd:
            local = read(fd, "passwd", 2 * 1024**2, 0o644).decode().splitlines()
            local_groups = read(fd, "group", 2 * 1024**2, 0o644).decode().splitlines()
        for role in ROLES:
            matches = [x for x in users if x["name"] == role]
            if matches:
                u = matches[0]
                need(
                    any(
                        line.split(":")[0] == role
                        and line.split(":")[2:4] == [str(u["uid"]), str(u["gid"])]
                        and line.split(":")[5:7] == [u["home"], u["shell"]]
                        for line in local
                    ),
                    "nonlocal_account",
                )
                need(
                    any(
                        line.split(":")[0] == role
                        and line.split(":")[2] == str(u["gid"])
                        for line in local_groups
                    ),
                    "nonlocal_group",
                )
                status = self.run(["/usr/bin/passwd", "-S", role]).split()
                need(
                    len(status) >= 2 and status[0] == role and status[1] == "L",
                    "account_not_locked",
                )
        return {"users": users, "groups": groups}

    def quiescent(self, accounts):
        for role in ROLES:
            unit = role.replace("ap-", "ap-worker-", 1) + ".service"
            for path in [
                f"/etc/systemd/system/{unit}",
                f"/etc/systemd/system/{unit}.d",
                f"/run/systemd/system/{unit}",
                f"/run/systemd/system/{unit}.d",
            ]:
                need(not os.path.lexists(path), "manual_unit_override")
            for root in ("/etc/systemd/system", "/run/systemd/system"):
                if os.path.lexists(root):
                    with directory(root):
                        need(
                            not self.run(
                                [
                                    "/usr/bin/find",
                                    root,
                                    "-maxdepth",
                                    "3",
                                    "-type",
                                    "l",
                                    "(",
                                    "-name",
                                    unit,
                                    "-o",
                                    "-lname",
                                    "*/" + unit,
                                    "-o",
                                    "-lname",
                                    unit,
                                    ")",
                                    "-print",
                                ]
                            ).strip(),
                            "unit_alias_or_enablement",
                        )
            if Path("/run/systemd/system").is_dir():
                fields = dict(
                    line.split("=", 1)
                    for line in self.run(
                        [
                            "/usr/bin/systemctl",
                            "show",
                            "--property=ActiveState,UnitFileState",
                            unit,
                        ]
                    ).splitlines()
                )
                need(
                    fields.get("ActiveState") == "inactive"
                    and fields.get("UnitFileState") in ("static", "disabled"),
                    "unit_not_quiescent",
                )
        uids = {u["uid"] for u in accounts.values()}
        processes = list(Path("/proc").glob("[0-9]*/status"))
        need(len(processes) <= 4096, "process_inventory_limit")
        for status in processes:
            try:
                lines = status.read_text().splitlines()
            except FileNotFoundError:
                continue
            need(
                not any(
                    line.startswith("Uid:")
                    and any(int(n) in uids for n in line.split()[1:])
                    for line in lines
                ),
                "principal_has_processes",
            )

    def payload(self):
        need(
            sys.platform == "linux" and platform.machine() == "x86_64",
            "unsupported_platform",
        )
        with directory("/usr/lib") as fd:
            release = read(fd, "os-release", 8192, 0o644)
        need(
            b"ID=debian\n" in release and b'VERSION_ID="13"' in release,
            "unsupported_distribution",
        )
        for tool in ("useradd", "groupadd"):
            for phase in ("pre", "post"):
                path = Path(f"/etc/shadow-maint/{tool}-{phase}.d")
                if os.path.lexists(path):
                    with directory(str(path)) as fd:
                        need(not os.listdir(fd), "account_hook_conflict")
        with directory("/usr/share/doc/agent-platform-worker") as fd:
            inventory = json.loads(read(fd, "manifest.json", 262144, 0o644))
        expected = {}
        for item in inventory["files"]:
            path = item["path"]
            if path.startswith(
                (
                    "/usr/lib/ap-worker-publisher/",
                    "/usr/libexec/ap-worker-publisher",
                    "/usr/lib/agent-platform-worker/provisioning/",
                )
            ) or path in (
                "/usr/bin/agent-platform-worker",
                "/usr/lib/systemd/system/ap-worker-publisher.service",
                "/usr/lib/systemd/system/ap-worker-publisher-signer.service",
                "/etc/apparmor.d/ap-worker-publisher",
                "/etc/apparmor.d/ap-worker-publisher-signer",
            ):
                expected[path] = item
        need(len(expected) >= 20, "missing_p1_inventory")
        for root in (
            "/usr/lib/ap-worker-publisher",
            "/usr/lib/agent-platform-worker/provisioning",
        ):
            closed_tree(root, [p for p in expected if p.startswith(root + "/")])
        for path, item in expected.items():
            parent, name = path.rsplit("/", 1)
            with directory(parent) as fd:
                data = read(fd, name, 131072, item["mode"])
            need(
                hashlib.sha256(data).hexdigest() == item["sha256"],
                "installed_payload_changed",
            )
        for name in ROLES:
            profile = name.replace("ap-", "ap-worker-", 1)
            self.run(
                [
                    "/usr/sbin/apparmor_parser",
                    "--skip-kernel-load",
                    "--skip-cache",
                    "/etc/apparmor.d/" + profile,
                ]
            )

    def new_account(self, name, uid, gid):
        self.run(["/usr/sbin/groupadd", "--system", "--gid", str(gid), name])
        self.run(
            [
                "/usr/sbin/useradd",
                "--system",
                "--uid",
                str(uid),
                "--no-create-home",
                "--no-user-group",
                "--no-log-init",
                "--gid",
                name,
                "--home-dir",
                "/var/lib/" + name,
                "--shell",
                "/usr/sbin/nologin",
                name,
            ]
        )

    def acl(self, path, ids, create_acl=False):
        if create_acl:
            self.run(
                [
                    "/usr/bin/setfacl",
                    "-m",
                    f"u:{ids[0]}:r-x,u:{ids[1]}:r-x,m::r-x",
                    path,
                ]
            )
        text = self.run(
            ["/usr/bin/getfacl", "--absolute-names", "--numeric", "--omit-header", path]
        )
        expected = {
            "user::rwx",
            f"user:{ids[0]}:r-x",
            f"user:{ids[1]}:r-x",
            "group::r-x",
            "mask::r-x",
            "other::---",
        }
        need(set(text.split()) == expected, "config_acl_conflict")


def identities(snapshot, allow_missing=False):
    users, groups = snapshot["users"], snapshot["groups"]
    result = {}
    for name in ROLES:
        us = [u for u in users if u["name"] == name]
        gs = [g for g in groups if g["name"] == name]
        if not us and not gs and allow_missing:
            continue
        need(len(us) == len(gs) == 1, "account_or_group_collision")
        u, g = us[0], gs[0]
        need(
            0 < u["uid"] < 1000 and 0 < g["gid"] < 1000 and u["gid"] == g["gid"],
            "unsafe_principal_identity",
        )
        need(
            u["shell"] in ("/usr/sbin/nologin", "/bin/false")
            and u["home"] in ("/nonexistent", "/var/lib/" + name),
            "unsafe_principal_login",
        )
        need(
            sum(x["uid"] == u["uid"] for x in users) == 1
            and sum(x["gid"] == g["gid"] for x in groups) == 1,
            "numeric_identity_collision",
        )
        need(
            not (set(g["members"]) - {name})
            and not any(name in x["members"] for x in groups if x["name"] != name),
            "supplementary_group_conflict",
        )
        need(
            not any(x["name"] != name and x["gid"] == g["gid"] for x in users),
            "shared_primary_group",
        )
        result[name] = {"uid": u["uid"], "gid": g["gid"]}
    need(
        len({x["uid"] for x in result.values()}) == len(result)
        and len({x["gid"] for x in result.values()}) == len(result),
        "shared_identity",
    )
    return result


def filesystem(parent, etc, accounts, system, allow_missing):
    records = {}
    missing = []
    for name in ROLES:
        need(exists(parent, ".ap-pkg-stage-" + name) is None, "retained_unknown_stage")
        m = exists(parent, name)
        if m is None:
            need(allow_missing, "missing_state_directory")
            missing.append(name)
            continue
        need(name in accounts, "state_without_principal")
        owner = accounts[name]
        with child(parent, name) as fd:
            records["/var/lib/" + name] = metadata(
                fd, owner["uid"], owner["gid"], 0o700, True
            )
            names = os.listdir(fd)
            need(len(names) <= 64, "missing_or_excess_state")
            if "journal" not in names:
                need(allow_missing and not names, "missing_or_excess_state")
                missing.append("journal:" + name)
            for item in names:
                file = os.open(item, os.O_RDONLY | FLAGS, dir_fd=fd)
                try:
                    st = os.fstat(file)
                    need(st.st_size <= 4 * 1024**2, "state_limit")
                    uid, gid = (
                        (owner["uid"], owner["gid"])
                        if item == "journal"
                        else (st.st_uid, st.st_gid)
                    )
                    need(
                        (uid, gid) in ((ROOT, ROOT), (owner["uid"], owner["gid"])),
                        "foreign_state_owner",
                    )
                    info = metadata(file, uid, gid, 0o600)
                    if item == "journal":
                        records["/var/lib/" + name + "/journal"] = info
                finally:
                    os.close(file)
    if exists(etc, "ap-publisher") is None:
        need(allow_missing, "missing_configuration_directory")
        missing.append("config")
    else:
        need(len(accounts) == 2, "config_without_principals")
        with child(etc, "ap-publisher") as fd:
            records[CONFIG] = metadata(fd, ROOT, ROOT, 0o750, True, True)
        system.acl(CONFIG, [accounts[n]["uid"] for n in ROLES])
    return records, missing


def checkpoint(_phase):
    """Only an offline fault-injection seam, no runtime override."""


def provision(system, *, initialize=False, recover=False):
    need(os.geteuid() == ROOT, "operator_root_required")
    system.payload()
    with directory("/var/lib") as parent, directory("/etc") as etc:
        try:
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Blocked("provisioning_busy") from exc
        with contextlib.ExitStack() as stack:
            ledger = None
            if exists(parent, "agent-platform-worker-provisioning") is not None:
                ledger = stack.enter_context(
                    child(parent, "agent-platform-worker-provisioning")
                )
                metadata(ledger, ROOT, ROOT, 0o700, True)
                need(
                    bool(os.listdir(ledger))
                    and set(os.listdir(ledger)) <= {"intent.json", "receipt.json"},
                    "unknown_ledger",
                )
                if exists(ledger, "intent.json") is not None:
                    need(
                        recover and exists(ledger, "receipt.json") is not None,
                        "reconciliation_required",
                    )
                else:
                    need(not recover, "no_recovery_intent")
            else:
                need(not recover, "no_recovery_intent")
            snapshot = system.accounts()
            accounts = identities(snapshot, allow_missing=not recover)
            system.quiescent(accounts)
            planned = {}
            used_uids = {u["uid"] for u in snapshot["users"]}
            used_gids = {g["gid"] for g in snapshot["groups"]} | {
                u["gid"] for u in snapshot["users"]
            }
            for role in ROLES:
                if role not in accounts:
                    uid = next(
                        (n for n in range(999, 99, -1) if n not in used_uids), None
                    )
                    gid = next(
                        (n for n in range(999, 99, -1) if n not in used_gids), None
                    )
                    need(
                        uid is not None and gid is not None, "system_id_range_exhausted"
                    )
                    planned[role] = {"uid": uid, "gid": gid}
                    used_uids.add(uid)
                    used_gids.add(gid)
            records, missing = filesystem(
                parent, etc, accounts, system, allow_missing=not recover
            )
            need(not missing or initialize, "explicit_initialization_required")
            need(not recover or len(accounts) == 2, "reconciliation_required")
            receipt = {
                "schema": "AP-WORKER-PROVISION/1",
                "accounts": accounts,
                "paths": records,
            }
            if ledger is not None and exists(ledger, "receipt.json") is not None:
                saved = parse(read(ledger, "receipt.json"))
                digest = saved.get("intent_sha256", "")
                need(
                    isinstance(digest, str)
                    and len(digest) == 64
                    and all(c in "0123456789abcdef" for c in digest),
                    "unknown_receipt",
                )
                receipt["intent_sha256"] = digest
                need(
                    saved == receipt and not missing and len(accounts) == 2,
                    "provisioned_identity_changed",
                )
                if recover:
                    intent_data = read(ledger, "intent.json")
                    need(
                        hashlib.sha256(intent_data).hexdigest() == digest,
                        "unknown_intent",
                    )
                    intent = parse(intent_data)
                    need(
                        set(intent)
                        == {"schema", "before_accounts", "new_accounts", "initialize"}
                        and intent.get("schema") == "AP-WORKER-INTENT/1"
                        and type(intent["initialize"]) is bool
                        and isinstance(intent["before_accounts"], dict)
                        and isinstance(intent["new_accounts"], dict)
                        and set(intent["before_accounts"]) | set(intent["new_accounts"])
                        == set(ROLES)
                        and all(
                            accounts.get(n) == value
                            for n, value in intent["new_accounts"].items()
                        )
                        and all(
                            accounts.get(n) == value
                            for n, value in intent["before_accounts"].items()
                        ),
                        "unknown_intent",
                    )
                    os.unlink("intent.json", dir_fd=ledger)
                    os.fsync(ledger)
                return {"status": "VERIFIED_NOT_ACTIVATED", "launch_allowed": False}
            need(
                not recover and (ledger is None or not os.listdir(ledger)),
                "unknown_ledger",
            )
            # Revalidate NSS and quiescence before the first persistent write.
            need(system.accounts() == snapshot, "changing_nss")
            # Include orphan processes using IDs not yet represented in NSS.
            # Check the complete plan before even creating the durable ledger.
            system.quiescent(accounts | planned)
            if ledger is None:
                os.mkdir("agent-platform-worker-provisioning", 0o700, dir_fd=parent)
                ledger = stack.enter_context(
                    child(parent, "agent-platform-worker-provisioning")
                )
                os.fchmod(ledger, 0o700)
                os.fsync(parent)
            intent_data = encoded(
                {
                    "schema": "AP-WORKER-INTENT/1",
                    "before_accounts": accounts,
                    "new_accounts": planned,
                    "initialize": initialize,
                }
            )
            create(ledger, "intent.json", intent_data)
            checkpoint("intent")
            for name in ROLES:
                if name not in accounts:
                    system.new_account(name, **planned[name])
                    checkpoint("account")
                    accounts = identities(system.accounts(), allow_missing=True)
                    need(
                        accounts.get(name) == planned[name],
                        "account_creation_unconfirmed",
                    )
            accounts = identities(system.accounts())
            system.quiescent(accounts)
            for name in missing:
                if name.startswith("journal:"):
                    role = name.split(":", 1)[1]
                    owner = accounts[role]
                    with child(parent, role) as fd:
                        metadata(fd, owner["uid"], owner["gid"], 0o700, True)
                        need(not os.listdir(fd), "state_changed_before_initialization")
                        create(fd, "journal", b"")
                        file = os.open("journal", os.O_RDONLY | FLAGS, dir_fd=fd)
                        try:
                            os.fchown(file, owner["uid"], owner["gid"])
                            os.fsync(file)
                        finally:
                            os.close(file)
                        os.fsync(fd)
                    checkpoint("journal_created")
                    continue
                if name == "config":
                    os.mkdir("ap-publisher", 0o700, dir_fd=etc)
                    with child(etc, "ap-publisher") as fd:
                        os.fchmod(fd, 0o750)
                    system.acl(CONFIG, [accounts[n]["uid"] for n in ROLES], True)
                    os.fsync(etc)
                    continue
                owner = accounts[name]
                stage = ".ap-pkg-stage-" + name
                os.mkdir(stage, 0o700, dir_fd=parent)
                with child(parent, stage) as fd:
                    create(fd, "journal", b"")
                    file = os.open("journal", os.O_RDONLY | FLAGS, dir_fd=fd)
                    try:
                        os.fchown(file, owner["uid"], owner["gid"])
                        os.fsync(file)
                    finally:
                        os.close(file)
                    os.fchown(fd, owner["uid"], owner["gid"])
                    os.fchmod(fd, 0o700)
                    os.fsync(fd)
                checkpoint("state_staged")
                os.rename(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            records, missing = filesystem(parent, etc, accounts, system, False)
            need(not missing, "provisioning_incomplete")
            receipt = {
                "schema": "AP-WORKER-PROVISION/1",
                "accounts": accounts,
                "paths": records,
            }
            receipt["intent_sha256"] = hashlib.sha256(intent_data).hexdigest()
            create(ledger, "receipt.json", encoded(receipt))
            checkpoint("receipt")
            os.unlink("intent.json", dir_fd=ledger)
            os.fsync(ledger)
            return {"status": "PROVISIONED_NOT_ACTIVATED", "launch_allowed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--initialize-journals", action="store_true")
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    if not args.approve:
        parser.error("explicit operator --approve required")
    try:
        need(os.geteuid() == ROOT, "operator_root_required")
        signal.signal(
            signal.SIGALRM,
            lambda *_: (_ for _ in ()).throw(Blocked("provisioning_timeout")),
        )
        signal.alarm(120)
        result = provision(
            System(), initialize=args.initialize_journals, recover=args.recover
        )
        result.update(
            runtime="LIVE_NO_GO",
            authentication="NOT_RUN",
            profiles="SYNTAX_ONLY_NOT_ATTACHMENT",
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Blocked as error:
        print(
            json.dumps(
                {"status": "BLOCKED", "reason": str(error), "launch_allowed": False},
                sort_keys=True,
            )
        )
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print(
            '{"status":"BLOCKED","reason":"provisioning_state_uncertain","launch_allowed":false}'
        )
    return 13


if __name__ == "__main__":
    raise SystemExit(main())
