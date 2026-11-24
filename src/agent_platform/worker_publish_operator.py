"""Root-supervised worker01 entrypoint for the existing PUB-02 one-shot units."""

import argparse
import fcntl
import os
import pwd
import secrets
import selectors
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import worker_publish_artifact as art
from . import worker_publisher as pub
from .worker_publish_io import (
    ACL_GROUP_OBJ,
    ACL_MASK,
    ACL_OTHER,
    ACL_USER,
    ACL_USER_OBJ,
    ACL_XATTR,
    HTTPS,
    Journal,
    acl_entries,
    read_file,
)

CONFIG = Path(pub.JOB_PATH).parent
PENDING = CONFIG / ".homelab-job.pending"
SIGNER_OUTPUT = "/run/ap-publisher-signer/app-jwt"
KEY = Path("/etc/ap-publisher-keys/worker.pem")
PROFILES = "/sys/kernel/security/apparmor/profiles"
ROLES = {
    "publisher": "ap-publisher",
    "signer": "ap-publisher-signer",
}


def unit(role):
    return "ap-worker-publisher" + ("-signer" if role == "signer" else "") + ".service"


def command(argv, *, timeout=5):
    deadline = time.monotonic() + timeout
    with (
        subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "PATH": "/usr/sbin:/usr/bin"},
        ) as process,
        selectors.DefaultSelector() as selector,
    ):
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        try:
            while True:
                remaining = deadline - time.monotonic()
                art.need(remaining > 0 and selector.select(remaining))
                part = os.read(process.stdout.fileno(), 32769 - len(output))
                if not part:
                    break
                output.extend(part)
                art.need(len(output) <= 32768)
            art.need(process.wait(timeout=max(0, deadline - time.monotonic())) == 0)
        finally:
            if process.poll() is None:
                process.kill()
    return output.decode("ascii").strip()


def systemctl(*args, timeout=5):
    return command(
        ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", *args],
        timeout=timeout,
    )


def exclusive_config():
    fd = os.open(CONFIG, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        art.need(info.st_uid == 0 and not info.st_mode & 0o022)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def host_identity():
    art.need(socket.gethostname().split(".")[0] == "worker01")
    worker = pwd.getpwnam("agentdev")
    identities = {"worker_uid": worker.pw_uid}
    for role, account in ROLES.items():
        identity = pwd.getpwnam(account)
        identities[role + "_uid"] = identity.pw_uid
        identities[role + "_gid"] = identity.pw_gid
    art.need(len({identities[k] for k in identities if k.endswith("_uid")}) == 3)
    art.need(all(v > 0 for v in identities.values()))
    art.need(identities["publisher_gid"] != identities["signer_gid"])
    return identities


def verify_unit(role, allow):
    service = unit(role)
    profile = service.removesuffix(".service")
    signer = role == "signer"
    if signer:
        allow = ""
    dropin = f"/run/systemd/system.control/{service}.d/50-IPAddressAllow.conf"
    account = ROLES[role]
    expected = {
        "LoadState": "loaded",
        "NeedDaemonReload": "no",
        "ActiveState": "inactive",
        "UnitFileState": "static",
        "FragmentPath": "/usr/lib/systemd/system/" + service,
        "DropInPaths": dropin if allow else "",
        "User": account,
        "Group": account,
        "Type": "oneshot",
        "Restart": "no",
        "TasksMax": "4" if signer else "8",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "AppArmorProfile": profile,
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateDevices": "yes",
        "ProtectProc": "invisible",
        "ProcSubset": "pid",
        "RestrictNamespaces": "yes",
        "RuntimeDirectory": "ap-publisher-signer" if signer else "",
        "RuntimeDirectoryPreserve": "yes" if signer else "no",
        "PrivateNetwork": "yes" if signer else "no",
        "NetworkNamespacePath": "",
        "JoinsNamespaceOf": "",
        "RestrictAddressFamilies": "AF_UNIX" if signer else "AF_INET",
        "IPAddressAllow": allow,
        "IPAddressDeny": "" if signer else "0.0.0.0/0 ::/0",
    }
    if not signer:
        expected["SocketBindDeny"] = "any"
    result = systemctl("show", "--all", "--property=" + ",".join(expected), service)
    rows = [line.split("=", 1) for line in result.splitlines()]
    actual = dict(rows)
    art.need(len(actual) == len(rows))
    if not signer and actual.get("IPAddressDeny") == "::/0 0.0.0.0/0":
        actual["IPAddressDeny"] = "0.0.0.0/0 ::/0"
    art.need(actual == expected)

    # D-Bus exposes exact argv, execution flags and credential paths. Unlike
    # human-readable systemctl output, it preserves list and argument boundaries.
    executable = "/usr/libexec/" + profile
    argv = [executable]
    if not signer:
        argv += [
            "--job",
            pub.JOB_PATH,
            "--artifact",
            str(CONFIG / "candidate.json"),
            "--execute",
        ]
    source = ["app-key", str(KEY)] if signer else ["app-jwt", SIGNER_OUTPUT]
    writable = [f"/var/lib/{account}/journal"]
    inaccessible = ["/etc/ap-publisher-keys", "/var/lib/ap-publisher-signer"]
    if signer:
        writable.append("/run/ap-publisher-signer")
        inaccessible = ["/var/lib/ap-publisher"]
    typed = {
        "LoadCredential": ("a(ss)", [source]),
        "LoadCredentialEncrypted": ("a(ss)", []),
        "ImportCredentialEx": ("a(ss)", []),
        "SocketBindAllow": ("a(iiqq)", []),
        "SupplementaryGroups": ("as", []),
        "ReadOnlyPaths": ("as", ["/etc/ap-publisher", "/usr/lib/ap-worker-publisher"]),
        "ReadWritePaths": ("as", writable),
        "InaccessiblePaths": ("as", inaccessible),
        "BindPaths": ("a(ssbt)", []),
        "BindReadOnlyPaths": ("a(ssbt)", []),
    }
    verify_exec(service, executable, argv, typed)


def verify_exec(service, executable, argv, typed):
    typed = dict(typed)
    for hook in (
        "ExecConditionEx",
        "ExecStartPreEx",
        "ExecStartPostEx",
        "ExecStopEx",
        "ExecStopPostEx",
    ):
        typed[hook] = ("a(sasasttttuii)", [])
    manager = "org.freedesktop.systemd1"
    unit_path = service.replace("-", "_2d").replace(".", "_2e")
    output = command(
        [
            "/usr/bin/busctl",
            "--system",
            "--no-pager",
            "--json=short",
            "get-property",
            manager,
            "/org/freedesktop/systemd1/unit/" + unit_path,
            manager + ".Service",
            "ExecStartEx",
            *typed,
        ]
    )
    replies = [art.decode(line.encode()) for line in output.splitlines()]
    art.need(len(replies) == 1 + len(typed))
    start = replies[0]
    art.need(start["type"] == "a(sasasttttuii)" and len(start["data"]) == 1)
    entry = start["data"][0]
    art.need(len(entry) == 10 and entry[:3] == [executable, argv, []])
    for (signature, data), reply in zip(typed.values(), replies[1:], strict=True):
        art.need(reply == {"type": signature, "data": data})


def inspect_units(allow=""):
    for role in ROLES:
        verify_unit(role, allow)


def inspect_host():
    identities = host_identity()
    for path in (pub.JOB_PATH, PENDING, SIGNER_OUTPUT):
        art.need(not os.path.lexists(path))
    # Inspect metadata only. The PEM is read by systemd and the confined signer.
    for path, kind in ((KEY.parent, stat.S_ISDIR), (KEY, stat.S_ISREG)):
        info = path.lstat()
        art.need(kind(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o7077)
    art.need(info.st_nlink == 1)
    with open(PROFILES, "rb") as source:
        profiles = source.read(131073)
    art.need(len(profiles) <= 131072)
    for role in ROLES:
        profile = unit(role).removesuffix(".service")
        art.need((profile + " (enforce)").encode() in profiles.splitlines())
    inspect_units()
    return identities


def journal(role, identities):
    return Journal(
        "/var/lib/" + ROLES[role] + "/journal",
        None,
        inspect_owner=identities[role + "_uid"],
    )


def inspect_journals(identities, job=None):
    pins = {}
    for role in ROLES:
        store = journal(role, identities)
        try:
            # With no candidate, detect unfinished stores without writing anything.
            records = store.events
            art.need(not records or records[-1]["record"].get("phase") == "COMPLETE")
            if job is not None:
                store.admissible(job, signer=role == "signer")
            prefix = "signer_" if role == "signer" else ""
            pins[prefix + "journal_sha256"] = store.sha256
        finally:
            store.close()
    return pins


def prepare(args, identities, journal_pins):
    data = read_file(pub.HOMELAB_ARTIFACT, 0, art.MAX_WIRE)
    art.need(art.digest(data) == args.artifact_sha256)
    objects, _, inventory, _ = art.validate(data, args.head, args.tree, args.parent)
    art.need(type(args.issue) is int and 0 < args.issue < 2**31)
    ipv4 = command(["/usr/bin/getent", "ahostsv4", "api.github.com"]).split()[0]
    wire = HTTPS.homelab(ipv4)

    def get(path):
        status, value = wire.exchange("GET", path, None, None)
        art.need(status == 200)
        return value

    app_id, installation_id, slug = pub.WORKERS["worker01"]
    bot_login = slug + "[bot]"
    repo = get(pub.ROOT)
    issue = get(pub.ROOT + f"/issues/{args.issue}")
    bot = get("/users/" + slug + "%5Bbot%5D")
    art.need(bot["type"] == "Bot" and bot["login"] == bot_login)
    job = {
        "contract": pub.HOMELAB,
        "version": art.VERSION,
        "id": secrets.token_hex(16),
        "worker": "worker01",
        "app_id": app_id,
        "installation_id": installation_id,
        "app_slug": slug,
        "repo_node": repo["node_id"],
        "owner_id": repo["owner"]["id"],
        "app_owner_id": args.app_owner_id,
        "bot_id": bot["id"],
        "bot_login": bot_login,
        "issue": args.issue,
        "issue_id": issue["id"],
        "ref": args.ref,
        "operation": "create",
        "old": "ABSENT",
        "pr": None,
        "head": args.head,
        "tree": args.tree,
        "parent": args.parent,
        "base": args.parent,
        "artifact_sha256": args.artifact_sha256,
        "github_ipv4": ipv4,
        "expires": int(time.time()) + 300,
        **identities,
        **journal_pins,
    }
    pub.validate_job(job, int(time.time()))
    client = pub.Client(job, objects, wire)
    client.observe(None)
    client.workflows(inventory)
    art.need(inspect_journals(identities, job) == journal_pins)
    job["expires"] = int(time.time()) + 300
    return job


def stage_job(job, directory):
    # Fixed pending name and exclusive creation retain evidence on failure.
    name = Path(pub.JOB_PATH).name
    value = art.encoded(job)
    readers = sorted(job[role + "_uid"] for role in ROLES)
    art.need(len(set(readers)) == 2 and all(0 < uid < 2**32 - 1 for uid in readers))
    undefined = 2**32 - 1
    acl = [
        (ACL_USER_OBJ, 4, undefined),
        *((ACL_USER, 4, uid) for uid in readers),
        (ACL_GROUP_OBJ, 0, undefined),
        (ACL_MASK, 4, undefined),
        (ACL_OTHER, 0, undefined),
    ]
    raw = b"\x02\x00\x00\x00" + b"".join(
        tag.to_bytes(2, "little")
        + perm.to_bytes(2, "little")
        + uid.to_bytes(4, "little")
        for tag, perm, uid in acl
    )
    fd = os.open(
        PENDING.name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
        dir_fd=directory,
    )

    def pin(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_ctime_ns,
            info.st_mtime_ns,
        )

    def verify(leaf):
        before = os.fstat(fd)
        art.need(
            stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o440
            and before.st_uid == before.st_gid == 0
            and before.st_nlink == 1
            and before.st_size == len(value)
        )
        art.need(acl_entries(os.getxattr(fd, ACL_XATTR)) == acl)
        art.need(os.pread(fd, len(value) + 1, 0) == value)
        for observed in (
            os.fstat(fd),
            os.stat(leaf, dir_fd=directory, follow_symlinks=False),
        ):
            art.need(pin(observed) == pin(before))

    try:
        os.fchown(fd, 0, 0)
        art.need(os.write(fd, value) == len(value))
        os.setxattr(fd, ACL_XATTR, raw)
        os.fsync(fd)
        verify(PENDING.name)
        os.fsync(directory)
        # link fails if an existing job occupies the destination.
        os.link(
            PENDING.name,
            name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.fsync(directory)
        os.unlink(PENDING.name, dir_fd=directory)
        os.fsync(fd)
        os.fsync(directory)
        verify(name)
    finally:
        os.close(fd)


def launch(job, identities):
    # Use a runtime-only exact IPv4 allowlist on the existing unit. The strict
    # transport still enforces its own configured address and certificate.
    service = unit("publisher")
    allow = job["github_ipv4"] + "/32"
    inspect_units()
    systemctl("set-property", "--runtime", service, "IPAddressAllow=" + allow)
    inspect_units(allow)
    art.need(time.time() < job["expires"])
    systemctl("start", unit("signer"), timeout=20)
    inspect_units(allow)
    art.need(time.time() < job["expires"])
    systemctl("start", service, timeout=325)
    store = journal("publisher", identities)
    try:
        record = store.events[-1]["record"]
        art.need(
            record["phase"] == "COMPLETE"
            and all(record[k] == job[k] for k in ("ref", "issue", "head"))
            and record["job"] == job["id"]
            and type(record["pr"]) is int
            and record["pr"] > 0
        )
        return record["pr"]
    finally:
        store.close()


def report(status, **fields):
    print(
        art.encoded({"status": status, **pub.HOMELAB_STATUS, **fields}).decode(),
        flush=True,
    )


def main(argv):
    if argv and argv[:1] == ["recovery-handoff"]:
        from . import worker_publish_generation as generation

        return generation.operator_main(argv[1:], sys.modules[__name__])
    if argv and argv[:1] == ["reconcile-v4"]:
        from . import worker_publish_case

        return worker_publish_case.main(argv[1:], sys.modules[__name__])
    parser = argparse.ArgumentParser(description="Root-only worker01 Draft Publisher")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("readiness")
    for action in ("preview", "approve-create"):
        sub = commands.add_parser(action)
        sub.add_argument("--issue", type=int, required=True)
        sub.add_argument("--app-owner-id", type=int, required=True)
        for key in ("ref", "head", "tree", "parent", "artifact-sha256"):
            sub.add_argument("--" + key, required=True)
        if action == "approve-create":
            sub.add_argument("--confirm-app-policy", action="store_true", required=True)
    args = parser.parse_args(argv)
    directory = None
    intent = False
    check = "root_required"
    try:
        art.need(os.getuid() == os.geteuid() == 0)
        # OpenSSL must use system trust, with neither overrides nor key logging.
        check = "unsafe_environment"
        art.need(
            not any(
                k in os.environ
                for k in (
                    "SSLKEYLOGFILE",
                    "SSL_CERT_FILE",
                    "SSL_CERT_DIR",
                    "OPENSSL_CONF",
                    "OPENSSL_MODULES",
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                )
            )
        )
        check = "config_lock"
        directory = exclusive_config()
        check = "host_identity_key_profiles_units_or_retained_job"
        identities = inspect_host()
        check = "journal_missing_busy_or_unfinished"
        journal_pins = inspect_journals(identities)
        if args.action == "readiness":
            report("LOCAL_CHECKS_PASSED", remote="NOT_RUN", live="NOT_RUN")
            return 0
        check = "candidate_remote_facts_or_journal"
        job = prepare(args, identities, journal_pins)
        facts = {
            k: job[k]
            for k in (
                "worker",
                "app_slug",
                "app_id",
                "installation_id",
                "app_owner_id",
                "issue",
                "ref",
                "head",
                "tree",
                "parent",
                "artifact_sha256",
                "old",
            )
        }
        report("DRY_RUN", repository=pub.REPOSITORY, operation="create-draft", **facts)
        if args.action == "preview":
            return 0
        check = "stage_job"
        intent = True
        stage_job(job, directory)
        check = "unit_or_publication_needs_reconciliation"
        pr = launch(job, identities)
        report("PUBLISHED", pr=pr, head=job["head"])
        return 0
    except Exception:
        report("UNKNOWN_NEEDS_HUMAN" if intent else "BLOCKED", check=check)
        return 1
    finally:
        if directory is not None:
            os.close(directory)
