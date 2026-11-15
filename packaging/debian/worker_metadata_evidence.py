"""Bounded public metadata evidence, only for the disposable package fixture.

This wraps the installed validator without changing any predicate or outcome.
No repair, private state read, service command or host probe is provided.
"""

import os
import stat

PUBLIC_PREFIXES = (
    "/usr/lib/agent-platform-worker/",
    "/usr/lib/ap-worker-publisher/",
    "/usr/share/doc/agent-platform-worker/",
)
PUBLIC_LEAVES = frozenset(
    (
        "/usr/bin/agent-platform-worker",
        "/usr/bin/agent-platform-worker-native-artifact",
        "/usr/libexec/ap-worker-publisher",
        "/usr/libexec/ap-worker-publisher-signer",
        "/usr/libexec/ap-worker-publisher-export",
        "/etc/agent-platform-worker/package.conf",
        "/etc/apparmor.d/ap-worker-publisher",
        "/etc/apparmor.d/ap-worker-publisher-signer",
        "/usr/lib/systemd/system/ap-worker-publisher.service",
        "/usr/lib/systemd/system/ap-worker-publisher-signer.service",
        "/usr/share/man/man1/agent-platform-worker.1.gz",
        "/usr/share/man/man1/agent-platform-worker-native-artifact.1.gz",
    )
)
PUBLIC_ANCESTORS = frozenset(
    (
        "/",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/usr/share/doc",
        "/usr/share/man",
        "/usr/share/man/man1",
        "/etc",
        "/etc/apparmor.d",
        "/etc/agent-platform-worker",
        "/usr/lib/systemd",
        "/usr/lib/systemd/system",
        "/usr/lib/agent-platform-worker",
        "/usr/lib/ap-worker-publisher",
        "/usr/share/doc/agent-platform-worker",
    )
)
ATTRS = (
    "system.posix_acl_access",
    "system.posix_acl_default",
    "system.nfs4_acl",
    "security.capability",
)


def public_name(path):
    if (
        len(path) <= 512
        and path.startswith("/")
        and not {".", ".."}.intersection(path.split("/"))
        and all(c.isascii() and (c.isalnum() or c in "/-_.") for c in path)
        and (
            path in PUBLIC_LEAVES
            or path in PUBLIC_ANCESTORS
            or path.startswith(PUBLIC_PREFIXES)
        )
    ):
        return path
    return "UNRECOGNIZED"


def metadata(value, attributes):
    return {
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": format(stat.S_IMODE(value.st_mode), "04o"),
        "nlink": value.st_nlink,
        "device": value.st_dev,
        "inode": value.st_ino,
        "type": "directory"
        if stat.S_ISDIR(value.st_mode)
        else "regular"
        if stat.S_ISREG(value.st_mode)
        else "symlink"
        if stat.S_ISLNK(value.st_mode)
        else "other",
        "xattrs": {key: key in attributes for key in ATTRS},
        "other_xattr_count": len(set(attributes) - set(ATTRS)),
    }


def fingerprint(value):
    return tuple(
        getattr(value, field)
        for field in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def first_control(value, uid, gid, mode, directory, acl, attributes):
    if (value.st_uid, value.st_gid) != (uid, gid):
        return "OWNER"
    if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):
        return "TYPE"
    if not directory and value.st_nlink != 1:
        return "LINK_COUNT"
    if value.st_mode & 0o7022:
        return "FORBIDDEN_MODE_BITS"
    if mode is not None and stat.S_IMODE(value.st_mode) != mode:
        return "EXACT_MODE"
    bad = set(ATTRS) - ({"system.posix_acl_access"} if acl else set())
    return "ATTRIBUTES" if bad.intersection(attributes) else "UNRESOLVED"


def capture(doctor):
    """Replay only Observer.package; keep original meta and exceptions intact."""
    original = doctor.meta
    ancestors = {}
    result = {
        "schema": "AP-PKG-METADATA-EVIDENCE/1",
        "status": "NOT_REPRODUCED",
        "failure": None,
        "ancestors": [],
        "host": "HOST_NOT_RUN",
        "launch_allowed": False,
    }

    def observed(fd, uid=0, gid=0, mode=None, directory=False, acl=False):
        before = os.fstat(fd)
        try:
            value = original(fd, uid, gid, mode, directory, acl)
            if directory:
                name = public_name(os.readlink("/proc/self/fd/" + str(fd)))
                if name != "UNRECOGNIZED" and len(ancestors) < 64:
                    ancestors[name] = {
                        "object": name,
                        "actual": metadata(value, os.listxattr(fd)),
                    }
            return value
        except doctor.Blocked:
            # Only fixed public paths/attributes; never raw exception text, env,
            # arbitrary stderr, xattr values or protected state/journal contents.
            after = os.fstat(fd)
            attrs = os.listxattr(fd)
            name = public_name(os.readlink("/proc/self/fd/" + str(fd)))
            stable = fingerprint(before) == fingerprint(after)
            result["failure"] = {
                "object": name,
                "stable": stable,
                "control": first_control(before, uid, gid, mode, directory, acl, attrs)
                if stable and name != "UNRECOGNIZED"
                else "UNRESOLVED",
                "actual": metadata(before, attrs) if name != "UNRECOGNIZED" else None,
                "expected": {
                    "uid": uid,
                    "gid": gid,
                    "mode": mode,
                    "directory": directory,
                    "acl_allowed": acl,
                },
            }
            result["ancestors"] = [
                ancestors[key]
                for key in sorted(ancestors)
                if name != "UNRECOGNIZED"
                and key != name
                and name.startswith(key.rstrip("/") + "/")
            ]
            result["status"] = (
                "REPRODUCED" if stable and name != "UNRECOGNIZED" else "UNCERTAIN"
            )
            raise

    doctor.meta = observed
    try:
        doctor.Observer().package()
    except (doctor.Blocked, OSError, ValueError, KeyError, TypeError):
        if result["failure"] is None:
            result["status"] = "EVIDENCE_UNAVAILABLE"
    finally:
        doctor.meta = original
    return result
