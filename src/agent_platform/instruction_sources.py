"""HAR-04 offline instruction-source diagnostics: one canonical root AGENTS.md.

SOURCE_ONLY, read-only and inert. It inspects names and metadata only (plus the
bytes of the repository's own root AGENTS.md for a digest). It never runs a
vendor CLI, reads a home directory, login store or session, or creates/links a
CLAUDE.md. A consistent scan is *not* proof that Claude Code loaded AGENTS.md:
that fact requires a separately authorized observation of the exact pinned
binary (see ``validate_load_evidence``) and is NOT_RUN here.

Vendor behavior modelled (official memory documentation, observed 2026-11-16):
Claude Code reads AGENTS.md only when no CLAUDE.md, .claude/CLAUDE.md or
CLAUDE.local.md exists in the working directory or any ancestor. AGENTS.md
reading needs v2.1.277; before v2.1.281 some sessions (Bedrock, telemetry
disabled) read CLAUDE.md only, so this contract requires >= 2.1.281.
"""

import hashlib
import os
import re
import stat

FIRST_NATIVE = (2, 1, 277)
MINIMUM = (2, 1, 281)
CLAUDE_NAMES = ("CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md")
AGENTS_NAMES = ("AGENTS.md", ".claude/AGENTS.md")
MAX_ANCESTORS = 64
MAX_ENTRIES = 50000
MAX_AGENTS_BYTES = 1024 * 1024
REASONS = frozenset(
    """claude_md_in_worktree claude_local_md_in_worktree
claude_md_in_ancestor claude_local_md_in_ancestor
agents_md_missing agents_md_not_regular agents_md_unreadable
agents_md_in_ancestor agents_md_nested claude_md_nested
claude_dir_agents_md scan_limit root_invalid""".split()
)
RESULTS = frozenset(
    "CONSISTENT_UNVERIFIED CONFLICT AGENTS_MD_MISSING VERSION_BLOCKED NOT_RUN".split()
)


def parse_version(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", text):
        raise ValueError("invalid_version")
    return tuple(map(int, text.split(".")))


def version_status(text):
    """Policy for a pinned release; never an observation of a binary."""
    version = parse_version(text)
    if version < FIRST_NATIVE:
        return "UNSUPPORTED"
    if version < MINIMUM:
        return "DOCUMENTED_GAPS"
    return "SUPPORTED_UNVERIFIED"


def _lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _names(directory):
    found = {}
    for name in CLAUDE_NAMES + AGENTS_NAMES:
        info = _lstat(os.path.join(directory, name))
        if info is not None:
            found[name] = info
    return found


def scan(root):
    """Closed, path-free report for a worktree root (absolute directory)."""
    reasons = set()
    root = os.fspath(root)
    info = _lstat(root) if os.path.isabs(root) else None
    if info is None or not stat.S_ISDIR(info.st_mode):
        return _report("NOT_RUN", {"root_invalid"}, "MISSING", None)
    # Names in the worktree and every ancestor (Claude loads upward from cwd).
    here = _names(root)
    for name in ("CLAUDE.md", ".claude/CLAUDE.md"):
        if name in here:
            reasons.add("claude_md_in_worktree")
    if "CLAUDE.local.md" in here:
        reasons.add("claude_local_md_in_worktree")
    if ".claude/AGENTS.md" in here:
        reasons.add("claude_dir_agents_md")
    ancestor, steps = os.path.dirname(root), 0
    while ancestor and ancestor != os.path.dirname(ancestor):
        steps += 1
        if steps > MAX_ANCESTORS:
            return _report("NOT_RUN", {"scan_limit"}, "MISSING", None)
        up = _names(ancestor)
        if "CLAUDE.md" in up or ".claude/CLAUDE.md" in up:
            reasons.add("claude_md_in_ancestor")
        if "CLAUDE.local.md" in up:
            reasons.add("claude_local_md_in_ancestor")
        if "AGENTS.md" in up or ".claude/AGENTS.md" in up:
            reasons.add("agents_md_in_ancestor")
        ancestor = os.path.dirname(ancestor)
    up = _names("/")
    if any(n in up for n in CLAUDE_NAMES):
        reasons.add("claude_md_in_ancestor")
    # Bounded nested scan; symlinks are never followed. The directory iterator is
    # consumed lazily and the entry budget is enforced per entry, *before* more
    # entries or pending directories can accumulate (never ``list(scandir)``).
    seen, stack = 0, [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > MAX_ENTRIES:
                        return _report("NOT_RUN", {"scan_limit"}, "MISSING", None)
                    if entry.name == ".git":
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif current != root:  # Root-level names are classified above.
                        if entry.name == "AGENTS.md":
                            reasons.add("agents_md_nested")
                        elif entry.name in ("CLAUDE.md", "CLAUDE.local.md"):
                            reasons.add("claude_md_nested")
        except OSError:
            # Open, iteration or type-probe failure: the tree was not fully
            # observed, so the result can only be NOT_RUN, never CONSISTENT.
            reasons.add("agents_md_unreadable")
            continue
    digest, state = None, "MISSING"
    agents = here.get("AGENTS.md")
    if agents is None:
        reasons.add("agents_md_missing")
    elif not stat.S_ISREG(agents.st_mode) or agents.st_nlink != 1:
        state = "NOT_REGULAR"
        reasons.add("agents_md_not_regular")
    else:
        try:
            fd = os.open(os.path.join(root, "AGENTS.md"), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                before = os.fstat(fd)
                data = os.read(fd, MAX_AGENTS_BYTES + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            if (
                len(data) > MAX_AGENTS_BYTES
                or before.st_size != len(data)
                or (before.st_ino, before.st_mtime_ns)
                != (after.st_ino, after.st_mtime_ns)
            ):
                raise OSError
            digest, state = hashlib.sha256(data).hexdigest(), "REGULAR"
        except OSError:
            state = "UNREADABLE"
            reasons.add("agents_md_unreadable")
    if "agents_md_missing" in reasons and len(reasons) == 1:
        result = "AGENTS_MD_MISSING"
    elif reasons & {"agents_md_unreadable", "scan_limit"}:
        result = "NOT_RUN"
    elif reasons:
        result = "CONFLICT"
    else:
        result = "CONSISTENT_UNVERIFIED"
    return _report(result, reasons, state, digest)


def _report(result, reasons, state, digest):
    assert result in RESULTS and reasons <= REASONS
    return {
        "schema": "AP-INSTRUCTION-SOURCES/1",
        "result": result,
        "reasons": sorted(reasons),
        "root_agents_md": state,
        "root_agents_md_sha256": digest,
        # Metadata consistency is never proof the vendor CLI actually loaded it.
        "load_confirmed": False,
    }


def diagnose(root, pinned_version):
    """Combine the pinned-version policy with the worktree scan."""
    status = version_status(pinned_version)
    report = scan(root)
    report = dict(report, version_status=status)
    if status != "SUPPORTED_UNVERIFIED" and report["result"] != "NOT_RUN":
        report["result"] = "VERSION_BLOCKED"
    return report


EVIDENCE_KEYS = {
    "schema",
    "claude_version",
    "binary_sha256",
    "agents_md_sha256",
    "observed_via",
    "startup_notice",
    "memory_files",
    "provenance",
}


def validate_load_evidence(record, *, version, binary_sha256, agents_md_sha256):
    """Shape/consistency of a FUTURE operator observation; never authenticates it.

    The observation itself (an authorized interactive ``/context all`` in the
    exact worktree with the exact managed binary) is NOT_RUN in this change.
    Success is only ``OPERATOR_ATTESTED_UNAUTHENTICATED``.
    """
    ok = (
        isinstance(record, dict)
        and set(record) == EVIDENCE_KEYS
        and record["schema"] == "AP-INSTRUCTION-LOAD-EVIDENCE/1"
        and record["claude_version"] == version
        and record["binary_sha256"] == binary_sha256
        and record["agents_md_sha256"] == agents_md_sha256
        and record["observed_via"] == "context_all"
        and record["startup_notice"] is True
        and record["memory_files"] == ["AGENTS.md"]
        and record["provenance"] == "operator_attested_unauthenticated"
        and version_status(version) == "SUPPORTED_UNVERIFIED"
    )
    return "OPERATOR_ATTESTED_UNAUTHENTICATED" if ok else "REJECTED"
