"""CP-06: explicit offline models and owned local scratch files, never host probes."""

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum

VERSION = "AP-CF/1"
MAX_BYTES = 64 * 1024
MAX_CHILDREN = 4
SHA256 = re.compile(r"[a-f0-9]{64}")


class Disposition(StrEnum):
    PASS = "PASS"
    DENIED = "DENIED"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    HOST_NOT_RUN = "HOST_NOT_RUN"


class Provenance(StrEnum):
    SYNTHETIC = "SYNTHETIC"
    OPERATOR_REPORTED = "OPERATOR_REPORTED"
    HOST_NOT_RUN = "HOST_NOT_RUN"
    INDEPENDENT_RETAINED = "INDEPENDENT_RETAINED"


class Role(StrEnum):
    ADMISSION = "ap-admission"
    CUSTODY = "ap-custody"
    SIGNER = "ap-signer"


class Case(StrEnum):
    OWN_READ = "own_read"
    CROSS_READ = "cross_read"
    CROSS_WRITE = "cross_write"
    CROSS_RENAME = "cross_rename"
    CROSS_LINK = "cross_link"
    PROC_ENVIRON = "proc_environ"
    PROC_FD = "proc_fd"
    PROC_MEM = "proc_mem"
    PTRACE = "ptrace"
    PROCESS_VM = "process_vm_readv"
    SAME_UID_BASELINE = "same_uid_baseline"
    SAME_UID_NONDUMPABLE = "same_uid_nondumpable"
    FD_ENV = "fd_env"
    PEER_VALID = "peer_valid"
    MISSING_PRINCIPAL = "missing_principal"
    WRONG_UID = "wrong_uid"
    WRONG_GID = "wrong_gid"
    WRONG_GROUPS = "wrong_groups"
    WRONG_PID = "wrong_pid"
    STALE_LIFETIME = "stale_lifetime"
    UNKNOWN_LIFETIME = "unknown_lifetime"
    SPOOFED_CLAIM = "spoofed_claim"
    INHERITED_FD = "inherited_fd"
    SOCKETPAIR = "socketpair"
    ABSTRACT_SOCKET = "abstract_socket"
    ANCILLARY_FD = "ancillary_fd"
    TRUNCATED = "truncated"
    OVERSIZED = "oversized"
    TRAILING = "trailing"
    SLOW = "slow"


class Frame(StrEnum):
    EXACT = "exact"
    TRUNCATED = "truncated"
    OVERSIZED = "oversized"
    TRAILING = "trailing"
    SLOW = "slow"


POSITIVE = frozenset(
    {Case.OWN_READ, Case.SAME_UID_BASELINE, Case.FD_ENV, Case.PEER_VALID}
)
PROC_CASES = frozenset(
    {Case.PROC_ENVIRON, Case.PROC_FD, Case.PROC_MEM, Case.PTRACE, Case.PROCESS_VM}
)
DAC_CASES = frozenset(
    {
        Case.OWN_READ,
        Case.CROSS_READ,
        Case.CROSS_WRITE,
        Case.CROSS_RENAME,
        Case.CROSS_LINK,
    }
)
FACTS = ("kernel", "os", "user", "groups", "systemd", "apparmor", "mnt", "yama")
HOST_MATRIX = (
    "identity_effective_config",
    "cross_uid_dac",
    "proc_ptrace_memory",
    "same_uid_dumpability",
    "fd_environment",
    "unix_peer_lifetime",
    "network_ipv4_ipv6_dns_inherited_fd_l2_management",
    "credential_loader",
    "journal_anchor_storage",
    "authenticated_admission",
    "crash_fsync",
    "reboot_rollback_deletion_external_witness",
    "systemd_seccomp_bpf_mac",
    "resource_stop_process_group_reaping",
    "apparmor_attachment_audit",
)


@dataclass(frozen=True, slots=True)
class Fact:
    name: str
    provenance: Provenance
    digest: str | None = None  # never raw kernel/env/identity/path text


@dataclass(frozen=True, slots=True)
class Identity:
    fixture_sha256: str
    source_sha256: str
    policy_sha256: str
    collector_sha256: str
    facts: tuple[Fact, ...]
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Config:
    identity: Identity
    probe_ms: int = 5000
    case_ms: int = 60000
    output_bytes: int = MAX_BYTES
    version: str = VERSION


@dataclass(frozen=True, slots=True)
class Peer:
    pid: int
    uid: int
    gid: int
    groups: tuple[int, ...]
    lifetime: str | None
    exists: bool = True


# Deliberately fabricated identities, unrelated to host-local account numbers.
MODEL_PEER = Peer(101, 10001, 10001, (10001,), "a" * 64)


@dataclass(frozen=True, slots=True)
class Stimulus:
    actor: Role = Role.ADMISSION
    owner: Role = Role.CUSTODY
    peer: Peer = MODEL_PEER
    claimed_peer: Peer = MODEL_PEER
    dumpable: bool = True
    inherited: bool = False
    socketpair: bool = False
    abstract: bool = False
    ancillary_fds: int = 0
    frame: Frame = Frame.EXACT
    leaked_fds: int = 0
    leaked_env: int = 0
    known_syscall: bool = True


@dataclass(frozen=True, slots=True)
class Step:
    case: Case
    stimulus: Stimulus
    fixture_sha256: str
    collector_sha256: str
    configuration_sha256: str
    elapsed_ms: int = 1
    stdout: bytes = b""
    stderr: bytes = b""
    children: int = 1
    can_reap: bool = True
    cleanup_complete: bool = True
    complete: bool = True
    cancelled: bool = False
    provenance: Provenance = Provenance.SYNTHETIC


@dataclass(frozen=True, slots=True)
class Plan:
    argv: tuple[str, ...]
    probe_ms: int
    case_ms: int
    output_bytes: int
    shell: bool = field(default=False, init=False)
    env: tuple = field(default=(), init=False)
    pass_fds: tuple = field(default=(), init=False)
    close_fds: bool = field(default=True, init=False)
    executable: None = field(default=None, init=False)  # no OS execution adapter


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: Case
    expected: Disposition
    observed: Disposition
    code: str
    model_matches: bool
    host: Disposition = field(default=Disposition.HOST_NOT_RUN, init=False)


@dataclass(frozen=True, slots=True)
class Report:
    status: str
    code: str
    identity: Identity | None
    cases: tuple[CaseResult, ...]
    configuration: Config | None = None
    version: str = field(default=VERSION, init=False)
    live: str = field(default="LIVE_NO_GO", init=False)
    launch_allowed: bool = field(default=False, init=False)
    gate_73: str = field(default="BLOCKED", init=False)

    def encode(self) -> bytes:
        _report(self)
        data = asdict(self)
        data["configuration_sha256"] = (
            configuration_digest(self.configuration) if self.configuration else None
        )
        data["host_matrix"] = {name: "HOST_NOT_RUN" for name in HOST_MATRIX}
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > MAX_BYTES:
            raise FixtureError("report_limit")
        return raw


class FixtureError(Exception):
    """Fixed codes only; never include paths, markers or raw errors."""


class FakeAdapter:
    """In-memory child/process-group model. No PID here is a real OS PID.

    No callable provider or command override is accepted. A real process runner,
    namespace launcher, syscall/socket probe or privileged adapter is absent.
    """

    def __init__(self):
        self.started = 0
        self.reaped = 0
        self.plans = []

    def execute(self, plan: Plan, step: Step) -> bool:
        self.plans.append(plan)
        self.started += step.children
        if step.can_reap:
            self.reaped += step.children
        return step.can_reap


def _require(ok):
    if not ok:
        raise FixtureError("invalid_evidence")


def _digest(value):
    return type(value) is str and SHA256.fullmatch(value) is not None


def _config(c):
    _require(type(c) is Config and c.version == VERSION)
    _require(type(c.identity) is Identity and c.identity.version == VERSION)
    i = c.identity
    _require(
        all(
            _digest(v)
            for v in (
                i.fixture_sha256,
                i.source_sha256,
                i.policy_sha256,
                i.collector_sha256,
            )
        )
    )
    _require(type(i.facts) is tuple and len(i.facts) == len(FACTS))
    _require(all(type(f) is Fact for f in i.facts))
    _require(all(type(f.name) is str for f in i.facts))
    _require(tuple(f.name for f in i.facts) == FACTS)
    for fact in i.facts:
        _require(type(fact.provenance) is Provenance)
        # This harness cannot authenticate independent host evidence.
        _require(fact.provenance != Provenance.INDEPENDENT_RETAINED)
        _require(
            (fact.digest is None and fact.provenance == Provenance.HOST_NOT_RUN)
            or (
                _digest(fact.digest)
                and fact.provenance
                in {Provenance.SYNTHETIC, Provenance.OPERATOR_REPORTED}
            )
        )
    for value, cap in (
        (c.probe_ms, 5000),
        (c.case_ms, 60000),
        (c.output_bytes, MAX_BYTES),
    ):
        _require(type(value) is int and 0 < value <= cap)
    _require(c.probe_ms <= c.case_ms)


def configuration_digest(config: Config) -> str:
    _config(config)
    return hashlib.sha256(
        json.dumps(asdict(config), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _step(s, c):
    _require(type(s) is Step and type(s.case) is Case)
    _require(
        s.fixture_sha256 == c.identity.fixture_sha256
        and s.collector_sha256 == c.identity.collector_sha256
    )
    _require(
        type(s.configuration_sha256) is str
        and s.configuration_sha256 == configuration_digest(c)
    )
    _require(s.provenance is Provenance.SYNTHETIC)
    _require(type(s.stimulus) is Stimulus)
    t = s.stimulus
    _require(type(t.actor) is Role and type(t.owner) is Role and type(t.frame) is Frame)
    for peer in (t.peer, t.claimed_peer):
        _require(type(peer) is Peer)
        _require(
            all(
                type(v) is int and 0 < v < 2**31 for v in (peer.pid, peer.uid, peer.gid)
            )
        )
        _require(type(peer.groups) is tuple and len(peer.groups) <= 8)
        _require(all(type(g) is int and 0 < g < 2**31 for g in peer.groups))
        _require(peer.lifetime is None or _digest(peer.lifetime))
        _require(type(peer.exists) is bool)
    for v in (
        t.dumpable,
        t.inherited,
        t.socketpair,
        t.abstract,
        t.known_syscall,
        s.can_reap,
        s.cleanup_complete,
        s.complete,
        s.cancelled,
    ):
        _require(type(v) is bool)
    for v in (t.ancillary_fds, t.leaked_fds, t.leaked_env):
        _require(type(v) is int and 0 <= v <= 64)
    _require(type(s.elapsed_ms) is int and 0 <= s.elapsed_ms <= 60001)
    _require(type(s.children) is int and 0 <= s.children <= MAX_CHILDREN)
    _require(type(s.stdout) is bytes and type(s.stderr) is bytes)
    _require(len(s.stdout) <= c.output_bytes and len(s.stderr) <= c.output_bytes)
    _require(len(s.stdout) + len(s.stderr) <= c.output_bytes)
    _require(s.complete)


def _model(case, t):
    # These are explicit reference-model rules, never observed kernel enforcement.
    if not t.known_syscall:
        return Disposition.UNSUPPORTED
    if t.leaked_fds or t.leaked_env:
        return Disposition.FAIL
    if case in DAC_CASES:
        return Disposition.PASS if t.actor == t.owner else Disposition.DENIED
    if case in PROC_CASES or case in {
        Case.SAME_UID_BASELINE,
        Case.SAME_UID_NONDUMPABLE,
    }:
        return (
            Disposition.PASS
            if t.actor == t.owner and t.dumpable
            else Disposition.DENIED
        )
    if case == Case.FD_ENV:
        return Disposition.PASS
    p = t.peer
    admitted = (
        p == MODEL_PEER
        and t.claimed_peer == p
        and p.exists
        and p.lifetime is not None
        and not t.inherited
        and not t.socketpair
        and not t.abstract
        and t.ancillary_fds == 0
        and t.frame == Frame.EXACT
    )
    return Disposition.PASS if admitted else Disposition.DENIED


def run_case(config: Config, step: Step, adapter: FakeAdapter) -> CaseResult:
    """Bounded simulation only; real OS probes are deliberately non-executable."""
    case = (
        step.case if type(step) is Step and type(step.case) is Case else Case.OWN_READ
    )
    expected = Disposition.PASS if case in POSITIVE else Disposition.DENIED

    def result(observed, code):
        return CaseResult(case, expected, observed, code, observed == expected)

    try:
        _config(config)
        _step(step, config)
        _require(type(adapter) is FakeAdapter)
    except (FixtureError, TypeError, ValueError, AttributeError):
        return result(Disposition.BLOCKED, "invalid_evidence")
    plan = Plan(
        ("CP06_MODEL_ONLY", case.value),
        config.probe_ms,
        config.case_ms,
        config.output_bytes,
    )
    # Fake children are always reaped before evaluating timeout/cancellation/results.
    reaped = adapter.execute(plan, step)
    if not reaped:
        return result(Disposition.FAIL, "owned_children_unreaped")
    if not step.cleanup_complete:
        return result(Disposition.UNKNOWN, "cleanup_incomplete")
    if step.cancelled:
        return result(Disposition.UNKNOWN, "cancelled")
    if step.elapsed_ms > config.probe_ms or step.elapsed_ms > config.case_ms:
        return result(Disposition.UNKNOWN, "deadline")
    observed = _model(case, step.stimulus)
    return result(observed, "model_match" if observed == expected else "model_mismatch")


def scenarios(config: Config) -> tuple[Step, ...]:
    """Reproducible positive/negative controls, with no host account lookup."""
    _config(config)
    steps = []
    peer_changes = {
        Case.MISSING_PRINCIPAL: {"exists": False},
        Case.WRONG_UID: {"uid": 10009},
        Case.WRONG_GID: {"gid": 10009},
        Case.WRONG_GROUPS: {"groups": (10001, 10009)},
        Case.WRONG_PID: {"pid": 102},
        Case.STALE_LIFETIME: {"lifetime": "b" * 64},
        Case.UNKNOWN_LIFETIME: {"lifetime": None},
        Case.SPOOFED_CLAIM: {"pid": 103},
    }
    for case in Case:
        t = Stimulus()
        if case == Case.OWN_READ or case in {
            Case.SAME_UID_BASELINE,
            Case.SAME_UID_NONDUMPABLE,
        }:
            t = replace(
                t, owner=Role.ADMISSION, dumpable=case != Case.SAME_UID_NONDUMPABLE
            )
        if case in peer_changes:
            t = replace(t, peer=replace(MODEL_PEER, **peer_changes[case]))
        for kind, field_name in (
            (Case.INHERITED_FD, "inherited"),
            (Case.SOCKETPAIR, "socketpair"),
            (Case.ABSTRACT_SOCKET, "abstract"),
        ):
            if case == kind:
                t = replace(t, **{field_name: True})
        if case == Case.ANCILLARY_FD:
            t = replace(t, ancillary_fds=1)
        if case.value in {f.value for f in Frame}:
            t = replace(t, frame=Frame(case.value))
        steps.append(
            Step(
                case,
                t,
                config.identity.fixture_sha256,
                config.identity.collector_sha256,
                configuration_digest(config),
            )
        )
    return tuple(steps)


def run(config: Config, steps: tuple[Step, ...]) -> Report:
    """Explicit library invocation, closed case inventory, deterministic safe JSON."""
    try:
        _config(config)
        _require(type(steps) is tuple and len(steps) == len(Case))
        _require(all(type(s) is Step and type(s.case) is Case for s in steps))
        _require(tuple(s.case for s in steps) == tuple(Case))
    except (FixtureError, TypeError, ValueError, AttributeError):
        return Report("BLOCKED", "invalid_evidence", None, ())
    adapter = FakeAdapter()
    results = []
    stopped = False
    for step in steps:
        if stopped:
            expected = Disposition.PASS if step.case in POSITIVE else Disposition.DENIED
            results.append(
                CaseResult(
                    step.case, expected, Disposition.HOST_NOT_RUN, "after_stop", False
                )
            )
        else:
            result = run_case(config, step, adapter)
            results.append(result)
            stopped = not result.model_matches
    results = tuple(results)
    status = (
        "VERIFIED_OFFLINE_FIXTURE"
        if all(r.model_matches for r in results)
        else "BLOCKED"
    )
    return Report(
        status,
        "model_only" if status == "VERIFIED_OFFLINE_FIXTURE" else "fixture_refused",
        config.identity,
        results,
        config,
    )


RESULT_CODES = frozenset(
    {
        "invalid_evidence",
        "owned_children_unreaped",
        "cleanup_incomplete",
        "cancelled",
        "deadline",
        "model_match",
        "model_mismatch",
        "after_stop",
    }
)


def _report(r):
    _require(type(r) is Report and type(r.cases) is tuple)
    _require(type(r.status) is str and type(r.code) is str)
    if r.identity is None:
        _require(
            r.status == "BLOCKED"
            and r.code == "invalid_evidence"
            and not r.cases
            and r.configuration is None
        )
        return
    _config(r.configuration)
    _require(type(r.identity) is Identity and r.configuration.identity == r.identity)
    _require(len(r.cases) == len(Case))
    _require(
        all(
            type(c) is CaseResult
            and type(c.case) is Case
            and type(c.expected) is Disposition
            and type(c.observed) is Disposition
            and type(c.model_matches) is bool
            and type(c.code) is str
            and c.code in RESULT_CODES
            for c in r.cases
        )
    )
    _require(tuple(c.case for c in r.cases) == tuple(Case))
    _require(
        all(
            c.expected
            == (Disposition.PASS if c.case in POSITIVE else Disposition.DENIED)
            and c.model_matches == (c.expected == c.observed)
            for c in r.cases
        )
    )
    status = (
        "VERIFIED_OFFLINE_FIXTURE"
        if all(c.model_matches for c in r.cases)
        else "BLOCKED"
    )
    _require(
        r.status == status
        and r.code
        == ("model_only" if status == "VERIFIED_OFFLINE_FIXTURE" else "fixture_refused")
    )


@dataclass(frozen=True, slots=True)
class FileIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _pin(s):
    return FileIdentity(
        s.st_dev,
        s.st_ino,
        s.st_uid,
        s.st_gid,
        s.st_mode,
        s.st_nlink,
        s.st_size,
        s.st_mtime_ns,
        s.st_ctime_ns,
    )


class DisposableFixture:
    """Explicit local scratch lifecycle; no path argument and no recursive deletion.

    create() uses the current private worktree/test directory only. Never passed
    to a subprocess. Cleanup refuses unknown/replaced objects and is one-shot.
    Private DAC is scratch hygiene, NOT a boundary against malicious same-UID code.
    """

    @classmethod
    def create(cls):
        root = child = None
        try:
            root = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            r = os.fstat(root)
            _require(r.st_uid == os.getuid() and not r.st_mode & 0o022)
            name = ".ap-cp06-" + uuid.uuid4().hex
            os.mkdir(name, 0o700, dir_fd=root)  # collision refuses; no retry/adoption
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
            )
            fd = os.open(
                "marker",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=child,
            )
            try:
                marker = os.urandom(32)  # fabricated marker, never a real credential
                _require(os.write(fd, marker) == len(marker))
                marker_pin = _pin(os.fstat(fd))
                _require(
                    marker_pin.links == 1
                    and marker_pin.uid == r.st_uid
                    and marker_pin.mode == 0o100600
                )
            finally:
                os.close(fd)
            obj = cls()
            obj._root, obj._child, obj._name = root, child, name
            obj._root_pin = (r.st_dev, r.st_ino, r.st_uid, r.st_gid, r.st_mode)
            obj._child_pin = _pin(os.fstat(child))
            _require(obj._child_pin.uid == r.st_uid and obj._child_pin.mode == 0o40700)
            obj._marker_pin = marker_pin
            obj._marker_digest = hashlib.sha256(marker).digest()
            obj._closed = False
            return obj
        except Exception:
            if child is not None:
                os.close(child)
            if root is not None:
                os.close(root)
            # A partial/uncertain creation is retained, never retried or removed.
            raise FixtureError("fixture_creation_uncertain") from None

    def cleanup(self) -> bool:
        if self._closed:
            return False
        self._closed = True
        fd = None
        try:
            r = os.fstat(self._root)
            _require(
                (r.st_dev, r.st_ino, r.st_uid, r.st_gid, r.st_mode) == self._root_pin
            )
            _require(
                _pin(os.stat(self._name, dir_fd=self._root, follow_symlinks=False))
                == self._child_pin
            )
            _require(_pin(os.fstat(self._child)) == self._child_pin)
            with os.scandir(self._child) as entries:
                first = next(entries, None)
                _require(first is not None and first.name == "marker")
                _require(next(entries, None) is None)
            fd = os.open(
                "marker",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self._child,
            )
            _require(_pin(os.fstat(fd)) == self._marker_pin)
            _require(hashlib.sha256(os.read(fd, 33)).digest() == self._marker_digest)
            _require(
                _pin(os.stat("marker", dir_fd=self._child, follow_symlinks=False))
                == self._marker_pin
            )
            os.unlink("marker", dir_fd=self._child)
            os.rmdir(self._name, dir_fd=self._root)
            return True
        except Exception:
            return False
        finally:
            if fd is not None:
                os.close(fd)
            os.close(self._child)
            os.close(self._root)


@dataclass(frozen=True, slots=True)
class PolicyCandidate:
    principal: Role
    directives: tuple[tuple[str, str], ...]
    writable_assets: tuple[str, ...]
    apparmor_requirements: tuple[str, ...]
    unresolved: tuple[str, ...]
    version: str = field(default=VERSION, init=False)
    installable: bool = field(default=False, init=False)
    attachment: None = field(default=None, init=False)


COMMON_DIRECTIVES = (
    ("Type", "notify"),
    ("NotifyAccess", "main"),
    ("TimeoutStartSec", "15s"),
    ("UMask", "0077"),
    ("SupplementaryGroups", ""),
    ("Restart", "no"),
    ("KillMode", "control-group"),
    ("TimeoutStopSec", "10s"),
    ("SendSIGKILL", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("NoNewPrivileges", "yes"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("ProtectControlGroups", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("LockPersonality", "yes"),
    ("RestrictRealtime", "yes"),
    ("ProtectProc", "invisible"),
    ("ProcSubset", "pid"),
    ("LimitCORE", "0"),
    ("KeyringMode", "private"),
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
    ("SystemCallFilter", "~@privileged @resources @mount @debug"),
    ("MemoryDenyWriteExecute", "yes"),
    ("RestrictNamespaces", "yes"),
    ("LimitNOFILE", "64"),
    ("TasksMax", "16"),
    ("CPUQuota", "25%"),
    ("MemoryHigh", "96M"),
    ("MemoryMax", "128M"),
    ("MemorySwapMax", "0"),
    ("StandardInput", "null"),
    ("StandardOutput", "null"),
    ("StandardError", "null"),
    ("PrivateNetwork", "yes"),
    ("IPAddressDeny", "any"),
)
MAC_REQUIREMENTS = (
    "deny_sibling_state_and_credentials",
    "deny_ptrace_and_process_vm",
    "deny_unsolicited_execution",
    "reviewed_immutable_runtime_and_library_closure",
    "deny_unapproved_unix_peers",
    "pathname_socket_0620_exact_named_acl_no_default_acl",
    "exact_pid_uid_gid_lifetime_both_ends",
    "reject_abstract_inherited_socketpair_scm_rights",
    "deny_unapproved_network",
    "enforce_attachment_and_independent_denial_audit",
)
UNRESOLVED = (
    "systemd257_effective_settings",
    "kernel_namespaces_proc_seccomp_bpf_cgroups",
    "apparmor_enforce_attachment",
    "external_continuity_and_storage",
    "authenticated_admission_and_peer_lifetime",
    "host_negative_tests_and_reboot",
    "runtime_compatibility_and_resource_capacity",
    "gate_73",
)


def policy_candidates() -> tuple[PolicyCandidate, ...]:
    """CP-01 candidate requirements, no executable/attachment/install path."""
    result = []
    for role in Role:
        families = "AF_UNIX" if role != Role.CUSTODY else "AF_UNIX AF_INET AF_INET6"
        assets = {
            Role.ADMISSION: ("FUTURE_EXACT_ADMISSION_LEDGER",),
            Role.CUSTODY: ("FUTURE_EXACT_CUSTODY_JOURNAL",),
            Role.SIGNER: (),
        }[role]
        extra = (
            ("signer_only_managed_copy_no_environment_same_uid_risk",)
            if role == Role.SIGNER
            else ("no_credential_mount",)
        )
        if role == Role.CUSTODY:
            extra += (
                "egress_blocked_until_separately_pinned_peer_tls_routes_firewall",
            )
        directives = (
            ("User", role.value),
            ("Group", role.value),
            *COMMON_DIRECTIVES,
            ("RestrictAddressFamilies", families),
        )
        result.append(
            PolicyCandidate(
                role, directives, assets, MAC_REQUIREMENTS + extra, UNRESOLVED
            )
        )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class PolicyAssessment:
    code: str
    status: str = field(default="BLOCKED", init=False)
    live: str = field(default="LIVE_NO_GO", init=False)
    installable: bool = field(default=False, init=False)


def assess_policies(candidates: tuple[PolicyCandidate, ...]) -> PolicyAssessment:
    """Static equality is no proof of directive support or effective confinement."""
    if (
        type(candidates) is not tuple
        or len(candidates) != 3
        or any(type(p) is not PolicyCandidate for p in candidates)
        or candidates != policy_candidates()
    ):
        return PolicyAssessment("invalid_or_unknown_candidate")
    return PolicyAssessment("host_mechanisms_unverified")
