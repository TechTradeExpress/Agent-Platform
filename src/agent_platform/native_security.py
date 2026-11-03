"""AP-NS/1 offline assessment only. No I/O, launcher, auth or enabling decision."""

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

MAX_REPORT_BYTES = 16 * 1024


@dataclass(frozen=True, slots=True)
class BuildPin:
    version: str
    source_commit: str
    artifact_sha256: str
    artifact_bytes: int
    target: str


PIN = BuildPin(
    "0.164.0",
    "6aaac694803004a63c6f393d153c96d22521a6b9",
    "b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306",
    308139304,
    "x86_64-unknown-linux-musl",
)

# Historical partial static audit, not fresh source retrieval/binary equivalence.
# S1..S6 resolve to exact-commit paths in docs/tool-dispatch-feasibility.md.
ROUTES = (
    ("dynamic_tools", "SUPPORTED_SUBSET", "S1/S2"),
    ("shell_exec", "UNSUPPORTED", "S1"),
    ("pty", "UNSUPPORTED", "S1"),
    ("write_stdin", "UNSUPPORTED", "S1"),
    ("patch", "UNSUPPORTED", "S1/S3"),
    ("file_reads", "UNKNOWN", "S1/S4"),
    ("file_mutations", "UNKNOWN", "schema_inventory"),
    ("mcp_connectors", "UNSUPPORTED", "S1/S4"),
    ("plugins_skills", "UNKNOWN", "S1/schema_inventory"),
    ("js_code_mode", "UNKNOWN", "S5"),
    ("hooks", "UNKNOWN", "S2"),
    ("background_children", "UNKNOWN", "S1/schema_inventory"),
    ("subagents", "UNSUPPORTED", "S1/S6"),
    ("hosted_tools", "UNKNOWN", "S1"),
    ("resume_fork_replay", "UNKNOWN", "schema_inventory"),
    ("cancellation", "UNKNOWN", "schema_inventory"),
    ("credential_refresh_persistence", "UNKNOWN", "audit_gap"),
    ("implicit_config_session_reads", "UNKNOWN", "audit_gap"),
    ("remote_alternate_dispatch", "UNKNOWN", "schema_inventory"),
    ("approvals_control_tools", "UNKNOWN", "S1/schema_inventory"),
)


class ProbeKind(StrEnum):
    FILE_KEYRING = "file_keyring"
    PROC_PARENT_MEMORY = "proc_parent_memory"
    INHERITED_FDS = "inherited_fds"
    MOUNTS_ALIASES = "mounts_aliases"
    IPC_SOCKETS = "ipc_sockets"
    NETWORK = "network"
    DESCENDANT_PERSISTENCE = "descendant_persistence"
    SAME_DOMAIN_HOME = "same_domain_home"
    REFRESH_SESSION_WRITES = "refresh_session_writes"
    CANCELLATION_RESUME = "cancellation_resume"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True, slots=True)
class SyntheticProbe:
    """Only fabricated test outcomes; caller types never authenticate evidence."""

    kind: ProbeKind
    verdict: Verdict


def _encoded(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def assess(probes=(), *, pin=PIN):
    """Pure bounded JSON-ready NO-GO report, including sanitized mock trace rows.

    There is intentionally no GO branch, real-evidence input, file/client argument,
    enabling flag, clock, environment lookup or runtime integration. Even all-PASS
    mock probes are OFFLINE_SYNTHETIC only. A different build needs new review.
    """
    valid_pin = (
        type(pin) is BuildPin
        and all(
            type(v) is str
            for v in (pin.version, pin.source_commit, pin.artifact_sha256, pin.target)
        )
        and type(pin.artifact_bytes) is int
        and pin == PIN
    )
    valid_probes = (
        type(probes) is tuple
        and len(probes) <= len(ProbeKind)
        and all(
            type(p) is SyntheticProbe
            and type(p.kind) is ProbeKind
            and type(p.verdict) is Verdict
            for p in probes
        )
    )
    if valid_probes:
        valid_probes = len({p.kind for p in probes}) == len(probes)
    valid = valid_pin and valid_probes
    observations = {p.kind: p.verdict for p in probes} if valid else {}
    result = {
        "schema_version": 1,
        "specification": "AP-NS/1",
        "status": "BLOCKED",
        "activation_decision": "NO-GO",
        "security_decision": "NO",
        "reason": "pinned_build_unverified"
        if not valid_pin
        else (
            "invalid_synthetic_evidence"
            if not valid_probes
            else "native_boundary_not_demonstrated"
        ),
        "subject": {
            "version": PIN.version,
            "source_commit": PIN.source_commit,
            "artifact_sha256": PIN.artifact_sha256,
            "artifact_bytes": PIN.artifact_bytes,
            "target": PIN.target,
            "source_binary_equivalence": "UNKNOWN",
            "current_installation_inspected": False,
            "input_pin_matched": valid_pin,
        },
        "routes": [
            {
                "route": name,
                "external_callback_dispatch": dispatch,
                "enforced_boundary": "UNKNOWN",
                "verified_mediated": False,
                "source_reference": reference,
                "evidence": "RECORDED_PARTIAL_STATIC_AUDIT",
            }
            for name, dispatch, reference in ROUTES
        ],
        "unlisted_routes": "UNKNOWN_BLOCKING",
        "complete_mediation": "UNKNOWN",
        "credential_isolation": "NO_FOR_REPORTED_SAME_DOMAIN_PROFILE",
        "prior_kernel_snapshot": {
            "provenance": "OPERATOR_REPORTED_REMOTE_SNAPSHOT",
            "evidence_label": "REAL_KERNEL_SYNTHETIC",
            "host_containment": "PASS",
            "worker_codex_home": "PASS",
            "same_domain_codex_home": "FAIL",
            "status": "BLOCKED",
            "reason": "same_domain_credential_exposure",
            "independently_reenacted": False,
            "fixture_reproduction": "BLOCKED_MISSING_INPUTS",
        },
        "synthetic_trace": [
            {
                "probe": kind.value,
                "verdict": observations.get(kind, Verdict.NOT_RUN).value,
                "evidence": "OFFLINE_SYNTHETIC",
                "real_probe": "NOT_RUN",
            }
            for kind in ProbeKind
        ],
        "blockers": [
            "no_exhaustive_supported_tool_mediation",
            "same_domain_synthetic_credential_exposure",
            "fixture_artifacts_and_provenance_incomplete",
            "native_artifact_exceeds_unchanged_runtime_cap",
            "source_binary_equivalence_unverified",
            "auth_refresh_and_session_boundary_unverified",
        ],
        "unchanged_runtime_cap_bytes": 268435456,
        "artifact_admission": "BLOCKED",
        "authentication": "AUTH_E2E_NOT_RUN",
        "kernel_probes_this_assessment": "NOT_RUN",
        "runtime_status": "SUBSCRIPTION_ISOLATION_BLOCKED",
        "runtime_exit_code": 13,
        "launch_allowed": False,
        "resume_authorized": False,
        "publish_authorized": False,
        "mutations_allowed": False,
    }
    result["report_sha256"] = hashlib.sha256(_encoded(result)).hexdigest()
    if len(_encoded(result)) > MAX_REPORT_BYTES:
        raise ValueError("assessment_report_limit")
    return result
