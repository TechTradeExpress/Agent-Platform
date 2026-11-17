"""AP-PKG12/1 pure release-evidence consistency checks, never release authority.

No CLI, file access, builder, registry writer, network or credential integration.
Pins come separately from a trusted reviewer, not serialized plan/Issue/model data.
Even consistent fabricated evidence cannot authorize generation/publication/install.
The external frozen-history continuity and all observations remain unauthenticated.
"""

import hashlib
import json
import re
from typing import NamedTuple

REPOSITORY = "TechTradeExpress/Agent-Platform"
VERSION = "0.1.0-8"
ROLES = ("control", "worker")
SOURCE_FIELDS = (
    "commit",
    "tree",
    "epoch",
    "builder_sha256",
    "final_recipe_path",
    "final_recipe_sha256",
)
ENVIRONMENT_FIELDS = (
    "platform",
    "image_digest",
    "python",
    "dpkg_deb",
    "xz",
    "packages_sha256",
)
ARTIFACT_FIELDS = frozenset(
    "package archive_sha256 archive_size manifest_sha256 embedded_build_sha256 "
    "provenance_sha256 rebuild_sha256 kind ci_only inputs".split()
)
PLAN_FIELDS = frozenset(
    "schema repository version architecture source environment roles".split()
)


class SourcePin(NamedTuple):
    commit: str
    tree: str
    epoch: int
    builder_sha256: str
    final_recipe_path: str
    final_recipe_sha256: str
    control_inputs_sha256: str
    worker_inputs_sha256: str


class EnvironmentPin(NamedTuple):
    platform: str
    image_digest: str
    python: str
    dpkg_deb: str
    xz: str
    packages_sha256: str


class HistoryPin(NamedTuple):
    # Caller-attested external continuity, NOT authenticated or persisted here.
    state: str  # EMPTY, FROZEN or UNKNOWN. Missing history is never EMPTY.
    continuity_sha256: str
    bundle_sha256: str | None


def digest(value):
    """Correlation of already bounded JSON-shaped facts, not a signature."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _hex(value, size=64):
    return (
        type(value) is str
        and len(value) == size
        and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None
    )


def _path(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 160
        and re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None
        and all(part not in ("", ".", "..") for part in value.split("/"))
        and (
            value.startswith(("packaging/", "debian/", "docs/", "src/"))
            or value in ("pyproject.toml", "uv.lock", "LICENSE")
        )
    )


def _source_pin(pin):
    return (
        type(pin) is SourcePin
        and _hex(pin.commit, 40)
        and _hex(pin.tree, 40)
        and type(pin.epoch) is int
        and 0 <= pin.epoch <= 2**31 - 1
        and _hex(pin.builder_sha256)
        and _hex(pin.final_recipe_sha256)
        and _hex(pin.control_inputs_sha256)
        and _hex(pin.worker_inputs_sha256)
        and _path(pin.final_recipe_path)
        and pin.final_recipe_path.startswith("packaging/")
        and pin.final_recipe_path.endswith(".py")
        and pin.final_recipe_path
        not in ("packaging/build_deb.py", "packaging/release_readiness.py")
    )


def _environment_pin(pin):
    return (
        type(pin) is EnvironmentPin
        and type(pin.platform) is str
        and pin.platform == "debian-13/amd64"
        and type(pin.image_digest) is str
        and len(pin.image_digest) == 71
        and pin.image_digest.startswith("sha256:")
        and _hex(pin.image_digest[7:])
        and _hex(pin.packages_sha256)
        and all(
            type(v) is str
            and len(v) <= 64
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+~][A-Za-z0-9.]+)?", v)
            for v in (pin.python, pin.dpkg_deb, pin.xz)
        )
    )


def _json_facts(value):
    budget = [2048]

    def visit(item, depth):
        budget[0] -= 1
        if budget[0] < 0 or depth > 5:
            return False
        if type(item) is dict:
            return len(item) <= 256 and all(
                type(key) is str and len(key) <= 160 and visit(child, depth + 1)
                for key, child in item.items()
            )
        return (
            type(item) is str
            and len(item) <= 1024
            or type(item) is bool
            or type(item) is int
            and 0 <= item <= 2**63 - 1
        )

    return visit(value, 0)


def _report(reason, *, fingerprint=None, history="UNKNOWN"):
    return {
        "schema": "AP-PKG12-ASSESSMENT/1",
        "result": "CONSISTENT_UNVERIFIED" if reason == "plan_only" else "BLOCKED",
        "reason": reason,
        "bundle_sha256": fingerprint,
        "history": history,
        "freeze_key": REPOSITORY + "/" + VERSION + "/amd64",
        "observations_authenticated": False,
        "final_generation_allowed": False,
        "release_authorized": False,
        "publication_allowed": False,
        "installation_allowed": False,
    }


def assess(plan, *, source_pin=None, environment_pin=None, history_pin=None):
    """Compare future evidence with separate caller pins, always deny actions.

    This is not an authorization service, artifact reader or freeze registry.
    A real post-merge release procedure/authorization and durable independently
    protected version registry are unimplemented. Unknown evidence blocks.
    """
    if not _json_facts(plan):
        return _report("plan_invalid")
    if not _source_pin(source_pin):
        return _report("source_pin_unverified")
    if not _environment_pin(environment_pin):
        return _report("environment_pin_unverified")
    if (
        type(history_pin) is not HistoryPin
        or type(history_pin.state) is not str
        or history_pin.state not in ("EMPTY", "FROZEN")
        or not _hex(history_pin.continuity_sha256)
        or (history_pin.state == "EMPTY" and history_pin.bundle_sha256 is not None)
        or (history_pin.state == "FROZEN" and not _hex(history_pin.bundle_sha256))
    ):
        return _report("history_unverified")
    if (
        type(plan) is not dict
        or set(plan) != PLAN_FIELDS
        or plan["schema"] != "AP-PKG12-PLAN/1"
        or plan["repository"] != REPOSITORY
        or plan["version"] != VERSION
        or plan["architecture"] != "amd64"
    ):
        return _report("plan_invalid")
    if (
        type(plan["source"]) is not dict
        or type(plan["environment"]) is not dict
        or type(plan["source"].get("epoch")) is not int
    ):
        return _report("plan_invalid")
    if plan["source"] != {key: getattr(source_pin, key) for key in SOURCE_FIELDS}:
        return _report("source_mismatch")
    if plan["environment"] != {
        key: getattr(environment_pin, key) for key in ENVIRONMENT_FIELDS
    }:
        return _report("environment_mismatch")
    roles = plan["roles"]
    if type(roles) is not dict or set(roles) != set(ROLES):
        return _report("roles_invalid")
    for role in ROLES:
        item = roles[role]
        if type(item) is not dict or set(item) != ARTIFACT_FIELDS:
            return _report("artifact_invalid")
        if item["kind"] != "future-final" or item["ci_only"] is not False:
            return _report("artifact_not_future_final")
        if (
            item["package"] != "agent-platform-" + role
            or type(item["archive_size"]) is not int
            or not 0 < item["archive_size"] <= 2**31 - 1
            or not all(
                _hex(item[key])
                for key in (
                    "archive_sha256",
                    "manifest_sha256",
                    "embedded_build_sha256",
                    "provenance_sha256",
                    "rebuild_sha256",
                )
            )
        ):
            return _report("artifact_invalid")
        if item["archive_sha256"] != item["rebuild_sha256"]:
            return _report("rebuild_mismatch")
        inputs = item["inputs"]
        if (
            type(inputs) is not dict
            or not 6 <= len(inputs) <= 256
            or not all(_path(path) and _hex(value) for path, value in inputs.items())
            or not {
                "packaging/build_deb.py",
                source_pin.final_recipe_path,
                "debian/control",
                "debian/changelog",
                "pyproject.toml",
                "uv.lock",
            }
            <= set(inputs)
        ):
            return _report("input_set_invalid")
        if (
            inputs["packaging/build_deb.py"] != source_pin.builder_sha256
            or inputs[source_pin.final_recipe_path] != source_pin.final_recipe_sha256
            or digest(inputs) != getattr(source_pin, role + "_inputs_sha256")
        ):
            return _report("input_set_mismatch")
    if roles["control"]["archive_sha256"] == roles["worker"]["archive_sha256"]:
        return _report("roles_not_distinct")
    fingerprint = digest(plan)
    if history_pin.state == "FROZEN" and history_pin.bundle_sha256 != fingerprint:
        return _report(
            "final_version_conflict", fingerprint=fingerprint, history="FROZEN"
        )
    # Identical existing final evidence still gives no resend/rebuild permission.
    return _report("plan_only", fingerprint=fingerprint, history=history_pin.state)
