"""Worker01 recovery observations signed outside the worker."""

import base64
import re
import time
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import worker_publish_artifact as art
from . import worker_publish_case as case
from . import worker_publish_reconciliation as reconciliation
from . import worker_publisher as pub
from .worker_publish_io import HTTPS

ADMIN = 34678780
APP_ID = 5748674
INSTALLATION = 181691110
RULESET = 26772477
LIMIT = 16384
WINDOW = 300
PURPOSES = (
    "selection",
    "report",
    "create-draft",
    "spent-continuity",
    "pre-spend",
    "recovery-signer",
    "recovery-publisher",
    "recovery-publisher-live",
    "recovery-egress-policy",
)
DOMAIN = b"AP-worker01-observer/1\0"


def _sha256(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value)


def binding(snapshot_pin, raw, archive_pin, challenge, now):
    job = pub.validate_job(art.decode(reconciliation._bounded(raw, LIMIT)), now)
    art.need(pub.homelab(job) and job["issue"] == 169)
    art.need(job["app_id"] == APP_ID and job["installation_id"] == INSTALLATION)
    art.need(job["ref"] != case.REF and job["head"] != case.HEAD)
    art.need(job["artifact_sha256"] != case.ARTIFACT and job["parent"] != case.PARENT)
    art.need(all(_sha256(value) for value in (snapshot_pin, archive_pin, challenge)))
    return {
        "snapshot": snapshot_pin,
        "archive": archive_pin,
        "challenge": challenge,
        "job": art.digest(raw),
        "artifact": job["artifact_sha256"],
        "head": job["head"],
        "main": job["parent"],
        "ref": job["ref"],
        "repository": pub.REPO_ID,
        "issue": 169,
        "issue_id": job["issue_id"],
        "app": APP_ID,
        "installation": INSTALLATION,
        "owner": job["owner_id"],
        "app_owner": job["app_owner_id"],
        "repo_node": job["repo_node"],
    }


def sign(key, purpose, value):
    """Operator-side helper. Key loading is owned by the external operator."""
    art.need(isinstance(key, Ed25519PrivateKey))
    art.need(purpose in PURPOSES)
    raw = art.encoded(value)
    art.need(len(raw) <= LIMIT)
    return key.sign(DOMAIN + purpose.encode() + b"\0" + raw)


def verify(public_key, key_pin, purpose, raw, signature):
    """The expected public key digest comes from separately trusted config."""
    art.need(type(public_key) is bytes and len(public_key) == 32)
    art.need(_sha256(key_pin) and art.digest(public_key) == key_pin)
    art.need(purpose in PURPOSES)
    art.need(type(signature) is bytes and len(signature) == 64)
    value = reconciliation._canonical(raw)
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, DOMAIN + purpose.encode() + b"\0" + raw)
    except Exception:
        raise art.Blocked() from None
    return value


def _fresh(value, now):
    art.need(type(now) is type(value) is int and 0 <= now - value <= WINDOW)


def selection(public_key, key_pin, raw, signature, bound, now):
    value = verify(public_key, key_pin, "selection", raw, signature)
    at = value["at"]
    _fresh(at, now)
    art.need(
        value
        == {
            "schema": "AP-worker01-selection/1",
            "administrator": ADMIN,
            "source": "administrative_installation_repository_inventory",
            "binding": bound,
            "at": at,
            "repository_ids": [pub.REPO_ID],
        }
    )
    return value


def _rules(get):
    prefix = pub.ROOT + "/rulesets"
    # Transport refuses Link headers, so a response that needs another page
    # cannot be used as proof. An exactly full page is also ambiguous.
    entries = get(prefix + "?includes_parents=true&per_page=100")
    art.need(type(entries) is list and len(entries) < 100)
    ids = [entry["id"] for entry in entries]
    art.need(all(type(i) is int and 0 < i < 2**63 for i in ids))
    art.need(len(ids) == len(set(ids)) and RULESET in ids)
    active = []
    fingerprints = []
    for entry in entries:
        i = entry["id"]
        value = get(f"{prefix}/{i}?includes_parents=true")
        art.need(type(value["id"]) is int and value["id"] == i)
        state = value["enforcement"]
        art.need(
            state == entry["enforcement"]
            and state in {"active", "disabled", "evaluate"}
        )
        if state == "active":
            art.need(value["bypass_actors"] == [])
            art.need(type(value["rules"]) is list and bool(value["rules"]))
            active.append(i)
        fingerprints.append([i, art.digest(art.encoded(value))])
    effective = get(pub.ROOT + "/rules/branches/main?per_page=100")
    art.need(type(effective) is list and 0 < len(effective) < 100)
    art.need(
        all(
            type(rule["ruleset_id"]) is int and rule["ruleset_id"] in active
            for rule in effective
        )
    )
    art.need(RULESET in {rule["ruleset_id"] for rule in effective})
    return sorted(fingerprints), art.digest(art.encoded(effective))


def _classic(value):
    art.need(value["enforce_admins"]["enabled"] is True)
    art.need(value["allow_force_pushes"]["enabled"] is False)
    art.need(value["allow_deletions"]["enabled"] is False)
    restrictions = value["restrictions"]
    art.need(restrictions["apps"] == restrictions["teams"] == [])
    users = restrictions["users"]
    art.need(
        len(users) == 1 and users[0]["login"] == "su-17" and users[0]["id"] == ADMIN
    )
    return art.digest(art.encoded(value))


def _installation(data, bound):
    entries = data["installations"]
    art.need(type(entries) is list and len(entries) < 100)
    art.need(type(data["total_count"]) is int and data["total_count"] == len(entries))
    matching = [entry for entry in entries if entry["id"] == INSTALLATION]
    art.need(len(matching) == 1)
    entry = matching[0]
    art.need(entry["app_id"] == APP_ID and entry["app_slug"] == "tte-agent-worker01")
    art.need(
        entry["account"]["id"] == bound["owner"]
        and entry["target_id"] == bound["owner"]
    )
    art.need(
        entry["repository_selection"] == "selected" and entry["suspended_at"] is None
    )
    art.need(entry["permissions"] == pub.PERMISSIONS and entry["events"] == [])
    return art.digest(art.encoded(entry))


def _read(get, graph, bound):
    user = get("/user")
    art.need(user["id"] == ADMIN and user["login"] == "su-17")
    repo = get(pub.ROOT)
    art.need(repo["id"] == pub.REPO_ID and repo["full_name"] == pub.REPOSITORY)
    art.need(
        repo["owner"]["id"] == bound["owner"] and repo["node_id"] == bound["repo_node"]
    )
    art.need(repo["permissions"]["admin"] is True and repo["default_branch"] == "main")
    art.need(repo["archived"] is False and repo["disabled"] is False)
    main = get(pub.ROOT + "/branches/main")
    art.need(main["name"] == "main" and main["commit"]["sha"] == bound["main"])
    classic = _classic(get(pub.ROOT + "/branches/main/protection"))
    rulesets, effective = _rules(get)
    installation = _installation(
        get("/orgs/TechTradeExpress/installations?per_page=100"), bound
    )
    app = get("/apps/tte-agent-worker01")
    art.need(app["id"] == APP_ID and app["slug"] == "tte-agent-worker01")
    art.need(app["owner"]["id"] == bound["app_owner"])
    art.need(app["permissions"] == pub.PERMISSIONS and app["events"] == [])
    for ref in (case.REF, bound["ref"]):
        branch = ref.removeprefix("refs/")
        art.need(get(pub.ROOT + f"/git/matching-refs/{branch}?per_page=100") == [])
        query = urlencode(
            {"head": "TechTradeExpress:" + ref[11:], "state": "all", "per_page": 100}
        )
        art.need(get(pub.ROOT + "/pulls?" + query) == [])
    result = graph()
    art.need("errors" not in result)
    blob = get(pub.ROOT + "/git/blobs/" + case.OBJECT)
    art.need(blob["sha"] == case.OBJECT and blob["encoding"] == "base64")
    blob_bytes = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
    art.need(art.oid("blob", blob_bytes) == case.OBJECT)
    issue = result["data"]["repository"]["issue"]
    art.need(pub.database_id(issue["fullDatabaseId"]) == bound["issue_id"])
    art.need(issue["number"] == 169 and issue["state"] == "OPEN")
    links = issue["closedByPullRequestsReferences"]
    art.need(links["nodes"] == [] and links["pageInfo"]["hasNextPage"] is False)
    return {
        "classic": classic,
        "rulesets": rulesets,
        "effective_rules": effective,
        "installation": installation,
        "app_metadata": art.digest(art.encoded(app)),
        "blob_sha256": art.digest(art.canonical("blob", blob_bytes)),
    }


def observe(
    ipv4,
    administrator_token,
    *,
    snapshot_pin,
    proposed_job,
    archive_pin,
    challenge,
    public_key,
    key_pin,
    selection_bytes,
    selection_signature,
):
    """Run explicitly outside worker01 with an independently supplied admin PAT.

    Only literal GETs and the existing read-only issue inventory query are sent.
    Authentication intake is the caller's responsibility. No CLI or host default.
    """
    art.need(
        type(administrator_token) is str
        and administrator_token.startswith("github_pat_")
    )
    wire = HTTPS.homelab(ipv4)

    def exchange(method, path, payload=None):
        status, data = wire.exchange(method, path, payload, administrator_token)
        art.need(status == 200)
        return data

    def graph():
        return exchange(
            "POST",
            "/graphql",
            {
                "query": pub.INVENTORY,
                "variables": {
                    "owner": "TechTradeExpress",
                    "name": "Agent-Platform",
                    "issue": 169,
                },
            },
        )

    def get(path):
        return exchange("GET", path)

    started = int(time.time())
    bound = binding(snapshot_pin, proposed_job, archive_pin, challenge, started)
    attested_selection = selection(
        public_key, key_pin, selection_bytes, selection_signature, bound, started
    )
    try:
        first = _read(get, graph, bound)
        art.need(_read(get, graph, bound) == first)
    except Exception:
        raise art.Blocked() from None
    now = int(time.time())
    _fresh(started, now)
    _fresh(attested_selection["at"], now)
    return {
        "schema": "AP-worker01-observation/1",
        "binding": bound,
        "administrator": ADMIN,
        "at": now,
        "started": started,
        "api": first,
        "selection_sha256": art.digest(art.encoded(attested_selection)),
    }


def verify_report(
    public_key,
    key_pin,
    raw,
    signature,
    *,
    bound,
    selection_bytes,
    selection_signature,
    blob_sha256,
    now,
):
    selected = selection(
        public_key, key_pin, selection_bytes, selection_signature, bound, now
    )
    value = verify(public_key, key_pin, "report", raw, signature)
    _fresh(value["at"], now)
    _fresh(value["started"], now)
    art.need(value["started"] <= value["at"])
    art.need(selected["at"] <= value["started"])
    api = value["api"]
    art.need(
        set(api)
        == {
            "classic",
            "rulesets",
            "effective_rules",
            "installation",
            "app_metadata",
            "blob_sha256",
        }
    )
    art.need(api["blob_sha256"] == blob_sha256)
    art.need(all(_sha256(v) for k, v in api.items() if k != "rulesets"))
    rulesets = api["rulesets"]
    art.need(type(rulesets) is list and 0 < len(rulesets) < 100)
    ids = []
    for identifier, digest in rulesets:
        art.need(type(identifier) is int and 0 < identifier < 2**63 and _sha256(digest))
        ids.append(identifier)
    art.need(ids == sorted(set(ids)) and RULESET in ids)
    art.need(
        value
        == {
            "schema": "AP-worker01-observation/1",
            "binding": bound,
            "administrator": ADMIN,
            "at": value["at"],
            "started": value["started"],
            "api": api,
            "selection_sha256": art.digest(selection_bytes),
        }
    )


def collect_signed(key, ipv4, administrator_token, **inputs):
    """Return canonical observation bytes and a detached operator signature."""
    art.need(isinstance(key, Ed25519PrivateKey))
    art.need(key.public_key().public_bytes_raw() == inputs["public_key"])
    value = observe(ipv4, administrator_token, **inputs)
    return art.encoded(value), sign(key, "report", value)
