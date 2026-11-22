"""Fixed worker01 administrative observations over fabricated wire responses."""

import copy
from urllib.parse import urlencode

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_worker_publish_reconciliation import case as evidence_case  # noqa: F401

from agent_platform import worker_publish_artifact as art
from agent_platform import worker_publish_case as case
from agent_platform import worker_publish_observer as observer
from agent_platform import worker_publish_reconciliation as reconciliation
from agent_platform import worker_publisher as pub


@pytest.fixture
def sample(evidence_case, monkeypatch):  # noqa: F811
    args = evidence_case.args()
    now = args["now"]
    snapshot = args["pins"].snapshot
    archive = "1" * 64
    challenge = "2" * 64
    job = args["proposed_job"]
    bound = observer.binding(snapshot, job, archive, challenge, now)
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    pin = art.digest(public)
    value = {
        "schema": "AP-worker01-selection/1",
        "administrator": observer.ADMIN,
        "source": "administrative_installation_repository_inventory",
        "binding": bound,
        "at": now - 1,
        "repository_ids": [pub.REPO_ID],
    }
    routes = {
        "/user": {"id": observer.ADMIN, "login": "su-17"},
        pub.ROOT: {
            "id": pub.REPO_ID,
            "full_name": pub.REPOSITORY,
            "owner": {"id": bound["owner"]},
            "node_id": bound["repo_node"],
            "permissions": {"admin": True},
            "default_branch": "main",
            "archived": False,
            "disabled": False,
        },
        pub.ROOT + "/branches/main": {"name": "main", "commit": {"sha": bound["main"]}},
        pub.ROOT + "/branches/main/protection": {
            "enforce_admins": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "restrictions": {
                "apps": [],
                "teams": [],
                "users": [{"login": "su-17", "id": observer.ADMIN}],
            },
        },
        pub.ROOT + "/rulesets?includes_parents=true&per_page=100": [
            {"id": observer.RULESET, "enforcement": "active"},
        ],
        pub.ROOT + f"/rulesets/{observer.RULESET}?includes_parents=true": {
            "id": observer.RULESET,
            "enforcement": "active",
            "bypass_actors": [],
            "rules": [{"type": "pull_request"}],
        },
        pub.ROOT + "/rules/branches/main?per_page=100": [
            {"ruleset_id": observer.RULESET}
        ],
        "/orgs/TechTradeExpress/installations?per_page=100": {
            "total_count": 1,
            "installations": [
                {
                    "id": observer.INSTALLATION,
                    "app_id": observer.APP_ID,
                    "app_slug": "tte-agent-worker01",
                    "account": {"id": bound["owner"]},
                    "target_id": bound["owner"],
                    "permissions": pub.PERMISSIONS,
                    "events": [],
                    "repository_selection": "selected",
                    "suspended_at": None,
                }
            ],
        },
        "/apps/tte-agent-worker01": {
            "id": observer.APP_ID,
            "slug": "tte-agent-worker01",
            "owner": {"id": bound["app_owner"]},
            "permissions": pub.PERMISSIONS,
            "events": [],
        },
        "/graphql": {
            "data": {
                "repository": {
                    "issue": {
                        "fullDatabaseId": bound["issue_id"],
                        "number": 169,
                        "state": "OPEN",
                        "closedByPullRequestsReferences": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False},
                        },
                    }
                }
            }
        },
    }
    oid = args["object_id"]
    monkeypatch.setattr(case, "OBJECT", oid)
    routes[pub.ROOT + "/git/blobs/" + oid] = {
        "sha": oid,
        "encoding": "base64",
        "content": "aGVsbG8K",
    }
    for ref in (case.REF, bound["ref"]):
        routes[pub.ROOT + "/git/matching-refs/" + ref[5:] + "?per_page=100"] = []
        query = urlencode(
            {"head": "TechTradeExpress:" + ref[11:], "state": "all", "per_page": 100}
        )
        routes[pub.ROOT + "/pulls?" + query] = []

    class Wire:
        def exchange(self, method, path, payload, token):
            assert token == "github_pat_fixture"
            if path == "/graphql":
                assert method == "POST" and payload["query"] == pub.INVENTORY
            else:
                assert method == "GET" and payload is None
            return 200, copy.deepcopy(routes[path])

    monkeypatch.setattr(observer.HTTPS, "homelab", lambda ip: Wire())
    monkeypatch.setattr(observer.time, "time", lambda: now)

    def collect(selection_value=value):
        return observer.observe(
            "140.82.112.6",
            "github_pat_fixture",
            snapshot_pin=snapshot,
            proposed_job=job,
            archive_pin=archive,
            challenge=challenge,
            public_key=public,
            key_pin=pin,
            selection_bytes=art.encoded(selection_value),
            selection_signature=observer.sign(key, "selection", selection_value),
        )

    def verify(report, *, binding=bound, key_pin=pin, at=now, signature=None):
        observer.verify_report(
            public,
            key_pin,
            art.encoded(report),
            signature or observer.sign(key, "report", report),
            bound=binding,
            selection_bytes=art.encoded(value),
            selection_signature=observer.sign(key, "selection", value),
            blob_sha256=art.digest(art.canonical("blob", b"hello\n")),
            now=at,
        )

    return routes, collect, verify, value, bound, now


def test_authenticated_reads_and_signed_worker_verification(sample):
    _, collect, verify, _, _, _ = sample
    report = collect()
    verify(report)
    assert "github_pat" not in art.encoded(report).decode()
    assert "bypass_actors" not in report["api"]  # only bounded fingerprints


@pytest.mark.parametrize(
    "failure",
    [
        "principal",
        "main",
        "bypass",
        "admin_visibility",
        "installation",
        "link_page",
        "prior_ref",
        "blob",
    ],
)
def test_observer_stops_on_missing_or_conflicting_evidence(sample, failure):
    routes, collect, _, _, _, _ = sample
    if failure == "principal":
        routes["/user"]["id"] = 1
    elif failure == "main":
        routes[pub.ROOT + "/branches/main"]["commit"]["sha"] = "c" * 40
    elif failure == "bypass":
        del routes[pub.ROOT + f"/rulesets/{observer.RULESET}?includes_parents=true"][
            "bypass_actors"
        ]
    elif failure == "admin_visibility":
        routes[pub.ROOT]["permissions"]["admin"] = False
    elif failure == "installation":
        routes["/orgs/TechTradeExpress/installations?per_page=100"]["total_count"] = 2
    elif failure == "link_page":
        issue = routes["/graphql"]["data"]["repository"]["issue"]
        issue["closedByPullRequestsReferences"]["pageInfo"]["hasNextPage"] = True
    elif failure == "prior_ref":
        routes[pub.ROOT + "/git/matching-refs/" + case.REF[5:] + "?per_page=100"] = [
            {"ref": case.REF}
        ]
    else:
        routes[pub.ROOT + "/git/blobs/" + case.OBJECT]["content"] = "YWJj"
    with pytest.raises(art.Blocked):
        collect()


def test_selection_is_separate_exact_attestation(sample):
    _, collect, _, value, _, _ = sample
    with pytest.raises(art.Blocked):
        collect(dict(value, repository_ids=[pub.REPO_ID, 123]))


@pytest.mark.parametrize("fault", ["signature", "key", "scope", "expiry"])
def test_worker_rejects_invalid_signature_pin_scope_or_freshness(sample, fault):
    _, collect, verify, _, bound, now = sample
    kwargs = {
        "signature": {"signature": b"0" * 64},
        "key": {"key_pin": "0" * 64},
        "scope": {"binding": dict(bound, challenge="f" * 64)},
        "expiry": {"at": now + 301},
    }
    with pytest.raises(art.Blocked):
        verify(collect(), **kwargs[fault])


def test_observer_has_no_admission_consumer():
    # The report contract is independent of runtime mutation and role claims.
    assert not hasattr(observer, "launch")
    assert not hasattr(observer, "consume")
    assert reconciliation._report("STOP", "stale")["admission_allowed"] is False


def test_live_snapshot_must_match_confirmed_archive_before_observation(monkeypatch):
    monkeypatch.setattr(case, "_confirm", lambda fd, pin: None)
    monkeypatch.setattr(
        case, "_read", lambda fd, name, limit: art.encoded({"snapshot": "1" * 64})
    )
    monkeypatch.setattr(
        reconciliation, "_history", lambda *args: pytest.fail("read live history")
    )
    with pytest.raises(art.Blocked):
        case._verify_observation(10, None, "2" * 64, "3" * 64, 123)
