"""PUB-02 operator-only one-shot publisher. Not an Agent Platform runtime adapter."""

import argparse
import base64
import os
import pwd
import re
import time
from pathlib import Path
from urllib.parse import quote

from . import worker_publish_artifact as art
from .worker_publish_io import HTTPS, Journal, read_file

REPOSITORY = "TechTradeExpress/Agent-Platform"
REPO_ID = 1436076348
WORKERS = {
    "worker01": (5748674, 181691110, "tte-agent-worker01"),
    "worker02": (5748675, 181691061, "tte-agent-worker02"),
}
ROOT = "/repos/" + REPOSITORY
PERMISSIONS = {"contents": "write", "pull_requests": "write", "metadata": "read"}
CAS = (
    "mutation($repository:ID!,$updates:[RefUpdate!]!){updateRefs(input:"
    "{repositoryId:$repository,refUpdates:$updates}){clientMutationId}}"
)
LINKS = (
    "query($owner:String!,$name:String!,$pr:Int!){repository(owner:$owner,name:$name)"
    "{pullRequest(number:$pr){closingIssuesReferences(first:2)"
    "{nodes{fullDatabaseId number} pageInfo{hasNextPage}}}}}"
)
INVENTORY = (
    "query($owner:String!,$name:String!,$issue:Int!){repository(owner:$owner,name:$name)"
    "{issue(number:$issue){fullDatabaseId number state "
    "closedByPullRequestsReferences(first:2,includeClosedPrs:true)"
    "{nodes{number} pageInfo{hasNextPage}}}}}"
)


def database_id(value):
    art.need(type(value) in (int, str))
    if type(value) is str:
        art.need(re.fullmatch(r"[1-9][0-9]{0,18}", value))
    number = int(value)
    art.need(0 < number < 2**63)
    return number


JOB_KEYS = {
    "version",
    "repo_node",
    "id",
    "worker",
    "app_id",
    "installation_id",
    "app_slug",
    "bot_id",
    "bot_login",
    "owner_id",
    "app_owner_id",
    "issue",
    "issue_id",
    "ref",
    "base",
    "old",
    "head",
    "tree",
    "parent",
    "operation",
    "pr",
    "artifact_sha256",
    "expires",
    "publisher_uid",
    "publisher_gid",
    "signer_uid",
    "signer_gid",
    "worker_uid",
    "github_ipv4",
    "peer_cert_sha256",
    "journal_sha256",
    "signer_journal_sha256",
    "approval",
    "gates",
}


def validate_job(job, now):
    art.need(
        type(job) is dict and set(job) == JOB_KEYS and job["version"] == art.VERSION
    )
    art.need(
        type(job["repo_node"]) is str
        and re.fullmatch(r"[A-Za-z0-9_=-]{1,128}", job["repo_node"])
    )
    art.need(job["worker"] in WORKERS)
    art.need(
        (job["app_id"], job["installation_id"], job["app_slug"])
        == WORKERS[job["worker"]]
    )
    art.need(type(job["id"]) is str and re.fullmatch("[a-f0-9]{32}", job["id"]))
    for k in (
        "app_id",
        "installation_id",
        "bot_id",
        "owner_id",
        "app_owner_id",
        "issue",
        "issue_id",
        "publisher_uid",
        "publisher_gid",
        "signer_uid",
        "signer_gid",
        "worker_uid",
    ):
        art.need(type(job[k]) is int and 0 < job[k] < 2**63)
    art.need(len({job[k] for k in ("publisher_uid", "signer_uid", "worker_uid")}) == 3)
    art.need(job["publisher_gid"] != job["signer_gid"])
    for k in ("base", "head", "tree", "parent"):
        art.need(art.sha(job[k]))
    for k in (
        "artifact_sha256",
        "peer_cert_sha256",
        "journal_sha256",
        "signer_journal_sha256",
        "approval",
    ):
        art.need(type(job[k]) is str and re.fullmatch("[a-f0-9]{64}", job[k]))
    art.need(type(job["expires"]) is int and now < job["expires"] <= now + 300)
    art.need(type(job["ref"]) is str and len(job["ref"]) <= 200)
    art.need(
        re.fullmatch(
            rf"refs/heads/feature/issue-{job['issue']}-[a-z0-9]+(?:-[a-z0-9]+)*",
            job["ref"],
        )
    )
    art.need(
        type(job["app_slug"]) is str
        and re.fullmatch("[a-z0-9-]{1,100}", job["app_slug"])
    )
    art.need(
        type(job["bot_login"]) is str
        and len(job["bot_login"]) <= 100
        and re.fullmatch(r"[a-zA-Z0-9-]+\[bot\]", job["bot_login"])
    )
    if job["operation"] == "create":
        art.need(
            job["old"] == "ABSENT"
            and job["pr"] is None
            and job["parent"] == job["base"]
        )
    else:
        art.need(job["operation"] == "update" and art.sha(job["old"]))
        art.need(
            job["parent"] == job["old"]
            and type(job["pr"]) is int
            and 0 < job["pr"] < 2**31
        )
    # Each digest is independently retained operator evidence, not a model boolean.
    gates = {
        "isolation",
        "independent_custody",
        "continuity",
        "main_app_merge_denied",
        "disposable_pilot",
    }
    art.need(type(job["gates"]) is dict and set(job["gates"]) == gates)
    art.need(
        all(
            type(v) is str and re.fullmatch("[a-f0-9]{64}", v)
            for v in job["gates"].values()
        )
    )
    HTTPS(job["github_ipv4"], job["peer_cert_sha256"])  # structural, never connects
    return job


def confinement(job, role):
    art.need(role in ("publisher", "signer"))
    art.need(
        not any(
            k in os.environ
            for k in (
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GIT_ASKPASS",
                "SSH_AUTH_SOCK",
                "SSLKEYLOGFILE",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
                "OPENSSL_CONF",
                "OPENSSL_MODULES",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
            )
        )
    )
    uid, gid = job[role + "_uid"], job[role + "_gid"]
    art.need(os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid)
    art.need(
        set(os.getgroups()) <= {gid}
        and len(set(os.getresuid())) == 1
        and len(set(os.getresgid())) == 1
    )
    base = Path(__file__).parent
    for name in (
        "worker_publisher.py",
        "worker_publish_io.py",
        "worker_publish_artifact.py",
        "worker_publish_signer.py",
        "worker_publish_export.py",
    ):
        read_file(str(base / name), 0, 128 * 1024)
    expected = "ap-worker-publisher" + ("-signer" if role == "signer" else "")
    # Only own process metadata, never another principal or a credential store.
    with open("/proc/self/attr/current", "rb") as f:
        art.need(f.read(256).strip(b"\0\n") == (expected + " (enforce)").encode())
    with open("/proc/self/status", "rb") as f:
        data = f.read(8193)
    art.need(len(data) <= 8192)
    facts = dict(line.split(b":", 1) for line in data.splitlines() if b":" in line)
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapAmb"):
        art.need(int(facts[key].strip(), 16) == 0)
    art.need(facts[b"NoNewPrivs"].strip() == b"1")
    art.need(
        pwd.getpwuid(uid).pw_name
        == ("ap-publisher" if role == "publisher" else "ap-publisher-signer")
    )


def receipts(job):
    raw = read_file("/etc/ap-publisher/receipts.json", 0, 32768)
    facts = art.decode(raw)
    art.need(type(facts) is dict and set(facts) == set(job["gates"]))
    for name, expected in job["gates"].items():
        value = facts[name]
        art.need(art.digest(art.encoded(value)) == expected)
        art.need(
            set(value)
            == {
                "repo_id",
                "ref",
                "head",
                "observed_at",
                "expires",
                "verdict",
                "method",
                "app_id",
                "installation_id",
                "worker",
                "job",
            }
        )
        art.need(
            value["repo_id"] == REPO_ID
            and value["ref"] == job["ref"]
            and value["head"] == job["head"]
        )
        art.need(
            all(
                type(value[k]) is type(job[k]) and value[k] == job[k]
                for k in ("app_id", "installation_id", "worker")
            )
        )
        art.need(value["job"] == job["id"])
        art.need(type(value["observed_at"]) is int and type(value["expires"]) is int)
        now = int(time.time())
        art.need(
            now - 300
            <= value["observed_at"]
            <= now
            < value["expires"]
            <= value["observed_at"] + 300
        )
        art.need(value["verdict"] == "VERIFIED_BY_OPERATOR")
        art.need(
            value["method"]
            == (
                "independent_admin_observation"
                if name == "main_app_merge_denied"
                else "independent_negative_controls"
            )
        )


class Client:
    """Fixed domain facade. No caller method/path/GraphQL/payload proxy."""

    def __init__(self, job, objects, wire):
        self.job, self.objects, self.wire = job, objects, wire
        self.token = None
        self.jwt = None
        self.deadline = time.monotonic() + 300

    def _call(
        self,
        method,
        path,
        body=None,
        *,
        jwt=False,
        missing=False,
        limit=2 * 1024 * 1024,
    ):
        j = self.job
        reads = {
            "/app",
            f"/app/installations/{j['installation_id']}",
            "/installation/repositories?per_page=2",
            ROOT,
            ROOT + f"/issues/{j['issue']}",
            ROOT + "/branches/main",
            ROOT + "/rules/branches/main",
            ROOT + "/branches/main/protection",
            ROOT + "/git/ref/heads/main",
            ROOT + "/git/ref/" + j["ref"][5:],
            ROOT + "/pulls?state=all&per_page=100",
            "/users/" + quote(j["bot_login"], safe=""),
        }
        if j["pr"] is not None:
            reads.add(ROOT + f"/pulls/{j['pr']}")
            reads.add(ROOT + f"/issues/{j['pr']}")
        object_reads = {
            ROOT + f"/git/{kind}s/{s}" for s, (kind, _) in self.objects.items()
        }
        # Prior ancestry reads are added only one pinned parent at a time by ancestry().
        reads |= getattr(self, "ancestry_routes", set())
        reads |= getattr(self, "workflow_routes", set())
        writes = {
            ("POST", f"/app/installations/{j['installation_id']}/access_tokens"),
            ("DELETE", "/installation/token"),
            ("POST", "/graphql"),
            ("POST", ROOT + "/git/blobs"),
            ("POST", ROOT + "/git/trees"),
            ("POST", ROOT + "/git/commits"),
            ("POST", ROOT + "/pulls"),
        }
        art.need(
            (method == "GET" and path in reads | object_reads)
            or (method, path) in writes
        )
        if method != "GET":
            art.need(method == "DELETE" or type(body) is dict)
            expected = None
            if path.endswith("/access_tokens"):
                expected = {"repository_ids": [REPO_ID], "permissions": PERMISSIONS}
            elif path == "/graphql" and body.get("query") == LINKS:
                expected = {
                    "query": LINKS,
                    "variables": {
                        "owner": "TechTradeExpress",
                        "name": "Agent-Platform",
                        "pr": j["pr"],
                    },
                }
            elif path == "/graphql" and body.get("query") == INVENTORY:
                expected = {
                    "query": INVENTORY,
                    "variables": {
                        "owner": "TechTradeExpress",
                        "name": "Agent-Platform",
                        "issue": j["issue"],
                    },
                }
            elif path == "/graphql" and body.get("query") == CAS:
                expected = {
                    "query": CAS,
                    "variables": {
                        "repository": self.repository_node,
                        "updates": [
                            {
                                "name": j["ref"],
                                "beforeOid": "0" * 40
                                if j["old"] == "ABSENT"
                                else j["old"],
                                "afterOid": j["head"],
                                "force": False,
                            }
                        ],
                    },
                }
            elif path == ROOT + "/pulls":
                expected = {
                    "title": f"Issue #{j['issue']}: proposed changes",
                    "body": f"Closes #{j['issue']}\n",
                    "head": j["ref"][11:],
                    "base": "main",
                    "draft": True,
                    "maintainer_can_modify": False,
                }
            elif path in (
                ROOT + "/git/blobs",
                ROOT + "/git/trees",
                ROOT + "/git/commits",
            ):
                for kind, raw in self.objects.values():
                    if path != ROOT + "/git/" + kind + "s":
                        continue
                    value = (
                        {
                            "content": base64.b64encode(raw).decode(),
                            "encoding": "base64",
                        }
                        if kind == "blob"
                        else {"tree": art.tree(raw)}
                        if kind == "tree"
                        else art.commit(raw)
                    )
                    if art.encoded(body) == art.encoded(value):
                        expected = value
                        break
            art.need(art.encoded(body) == art.encoded(expected))
        art.need(time.monotonic() < self.deadline and int(time.time()) < j["expires"])
        status, value = self.wire.exchange(
            method,
            path,
            body,
            self.jwt
            if jwt
            else None
            if path == ROOT + f"/issues/{j['issue']}" or path.startswith("/users/")
            else self.token,
            limit,
        )
        art.need(time.monotonic() < self.deadline)
        art.need(
            status
            == (
                201
                if method == "POST" and path != "/graphql"
                else 204
                if method == "DELETE"
                else 200
            )
            or missing
            and status == 404
        )
        return None if status == 404 else value

    def app(self):
        j = self.job
        app = self._call("GET", "/app", jwt=True)
        art.need(
            type(app["id"]) is int
            and app["id"] == j["app_id"]
            and app["slug"] == j["app_slug"]
        )
        art.need(
            app["owner"]["id"] == j["app_owner_id"]
            and app["permissions"] == PERMISSIONS
            and app["events"] == []
        )
        install = self._call(
            "GET", f"/app/installations/{j['installation_id']}", jwt=True
        )
        art.need(
            install["id"] == j["installation_id"] and install["app_id"] == j["app_id"]
        )
        art.need(
            install["account"]["id"] == j["owner_id"]
            and install["repository_selection"] == "selected"
        )
        art.need(
            install["permissions"] == PERMISSIONS
            and install["events"] == []
            and install["suspended_at"] is None
        )
        bot = self._call("GET", "/users/" + quote(j["bot_login"], safe=""))
        art.need(
            bot["id"] == j["bot_id"]
            and bot["login"] == j["bot_login"]
            and bot["type"] == "Bot"
        )

    def mint(self):
        j = self.job
        value = self._call(
            "POST",
            f"/app/installations/{j['installation_id']}/access_tokens",
            {"repository_ids": [REPO_ID], "permissions": PERMISSIONS},
            jwt=True,
        )
        art.need(type(value.get("token")) is str and 0 < len(value["token"]) < 8192)
        self.token = value[
            "token"
        ]  # retain for finally-revocation even if scope validation fails
        art.need(value["permissions"] == PERMISSIONS)
        from datetime import datetime

        expiry = datetime.fromisoformat(
            value["expires_at"].replace("Z", "+00:00")
        ).timestamp()
        art.need(time.time() + 30 < expiry <= time.time() + 3660)
        scope = self._call("GET", "/installation/repositories?per_page=2")
        art.need(scope["total_count"] == 1 and len(scope["repositories"]) == 1)
        art.need(
            scope["repositories"][0]["id"] == REPO_ID
            and scope["repositories"][0]["full_name"] == REPOSITORY
        )
        return b"token_issued"

    def ancestry(self):
        j = self.job
        tip = j["old"] if j["operation"] == "update" else j["base"]
        self.ancestry_routes = set()
        for _ in range(65):
            if tip == j["base"]:
                return
            art.need(art.sha(tip))
            path = ROOT + "/git/commits/" + tip
            self.ancestry_routes.add(path)
            value = self._call("GET", path)
            art.need(value["sha"] == tip and len(value["parents"]) == 1)
            tip = value["parents"][0]["sha"]
        raise art.Blocked()

    def workflows(self, inventory):
        # Contents-only writers may not change workflow files. Prove unchanged
        # against the exact current base before even issuing an installation token.
        j = self.job
        path = ROOT + "/git/commits/" + j["base"]
        self.workflow_routes = {path}
        c = self._call("GET", path)
        art.need(c["sha"] == j["base"] and art.sha(c["tree"]["sha"]))
        path = ROOT + "/git/trees/" + c["tree"]["sha"] + "?recursive=1"
        self.workflow_routes.add(path)
        value = self._call("GET", path)
        art.need(value["sha"] == c["tree"]["sha"] and value["truncated"] is False)
        art.need(type(value["tree"]) is list and len(value["tree"]) <= art.MAX_OBJECTS)
        self.known_objects = {value["sha"], *(e["sha"] for e in value["tree"])}
        actual = sorted(
            (e["path"], e["mode"], e["sha"])
            for e in value["tree"]
            if e["path"].startswith(".github/workflows/") and e["type"] == "blob"
        )
        expected = sorted(e for e in inventory if e[0].startswith(".github/workflows/"))
        art.need(actual == expected)

    def observe(self, tip):
        j = self.job
        repo = self._call("GET", ROOT)
        art.need(
            repo["id"] == REPO_ID
            and repo["full_name"] == REPOSITORY
            and repo["node_id"] == j["repo_node"]
            and repo["owner"]["id"] == j["owner_id"]
        )
        art.need(
            repo["default_branch"] == "main"
            and repo["archived"] is False
            and repo["disabled"] is False
        )
        issue = self._call("GET", ROOT + f"/issues/{j['issue']}")
        art.need(
            issue["id"] == j["issue_id"]
            and issue["number"] == j["issue"]
            and issue["state"] == "open"
            and "pull_request" not in issue
        )
        base = self._call("GET", ROOT + "/git/ref/heads/main")
        art.need(
            base["object"]["sha"] == j["base"] and base["object"]["type"] == "commit"
        )
        main = self._call("GET", ROOT + "/branches/main")
        art.need(main["protected"] is True and main["commit"]["sha"] == j["base"])
        # Classic protection requires Administration access, deliberately absent
        # from these Apps. Root/operator's separately authenticated, expiring
        # receipt is checked by authorize(), never guessed from required checks.
        feature = self._call("GET", ROOT + "/git/ref/" + j["ref"][5:], missing=True)
        art.need(
            (feature is None and tip is None)
            or feature is not None
            and feature["ref"] == j["ref"]
            and feature["object"]["type"] == "commit"
            and feature["object"]["sha"] == tip
        )
        prs = self._call("GET", ROOT + "/pulls?state=all&per_page=100")
        art.need(type(prs) is list and len(prs) < 100)
        relevant = [
            p
            for p in prs
            if p["head"]["ref"] == j["ref"][11:]
            or re.search(
                rf"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#{j['issue']}\b",
                p["body"] or "",
            )
        ]
        art.need(len(relevant) == (0 if j["pr"] is None else 1))
        if j["pr"] is not None:
            art.need(relevant[0]["number"] == j["pr"])
            self.pr(tip, native=self.token is not None)
        if self.token is not None:
            refs = self._call(
                "POST",
                "/graphql",
                {
                    "query": INVENTORY,
                    "variables": {
                        "owner": "TechTradeExpress",
                        "name": "Agent-Platform",
                        "issue": j["issue"],
                    },
                },
            )
            art.need("errors" not in refs)
            node = refs["data"]["repository"]["issue"]
            art.need(
                database_id(node["fullDatabaseId"]) == j["issue_id"]
                and node["number"] == j["issue"]
                and node["state"] == "OPEN"
            )
            refs = node["closedByPullRequestsReferences"]
            art.need(refs["pageInfo"]["hasNextPage"] is False)
            art.need(
                refs["nodes"] == ([] if j["pr"] is None else [{"number": j["pr"]}])
            )
        self.ancestry()
        self.repository_node = repo["node_id"]
        return self.repository_node

    def pr(self, tip, *, native=True):
        j = self.job
        p = self._call("GET", ROOT + f"/pulls/{j['pr']}")
        art.need(p["number"] == j["pr"] and p["state"] == "open" and p["draft"] is True)
        art.need(
            p["head"]["repo"]["id"] == REPO_ID and p["base"]["repo"]["id"] == REPO_ID
        )
        art.need(p["head"]["ref"] == j["ref"][11:] and p["head"]["sha"] == tip)
        art.need(p["base"]["ref"] == "main" and p["base"]["sha"] == j["base"])
        art.need(
            p["user"]["id"] == j["bot_id"] and p["user"]["login"] == j["bot_login"]
        )
        art.need(p["body"] == f"Closes #{j['issue']}\n")
        # Actual PR App attribution, not commit author text or Bot-profile guessing.
        issue_pr = self._call("GET", ROOT + f"/issues/{j['pr']}")
        art.need(issue_pr["performed_via_github_app"]["id"] == j["app_id"])
        if not native:
            return
        links = self._call(
            "POST",
            "/graphql",
            {
                "query": LINKS,
                "variables": {
                    "owner": "TechTradeExpress",
                    "name": "Agent-Platform",
                    "pr": j["pr"],
                },
            },
        )
        art.need("errors" not in links)
        refs = links["data"]["repository"]["pullRequest"]["closingIssuesReferences"]
        art.need(refs["pageInfo"]["hasNextPage"] is False and len(refs["nodes"]) == 1)
        node = refs["nodes"][0]
        art.need(
            set(node) == {"fullDatabaseId", "number"}
            and database_id(node["fullDatabaseId"]) == j["issue_id"]
            and node["number"] == j["issue"]
        )

    def upload(self, s):
        kind, payload = self.objects[s]
        if kind == "blob":
            body = {"content": base64.b64encode(payload).decode(), "encoding": "base64"}
        elif kind == "tree":
            body = {"tree": art.tree(payload)}
        else:
            body = art.commit(payload)
        v = self._call("POST", ROOT + "/git/" + kind + "s", body)
        art.need(v["sha"] == s)
        self.verify(s)
        return bytes.fromhex(s)

    def verify(self, s):
        kind, payload = self.objects[s]
        v = self._call("GET", ROOT + "/git/" + kind + "s/" + s, limit=6 * 1024 * 1024)
        art.need(v["sha"] == s)
        if kind == "blob":
            art.need(
                v["encoding"] == "base64"
                and base64.b64decode(v["content"], validate=False) == payload
            )
        elif kind == "tree":
            art.need(v.get("truncated", False) is False)
            actual = [
                {k: e[k] for k in ("path", "mode", "type", "sha")} for e in v["tree"]
            ]
            art.need(actual == art.tree(payload))
        else:
            expected = art.commit(payload)
            art.need(
                v["tree"]["sha"] == expected["tree"]
                and [p["sha"] for p in v["parents"]] == expected["parents"]
            )
            art.need(v["message"].rstrip("\n") == expected["message"].rstrip("\n"))
            art.need(
                all(
                    {k: v[who][k] for k in ("name", "email", "date")} == expected[who]
                    for who in ("author", "committer")
                )
            )

    def cas(self, repository_node):
        j = self.job
        v = self._call(
            "POST",
            "/graphql",
            {
                "query": CAS,
                "variables": {
                    "repository": repository_node,
                    "updates": [
                        {
                            "name": j["ref"],
                            "beforeOid": "0" * 40 if j["old"] == "ABSENT" else j["old"],
                            "afterOid": j["head"],
                            "force": False,
                        }
                    ],
                },
            },
        )
        art.need("errors" not in v and v["data"]["updateRefs"] is not None)
        return bytes.fromhex(j["head"])

    def draft(self):
        j = self.job
        v = self._call(
            "POST",
            ROOT + "/pulls",
            {
                "title": f"Issue #{j['issue']}: proposed changes",
                "body": f"Closes #{j['issue']}\n",
                "head": j["ref"][11:],
                "base": "main",
                "draft": True,
                "maintainer_can_modify": False,
            },
        )
        art.need(type(v["number"]) is int and v["number"] > 0)
        return v["number"]

    def revoke(self):
        # Revocation must still be attempted after job expiry; separate fixed 5s call.
        status, _ = self.wire.exchange(
            "DELETE", "/installation/token", None, self.token
        )
        art.need(status == 204)
        self.token = None
        return b"revoked"


def publish(job, data, jwt, journal, client, authorize):
    validate_job(job, int(time.time()))
    art.need(art.digest(data) == job["artifact_sha256"])
    objects, order, inventory, _ = art.validate(
        data, job["head"], job["tree"], job["parent"]
    )
    art.need(client.objects == objects)

    def effect(name, payload, fn, *, cleanup=False):
        if not cleanup:
            authorize()
        journal.append(
            {
                "phase": "UNKNOWN",
                "job": job["id"],
                "operation": name,
                "digest": art.digest(payload),
            }
        )
        value = fn()
        journal.append(
            {
                "phase": "CONFIRMED",
                "job": job["id"],
                "operation": name,
                "digest": art.digest(
                    value if type(value) is bytes else art.encoded(value)
                ),
            }
        )
        return value

    journal.claim(job)
    client.jwt = jwt
    pr = job["pr"]
    try:
        authorize()
        client.app()
        # Public reads establish source/main facts before token issuance.
        client.observe(None if job["old"] == "ABSENT" else job["old"])
        client.workflows(inventory)
        effect(
            "mint",
            art.encoded({"repository_ids": [REPO_ID], "permissions": PERMISSIONS}),
            client.mint,
        )
        for s in order:
            if s in client.known_objects:
                continue
            authorize()
            client.app()
            client.observe(None if job["old"] == "ABSENT" else job["old"])
            effect("object", bytes.fromhex(s), lambda s=s: client.upload(s))
        for s in order:
            client.verify(s)
        node = client.observe(None if job["old"] == "ABSENT" else job["old"])

        def change():
            result = client.cas(node)
            client.observe(job["head"])
            return result

        effect(
            "ref",
            art.encoded(
                {"before": job["old"], "after": job["head"], "ref": job["ref"]}
            ),
            change,
        )
        if job["operation"] == "create":
            client.observe(job["head"])

            def create():
                nonlocal pr
                pr = client.draft()
                # Bind only the observed new PR number for independent readback.
                client.job = dict(job, pr=pr)
                client.pr(job["head"])
                client.observe(job["head"])
                return pr

            effect(
                "draft",
                art.encoded({"head": job["head"], "issue": job["issue"]}),
                create,
            )
        for _ in range(2):
            client.pr(job["head"])
    finally:
        if client.token is not None:
            effect("revoke", b"revoke", client.revoke, cleanup=True)
        client.jwt = None
    journal.append(
        {
            "phase": "COMPLETE",
            "job": job["id"],
            "ref": job["ref"],
            "issue": job["issue"],
            "head": job["head"],
            "pr": pr,
        }
    )
    return {
        "status": "PUBLISHED",
        "pr": pr,
        "head": job["head"],
        "runtime": "LIVE_NO_GO",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Operator-only one-shot Publisher; dry-run by default."
    )
    parser.add_argument("--job", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    journal = None
    attempted = False
    try:
        original = read_file(args.job, 0, 16384)
        job = validate_job(art.decode(original), int(time.time()))
        data = read_file(args.artifact, 0, art.MAX_WIRE)
        art.need(art.digest(data) == job["artifact_sha256"])
        objects, _, inventory, _ = art.validate(
            data, job["head"], job["tree"], job["parent"]
        )
        if not args.execute:
            print(
                art.encoded(
                    {
                        "status": "DRY_RUN",
                        "operation": job["operation"],
                        "head": job["head"],
                        "files": len(inventory),
                        "runtime": "LIVE_NO_GO",
                    }
                ).decode()
            )
            return 0
        confinement(job, "publisher")

        def authorize():
            art.need(
                read_file(args.job, 0, 16384) == original
                and int(time.time()) < job["expires"]
            )
            confinement(job, "publisher")
            receipts(job)

        authorize()
        journal = Journal("/var/lib/ap-publisher/journal", job["journal_sha256"])
        credential = Path(os.environ.get("CREDENTIALS_DIRECTORY", "")) / "app-jwt"
        bundle = art.decode(
            read_file(
                str(credential), os.getuid(), 16384, writable_parent=True, private=True
            )
        )
        art.need(type(bundle) is dict and set(bundle) == {"job_sha256", "jwt"})
        art.need(bundle["job_sha256"] == art.digest(original))
        jwt = bundle["jwt"]
        attempted = True
        result = publish(
            job,
            data,
            jwt,
            journal,
            Client(job, objects, HTTPS(job["github_ipv4"], job["peer_cert_sha256"])),
            authorize,
        )
        print(art.encoded(result).decode())
        return 0
    except Exception:
        print(
            art.encoded(
                {
                    "status": "UNKNOWN_NEEDS_HUMAN" if attempted else "BLOCKED",
                    "code": "publisher_stopped",
                    "runtime": "LIVE_NO_GO",
                }
            ).decode()
        )
        return 1
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
