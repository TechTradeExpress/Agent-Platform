"""PUB-02 actual exporter/validator/journal/CLI with offline GitHub wire mocks."""

import base64
import errno
import json
import os
import re
import stat
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agent_platform import worker_publish_artifact as a
from agent_platform import worker_publish_io as io
from agent_platform import worker_publish_operator as op
from agent_platform import worker_publish_signer as signer
from agent_platform import worker_publisher as p


def artifact(parent="a" * 40, text=b"hello\n"):
    blob = a.oid("blob", text)
    nested = b"100644 file.py\0" + bytes.fromhex(blob)
    sub = a.oid("tree", nested)
    root = b"40000 src\0" + bytes.fromhex(sub)
    tree = a.oid("tree", root)
    payload = (
        f"tree {tree}\nparent {parent}\nauthor Fixture <a@example.test> 1 +0000\n"
        "committer Fixture <a@example.test> 1 +0000\n\n"
        "Multi-line commit\n\nexact bytes\n"
    ).encode()
    head = a.oid("commit", payload)
    values = {
        blob: ("blob", text),
        sub: ("tree", nested),
        tree: ("tree", root),
        head: ("commit", payload),
    }
    data = a.encoded(
        {
            "version": a.VERSION,
            "head": head,
            "objects": [
                {"oid": s, "kind": k, "data": base64.b64encode(b).decode()}
                for s, (k, b) in values.items()
            ],
        }
    )
    return data, head, tree, values


def job_for(data, head, tree, *, old="ABSENT", pr=None):
    j = dict(
        version=a.VERSION,
        repo_node="REPO_NODE",
        id="a" * 32,
        worker="worker01",
        app_id=5748674,
        installation_id=181691110,
        app_slug="tte-agent-worker01",
        bot_id=40,
        bot_login="fixture[bot]",
        owner_id=30,
        app_owner_id=31,
        issue=108,
        issue_id=500,
        ref="refs/heads/feature/issue-108-fixture",
        base="a" * 40,
        old=old,
        head=head,
        tree=tree,
        parent="a" * 40 if old == "ABSENT" else old,
        operation="create" if old == "ABSENT" else "update",
        pr=pr,
        artifact_sha256=a.digest(data),
        expires=int(time.time()) + 240,
        publisher_uid=1000,
        publisher_gid=1000,
        signer_uid=1001,
        signer_gid=1001,
        worker_uid=1002,
        github_ipv4="140.82.112.6",
        peer_cert_sha256="b" * 64,
        journal_sha256=a.digest(b""),
        signer_journal_sha256=a.digest(b""),
        approval="c" * 64,
        gates={
            k: "d" * 64
            for k in (
                "isolation",
                "independent_custody",
                "continuity",
                "main_app_merge_denied",
                "disposable_pilot",
            )
        },
    )
    p.validate_job(j, int(time.time()))
    return j


def homelab_job(job):
    return {
        **{key: val for key, val in job.items() if key in p.HOMELAB_KEYS},
        "contract": p.HOMELAB,
        "bot_login": "tte-agent-worker01[bot]",
    }


class Wire:
    """Real wire-shaped JSON; canonical objects recomputed independently on POST."""

    def __init__(self, journal, job):
        self.journal, self.job = journal, job
        self.tip = None if job["old"] == "ABSENT" else job["old"]
        self.pr_number = job["pr"]
        self.objects = {}
        self.calls = []
        self.mutate = lambda path, value: value
        self.fail = None
        self.token = False

    def pr(self):
        j = self.job
        return {
            "number": self.pr_number,
            "state": "open",
            "draft": True,
            "head": {"ref": j["ref"][11:], "sha": self.tip, "repo": {"id": p.REPO_ID}},
            "base": {"ref": "main", "sha": j["base"], "repo": {"id": p.REPO_ID}},
            "body": f"Closes #{j['issue']}\n",
            "user": {"id": j["bot_id"], "login": j["bot_login"]},
        }

    def exchange(self, method, path, body, secret, limit=256 * 1024):
        self.calls.append((method, path))
        j = self.job
        mutation = method != "GET" and not (
            path == "/graphql" and body["query"] in (p.LINKS, p.INVENTORY)
        )
        if mutation:
            assert self.journal.events[-1]["record"]["phase"] == "UNKNOWN"
        status, value = 200, None
        if path == "/app":
            assert secret == "JWT_FAKE"
            value = {
                "id": j["app_id"],
                "slug": j["app_slug"],
                "owner": {"id": j["app_owner_id"]},
                "permissions": p.PERMISSIONS,
                "events": [],
            }
        elif path == f"/app/installations/{j['installation_id']}":
            value = {
                "id": j["installation_id"],
                "app_id": j["app_id"],
                "account": {"id": j["owner_id"]},
                "repository_selection": "selected",
                "permissions": p.PERMISSIONS,
                "events": [],
                "suspended_at": None,
            }
        elif path.startswith("/users/"):
            value = {"id": j["bot_id"], "login": j["bot_login"], "type": "Bot"}
        elif path.endswith("/access_tokens"):
            assert body == {"repository_ids": [p.REPO_ID], "permissions": p.PERMISSIONS}
            assert secret == "JWT_FAKE"
            self.token = True
            status = 201
            value = {
                "token": "INSTALLATION_FAKE_PRIVATE",
                "permissions": p.PERMISSIONS,
                "expires_at": datetime.fromtimestamp(
                    time.time() + 3600, UTC
                ).isoformat(),
            }
        elif path == "/installation/repositories?per_page=2":
            assert secret == "INSTALLATION_FAKE_PRIVATE"
            value = {
                "total_count": 1,
                "repositories": [{"id": p.REPO_ID, "full_name": p.REPOSITORY}],
            }
        elif path == "/installation/token":
            self.token = False
            status = 204
        elif path == p.ROOT:
            value = {
                "id": p.REPO_ID,
                "full_name": p.REPOSITORY,
                "owner": {"id": j["owner_id"]},
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "node_id": "REPO_NODE",
                "private": False,
            }
        elif path == p.ROOT + f"/issues/{j['issue']}":
            value = {"id": j["issue_id"], "number": j["issue"], "state": "open"}
        elif path == p.ROOT + "/branches/main":
            value = {"protected": True, "commit": {"sha": j["base"]}}
        elif path == p.ROOT + "/git/ref/heads/main":
            value = {"object": {"type": "commit", "sha": j["base"]}}
        elif path == p.ROOT + "/git/ref/" + j["ref"][5:]:
            if self.tip is None:
                status = 404
            else:
                value = {"ref": j["ref"], "object": {"type": "commit", "sha": self.tip}}
        elif path == p.head_pulls(j):
            # GitHub's head filter: only PRs whose head is this exact branch.
            value = [] if self.pr_number is None else [self.pr()]
        elif path == p.ROOT + f"/pulls/{self.pr_number}":
            value = self.pr()
        elif path == p.ROOT + f"/issues/{self.pr_number}":
            value = {"performed_via_github_app": {"id": j["app_id"]}}
        elif path == "/graphql":
            if body["query"] == p.INVENTORY:
                value = {
                    "data": {
                        "repository": {
                            "issue": {
                                "fullDatabaseId": str(j["issue_id"]),
                                "number": j["issue"],
                                "state": "OPEN",
                                "closedByPullRequestsReferences": {
                                    "nodes": []
                                    if self.pr_number is None
                                    else [{"number": self.pr_number}],
                                    "pageInfo": {"hasNextPage": False},
                                },
                            }
                        }
                    }
                }
            elif body["query"] == p.CAS:
                u = body["variables"]["updates"][0]
                assert (
                    u["name"] == j["ref"]
                    and u["force"] is False
                    and u["afterOid"] == j["head"]
                )
                expected = "0" * 40 if self.tip is None else self.tip
                if u["beforeOid"] != expected:
                    return 200, {"errors": [{"message": "FAKE_PRIVATE_CONFLICT"}]}
                self.tip = u["afterOid"]
                value = {"data": {"updateRefs": {"clientMutationId": None}}}
            else:
                assert secret == "INSTALLATION_FAKE_PRIVATE"
                value = {
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "closingIssuesReferences": {
                                    "nodes": [
                                        {
                                            "fullDatabaseId": str(j["issue_id"]),
                                            "number": j["issue"],
                                        }
                                    ],
                                    "pageInfo": {"hasNextPage": False},
                                }
                            }
                        }
                    }
                }
        elif path == p.ROOT + "/pulls":
            assert body["draft"] is True and body["base"] == "main"
            assert self.pr_number is None
            self.pr_number = 111
            status, value = 201, {"number": 111}
        elif path == p.ROOT + "/git/commits/" + j["base"]:
            value = {"sha": j["base"], "tree": {"sha": "e" * 40}}
        elif path.endswith("?recursive=1"):
            value = {"sha": "e" * 40, "truncated": False, "tree": []}
        elif method == "POST" and "/git/" in path:
            kind = path.rsplit("/", 1)[-1][:-1]
            if kind == "blob":
                payload = base64.b64decode(body["content"])
            elif kind == "tree":
                payload = b"".join(
                    e["mode"].lstrip("0").encode()
                    + b" "
                    + e["path"].encode()
                    + b"\0"
                    + bytes.fromhex(e["sha"])
                    for e in body["tree"]
                )
            else:

                def ident(v):
                    n = int(
                        datetime.fromisoformat(
                            v["date"].replace("Z", "+00:00")
                        ).timestamp()
                    )
                    return f"{v['name']} <{v['email']}> {n} +0000"

                payload = (
                    f"tree {body['tree']}\nparent {body['parents'][0]}\nauthor "
                    + ident(body["author"])
                    + "\ncommitter "
                    + ident(body["committer"])
                    + "\n\n"
                    + body["message"]
                ).encode()
            s = a.oid(kind, payload)
            self.objects[s] = (kind, payload)
            status, value = 201, {"sha": s}
        elif "/git/" in path:
            s = path.rsplit("/", 1)[-1]
            kind, payload = self.objects[s]
            value = {"sha": s}
            if kind == "blob":
                value |= {
                    "encoding": "base64",
                    "content": base64.b64encode(payload).decode(),
                }
            elif kind == "tree":
                value |= {"tree": a.tree(payload), "truncated": False}
            else:
                c = a.commit(payload)
                value |= c | {
                    "tree": {"sha": c["tree"]},
                    "parents": [{"sha": v} for v in c["parents"]],
                    "message": c["message"].rstrip("\n"),
                }
        else:
            raise AssertionError("unimplemented fixture route")
        value = self.mutate(path, value)
        if self.fail == path:
            raise TimeoutError("FAKE_PRIVATE lost reply after effect")
        return status, value


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "journal"
    path.write_bytes(b"")
    path.chmod(0o600)
    # Only ancestor traversal is synthetic here (/tmp is intentionally disallowed
    # in production). Journal's real flock/append/fsync/readback remain exercised.
    monkeypatch.setattr(io, "read_file", lambda *args, **kwargs: b"")
    journal = io.Journal(str(path), a.digest(b""))
    yield journal, path
    journal.close()


def invoke(j, data, store, wire=None):
    objects, *_ = a.validate(data, j["head"], j["tree"], j["parent"])
    wire = wire or Wire(store, j)
    c = p.Client(j, objects, wire)
    return p.publish(j, data, "JWT_FAKE", store, c, lambda: None), wire


def test_real_wire_encoding_create_then_update_exact_sha(store):
    journal, path = store
    data, head, tree, objects = artifact()
    j = job_for(data, head, tree)
    result, wire = invoke(j, data, journal)
    assert result["status"] == "PUBLISHED" and result["pr"] == 111 and wire.tip == head
    assert wire.objects == objects and wire.token is False
    assert journal.events[-1]["record"]["phase"] == "COMPLETE"
    assert b"INSTALLATION_FAKE_PRIVATE" not in path.read_bytes()
    new, newhead, newtree, _ = artifact(head, b"changed\n")
    update = job_for(new, newhead, newtree, old=head, pr=111)
    update["id"] = "b" * 32
    wire.job = update
    result, _ = invoke(update, new, journal, wire)
    assert result["head"] == newhead and wire.tip == newhead and not wire.token
    assert (
        sum(method == "POST" and url == p.ROOT + "/pulls" for method, url in wire.calls)
        == 1
    )


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize(
    "route",
    [
        "/app",
        p.ROOT,
        p.ROOT + "/issues/108",
        p.ROOT + "/branches/main",
        "/installation/repositories?per_page=2",
    ],
)
def test_auth_scope_and_source_mismatch_stop_before_ref(store, route, local):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    if local:
        j = homelab_job(j)
    wire = Wire(journal, j)
    wire.mutate = lambda path, value: {} if path == route else value
    with pytest.raises((a.Blocked, KeyError, ValueError, TimeoutError)):
        invoke(j, data, journal, wire)
    assert wire.tip is None and wire.pr_number is None
    assert not any(path == "/graphql" for _, path in wire.calls)


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize(
    "route", [p.ROOT + "/git/blobs", "/graphql", p.ROOT + "/pulls"]
)
def test_lost_response_retains_unknown_and_no_replay(store, route, local):
    journal, path = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    if local:
        j = homelab_job(j)
    wire = Wire(journal, j)
    wire.fail = route
    with pytest.raises((a.Blocked, KeyError, ValueError, TimeoutError)):
        invoke(j, data, journal, wire)
    assert any(e["record"].get("phase") == "UNKNOWN" for e in journal.events)
    before = tuple(wire.calls)
    wire.fail = None
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert tuple(wire.calls) == before
    assert journal.events[-1]["record"]["phase"] != "COMPLETE"
    assert b"FAKE_PRIVATE" not in path.read_bytes()


@pytest.mark.parametrize("local", [False, True])
def test_cas_race_after_observation_is_not_overwritten(store, local):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    if local:
        j = homelab_job(j)
    wire = Wire(journal, j)
    original = wire.exchange

    def race(method, path, body, secret, limit=256 * 1024):
        if path == "/graphql" and body["query"] == p.CAS:
            wire.tip = "f" * 40
        return original(method, path, body, secret, limit)

    wire.exchange = race
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert wire.tip == "f" * 40 and wire.pr_number is None


@pytest.mark.parametrize(
    "changes",
    [
        {"ref": "refs/heads/main"},
        {"ref": "refs/tags/x"},
        {"operation": "merge"},
        {"operation": "force"},
        {"old": "0" * 40},
        {"head": "0" * 40},
        {"expires": 0},
        {"publisher_uid": 0},
        {"signer_uid": 1000},
        {"worker": "worker03"},
        {"approval": "model PASS"},
        {"gates": {}},
        {"force": False},
        {"url": "https://evil.invalid"},
    ],
)
def test_closed_operator_job_and_forbidden_operations(changes):
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    j.update(changes)
    with pytest.raises((a.Blocked, ValueError)):
        p.validate_job(j, int(time.time()))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda raw: raw[:-1],
        lambda raw: b"PACK" + raw,
        lambda raw: raw.replace(
            b'"version":"AP-WP/1"', b'"version":"AP-WP/1","version":"AP-WP/1"'
        ),
        lambda raw: raw.replace(b'"kind":"blob"', b'"kind":"tag"'),
        lambda raw: raw.replace(b'"head":', b'"path":"/etc/shadow","head":'),
        lambda raw: b"x" * (a.MAX_WIRE + 1),
    ],
)
def test_untrusted_artifact_corruption_and_limits(mutation):
    data, head, tree, _ = artifact()
    with pytest.raises((a.Blocked, KeyError, ValueError, TimeoutError)):
        a.validate(mutation(data), head, tree, "a" * 40)


@pytest.mark.parametrize(
    "mode,name",
    [
        (b"120000", b"link"),
        (b"160000", b"module"),
        (b"100644", b".."),
        (b"100644", b".git"),
        (b"100644", b"a/b"),
    ],
)
def test_unsafe_tree_types_and_paths(mode, name):
    with pytest.raises(a.Blocked):
        a.tree(mode + b" " + name + b"\0" + b"a" * 20)


def test_real_export_multidirectory_and_no_hook_execution(tmp_path, monkeypatch):
    from types import SimpleNamespace

    real_stat = a.os.stat

    def admitted_binary(path, *args, **kwargs):
        value = real_stat(path, *args, **kwargs)
        if path == "/usr/bin/git":
            # Synthetic ownership admission only. Actual Git, its output and
            # the untrusted repository are exercised; no host chown or bypass.
            return SimpleNamespace(st_uid=0, st_mode=value.st_mode)
        return value

    monkeypatch.setattr(a.os, "stat", admitted_binary)
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }

    def git(*args):
        return (
            subprocess.check_output(
                ["/usr/bin/git", *args], cwd=repo, env=env, stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )

    git("init")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "a@example.test")
    (repo / "initial").write_text("base")
    git("add", "initial")
    git("commit", "-m", "base")
    parent = git("rev-parse", "HEAD")
    (repo / "src").mkdir()
    (repo / "src/file.py").write_text("source\n")
    git("add", "src/file.py")
    git("commit", "-m", "multi\n\nline")
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    hook = repo / ".git/hooks/pre-commit"
    hook.write_text("#!/bin/sh\nexit 99\n")
    hook.chmod(0o755)
    git("config", "core.fsmonitor", "/must-not-run")
    data, c = a.export(str(repo), head)
    _, _, files, _ = a.validate(data, head, tree, parent)
    assert ("src/file.py", "100644", a.oid("blob", b"source\n")) in files
    assert c["parents"] == [parent]


def test_actual_rs256_in_memory_no_pem_file_or_real_credential():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    token = signer.jwt_for(key, 10, now + 240, now)
    first, second, signature = token.split(b".")
    claims = json.loads(base64.urlsafe_b64decode(second + b"=" * ((-len(second)) % 4)))
    assert claims == {"iat": now - 60, "exp": now + 240, "iss": "10"}
    key.public_key().verify(
        base64.urlsafe_b64decode(signature + b"=" * ((-len(signature)) % 4)),
        first + b"." + second,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_no_generic_routes_or_payloads_even_with_client_handle(store):
    journal, _ = store
    data, head, tree, objects = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    c = p.Client(j, objects, wire)
    c.repository_node = "REPO_NODE"
    for method, path, body in [
        ("PUT", p.ROOT + "/pulls/1/merge", {}),
        ("DELETE", p.ROOT + "/git/refs/heads/main", None),
        ("PATCH", p.ROOT + "/git/refs/" + j["ref"][5:], {"sha": head}),
        ("POST", "/graphql", {"query": "mutation { mergePullRequest }"}),
        ("POST", p.ROOT + "/pulls", {"draft": False}),
        (
            "POST",
            "/graphql",
            {
                "query": p.CAS,
                "variables": {
                    "repository": "REPO_NODE",
                    "updates": [{"name": "refs/heads/main", "force": True}],
                },
            },
        ),
    ]:
        with pytest.raises(a.Blocked):
            c._call(method, path, body)
    assert not wire.calls


def test_cli_dry_run_never_reads_secrets_or_calls_network(monkeypatch, capsys):
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    monkeypatch.setattr(
        p,
        "read_file",
        lambda path, *args, **kwargs: a.encoded(j) if path == "job" else data,
    )
    monkeypatch.setattr(
        io.HTTPS, "exchange", lambda *args, **kwargs: pytest.fail("network")
    )
    monkeypatch.setattr(p, "confinement", lambda *args: pytest.fail("execution"))
    assert p.main(["--job", "job", "--artifact", "artifact"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (
        result["status"] == "DRY_RUN"
        and result["head"] == head
        and result["runtime"] == "LIVE_NO_GO"
    )


def test_journal_real_flock_tamper_and_missing_store_refuse(store):
    journal, path = store
    with pytest.raises((a.Blocked, BlockingIOError)):
        io.Journal(str(path), a.digest(b""))
    journal.append({"phase": "UNKNOWN", "job": "a" * 32})
    path.write_bytes(b"corrupt")
    with pytest.raises(a.Blocked):
        journal.append({"phase": "CONFIRMED"})
    assert journal.poisoned
    with pytest.raises(FileNotFoundError):
        io.Journal(str(path.with_name("absent")), a.digest(b""))


def test_workflow_mutation_is_not_given_workflows_permission(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    wire.mutate = lambda path, v: (
        dict(
            v,
            tree=[
                {
                    "path": ".github/workflows/ci.yml",
                    "mode": "100644",
                    "sha": "f" * 40,
                    "type": "blob",
                }
            ],
        )
        if path.endswith("?recursive=1")
        else v
    )
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert not any(path.endswith("/access_tokens") for _, path in wire.calls)


def test_fixed_tls_peer_cert_headers_and_bounded_no_retry_transport(monkeypatch):
    cert = b"fabricated certificate"
    requests = []

    class Sock:
        def getpeername(self):
            return ("140.82.112.6", 443)

        def getpeercert(self, **kwargs):
            return cert

        def settimeout(self, value):
            assert 0 < value <= 5

        def dup(self):
            return Sock()

        def shutdown(self, *args):
            pass

        def close(self):
            pass

    class Context:
        def load_default_certs(self):
            pass

        def wrap_socket(self, sock, **kwargs):
            assert kwargs == {"server_hostname": "api.github.com"}
            return sock

    class Response:
        status = 200
        data = b'{"ok":true}'
        location = None

        def close(self):
            pass

        def getheaders(self):
            return []

        def getheader(self, name):
            return self.location if name == "Location" else None

        def read1(self, n):
            data, self.data = self.data[:n], self.data[n:]
            return data

    class Connection:
        def __init__(self, host, timeout, context):
            assert host == "api.github.com" and timeout == 5
            self._context = context

        def request(self, *args, **kwargs):
            requests.append((args, kwargs))

        def getresponse(self):
            # http.client may clear .sock when Connection: close is received.
            self.sock = None
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(io.ssl, "SSLContext", lambda *args: Context())
    monkeypatch.setattr(io.socket, "create_connection", lambda *args, **kwargs: Sock())
    monkeypatch.setattr(io.http.client, "HTTPSConnection", Connection)
    transport = io.HTTPS("140.82.112.6", a.digest(cert))
    assert transport.exchange("GET", "/app", None, "JWT_FAKE") == (200, {"ok": True})
    assert requests[0][1]["headers"]["Authorization"] == "Bearer JWT_FAKE"
    with pytest.raises(a.Blocked, match="^publisher_blocked$"):
        io.HTTPS("140.82.112.6", "f" * 64).exchange("GET", "/app", None, "JWT_FAKE")
    assert len(requests) == 1
    assert io.HTTPS.homelab("140.82.112.6").exchange(
        "GET", "/app", None, "JWT_FAKE"
    ) == (200, {"ok": True})
    for payload in (b"x" * 20, b'{"ok":1,"ok":2}', b'{"token":"FAKE_PRIVATE"'):
        Response.data = payload
        with pytest.raises(a.Blocked, match="^publisher_blocked$"):
            transport.exchange("GET", "/app", None, "JWT_FAKE", limit=16)
    Response.data = b"{}"
    Response.location = "https://evil.invalid"
    with pytest.raises(a.Blocked):
        transport.exchange("GET", "/app", None, "JWT_FAKE")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "::1",
        "::ffff:140.82.112.6",
        "api.github.com",
        "169.254.169.254",
        "224.0.0.1",
    ],
)
def test_private_loopback_dns_ipv6_and_metadata_destinations_block(address):
    with pytest.raises((a.Blocked, ValueError)):
        io.HTTPS(address, "f" * 64)


def test_secure_file_walk_refuses_world_writable_ancestors(tmp_path):
    f = tmp_path / "file"
    f.write_bytes(b"FAKE_PRIVATE")
    with pytest.raises(a.Blocked):
        io.read_file(str(f), os.getuid(), 100, writable_parent=True)


@pytest.mark.parametrize(
    "fault", ["symlink", "hardlink", "writable", "oversize", "fifo", "owner"]
)
def test_descriptor_file_leaf_negative_cases(tmp_path, monkeypatch, fault):
    import stat
    from types import SimpleNamespace

    f = tmp_path / "file"
    f.write_bytes(b"fixture")
    real = io.os.fstat

    def safe_parents(fd):
        m = real(fd)
        if not stat.S_ISDIR(m.st_mode):
            return m
        # Synthetic trusted ancestors; leaf descriptor checks remain real.
        return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)

    monkeypatch.setattr(io.os, "fstat", safe_parents)
    if fault == "symlink":
        link = tmp_path / "link"
        link.symlink_to(f)
        f = link
    elif fault == "hardlink":
        (tmp_path / "link").hardlink_to(f)
    elif fault == "writable":
        f.chmod(0o666)
    elif fault == "fifo":
        f.unlink()
        os.mkfifo(f)
    owner = 0 if fault == "owner" else os.getuid()
    limit = 1 if fault == "oversize" else 100
    with pytest.raises((a.Blocked, OSError)):
        io.read_file(str(f), owner, limit, writable_parent=True)


@pytest.mark.parametrize(
    "defect", ["expired", "digest", "actor", "verdict", "scope", "method"]
)
def test_operator_receipts_cannot_be_model_text_or_rotated_identity(
    monkeypatch, defect
):
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    now = int(time.time())
    value = {
        "repo_id": p.REPO_ID,
        "ref": j["ref"],
        "head": head,
        "observed_at": now,
        "expires": now + 200,
        "verdict": "VERIFIED_BY_OPERATOR",
        "method": "independent_negative_controls",
        "app_id": j["app_id"],
        "installation_id": j["installation_id"],
        "worker": j["worker"],
        "job": j["id"],
    }
    facts = {}
    for k in j["gates"]:
        facts[k] = dict(
            value,
            method="independent_admin_observation"
            if k == "main_app_merge_denied"
            else "independent_negative_controls",
        )
        j["gates"][k] = a.digest(a.encoded(facts[k]))
    monkeypatch.setattr(p, "read_file", lambda *args, **kwargs: a.encoded(facts))
    p.receipts(j)
    first = next(iter(facts))
    if defect == "expired":
        facts[first]["expires"] = now - 1
    elif defect == "actor":
        facts[first]["app_id"] += 1
    elif defect == "scope":
        facts[first]["head"] = "f" * 40
    elif defect == "verdict":
        facts[first]["verdict"] = "model PASS"
    elif defect == "method":
        facts[first]["method"] = "Issue body"
    else:
        facts[first]["observed_at"] -= 1
    if defect != "digest":
        j["gates"][first] = a.digest(a.encoded(facts[first]))
    with pytest.raises(a.Blocked):
        p.receipts(j)


def test_signer_and_publisher_confinement_refuses_current_contributor_identity():
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    for role in ("publisher", "signer"):
        with pytest.raises((a.Blocked, OSError, KeyError)):
            p.confinement(j, role)


def test_job_worker_app_installation_cannot_be_swapped():
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    j["worker"] = "worker02"
    with pytest.raises(a.Blocked):
        p.validate_job(j, int(time.time()))


def test_signed_and_non_utc_commits_are_rejected_not_rewritten():
    data, head, tree, objects = artifact()
    raw = objects[head][1]
    for value in (
        raw.replace(b"author ", b"gpgsig fake\nauthor ", 1),
        raw.replace(b"+0000", b"+0100"),
    ):
        with pytest.raises(a.Blocked):
            a.commit(value)


def test_deployment_has_no_enablement_or_worker_key_access():
    root = Path(__file__).resolve().parents[1] / "packaging/worker-publisher"
    publisher = (root / "ap-worker-publisher.service").read_text()
    signed = (root / "ap-worker-publisher-signer.service").read_text()
    for unit in (publisher, signed):
        assert "\n[Install]" not in unit and "Restart=no" in unit
        assert "NoNewPrivileges=yes" in unit and "CapabilityBoundingSet=\n" in unit
        assert "AppArmorProfile=" in unit and "LimitCORE=0" in unit
        assert "ProtectHome=yes" in unit and "TimeoutStartSec=" in unit
    assert [line for line in signed.splitlines() if line.startswith("TasksMax=")] == [
        "TasksMax=4"
    ]
    assert "LoadCredential=app-key:" not in publisher
    assert "LoadCredential=app-key:" in signed and "PrivateNetwork=yes" in signed
    assert "IPAddressDeny=any" in publisher
    assert "User=ap-publisher\n" in publisher and "User=ap-publisher-signer\n" in signed


def test_cli_execute_complete_flow_without_any_real_credentials(
    store, monkeypatch, capsys
):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    original = a.encoded(j)
    wire = Wire(journal, j)

    class Session:
        def __getattr__(self, name):
            return getattr(journal, name)

        def close(self):
            pass

    seen = []

    def read(path, *args, **kwargs):
        seen.append(path)
        if path == "job":
            return original
        if path == "artifact":
            return data
        assert path.endswith("/app-jwt")
        return a.encoded({"job_sha256": a.digest(original), "jwt": "JWT_FAKE"})

    monkeypatch.setattr(p, "read_file", read)
    monkeypatch.setattr(p, "confinement", lambda *args: None)
    monkeypatch.setattr(p, "receipts", lambda *args: None)
    monkeypatch.setattr(p, "Journal", lambda *args: Session())
    monkeypatch.setattr(p, "HTTPS", lambda *args: wire)
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY",
        "/run/credentials/ap-worker-publisher.service",
    )
    assert p.main(["--job", "job", "--artifact", "artifact", "--execute"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["head"] == head and "FAKE_PRIVATE" not in output
    assert not any("app-key" in path for path in seen)
    assert wire.token is False and wire.pr_number == 111


@pytest.mark.parametrize("interrupted", [False, True])
def test_signer_one_shot_binds_job_and_keeps_key_out_of_publisher(
    store, tmp_path, monkeypatch, capsys, interrupted
):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    original = a.encoded(j)

    class Session:
        def __getattr__(self, name):
            return getattr(journal, name)

        def close(self):
            pass

    seen = []

    def read(path, *args, **kwargs):
        seen.append(path)
        if path == "/etc/ap-publisher/job.json":
            return original
        assert path == "/run/credentials/ap-worker-publisher-signer.service/app-key"
        return b"FABRICATED_KEY_NOT_A_PEM"

    monkeypatch.setattr(signer, "read_file", read)
    monkeypatch.setattr(signer, "confinement", lambda *args: None)
    monkeypatch.setattr(signer, "receipts", lambda *args: None)
    monkeypatch.setattr(signer, "Journal", lambda *args: Session())
    monkeypatch.setattr(
        signer.serialization, "load_pem_private_key", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(signer, "jwt_for", lambda *args: b"JWT_FAKE")
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY",
        "/run/credentials/ap-worker-publisher-signer.service",
    )
    real = signer.os.open
    output = tmp_path / "app-jwt"
    monkeypatch.setattr(signer.os.path, "lexists", lambda _: output.exists())

    def open_private(path, *args, **kwargs):
        return real(
            str(output) if path == "/run/ap-publisher-signer/app-jwt" else path,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(signer.os, "open", open_private)
    real_fsync = signer.os.fsync

    def sync(fd):
        if (
            interrupted
            and output.exists()
            and os.fstat(fd).st_ino == output.stat().st_ino
        ):
            raise OSError("FABRICATED interruption")
        return real_fsync(fd)

    monkeypatch.setattr(signer.os, "fsync", sync)
    assert signer.main() == (1 if interrupted else 0)
    if interrupted:
        assert journal.events[-1]["record"]["phase"] == "UNKNOWN"
    bundle = a.decode(output.read_bytes())
    assert bundle == {"job_sha256": a.digest(original), "jwt": "JWT_FAKE"}
    assert output.stat().st_mode & 0o777 == 0o400
    count = len(seen)
    if not interrupted:
        # Only this exact fabricated fixture: model separately reconciled cleanup.
        # Restart must still be denied by the journal even with no output present.
        output.unlink()
    assert signer.main() == 1
    assert len(seen) == count + 1  # replay/stale state stops before another key read
    assert "JWT_FAKE" not in capsys.readouterr().out


def test_ordinary_lockfiles_are_data_in_new_real_tree_profile():
    blob = a.oid("blob", b"lock data")
    assert a.tree(b"100644 uv.lock\0" + bytes.fromhex(blob))[0]["path"] == "uv.lock"


def test_approved_artifact_digest_is_checked_even_for_direct_engine_calls(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    with pytest.raises(a.Blocked):
        invoke(j, data + b" ", journal, wire)
    assert not wire.calls and not journal.events


def test_repository_node_identity_cannot_redirect_graphql_to_another_repository(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    wire.mutate = lambda path, value: (
        dict(value, node_id="FOREIGN_NODE") if path == p.ROOT else value
    )
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert not any(method == "POST" for method, _ in wire.calls)


def test_exporter_rejects_unadmitted_binary_owner_without_launch(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        a.os,
        "stat",
        lambda *args, **kwargs: SimpleNamespace(st_uid=65534, st_mode=0o100755),
    )
    monkeypatch.setattr(
        a.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("launch")
    )
    with pytest.raises(a.Blocked):
        a.export("/not-opened", "a" * 40)


def test_deployment_examples_have_no_implicit_admission():
    root = Path(__file__).resolve().parents[1] / "packaging/worker-publisher"
    example = a.decode((root / "job.example.json").read_bytes())
    with pytest.raises((a.Blocked, ValueError)):
        p.validate_job(example, int(time.time()))
    receipts = a.decode((root / "receipts.example.json").read_bytes())
    assert all(
        v["verdict"] == "NOT_VERIFIED" and v["expires"] == 0 for v in receipts.values()
    )


def test_exponential_shared_tree_expansion_is_bounded():
    _, _, _, original = artifact()
    values = {}
    raw = b""
    child = a.oid("tree", raw)
    values[child] = ("tree", raw)
    for _ in range(13):
        raw = b"40000 a\0" + bytes.fromhex(child) + b"40000 b\0" + bytes.fromhex(child)
        child = a.oid("tree", raw)
        values[child] = ("tree", raw)
    commit_raw = next(b for k, b in original.values() if k == "commit")
    _, _, tail = commit_raw.partition(b"\n")
    commit_raw = b"tree " + child.encode() + b"\n" + tail
    head = a.oid("commit", commit_raw)
    values[head] = ("commit", commit_raw)
    data = a.encoded(
        {
            "version": a.VERSION,
            "head": head,
            "objects": [
                {"oid": s, "kind": k, "data": base64.b64encode(b).decode()}
                for s, (k, b) in values.items()
            ],
        }
    )
    with pytest.raises(a.Blocked):
        a.validate(data, head, child, "a" * 40)


def test_failed_child_pin_never_uses_numeric_pid_signals(tmp_path, monkeypatch):
    real = a.os.pidfd_open

    def pin(pid, flags):
        if pid != os.getpid():
            raise OSError("fabricated missing child pin")
        return real(pid, flags)

    monkeypatch.setattr(a.os, "pidfd_open", pin)
    monkeypatch.setattr(a.os, "kill", lambda *args: pytest.fail("numeric signal"))
    monkeypatch.setattr(
        a.signal, "pidfd_send_signal", lambda *args: pytest.fail("unknown pin")
    )
    with pytest.raises(OSError):
        a._git(str(tmp_path), ["--version"], 4096)


def test_realistic_bigint_issue_identity_is_not_truncated(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    j["issue_id"] = 6378023250
    p.validate_job(j, int(time.time()))
    result, wire = invoke(j, data, journal)
    assert result["status"] == "PUBLISHED" and wire.pr_number == 111


def test_native_issue_inventory_rejects_hidden_conflicting_pr(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    real = wire.exchange

    def conflict(method, path, body, secret, limit=256 * 1024):
        status, value = real(method, path, body, secret, limit)
        if path == "/graphql" and body["query"] == p.INVENTORY:
            value["data"]["repository"]["issue"]["closedByPullRequestsReferences"][
                "nodes"
            ] = [{"number": 999}]
        return status, value

    wire.exchange = conflict
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert wire.tip is None and wire.pr_number is None
    assert not any(path.endswith("/git/blobs") for _, path in wire.calls)


@pytest.mark.parametrize(
    "namespace",
    [None, "", "/fabricated", "/run/credentials/ap-worker-publisher.service"],
)
def test_signer_wrong_namespace_blocks_before_journal(
    store, monkeypatch, capsys, namespace
):
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    monkeypatch.setattr(signer, "read_file", lambda *args, **kwargs: a.encoded(j))
    monkeypatch.setattr(signer, "confinement", lambda *a: None)
    monkeypatch.setattr(signer, "receipts", lambda *a: None)
    monkeypatch.setattr(signer, "Journal", lambda *a: pytest.fail("journal claim"))
    if namespace is None:
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    else:
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", namespace)
    assert signer.main() == 1
    assert capsys.readouterr().out == '{"status":"BLOCKED","code":"signer_stopped"}\n'


def test_stale_handoff_blocks_before_claim_or_key_read(store, monkeypatch, capsys):
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    monkeypatch.setattr(signer, "read_file", lambda *args, **kwargs: a.encoded(j))
    monkeypatch.setattr(signer, "confinement", lambda *args: None)
    monkeypatch.setattr(signer, "receipts", lambda *args: None)
    monkeypatch.setattr(signer, "Journal", lambda *args: pytest.fail("journal claim"))
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY", "/run/credentials/ap-worker-publisher-signer.service"
    )
    monkeypatch.setattr(signer.os.path, "lexists", lambda _: True)
    assert signer.main() == 1
    assert "signer_stopped" in capsys.readouterr().out


@pytest.mark.parametrize("offset", [0, -1, 301])
def test_signer_jwt_lifetime_is_bounded(offset):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(a.Blocked):
        signer.jwt_for(key, 10, 1000 + offset, 1000)


def test_missing_signer_credential_retains_unknown_and_blocks_restart(
    store, monkeypatch, capsys
):
    journal, _ = store
    data, head, tree, _ = artifact()
    job = job_for(data, head, tree)
    seen = []

    def read(path, *args, **kwargs):
        if path == "/etc/ap-publisher/job.json":
            return a.encoded(job)
        seen.append(path)
        raise FileNotFoundError

    class Session:
        def __getattr__(self, name):
            return getattr(journal, name)

        def close(self):
            pass

    monkeypatch.setattr(signer, "read_file", read)
    monkeypatch.setattr(signer, "confinement", lambda *args: None)
    monkeypatch.setattr(signer, "receipts", lambda *args: None)
    monkeypatch.setattr(signer, "Journal", lambda *args: Session())
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY", "/run/credentials/ap-worker-publisher-signer.service"
    )
    monkeypatch.setattr(signer.os.path, "lexists", lambda _: False)
    assert signer.main() == 1
    assert journal.events[-1]["record"]["phase"] == "UNKNOWN"
    assert signer.main() == 1
    assert seen == ["/run/credentials/ap-worker-publisher-signer.service/app-key"]
    assert "signer_stopped" in capsys.readouterr().out


# --- PUB-02 pilot-readiness regressions (#108, F-01/F-03/F-04/F-05) -----------

UNDEFINED_ID = 0xFFFFFFFF


def acl(*entries):
    """Linux posix_acl_xattr: le32 version 2, then (le16 tag, le16 perm, le32 id)."""
    return (2).to_bytes(4, "little") + b"".join(
        t.to_bytes(2, "little") + perm.to_bytes(2, "little") + i.to_bytes(4, "little")
        for t, perm, i in entries
    )


def systemd_acl(uid, granted):
    # Shape written by systemd 257 fd_add_uid_acl_permission() + calc mask.
    return acl(
        (io.ACL_USER_OBJ, granted, UNDEFINED_ID),
        (io.ACL_USER, granted, uid),
        (io.ACL_GROUP_OBJ, 0, UNDEFINED_ID),
        (io.ACL_MASK, granted, UNDEFINED_ID),
        (io.ACL_OTHER, 0, UNDEFINED_ID),
    )


def credential_layout(tmp_path, monkeypatch, case="systemd_acl"):
    """Real descriptor walk/read; only ownership, modes and the ACL are synthetic.

    An unprivileged test cannot create root-owned files or tmpfs ACLs, so fstat
    metadata and getxattr are injected per inode; open/O_NOFOLLOW/read are real.
    """
    uid = os.getuid()
    assert uid != 0
    unit = tmp_path / "ap-worker-publisher.service"
    unit.mkdir()
    leaf = unit / "app-jwt"
    leaf.write_bytes(b'{"fixture":"FAKE_PRIVATE_JWT"}')
    unit_ino = unit.stat().st_ino
    # Default: systemd 257 on tmpfs (noswap) with POSIX ACL support.
    d = {"uid": 0, "mode": 0o550, "acl": systemd_acl(uid, 0o5)}
    f = {"uid": 0, "mode": 0o440, "acl": systemd_acl(uid, 0o4)}
    no_acl = OSError(errno.ENODATA, "no ACL")
    if case == "ownership_fallback":  # ramfs: chown to the unit user, no ACL
        d, f = (
            {"uid": uid, "mode": 0o500, "acl": no_acl},
            {
                "uid": uid,
                "mode": 0o400,
                "acl": OSError(errno.EOPNOTSUPP, "unsupported"),
            },
        )
    elif case == "root_no_acl":
        f = {"uid": 0, "mode": 0o440, "acl": no_acl}
    elif case == "extra_named_user":
        f["acl"] = f["acl"] + acl((io.ACL_USER, 4, uid + 1))[4:]
    elif case == "named_group":
        f["acl"] = f["acl"] + acl((io.ACL_GROUP, 4, 4242))[4:]
    elif case == "named_group_without_access":  # not systemd's exact structure
        f["acl"] = f["acl"] + acl((io.ACL_GROUP, 0, 4242))[4:]
    elif case == "acl_without_mask":
        f["acl"] = acl(
            (io.ACL_USER_OBJ, 4, UNDEFINED_ID),
            (io.ACL_USER, 4, uid),
            (io.ACL_GROUP_OBJ, 0, UNDEFINED_ID),
            (io.ACL_OTHER, 0, UNDEFINED_ID),
        )
    elif case == "foreign_user":
        f["acl"] = systemd_acl(uid + 1, 0o4)
    elif case == "mask_write":
        f["acl"] = f["acl"].replace(
            (io.ACL_MASK).to_bytes(2, "little") + (4).to_bytes(2, "little"),
            (io.ACL_MASK).to_bytes(2, "little") + (6).to_bytes(2, "little"),
        )
    elif case == "group_obj_read":
        f["acl"] = f["acl"].replace(
            (io.ACL_GROUP_OBJ).to_bytes(2, "little") + (0).to_bytes(2, "little"),
            (io.ACL_GROUP_OBJ).to_bytes(2, "little") + (4).to_bytes(2, "little"),
        )
    elif case == "user_obj_write":
        f["acl"] = f["acl"].replace(
            (io.ACL_USER_OBJ).to_bytes(2, "little") + (4).to_bytes(2, "little"),
            (io.ACL_USER_OBJ).to_bytes(2, "little") + (6).to_bytes(2, "little"),
        )
    elif case == "other_read":
        f["mode"] = 0o444
    elif case == "writable_leaf":
        f["mode"] = 0o640
    elif case == "self_owned_group_readable":
        f = {"uid": uid, "mode": 0o440, "acl": no_acl}
    elif case == "dir_writable":
        d["mode"] = 0o750
    elif case == "dir_setgid":
        d["mode"] = 0o2550
    elif case == "dir_foreign_owner":
        d = {"uid": uid + 1, "mode": 0o500, "acl": no_acl}
    elif case == "dir_other_access":
        d["mode"] = 0o551
    elif case == "acl_unreadable":
        f["acl"] = OSError(errno.EACCES, "denied")
    elif case == "acl_bad_version":
        f["acl"] = (3).to_bytes(4, "little") + f["acl"][4:]
    elif case == "acl_truncated":
        f["acl"] = f["acl"][:-1]
    elif case == "hardlink":
        (tmp_path / "second-name").hardlink_to(leaf)
    elif case == "symlink":
        target = tmp_path / "elsewhere"
        target.write_bytes(b"{}")
        leaf.unlink()
        leaf.symlink_to(target)
    real_fstat = io.os.fstat

    def meta(m, values, kind):
        return SimpleNamespace(
            st_dev=m.st_dev,
            st_ino=m.st_ino,
            st_uid=values["uid"],
            st_gid=0,
            st_mode=kind | values["mode"],
            st_nlink=m.st_nlink,
            st_size=m.st_size,
            st_mtime_ns=m.st_mtime_ns,
            st_ctime_ns=m.st_ctime_ns,
        )

    def fstat(fd):
        m = real_fstat(fd)
        if stat.S_ISDIR(m.st_mode):
            if m.st_ino == unit_ino:
                return meta(m, d, stat.S_IFDIR)
            # Synthetic trusted ancestors (/, /run, /run/credentials analogues).
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        return meta(m, f, stat.S_IFREG)

    def getxattr(fd, name):
        assert name == "system.posix_acl_access"
        value = d["acl"] if stat.S_ISDIR(real_fstat(fd).st_mode) else f["acl"]
        if isinstance(value, OSError):
            raise value
        return value

    monkeypatch.setattr(io.os, "fstat", fstat)
    monkeypatch.setattr(io.os, "getxattr", getxattr)
    return str(leaf), uid


@pytest.mark.parametrize("case", ["systemd_acl", "ownership_fallback"])
def test_systemd_257_credential_layouts_are_read(tmp_path, monkeypatch, case):
    path, uid = credential_layout(tmp_path, monkeypatch, case)
    assert io.read_file(path, uid, 16384, credential=True) == (
        b'{"fixture":"FAKE_PRIVATE_JWT"}'
    )


def test_legacy_private_owner_check_rejected_the_real_systemd_layout(
    tmp_path, monkeypatch
):
    # F-01 evidence: the pre-fix call shape could never read a systemd 257
    # tmpfs+ACL credential (root-owned 0440 leaf, 0550 directory).
    path, uid = credential_layout(tmp_path, monkeypatch)
    with pytest.raises(a.Blocked):
        io.read_file(path, uid, 16384, writable_parent=True, private=True)


@pytest.mark.parametrize(
    "case",
    [
        "root_no_acl",
        "extra_named_user",
        "named_group",
        "named_group_without_access",
        "acl_without_mask",
        "foreign_user",
        "mask_write",
        "group_obj_read",
        "user_obj_write",
        "other_read",
        "writable_leaf",
        "self_owned_group_readable",
        "dir_writable",
        "dir_setgid",
        "dir_foreign_owner",
        "dir_other_access",
        "acl_unreadable",
        "acl_bad_version",
        "acl_truncated",
        "hardlink",
        "symlink",
    ],
)
def test_credential_layout_negative_cases(tmp_path, monkeypatch, case):
    path, uid = credential_layout(tmp_path, monkeypatch, case)
    with pytest.raises((a.Blocked, OSError)):
        io.read_file(path, uid, 16384, credential=True)


@pytest.mark.parametrize(
    "relaxation",
    [{"writable_parent": True}, {"private": True}, {"allow_empty": True}],
)
def test_credential_mode_cannot_be_combined_with_other_relaxations(
    tmp_path, monkeypatch, relaxation
):
    path, uid = credential_layout(tmp_path, monkeypatch)
    with pytest.raises(a.Blocked):
        io.read_file(path, uid, 16384, credential=True, **relaxation)


def test_both_roles_read_only_their_credential_through_systemd_policy(
    store, tmp_path, monkeypatch, capsys
):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    original = a.encoded(j)
    calls = []

    class Session:
        def __getattr__(self, name):
            return getattr(journal, name)

        def close(self):
            pass

    def read(path, *args, **kwargs):
        calls.append((path, kwargs))
        if path in ("job", "/etc/ap-publisher/job.json"):
            return original
        if path == "artifact":
            return data
        if path.endswith("/app-key"):
            return b"FABRICATED_KEY_NOT_A_PEM"
        return a.encoded({"job_sha256": a.digest(original), "jwt": "JWT_FAKE"})

    for module in (p, signer):
        monkeypatch.setattr(module, "read_file", read)
        monkeypatch.setattr(module, "confinement", lambda *args: None)
        monkeypatch.setattr(module, "receipts", lambda *args: None)
        monkeypatch.setattr(module, "Journal", lambda *args: Session())
    monkeypatch.setattr(p, "HTTPS", lambda *args: Wire(journal, j))
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY", "/run/credentials/ap-worker-publisher.service"
    )
    assert p.main(["--job", "job", "--artifact", "artifact", "--execute"]) == 0
    assert [c for c in calls if c[0].endswith("/app-jwt")] == [
        (
            "/run/credentials/ap-worker-publisher.service/app-jwt",
            {"credential": True},
        )
    ]
    assert not any(c[0].endswith("/app-key") for c in calls)
    signer_path = tmp_path / "signer-journal"
    signer_path.write_bytes(b"")
    signer_path.chmod(0o600)
    signer_journal = io.Journal(str(signer_path), a.digest(b""))

    class SignerSession:
        def __getattr__(self, name):
            return getattr(signer_journal, name)

        def close(self):
            signer_journal.close()

    def no_output(*args, **kwargs):
        raise OSError("FABRICATED stop before any JWT output")

    monkeypatch.setattr(signer, "Journal", lambda *args: SignerSession())
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY", "/run/credentials/ap-worker-publisher-signer.service"
    )
    monkeypatch.setattr(signer.os.path, "lexists", lambda _: False)
    monkeypatch.setattr(
        signer.serialization, "load_pem_private_key", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(signer, "jwt_for", lambda *args: b"JWT_FAKE")
    monkeypatch.setattr(signer.os, "open", no_output)
    calls.clear()
    assert signer.main() == 1  # output write is stubbed to fail after the key read
    assert signer_journal.events[-1]["record"]["phase"] == "UNKNOWN"
    assert (
        "/run/credentials/ap-worker-publisher-signer.service/app-key",
        {"credential": True},
    ) in calls
    assert "FAKE" not in capsys.readouterr().out.replace("signer_stopped", "")


def test_pr_enumeration_is_bounded_to_the_exact_head_branch(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    result, wire = invoke(j, data, journal)
    assert result["status"] == "PUBLISHED"
    listings = {path for _, path in wire.calls if "/pulls?" in path}
    assert listings == {
        p.ROOT
        + "/pulls?state=all&head=TechTradeExpress:feature/issue-108-fixture&per_page=2"
    }
    assert not any("per_page=100" in path for _, path in wire.calls)


@pytest.mark.parametrize("defect", ["prior_closed_pr", "foreign_head", "two_prs"])
def test_head_listing_conflicts_block_before_any_token(store, defect):
    journal, path = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)

    def listing(route, value):
        if route != p.head_pulls(j):
            return value
        prior = dict(wire.pr(), number=7, state="closed", draft=False)
        if defect == "foreign_head":
            prior["head"] = dict(prior["head"], ref="feature/issue-108-other")
        return [prior, prior] if defect == "two_prs" else [prior]

    wire.mutate = listing
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert not any(route.endswith("/access_tokens") for _, route in wire.calls)
    assert path.read_bytes() == b"" and not journal.events


def large_base_artifact(count=300):
    """Full-tree candidate: `count` unchanged base blobs plus one new file."""
    values, docs = {}, []
    for n in range(count):
        text = f"unchanged base document {n}\n".encode()
        s = a.oid("blob", text)
        values[s] = ("blob", text)
        docs.append((f"d{n:04d}.md", s))
    docs_raw = b"".join(
        b"100644 " + name.encode() + b"\0" + bytes.fromhex(s) for name, s in docs
    )
    docs_sha = a.oid("tree", docs_raw)
    values[docs_sha] = ("tree", docs_raw)
    pilot = b"supervised pilot change\n"
    pilot_sha = a.oid("blob", pilot)
    values[pilot_sha] = ("blob", pilot)
    root_raw = (
        b"40000 docs\0"
        + bytes.fromhex(docs_sha)
        + b"100644 pilot.md\0"
        + bytes.fromhex(pilot_sha)
    )
    root = a.oid("tree", root_raw)
    values[root] = ("tree", root_raw)
    payload = (
        f"tree {root}\nparent {'a' * 40}\n"
        "author Fixture <a@example.test> 1 +0000\n"
        "committer Fixture <a@example.test> 1 +0000\n\nPilot\n"
    ).encode()
    head = a.oid("commit", payload)
    values[head] = ("commit", payload)
    data = a.encoded(
        {
            "version": a.VERSION,
            "head": head,
            "objects": [
                {"oid": s, "kind": k, "data": base64.b64encode(b).decode()}
                for s, (k, b) in values.items()
            ],
        }
    )
    base_listing = [
        {"path": "docs", "mode": "040000", "type": "tree", "sha": docs_sha}
    ] + [
        {"path": "docs/" + name, "mode": "100644", "type": "blob", "sha": s}
        for name, s in docs
    ]
    return data, head, root, base_listing, {pilot_sha, root, head}


def test_base_tree_objects_are_reused_without_bulk_readback(store, tmp_path):
    # F-04: 340-object main tree => ~340 sequential TLS GETs (~0.3 s each,
    # measured 2026-11-17) inside one 300 s budget. Only new objects are read.
    journal, _ = store
    totals = {}
    for count in (5, 300):
        if count == 300:  # fresh store: same ref/Issue cannot be created twice
            fresh = tmp_path / "journal-300"
            fresh.write_bytes(b"")
            fresh.chmod(0o600)
            journal = io.Journal(str(fresh), a.digest(b""))
        data, head, root, listing, new = large_base_artifact(count)
        j = job_for(data, head, root)
        wire = Wire(journal, j)
        wire.mutate = lambda route, value, listing=listing: (
            dict(value, tree=listing) if route.endswith("?recursive=1") else value
        )
        result, wire = invoke(j, data, journal, wire)
        assert result["status"] == "PUBLISHED" and set(wire.objects) == new
        object_gets = [
            route
            for method, route in wire.calls
            if method == "GET"
            and re.search(r"/git/(blobs|trees|commits)/[0-9a-f]{40}$", route)
            and not route.endswith("/git/commits/" + "a" * 40)
        ]
        # Each new object: one readback after upload, one before the ref CAS.
        assert sorted(object_gets) == sorted(
            p.ROOT + "/git/" + wire.objects[s][0] + "s/" + s
            for s in new
            for _ in (0, 1)
        )
        totals[count] = len(wire.calls)
        if count == 300:
            journal.close()
    assert totals[5] == totals[300]  # independent of unchanged base objects


def test_truncated_base_listing_cannot_be_used_to_skip_readback(store):
    journal, _ = store
    data, head, root, listing, _ = large_base_artifact(5)
    j = job_for(data, head, root)
    wire = Wire(journal, j)
    wire.mutate = lambda route, value: (
        dict(value, tree=listing, truncated=True)
        if route.endswith("?recursive=1")
        else value
    )
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert not any(route.endswith("/access_tokens") for _, route in wire.calls)


def test_read_only_admission_failure_leaves_journal_untouched_then_new_job_runs(
    store,
):
    # F-05: before the fix, any read-only mismatch after CLAIM stuck the store.
    journal, path = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    wire.mutate = lambda route, value: (
        dict(value, events=["pull_request"]) if route == "/app" else value
    )
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert path.read_bytes() == b"" and not journal.events and not wire.token
    retry = dict(j, id="c" * 32)
    result, wire = invoke(retry, data, journal)
    assert result["status"] == "PUBLISHED"
    phases = [
        (e["record"]["phase"], e["record"].get("operation")) for e in journal.events
    ]
    assert phases[:3] == [("CLAIM", None), ("UNKNOWN", "mint"), ("CONFIRMED", "mint")]
    assert all(e["record"]["job"] == "c" * 32 for e in journal.events)


def test_completed_job_replay_makes_no_network_call(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    _, wire = invoke(j, data, journal)
    before = list(wire.calls)
    with pytest.raises(a.Blocked):
        invoke(j, data, journal, wire)
    assert wire.calls == before


@pytest.mark.parametrize(
    "fault, status",
    [("pre_claim_read", "BLOCKED"), ("lost_mint_reply", "UNKNOWN_NEEDS_HUMAN")],
)
def test_cli_status_distinguishes_untouched_journal_from_needs_reconciliation(
    store, monkeypatch, capsys, fault, status
):
    journal, path = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    original = a.encoded(j)
    wire = Wire(journal, j)
    if fault == "pre_claim_read":
        wire.mutate = lambda route, value: {} if route == p.ROOT else value
    else:
        wire.fail = f"/app/installations/{j['installation_id']}/access_tokens"

    configure_publisher_cli(monkeypatch, original, data, journal, wire)
    assert p.main(["--job", "job", "--artifact", "artifact", "--execute"]) == 1
    out = capsys.readouterr().out
    assert json.loads(out)["status"] == status and "FAKE" not in out
    assert (path.read_bytes() == b"") is (status == "BLOCKED")


def configure_publisher_cli(monkeypatch, original, data, journal, wire):
    class Session:
        def __getattr__(self, name):
            return getattr(journal, name)

        def close(self):
            pass

    def read(route, *args, **kwargs):
        if route == "job":
            return original
        if route == "artifact":
            return data
        return a.encoded({"job_sha256": a.digest(original), "jwt": "JWT_FAKE"})

    monkeypatch.setattr(p, "read_file", read)
    monkeypatch.setattr(p, "confinement", lambda *args: None)
    monkeypatch.setattr(p, "receipts", lambda *args: None)
    monkeypatch.setattr(p, "Journal", lambda *args: Session())
    monkeypatch.setattr(p, "HTTPS", lambda *args: wire)
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY", "/run/credentials/ap-worker-publisher.service"
    )


@pytest.mark.parametrize(
    "fault,stage,reason",
    [
        ("post_disconnect", "object_post", "transport_error"),
        ("post_timeout", "object_post", "timeout"),
        ("post_malformed_wire", "object_post_response", "invalid_response"),
        ("post_status", "object_post_response", "unexpected_status"),
        ("post_shape", "object_post_response", "invalid_response"),
        ("post_sha", "object_post_response", "object_sha_mismatch"),
        ("get_disconnect", "object_readback", "transport_error"),
        ("get_timeout", "object_readback", "timeout"),
        ("get_shape", "object_readback", "invalid_response"),
        ("get_sha", "object_readback", "object_sha_mismatch"),
        ("get_content", "object_readback", "object_content_mismatch"),
        ("revoke_lost", "token_revoke", "transport_error"),
        ("post_and_revoke_lost", "object_post", "transport_error"),
    ],
)
def test_cli_classifies_failed_publication_without_replaying(
    store,
    monkeypatch,
    capsys,
    fault,
    stage,
    reason,
):
    journal, path = store
    data, head, tree, _ = artifact()
    job = job_for(data, head, tree)
    wire = Wire(journal, job)
    exchange = wire.exchange

    def faulty(method, route, body, secret, limit=256 * 1024):
        status, value = exchange(method, route, body, secret, limit)
        if method == "DELETE" and fault in {"revoke_lost", "post_and_revoke_lost"}:
            raise ConnectionResetError("FAKE_PRIVATE revoke reply")
        is_post = route == p.ROOT + "/git/blobs"
        is_readback = route.startswith(p.ROOT + "/git/blobs/")
        if (is_post and fault.startswith("post")) or (
            is_readback and fault.startswith("get")
        ):
            if fault.endswith("disconnect") or fault == "post_and_revoke_lost":
                raise ConnectionResetError("FAKE_PRIVATE response lost")
            if fault.endswith("timeout"):
                raise TimeoutError("FAKE_PRIVATE timeout")
            if fault.endswith("wire"):
                raise io.ExchangeFailure(io.FailureReason.RESPONSE)
            if fault.endswith("shape"):
                return status, {"secret": "FAKE_PRIVATE_RESPONSE"}
            if fault.endswith("status"):
                return 200, value
            if fault.endswith("sha"):
                return status, dict(value, sha="f" * 40)
            if fault.endswith("content"):
                return status, dict(value, content="d3Jvbmc=")
        return status, value

    wire.exchange = faulty
    configure_publisher_cli(monkeypatch, a.encoded(job), data, journal, wire)
    args = ["--job", "job", "--artifact", "artifact", "--execute"]
    assert p.main(args) == 1
    output = capsys.readouterr().out
    expected = {
        "status": "UNKNOWN_NEEDS_HUMAN",
        "code": "publisher_stopped",
        "runtime": "LIVE_NO_GO",
        "failure": {"stage": stage, "reason": reason},
    }
    if fault == "post_and_revoke_lost":
        expected["cleanup_failure"] = {
            "stage": "token_revoke",
            "reason": "transport_error",
        }
    assert json.loads(output) == expected
    assert "FAKE" not in output and b"FAKE" not in path.read_bytes()
    records = [
        (e["record"]["phase"], e["record"].get("operation")) for e in journal.events
    ]
    assert ("COMPLETE", None) not in records
    assert [call for call in wire.calls if call[0] == "DELETE"] == [
        ("DELETE", "/installation/token")
    ]
    if fault != "revoke_lost":
        assert wire.tip is None and wire.pr_number is None
        assert records[:5] == [
            ("CLAIM", None),
            ("UNKNOWN", "mint"),
            ("CONFIRMED", "mint"),
            ("UNKNOWN", "object"),
            ("UNKNOWN", "revoke"),
        ]
    if fault in {"revoke_lost", "post_and_revoke_lost"}:
        assert records[-1] == ("UNKNOWN", "revoke")
    else:
        assert records[-1] == ("CONFIRMED", "revoke")
    calls, retained = list(wire.calls), path.read_bytes()
    assert p.main(args) == 1
    assert wire.calls == calls and path.read_bytes() == retained
    # Even a different, freshly authorized job cannot bypass this history.
    with pytest.raises(a.Blocked):
        invoke(dict(job, id="d" * 32), data, journal, wire)
    assert wire.calls == calls and path.read_bytes() == retained


REPO = Path(__file__).resolve().parents[1]


def apparmor_file_rules(text):
    return [
        m.groups()
        for m in (re.fullmatch(r"\s*(/\S*)\s+([a-z]+),", x) for x in text.splitlines())
        if m
    ]


def apparmor_regex(pattern):
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] in "{[":
            j = pattern.index("}" if pattern[i] == "{" else "]", i)
            body = pattern[i + 1 : j]
            out += (
                "(?:" + "|".join(map(re.escape, body.split(","))) + ")"
                if pattern[i] == "{"
                else "[" + body + "]"
            )
            i = j + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out)


def role_read_paths(role, monkeypatch):
    """Every path each role opens through read_file(), derived from shipped code."""
    source = (REPO / "src/agent_platform/worker_publisher.py").read_text()
    signer_source = (REPO / "src/agent_platform/worker_publish_signer.py").read_text()
    wrapper = (REPO / "packaging/worker-publisher/ap-worker-publisher").read_text()
    library = re.search(r"sys\.path\.insert\(0, '(/[^']+)'\)", wrapper)[1]
    modules = re.findall(r'"(worker_publish\w*\.py)"', source)
    assert len(modules) == 5
    paths = {f"{library}/agent_platform/{name}" for name in modules}
    paths |= set(re.findall(r'read_file\("(/etc/ap-publisher/\w+\.json)"', source))
    unit = "ap-worker-publisher" + ("-signer" if role == "signer" else "")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", f"/run/credentials/{unit}.service")
    paths.add(io.credential_path(role))
    if role == "publisher":
        service = (
            REPO / "packaging/worker-publisher" / (unit + ".service")
        ).read_text()
        paths |= set(re.search(r"--job (\S+) --artifact (\S+)", service).groups())
        paths |= set(re.findall(r'Journal\("(/var/lib/ap-publisher/journal)"', source))
    else:
        paths |= set(re.findall(r'"(/etc/ap-publisher/job\.json)"', signer_source))
        paths |= set(
            re.findall(r'"(/var/lib/ap-publisher-signer/journal)"', signer_source)
        )
    return unit, paths


@pytest.mark.parametrize("role", ["publisher", "signer"])
def test_apparmor_ancestor_gap_matches_documented_f02_status(role, monkeypatch):
    unit, paths = role_read_paths(role, monkeypatch)
    profile = (REPO / "packaging/worker-publisher" / (unit + ".apparmor")).read_text()
    rules = apparmor_file_rules(profile)
    for path in paths:  # the leaves themselves are granted today
        assert any(
            "r" in perms and apparmor_regex(pattern).fullmatch(path)
            for pattern, perms in rules
        ), path
    ancestors = {
        str(parent).rstrip("/") + "/" for path in paths for parent in Path(path).parents
    }
    doc = (REPO / "docs/pub02-pilot-readiness.md").read_text()
    block = doc.split("AP-PUB02-F02 " + unit + "\n", 1)[1].split("AP-PUB02-F02 ")[0]
    proposed = {line[: -len(" r,")] for line in block.split("```")[0].splitlines()}
    assert proposed == ancestors  # the documented fix covers every opened ancestor
    missing = {d for d in ancestors if f"  {d} r," not in profile.splitlines()}
    assert ("F-02 status: BLOCKED_SCOPE_DEPENDENCY" in doc) is bool(missing)


def test_homelab_creates_exact_worker01_draft_and_revokes(store):
    journal, _ = store
    data, head, tree, objects = artifact()
    job = homelab_job(job_for(data, head, tree))
    result, wire = invoke(job, data, journal)
    assert result == {
        "status": "PUBLISHED",
        "pr": 111,
        "head": head,
        "runtime": "LIVE_NO_GO",
        "contract": p.HOMELAB,
        "external_rollback_protection": "NOT_PROVIDED",
    }
    assert wire.tip == head and wire.objects == objects and wire.token is False
    assert wire.calls[-1] == ("DELETE", "/installation/token")
    assert all("/merge" not in path for _, path in wire.calls)


@pytest.mark.parametrize(
    "change",
    [
        {"expires": 0},
        {"ref": "refs/heads/main"},
        {
            "worker": "worker02",
            "app_id": 5748675,
            "installation_id": 181691061,
            "app_slug": "tte-agent-worker02",
            "bot_login": "tte-agent-worker02[bot]",
        },
        {"bot_login": "tte-agent-worker02[bot]"},
        {"operation": "merge"},
        {"operation": "update", "pr": 12, "old": "a" * 40},
        {"parent": "f" * 40},
        {"gates": {}},
    ],
)
def test_homelab_wrong_authority_or_expired_approval_blocks(change):
    data, head, tree, _ = artifact()
    job = homelab_job(job_for(data, head, tree))
    with pytest.raises(a.Blocked):
        p.validate_job({**job, **change}, int(time.time()))


def test_operator_prepare_uses_only_public_reads_and_exact_artifact(
    store,
    monkeypatch,
):
    log, _ = store
    data, head, tree, _ = artifact()
    expected = homelab_job(job_for(data, head, tree))
    wire = Wire(log, expected)
    original = wire.exchange

    def no_writes(method, path, body, secret, limit=256 * 1024):
        assert method == "GET" and body is secret is None
        return original(method, path, body, secret, limit)

    def candidate(path, owner, limit):
        assert path == p.HOMELAB_ARTIFACT and owner == 0 and limit == a.MAX_WIRE
        return data

    monkeypatch.setattr(op, "read_file", candidate)
    monkeypatch.setattr(op, "command", lambda argv: expected["github_ipv4"] + " STREAM")
    monkeypatch.setattr(op.HTTPS, "homelab", lambda ip: wire)
    monkeypatch.setattr(
        op,
        "inspect_journals",
        lambda ids, job=None: {k: expected[k] for k in expected if "journal_sha" in k},
    )
    args = SimpleNamespace(
        **{
            k: expected[k]
            for k in (
                "issue",
                "ref",
                "head",
                "tree",
                "parent",
                "artifact_sha256",
                "app_owner_id",
            )
        }
    )
    ids = {k: expected[k] for k in expected if k.endswith(("_uid", "_gid"))}
    wire.exchange = no_writes
    pins = op.inspect_journals(ids)
    job = op.prepare(args, ids, pins)
    assert job["head"] == head and job["tree"] == tree
    assert job["artifact_sha256"] == a.digest(data)
    assert job["bot_login"] == "tte-agent-worker01[bot]"
    assert not log.events

    wire.mutate = lambda path, value: dict(value, id=42) if path == p.ROOT else value
    with pytest.raises(a.Blocked):
        op.prepare(args, ids, pins)
    args.artifact_sha256 = "f" * 64
    before = tuple(wire.calls)
    with pytest.raises(a.Blocked):
        op.prepare(args, ids, pins)
    assert tuple(wire.calls) == before


def test_operator_root_guard_precedes_local_or_network_access(monkeypatch, capsys):
    monkeypatch.setattr(op.os, "getuid", lambda: 2000)
    monkeypatch.setattr(op, "exclusive_config", lambda: pytest.fail("local access"))
    assert op.main(["readiness"]) == 1
    assert json.loads(capsys.readouterr().out)["check"] == "root_required"


@pytest.fixture
def staged_job_fs(tmp_path, monkeypatch):
    # Exercise real ACL xattr, readback, fsync and no-replace links as the
    # test user. Only ownership operations and reported root IDs are simulated.
    class StageFilesystem:
        uid = gid = 0

        def __getattr__(self, name):
            return getattr(os, name)

        def fchown(self, fd, uid, gid):
            assert (uid, gid) == (0, 0)

        def root_metadata(self, info):
            names = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_ctime_ns",
                "st_mtime_ns",
            )
            return SimpleNamespace(
                st_uid=self.uid,
                st_gid=self.gid,
                **{name: getattr(info, name) for name in names},
            )

        def fstat(self, fd):
            return self.root_metadata(os.fstat(fd))

        def stat(self, *args, **kwargs):
            return self.root_metadata(os.stat(*args, **kwargs))

    fs = StageFilesystem()
    monkeypatch.setattr(op, "os", fs)
    monkeypatch.setattr(op, "PENDING", tmp_path / ".homelab-job.pending")
    dirfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    data, head, tree, _ = artifact()
    try:
        yield fs, dirfd, tmp_path / "job.json", homelab_job(job_for(data, head, tree))
    finally:
        os.close(dirfd)


def test_operator_intent_is_durable_exact_and_never_replaces_retained_job(
    staged_job_fs,
):
    _, dirfd, job_path, job = staged_job_fs
    op.stage_job(job, dirfd)
    assert stat.S_IMODE(job_path.stat().st_mode) == 0o440
    assert io.acl_entries(os.getxattr(job_path, io.ACL_XATTR)) == [
        (io.ACL_USER_OBJ, 4, 2**32 - 1),
        (io.ACL_USER, 4, job["publisher_uid"]),
        (io.ACL_USER, 4, job["signer_uid"]),
        (io.ACL_GROUP_OBJ, 0, 2**32 - 1),
        (io.ACL_MASK, 4, 2**32 - 1),
        (io.ACL_OTHER, 0, 2**32 - 1),
    ]
    assert job_path.read_bytes() == a.encoded(job)
    assert not op.PENDING.exists()
    with pytest.raises(FileExistsError):
        op.stage_job(dict(job, id="b" * 32), dirfd)
    assert job_path.read_bytes() == a.encoded(job)
    assert op.PENDING.exists()


@pytest.mark.parametrize(
    "fault",
    ["uid", "gid", "world_read", "third_reader", "changed", "replacement"],
)
def test_operator_rejects_unsafe_staged_metadata(staged_job_fs, monkeypatch, fault):
    fs, dirfd, job_path, job = staged_job_fs
    if fault in {"uid", "gid"}:
        setattr(fs, fault, job["worker_uid"])
    if fault in {"world_read", "third_reader"}:

        def wrong_acl(fd, key, raw):
            if fault == "world_read":
                raw = raw[:-6] + b"\x04\x00" + raw[-4:]
            else:
                extra = b"\x02\x00\x04\x00" + job["worker_uid"].to_bytes(4, "little")
                raw = raw[:28] + extra + raw[28:]
            os.setxattr(fd, key, raw)

        monkeypatch.setattr(fs, "setxattr", wrong_acl)
    if fault == "changed":
        monkeypatch.setattr(
            fs, "pread", lambda fd, *args: b"x" + os.pread(fd, *args)[1:]
        )
    if fault == "replacement":
        orig = fs.stat

        def other_inode(*args, **kwargs):
            observed = orig(*args, **kwargs)
            observed.st_ino += 1
            return observed

        monkeypatch.setattr(fs, "stat", other_inode)
    with pytest.raises(a.Blocked):
        op.stage_job(job, dirfd)
    assert not job_path.exists()
    assert op.PENDING.exists()


def test_operator_reads_existing_journal_under_lock_without_renewing_history(
    store,
    monkeypatch,
):
    log, path = store
    data, head, tree, _ = artifact()
    job = homelab_job(job_for(data, head, tree))
    log.claim(job)
    log.append({"phase": "UNKNOWN", "job": job["id"], "operation": "mint"})
    before = path.read_bytes()
    uid = os.getuid()
    monkeypatch.setattr(io.os, "getuid", lambda: 0)
    monkeypatch.setattr(io.os, "geteuid", lambda: 0)
    with pytest.raises(BlockingIOError):
        io.Journal(str(path), None, inspect_owner=uid)
    log.close()
    try:
        with pytest.raises(FileNotFoundError):
            io.Journal(str(path) + ".missing", None, inspect_owner=uid)
        reader = io.Journal(str(path), None, inspect_owner=uid)
        try:
            assert reader.sha256 == a.digest(before)
            with pytest.raises(a.Blocked):
                reader.admissible(dict(job, id="b" * 32))
            with pytest.raises(a.Blocked):
                reader.append({"phase": "COMPLETE"})
        finally:
            reader.close()
        assert path.read_bytes() == before
    finally:
        # Restore a descriptor for the shared fixture's teardown.
        log.fd = os.open(path, os.O_RDONLY)


def test_homelab_artifact_policy_keeps_pem_and_candidate_from_other_roles():
    publisher = (
        REPO / "packaging/worker-publisher/ap-worker-publisher.apparmor"
    ).read_text()
    signer_profile = (
        REPO / "packaging/worker-publisher/ap-worker-publisher-signer.apparmor"
    ).read_text()
    assert "/etc/ap-publisher/{job,receipts,candidate,homelab-candidate}.json r," in (
        publisher
    )
    assert "deny /etc/ap-publisher/{candidate,homelab-candidate}.json rwklmx," in (
        signer_profile
    )
    assert "deny /etc/ap-publisher-keys/** rwklmx," in publisher
    assert "deny /etc/ap-publisher-keys/** rwklmx," in signer_profile


def test_operator_starts_fixed_units_once_and_requires_exact_completed_journal(
    monkeypatch,
):
    data, head, tree, _ = artifact()
    job = homelab_job(job_for(data, head, tree))
    calls = []
    journal_record = {
        "phase": "COMPLETE",
        "job": job["id"],
        "ref": job["ref"],
        "issue": job["issue"],
        "head": job["head"],
        "pr": 111,
    }

    def systemctl(*args, timeout=5):
        calls.append((args, timeout))

    def inspect(allow=""):
        calls.append((("verify", allow), 0))

    monkeypatch.setattr(op, "inspect_units", inspect)
    monkeypatch.setattr(op, "systemctl", systemctl)
    monkeypatch.setattr(
        op,
        "journal",
        lambda role, identities: SimpleNamespace(
            events=[{"record": journal_record}],
            close=lambda: None,
        ),
    )
    assert op.launch(job, {}) == 111
    assert calls == [
        (("verify", ""), 0),
        (
            (
                "set-property",
                "--runtime",
                "ap-worker-publisher.service",
                "IPAddressAllow=140.82.112.6/32",
            ),
            5,
        ),
        (("verify", "140.82.112.6/32"), 0),
        (("start", "ap-worker-publisher-signer.service"), 20),
        (("verify", "140.82.112.6/32"), 0),
        (("start", "ap-worker-publisher.service"), 325),
    ]

    journal_record["job"] = "f" * 32
    with pytest.raises(a.Blocked):
        op.launch(job, {})
    assert len(calls) == 12


def test_operator_failed_oneshot_retains_intent_and_makes_no_second_attempt(
    monkeypatch,
    capsys,
):
    data, head, tree, _ = artifact()
    job = homelab_job(job_for(data, head, tree))
    observed = []
    monkeypatch.setattr(
        op,
        "os",
        SimpleNamespace(
            getuid=lambda: 0, geteuid=lambda: 0, close=lambda fd: None, environ={}
        ),
    )
    monkeypatch.setattr(op, "exclusive_config", lambda: 99)
    monkeypatch.setattr(op, "inspect_host", lambda: {})
    monkeypatch.setattr(op, "inspect_journals", lambda identities: {})
    monkeypatch.setattr(op, "prepare", lambda *args: job)
    monkeypatch.setattr(
        op,
        "stage_job",
        lambda value, directory: observed.append(("intent", value)),
    )

    def fail(value, identities):
        observed.append(("attempt", value))
        raise TimeoutError("fabricated private transport detail")

    monkeypatch.setattr(op, "launch", fail)
    flags = [
        flag
        for k in (
            "issue",
            "app_owner_id",
            "ref",
            "head",
            "tree",
            "parent",
            "artifact_sha256",
        )
        for flag in ("--" + k.replace("_", "-"), str(job[k]))
    ]
    assert op.main(["preview", *flags]) == 0
    assert observed == []
    assert op.main(["approve-create", *flags, "--confirm-app-policy"]) == 1
    output = capsys.readouterr().out
    assert output.count('"status":"DRY_RUN"') == 2
    assert '"status":"UNKNOWN_NEEDS_HUMAN"' in output
    assert "fabricated private" not in output
    assert observed == [("intent", job), ("attempt", job)]


@pytest.fixture
def effective_units(monkeypatch):
    # systemd 257's human-readable scalar properties and typed Service replies.
    scalar, replies = {}, {}
    signature = "a(sasasttttuii)"
    for role in ("publisher", "signer"):
        signer_role = role == "signer"
        profile = "ap-worker-publisher" + ("-signer" if signer_role else "")
        service = profile + ".service"
        account = "ap-publisher" + ("-signer" if signer_role else "")
        scalar[service] = {
            "LoadState": "loaded",
            "NeedDaemonReload": "no",
            "ActiveState": "inactive",
            "UnitFileState": "static",
            "FragmentPath": "/usr/lib/systemd/system/" + service,
            "DropInPaths": "",
            "User": account,
            "Group": account,
            "SupplementaryGroups": "",
            "Type": "oneshot",
            "Restart": "no",
            "TasksMax": "4" if signer_role else "8",
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
            "RuntimeDirectory": account if signer_role else "",
            "RuntimeDirectoryPreserve": "yes" if signer_role else "no",
            "ReadOnlyPaths": "/etc/ap-publisher /usr/lib/ap-worker-publisher",
            "ReadWritePaths": f"/var/lib/{account}/journal",
            "InaccessiblePaths": "/etc/ap-publisher-keys /var/lib/ap-publisher-signer",
            "PrivateNetwork": "no",
            "NetworkNamespacePath": "",
            "JoinsNamespaceOf": "",
            "RestrictAddressFamilies": "AF_INET",
            "IPAddressAllow": "",
            "IPAddressDeny": "::/0 0.0.0.0/0",
            "SocketBindDeny": "any",
        }
        executable = "/usr/libexec/" + profile
        argv = [executable]
        if signer_role:
            scalar[service].update(
                ReadWritePaths=f"/var/lib/{account}/journal /run/ap-publisher-signer",
                InaccessiblePaths="/var/lib/ap-publisher",
                PrivateNetwork="yes",
                RestrictAddressFamilies="AF_UNIX",
                IPAddressDeny="",
            )
            credential = ["app-key", "/etc/ap-publisher-keys/worker.pem"]
        else:
            argv.extend(
                [
                    "--job",
                    "/etc/ap-publisher/job.json",
                    "--artifact",
                    "/etc/ap-publisher/candidate.json",
                    "--execute",
                ]
            )
            credential = ["app-jwt", "/run/ap-publisher-signer/app-jwt"]
        node = "/org/freedesktop/systemd1/unit/" + (
            service.replace("-", "_2d").replace(".", "_2e")
        )
        replies[node] = {
            "ExecStartEx": (signature, [[executable, argv, [], 0, 0, 0, 0, 0, 0, 0]]),
            "LoadCredential": ("a(ss)", [credential]),
            "LoadCredentialEncrypted": ("a(ss)", []),
            "ImportCredentialEx": ("a(ss)", []),
            "SocketBindAllow": ("a(iiqq)", []),
            "SupplementaryGroups": ("as", []),
            "ReadOnlyPaths": ("as", scalar[service]["ReadOnlyPaths"].split()),
            "ReadWritePaths": ("as", scalar[service]["ReadWritePaths"].split()),
            "InaccessiblePaths": ("as", scalar[service]["InaccessiblePaths"].split()),
            "BindPaths": ("a(ssbt)", []),
            "BindReadOnlyPaths": ("a(ssbt)", []),
            **{
                key: (signature, [])
                for key in (
                    "ExecConditionEx",
                    "ExecStartPreEx",
                    "ExecStartPostEx",
                    "ExecStopEx",
                    "ExecStopPostEx",
                )
            },
        }

    def systemctl(action, all_flag, properties, service):
        assert (action, all_flag) == ("show", "--all")
        keys = properties.removeprefix("--property=").split(",")
        return "\n".join(f"{key}={scalar[service][key]}" for key in keys)

    def busctl(argv):
        assert argv[:6] == [
            "/usr/bin/busctl",
            "--system",
            "--no-pager",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
        ]
        assert argv[7] == "org.freedesktop.systemd1.Service"
        return "\n".join(
            json.dumps({"type": wire_type, "data": data})
            for wire_type, data in (replies[argv[6]][key] for key in argv[8:])
        )

    monkeypatch.setattr(op, "systemctl", systemctl)
    monkeypatch.setattr(op, "command", busctl)
    return scalar, replies


def test_operator_only_allows_exact_runtime_network_dropin(effective_units):
    units, _ = effective_units
    op.inspect_units()
    publisher = units["ap-worker-publisher.service"]
    publisher["DropInPaths"] = (
        "/run/systemd/system.control/ap-worker-publisher.service.d/"
        "50-IPAddressAllow.conf"
    )
    publisher["IPAddressAllow"] = "140.82.112.6/32"
    op.inspect_units("140.82.112.6/32")
    with pytest.raises(a.Blocked):
        op.inspect_units()
    publisher["DropInPaths"] += " /etc/systemd/system/service.d/override.conf"
    with pytest.raises(a.Blocked):
        op.inspect_units("140.82.112.6/32")


@pytest.mark.parametrize(
    "role,property_name,bad_value",
    [
        ("publisher", "NeedDaemonReload", "yes"),
        ("publisher", "IPAddressDeny", "0.0.0.0/0"),
        ("publisher", "SocketBindDeny", "ipv4:any"),
        ("signer", "TasksMax", "1"),
        ("signer", "TasksMax", "infinity"),
        ("signer", "PrivateNetwork", "no"),
        ("signer", "NetworkNamespacePath", "/run/netns/publisher"),
        ("signer", "RestrictAddressFamilies", "AF_UNIX AF_INET"),
        ("signer", "DropInPaths", "/etc/systemd/system/service.d/override.conf"),
    ],
)
def test_operator_rejects_modified_effective_unit(
    effective_units,
    role,
    property_name,
    bad_value,
):
    units, _ = effective_units
    service = (
        "ap-worker-publisher" + ("-signer" if role == "signer" else "") + ".service"
    )
    units[service][property_name] = bad_value
    with pytest.raises(a.Blocked):
        op.inspect_units()


@pytest.mark.parametrize("fault", ["argv", "privileged", "credential", "hook"])
def test_operator_rejects_alternate_exec_or_credential(
    effective_units,
    fault,
):
    _, replies = effective_units
    service = replies[
        "/org/freedesktop/systemd1/unit/ap_2dworker_2dpublisher_2dsigner_2eservice"
    ]
    start = service["ExecStartEx"][1][0]
    if fault == "argv":
        start[1].append("--unexpected")
    if fault == "privileged":
        start[2].append("privileged")
    if fault == "credential":
        service["LoadCredential"][1][0][1] = "/tmp/alternate-key"
    if fault == "hook":
        service["ExecStartPostEx"][1].append(start)
    with pytest.raises(a.Blocked):
        op.inspect_units()


@pytest.mark.parametrize(
    "role,key,value",
    [
        ("publisher", "InaccessiblePaths", ["/var/lib/ap-publisher-signer"]),
        (
            "publisher",
            "InaccessiblePaths",
            ["/etc/ap-publisher-keys /var/lib/ap-publisher-signer"],
        ),
        ("signer", "ReadWritePaths", ["/var/lib/ap-publisher-signer/journal"]),
        ("signer", "SupplementaryGroups", ["agentdev"]),
    ],
)
def test_operator_rejects_modified_path_or_group_lists(
    effective_units, role, key, value
):
    _, replies = effective_units
    suffix = "_2dsigner" if role == "signer" else ""
    service = (
        f"/org/freedesktop/systemd1/unit/ap_2dworker_2dpublisher{suffix}_2eservice"
    )
    replies[service][key] = ("as", value)
    with pytest.raises(a.Blocked):
        op.inspect_units()
