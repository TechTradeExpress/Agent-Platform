"""PUB-02 actual exporter/validator/journal/CLI with offline GitHub wire mocks."""

import base64
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from agent_platform import worker_publish_artifact as a
from agent_platform import worker_publish_io as io
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
        elif path == p.ROOT + "/pulls?state=all&per_page=100":
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
def test_auth_scope_and_source_mismatch_stop_before_ref(store, route):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
    wire = Wire(journal, j)
    wire.mutate = lambda path, value: {} if path == route else value
    with pytest.raises((a.Blocked, KeyError, ValueError, TimeoutError)):
        invoke(j, data, journal, wire)
    assert wire.tip is None and wire.pr_number is None
    assert not any(path == "/graphql" for _, path in wire.calls)


@pytest.mark.parametrize(
    "route", [p.ROOT + "/git/blobs", "/graphql", p.ROOT + "/pulls"]
)
def test_lost_response_retains_unknown_and_no_replay(store, route):
    journal, path = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
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


def test_cas_race_after_observation_is_not_overwritten(store):
    journal, _ = store
    data, head, tree, _ = artifact()
    j = job_for(data, head, tree)
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
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/fabricated")
    assert p.main(["--job", "job", "--artifact", "artifact", "--execute"]) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["head"] == head and "FAKE_PRIVATE" not in output
    assert not any("app-key" in path for path in seen)
    assert wire.token is False and wire.pr_number == 111


def test_signer_one_shot_binds_job_and_keeps_key_out_of_publisher(
    store, tmp_path, monkeypatch, capsys
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
        assert path == "/fabricated/app-key"
        return b"FABRICATED_KEY_NOT_A_PEM"

    monkeypatch.setattr(signer, "read_file", read)
    monkeypatch.setattr(signer, "confinement", lambda *args: None)
    monkeypatch.setattr(signer, "receipts", lambda *args: None)
    monkeypatch.setattr(signer, "Journal", lambda *args: Session())
    monkeypatch.setattr(
        signer.serialization, "load_pem_private_key", lambda *args, **kwargs: object()
    )
    monkeypatch.setattr(signer, "jwt_for", lambda *args: b"JWT_FAKE")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/fabricated")
    real = signer.os.open
    output = tmp_path / "app-jwt"

    def open_private(path, *args, **kwargs):
        return real(
            str(output) if path == "/run/ap-publisher-signer/app-jwt" else path,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(signer.os, "open", open_private)
    assert signer.main() == 0
    bundle = a.decode(output.read_bytes())
    assert bundle == {"job_sha256": a.digest(original), "jwt": "JWT_FAKE"}
    assert output.stat().st_mode & 0o777 == 0o400
    count = len(seen)
    assert signer.main() == 1
    assert len(seen) == count + 1  # replay stops before another key read
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
