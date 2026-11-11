"""Deterministic fabricated bytes; no Git or remote fixtures."""

import hashlib
import json
from dataclasses import FrozenInstanceError, replace

import pytest

from agent_platform import publisher_candidate as pc


def obj(kind, payload):
    raw = kind.encode() + b" " + str(len(payload)).encode() + b"\0" + payload
    return pc.GitObject(hashlib.sha1(raw).hexdigest(), raw)


def fixture(names=("file.txt",), mode="100644", operation="create", extra=b""):
    blob = obj("blob", b"hello\n")
    tree = obj(
        "tree",
        b"".join(
            mode.encode() + b" " + n.encode() + b"\0" + bytes.fromhex(blob.oid)
            for n in names
        ),
    )
    commit = obj(
        "commit",
        b"tree "
        + tree.oid.encode()
        + b"\nparent "
        + b"a" * 40
        + b"\n"
        + extra
        + b"author Fixture <a@example.test> 1 +0000\n"
        + b"committer Fixture <a@example.test> 1 +0000\n\nfixture\n",
    )
    policy = pc.Policy(
        1,
        "example/target",
        91,
        100,
        "b" * 64,
        "a" * 40,
        "refs/heads/feature/issue-91-test",
        names,
    )
    policy = replace(
        policy,
        operation=operation,
        expected_old="ABSENT" if operation == "create" else "a" * 40,
    )
    descriptor = dict(
        version=pc.VERSION,
        repo_id=1,
        repository="example/target",
        issue=91,
        issue_id=100,
        scope="b" * 64,
        base_sha="a" * 40,
        operation=operation,
        feature_ref=policy.feature_ref,
        expected_old="ABSENT" if operation == "create" else "a" * 40,
        commit=commit.oid,
        tree=tree.oid,
        object_format="sha1",
        inventory=[dict(path=n, mode=mode, oid=blob.oid) for n in names],
    )
    return pc.Candidate(json.dumps(descriptor).encode(), (blob, tree, commit)), policy


def change(c, **fields):
    return replace(c, descriptor=json.dumps(json.loads(c.descriptor) | fields).encode())


def blocked(c, p, code=None):
    result = pc.verify(c, p)
    assert result.status == "BLOCKED"
    assert result.code in pc.CODES
    assert not result.publish_authorized
    if code:
        assert result.code == code


def test_valid_and_immutable():
    c, p = fixture()
    r = pc.verify(c, p)
    assert r.status == "VERIFIED_OFFLINE_FIXTURE"
    assert not r.publish_authorized
    for value, field in ((r, "publish_authorized"), (c, "version"), (p, "issue")):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, True)
    with pytest.raises(TypeError):
        pc.Result("VERIFIED_OFFLINE_FIXTURE", "verified", publish_authorized=True)


@pytest.mark.parametrize("index", range(3))
def test_object_ids(index):
    c, p = fixture()
    objects = list(c.objects)
    objects[index] = replace(objects[index], oid="0" * 40)
    blocked(replace(c, objects=tuple(objects)), p, "object_id_mismatch")


@pytest.mark.parametrize(
    "raw",
    [
        b"blob 06\0hello\n",
        b"blob 7\0hello\n",
        b"blob 6hello\n",
        b"tag 0\0",
        b"blob -1\0",
        b"blob 0\0x",
        b"tree 1\0",
    ],
)
def test_headers_and_truncation(raw):
    c, p = fixture()
    blocked(replace(c, objects=(pc.GitObject("0" * 40, raw), *c.objects[1:])), p)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("object_format", "sha256"),
        ("repo_id", 2),
        ("repo_id", True),
        ("repository", "evil/target"),
        ("issue", 92),
        ("issue_id", 101),
        ("scope", "c" * 64),
        ("base_sha", "c" * 40),
        ("operation", "force"),
        ("feature_ref", "refs/heads/main"),
        ("feature_ref", "refs/tags/v1"),
        ("feature_ref", "refs/heads/feature/../main"),
        ("expected_old", "a" * 40),
        ("publish_authorized", True),
        ("operator_approved", True),
        ("inventory", []),
        ("commit", "a" * 64),
        ("version", "AP-PC/2"),
    ],
)
def test_descriptor_rejections(key, value):
    c, p = fixture()
    blocked(change(c, **{key: value}), p)


@pytest.mark.parametrize(
    "name",
    ["../x", "/tmp/x", "a/b", ".git", "GIT~1", "a..b", "a.", "con.txt", "x.lock", "é"],
)
def test_unsafe_paths(name):
    c, p = fixture((name,))
    blocked(c, p, "unsafe_path")


@pytest.mark.parametrize("names", [("A", "a"), ("a", "a")])
def test_duplicate_aliases(names):
    c, p = fixture(names)
    blocked(c, p)


@pytest.mark.parametrize("mode", ["120000", "160000", "100755", "100664", "040000"])
def test_modes(mode):
    c, p = fixture(mode=mode)
    blocked(c, p, "invalid_mode")


def test_explicit_executable():
    c, p = fixture(mode="100755")
    assert (
        pc.verify(c, replace(p, executable_paths=p.paths)).status
        == "VERIFIED_OFFLINE_FIXTURE"
    )


@pytest.mark.parametrize(
    "extra", [b"parent " + b"b" * 40 + b"\n", b"encoding UTF-8\n", b"gpgsig fake\n"]
)
def test_merge_and_headers(extra):
    c, p = fixture(extra=extra)
    blocked(c, p, "invalid_commit")


def test_parent_and_tree_mismatch():
    c, p = fixture()
    blocked(
        change(c, base_sha="d" * 40), replace(p, base_sha="d" * 40), "parent_mismatch"
    )
    d = json.loads(c.descriptor)
    d["inventory"][0]["path"] = "other"
    blocked(
        replace(c, descriptor=json.dumps(d).encode()),
        replace(p, paths=("other",)),
        "invalid_tree",
    )


def test_update_is_never_remote_proof():
    c, p = fixture(operation="update")
    blocked(c, p, "remote_update_unverified")
    blocked(change(c, remote_cas_verified=True), p, "invalid_descriptor")
    blocked(change(c, expected_old="ABSENT"), p, "invalid_operation")


def test_duplicate_unknown_truncated_descriptor():
    c, p = fixture()
    blocked(
        replace(c, descriptor=c.descriptor[:-1] + b', "issue":91}'),
        p,
        "invalid_descriptor",
    )
    blocked(change(c, unknown=0), p, "invalid_descriptor")
    blocked(replace(c, descriptor=c.descriptor[:-1]), p)


def test_limits():
    c, p = fixture()
    blocked(replace(c, descriptor=b" " * (pc.MAX_DESCRIPTOR + 1)), p, "limit_exceeded")
    huge = pc.GitObject("0" * 40, b"x" * (pc.MAX_OBJECT + 1))
    blocked(replace(c, objects=(huge,)), p, "limit_exceeded")
    large = pc.GitObject("0" * 40, b"x" * pc.MAX_OBJECT)
    blocked(replace(c, objects=(large,) * 4), p, "limit_exceeded")
    blocked(replace(c, objects=c.objects * 44), p, "limit_exceeded")
    c, p = fixture(tuple(f"f{i:03}" for i in range(129)))
    blocked(c, p)


def test_no_io_dependencies():
    # Syntax-level dependency allowlist guards this deliberately pure boundary.
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(pc))
    imports = {
        n.names[0].name if isinstance(n, ast.Import) else n.module
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
    }
    assert imports == {"hashlib", "json", "re", "dataclasses"}


def test_verifier_does_not_call_io(monkeypatch):
    import builtins
    import os
    import socket
    import subprocess

    c, p = fixture()

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected I/O")

    with monkeypatch.context() as patch:
        for module, name in (
            (builtins, "open"),
            (os, "open"),
            (os, "system"),
            (socket, "socket"),
            (subprocess, "Popen"),
        ):
            patch.setattr(module, name, forbidden)
        assert pc.verify(c, p).status == "VERIFIED_OFFLINE_FIXTURE"
        blocked(change(c, publish_authorized=True), p)
        c, p = fixture(operation="update")
        blocked(c, p, "remote_update_unverified")


def test_unreachable_duplicate_and_wrong_object_kind():
    c, p = fixture()
    blocked(
        replace(c, objects=(*c.objects, obj("blob", b"unreachable"))),
        p,
        "inventory_mismatch",
    )
    blocked(replace(c, objects=(*c.objects, c.objects[0])), p, "invalid_object")
    # Tree payload remains hash-valid but no longer canonical for the inventory.
    tree = obj("tree", c.objects[1].canonical.partition(b"\0")[2][:-1])
    blocked(
        change(replace(c, objects=(c.objects[0], tree, c.objects[2])), tree=tree.oid),
        p,
        "invalid_tree",
    )


def test_policy_operation_and_old_sha_are_independent_pins():
    c, p = fixture(operation="update")
    blocked(c, replace(p, operation="create"), "invalid_operation")
    blocked(c, replace(p, expected_old="d" * 40), "invalid_operation")
    c, p = fixture()
    blocked(c, replace(p, version="unknown"), "unsupported_format")


@pytest.mark.parametrize(
    "ref",
    [
        "refs/heads/main",
        "refs/tags/v1",
        "HEAD",
        "refs/heads/feature/issue-92-test",
        "refs/heads/feature/issue-91-test.lock",
        "refs/heads/feature/issue-91-a/../main",
    ],
)
def test_ref_is_restricted_even_when_policy_matches(ref):
    c, p = fixture()
    blocked(change(c, feature_ref=ref), replace(p, feature_ref=ref), "invalid_ref")


def test_known_git_blob_vector_and_full_inventory():
    c, p = fixture(tuple(f"f{i:03}" for i in range(128)))
    assert c.objects[0].oid == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert pc.verify(c, p).status == "VERIFIED_OFFLINE_FIXTURE"


def test_nested_descriptor_fields_are_closed():
    c, p = fixture()
    raw = c.descriptor.replace(
        b'"mode": "100644"', b'"mode": "100644", "mode": "100644"'
    )
    blocked(replace(c, descriptor=raw), p, "invalid_descriptor")
    d = json.loads(c.descriptor)
    d["inventory"][0]["approved"] = True
    blocked(replace(c, descriptor=json.dumps(d).encode()), p, "invalid_descriptor")
