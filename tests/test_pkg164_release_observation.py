"""Source and Unix peer tests without production authorization or credentials."""

import importlib
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def observer(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "packaging"))
    return importlib.import_module("release_observation")


@pytest.fixture(scope="module")
def checkout(tmp_path_factory):
    supplied = os.environ.get("PKG164_TEST_CHECKOUT")
    if supplied:
        return Path(supplied)
    root = tmp_path_factory.mktemp("pkg164") / "source"
    subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-tags",
            str(ROOT),
            str(root),
        ],
        check=True,
        capture_output=True,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    return root


def test_source_observation_of_clean_checkout(observer, checkout):
    # The committed checkout is read-only. During editing, use the independently
    # prepared clean snapshot supplied by the test runner.
    root = checkout
    data = observer.observe_source(root)
    assert set(data["recipes"]) == set(observer.RECIPE_PATHS)
    assert data["historical_source"]["version"] == "0.1.0-7"
    for name, digest in data["recipes"].items():
        assert observer.sha((root / name).read_bytes()) == digest


def test_source_swap_fails(observer, monkeypatch, checkout):
    root = checkout
    read = observer._read

    def changed(argv, *args):
        result = read(argv, *args)
        if argv[2:4] == ["cat-file", "commit"]:
            return result + b"drift"
        return result

    monkeypatch.setattr(observer, "_read", changed)
    with pytest.raises(observer.Blocked, match="commit_digest_mismatch"):
        observer.observe_source(root)


def test_historical_archive_absence_and_wrong_hash(observer, tmp_path):
    pin = json.loads((ROOT / "packaging/debian/pkg11-baseline.json").read_bytes())
    with pytest.raises(observer.Blocked, match="historical_archive_unavailable"):
        observer.observe_historical_archives(tmp_path, pin)
    (tmp_path / "agent-platform-control_0.1.0-7_amd64.deb").write_bytes(b"wrong")
    with pytest.raises(observer.Blocked, match="historical_archive_mismatch"):
        observer.observe_historical_archives(tmp_path, pin)
    with pytest.raises(observer.Blocked, match="historical_pin_changed"):
        observer.observe_historical_archives(tmp_path, pin | {"version": "wrong"})


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "json",
        "wrong_binding",
        "same_uid",
        "stale",
        "interrupted",
        "slot_replaced",
        "non_string_challenge",
    ],
)
def test_fixture_peer_choice_is_not_release_authority(
    observer, tmp_path, monkeypatch, case
):
    uid = os.getuid()
    target = tmp_path / "slot"
    choice = dict(
        operator_uid=uid,
        observer_uid=uid + 1,
        challenge="a" * 64,
        observation=observer.Observation(
            b"synthetic source", b"synthetic env", b"synthetic history"
        ),
        now=10,
        expires=20,
    )
    binding = observer.sha(
        observer.encoded(
            {
                "release": observer.KEY,
                "roles": observer.ROLES,
                "challenge": choice["challenge"],
                "slot": str(target),
                "provenance": "UNVERIFIED_CALLER_FIXTURE",
                "observation": [observer.sha(value) for value in choice["observation"]],
                "expires": choice["expires"],
            }
        )
    )
    if case == "non_string_challenge":
        choice["challenge"] = None
    if case == "stale":
        choice["now"] = 30
    # Real kernel socket credentials for the client. Observer UID is modeled
    # because creating another OS principal is outside this test's privileges.
    if case != "same_uid":

        class ModeledOS:
            def __getattr__(self, name):
                return getattr(os, name)

            def getuid(self):
                return uid + 1

        monkeypatch.setattr(observer, "os", ModeledOS())
    if case == "interrupted":
        # Inject failure after the existing writer has durably recorded intent.
        fsync = os.fsync

        def interrupted(fd):
            if (target / "INTENT-REVIEW.json").exists():
                raise OSError
            return fsync(fd)

        monkeypatch.setattr(os, "fsync", interrupted)
    retained = tmp_path / "retained"
    if case == "slot_replaced":
        fsync = os.fsync

        def replace_after_intent(fd):
            fsync(fd)
            if (target / "INTENT.json").exists() and not retained.exists():
                target.rename(retained)
                target.mkdir()

        monkeypatch.setattr(os, "fsync", replace_after_intent)
    packet = {
        "json": b'{"approved":true}',
        "wrong_binding": b"OBSERVE " + b"0" * 64,
    }.get(case, ("OBSERVE " + binding).encode())

    def attempt(slot=target):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with a, b:
            a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            b.sendall(packet)
            return observer.record_fixture_intent(a, slot, **choice)

    if case == "success":
        result = attempt()
        assert result["status"] == "BLOCKED"
        assert result["authority"] == "NOT_CONFIGURED"
        assert result["fixture_peer_choice"] == "UNVERIFIED_CALLER_FIXTURE"
        assert result["release_authorized"] is False
        with pytest.raises(observer.Blocked, match="operator_choice_invalid"):
            attempt(tmp_path / "fresh-slot")
    else:
        with pytest.raises(observer.Blocked):
            attempt()
    if case in ("success", "interrupted"):
        assert json.loads((target / "INTENT.json").read_bytes())["state"] == "UNKNOWN"
        assert (target / "COMPLETED.json").exists() == (case == "success")
        with pytest.raises(observer.Blocked, match="intent_unknown_or_slot_exists"):
            attempt()
    elif case == "slot_replaced":
        assert json.loads((retained / "INTENT.json").read_bytes())["state"] == "UNKNOWN"
        assert not (retained / "COMPLETED.json").exists()
        assert not list(target.iterdir())
        with pytest.raises(observer.Blocked, match="intent_unknown_or_slot_exists"):
            attempt()
    else:
        assert not target.exists()


def test_checkout_dirty(observer, checkout, monkeypatch):
    # Simulate a different working-tree blob without modifying the checkout.
    read = observer._regular
    target = checkout / "packaging/build_deb.py"
    monkeypatch.setattr(
        observer,
        "_regular",
        lambda path: read(path) + b"drift" if path == target else read(path),
    )
    with pytest.raises(observer.Blocked, match="checkout_dirty"):
        observer.observe_source(checkout)


def test_environment_drift_blocks_before_intent(observer, monkeypatch):
    source = {"historical_source": {}}
    environments = iter([{"python": "a"}, {"python": "b"}])
    monkeypatch.setattr(observer, "observe_source", lambda _: source)
    monkeypatch.setattr(observer, "observe_environment", lambda: next(environments))
    monkeypatch.setattr(observer, "observe_historical_archives", lambda *args: {})
    with pytest.raises(observer.Blocked, match="environment_changed"):
        observer.collect(None, None)


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("tree", "tree_digest_mismatch"),
        ("index", "checkout_dirty"),
        ("blob", "export_digest_mismatch"),
        ("history", "observation_unavailable"),
    ],
)
def test_git_observation_mutants(observer, checkout, monkeypatch, mutation, reason):
    original = observer._read
    files = observer._files

    def changed(argv, *args):
        if mutation == "history" and argv[2:4] == ["cat-file", "commit"]:
            if argv[-1] == "0fbc940ae94144f8cc29c9a0fd98afc704f58168":
                raise observer.Blocked("observation_unavailable")
        result = original(argv, *args)
        if mutation == "tree" and argv[2:4] == ["cat-file", "tree"]:
            return result + b"changed object"
        if mutation == "index" and argv[1:3] == ["ls-files", "--stage"]:
            return b""
        return result

    def changed_export(*args):
        blobs, modes = files(*args)
        if mutation == "blob":
            blobs["packaging/build_deb.py"] += b"changed export"
        return blobs, modes

    monkeypatch.setattr(observer, "_read", changed)
    monkeypatch.setattr(observer, "_files", changed_export)
    with pytest.raises(observer.Blocked, match=reason):
        observer.observe_source(checkout)


def test_head_moves(observer, checkout, monkeypatch):
    head = observer._head
    seen = False

    def changed(*args):
        nonlocal seen
        if seen:
            return "0" * 40
        seen = True
        return head(*args)

    monkeypatch.setattr(observer, "_head", changed)
    with pytest.raises(observer.Blocked, match="head_changed"):
        observer.observe_source(checkout)


def test_alias_checkout_and_alternate_store(observer, checkout, tmp_path, monkeypatch):
    alias = tmp_path / "alias"
    alias.symlink_to(checkout, target_is_directory=True)
    with pytest.raises(observer.Blocked, match="source_observation_unverified"):
        observer.observe_source(alias)
    lexists = os.path.lexists
    monkeypatch.setattr(
        os.path,
        "lexists",
        lambda path: Path(path).name == "alternates" or lexists(path),
    )
    with pytest.raises(observer.Blocked, match="alternate_objects"):
        observer.observe_source(checkout)


@pytest.mark.parametrize("error", [FileNotFoundError, PermissionError, StopIteration])
def test_missing_environment_and_header(observer, checkout, monkeypatch, error):
    def unavailable(*args):
        raise error("must not disclose")

    if error is StopIteration:
        monkeypatch.setattr(observer, "_oid", unavailable)
        with pytest.raises(observer.Blocked, match="^source_observation_unverified$"):
            observer.observe_source(checkout)
    else:
        monkeypatch.setattr(observer, "_observe_environment", unavailable)
        with pytest.raises(observer.Blocked, match="^environment_unverified$"):
            observer.observe_environment()


def test_closed_socket_is_blocked(observer, tmp_path):
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    peer.close()
    with pytest.raises(observer.Blocked, match="peer_identity_unavailable"):
        observer.record_fixture_intent(
            peer,
            tmp_path / "slot",
            operator_uid=1,
            observer_uid=2,
            challenge="a" * 64,
            observation=None,
            now=10,
            expires=20,
        )


@pytest.mark.parametrize("with_fd", [False, True])
def test_mismatched_message_credentials_and_fd_closed(
    observer, tmp_path, monkeypatch, with_fd
):
    import struct

    uid = os.getuid()
    fd = os.open("/dev/null", os.O_RDONLY) if with_fd else None

    class Peer:
        family = socket.AF_UNIX
        type = socket.SOCK_SEQPACKET

        def getsockopt(self, *args):
            return struct.pack("3i", 50, uid + 1, 10)

        def setsockopt(self, *args):
            pass

        def settimeout(self, *args):
            pass

        def recvmsg(self, *args):
            ancillary = [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_CREDENTIALS,
                    struct.pack("3i", 51, uid + 1, 10),
                )
            ]
            if fd is not None:
                ancillary.append(
                    (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))
                )
            return b"", ancillary, 0, None

    output = tmp_path / "slot"
    with pytest.raises(observer.Blocked, match="operator_choice_invalid"):
        observer.record_fixture_intent(
            Peer(),
            output,
            operator_uid=uid + 1,
            observer_uid=uid,
            challenge="a" * 64,
            observation=observer.Observation(b"a", b"b", b"c"),
            now=10,
            expires=20,
        )
    if fd is not None:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert not output.exists()


@pytest.mark.parametrize("field", ["epoch", "parents", "repository", "tree"])
def test_source_tuple_drift_blocks_collection(observer, monkeypatch, field):
    first = {"historical_source": {}, field: "initial"}
    observations = iter([first, first | {field: "substituted"}])
    monkeypatch.setattr(observer, "observe_source", lambda _: next(observations))
    monkeypatch.setattr(observer, "observe_environment", dict)
    monkeypatch.setattr(observer, "observe_historical_archives", lambda *args: {})
    with pytest.raises(observer.Blocked, match="source_changed"):
        observer.collect(None, None)


def test_caller_pin_is_not_an_observer_input(observer, checkout):
    with pytest.raises(TypeError):
        observer.observe_source(checkout, commit="0" * 40)


@pytest.mark.parametrize("failure", ["untracked", "tracked", "root"])
def test_unenumerated_checkout_is_blocked(observer, tmp_path, monkeypatch, failure):
    directory = tmp_path / "sub"
    directory.mkdir()
    (directory / "nested").write_bytes(b"nested")
    (tmp_path / "visible").write_bytes(b"visible")
    blobs = {"visible": b"visible"}
    if failure == "tracked":
        blobs["sub/nested"] = b"nested"
    denied = tmp_path if failure == "root" else directory
    scandir = os.scandir

    def unreadable(path):
        if Path(path) == denied:
            # Inject the filesystem error without requiring a second principal.
            raise PermissionError("private path")
        return scandir(path)

    monkeypatch.setattr(os, "scandir", unreadable)
    with pytest.raises(observer.Blocked, match="^checkout_traversal_unverified$"):
        observer._observed_files(tmp_path, blobs, dict.fromkeys(blobs, 0o644))
