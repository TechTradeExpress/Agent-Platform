"""PKG-06 synthetic operator records; never host or authenticated live evidence."""

import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location("network_test", ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def network(tmp_path, monkeypatch):
    doctor = load("packaging/worker-provisioning/worker_doctor.py")
    helpers = load("tests/test_worker_doctor.py")
    root = tmp_path / "root"
    root.mkdir()
    root.chmod(0o755)
    real_open, real_meta, real_lstat = os.open, doctor.meta, os.lstat

    def opened(path, flags, **kwargs):
        # Fixed disposable root mapping; production has no --root override.
        if path == "/":
            path = root
        return real_open(path, flags, **kwargs)

    def model_meta(fd, uid=0, gid=0, **kwargs):
        assert uid == gid == 0
        return real_meta(fd, os.getuid(), os.getgid(), **kwargs)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(doctor, "meta", model_meta)
    monkeypatch.setattr(doctor.time, "time", lambda: 1000)
    observer = doctor.Observer()
    observer.artifacts = {"source_commit": "a" * 40}
    observer.accounts = {
        "ap-publisher": {"uid": 999, "gid": 989},
        "ap-publisher-signer": {"uid": 998, "gid": 988},
    }
    paths = {}

    def write(path, data, mode):
        dest = root / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(mode)
        paths[path] = dest
        return dest

    machine = b"a" * 32 + b"\n"
    write("/etc/machine-id", machine, 0o444)
    job = {
        "version": "AP-WP/1",
        "github_ipv4": "140.82.112.5",
        "peer_cert_sha256": "c" * 64,
        "expires": 1100,
    }
    write(doctor.NETWORK_JOB, encoded(job), 0o440)
    paths[doctor.NETWORK_JOB].parent.chmod(0o750)
    dropin = doctor.network_dropin(job["github_ipv4"])
    write(doctor.NETWORK_DROPIN, dropin, 0o644)
    paths[doctor.NETWORK_DROPIN].parent.chmod(0o755)
    record = {
        "schema": "AP-WORKER-NETWORK/1",
        "authority": "root_operator_network_only",
        "machine_id_sha256": sha(machine),
        "job_sha256": sha(encoded(job)),
        "dropin_sha256": sha(dropin),
        "github_ipv4": job["github_ipv4"],
        "peer_cert_sha256": job["peer_cert_sha256"],
        "issued_at": 900,
        "expires_at": 1100,
    }
    write(doctor.NETWORK_APPROVAL, encoded(record), 0o600)

    def query(argv):
        if argv[0] == "/usr/bin/getfacl":
            folder = argv[-1] == "/etc/ap-publisher"
            rights = "r-x" if folder else "r--"
            return "\n".join(
                [
                    "user::" + ("rwx" if folder else "r--"),
                    "group::" + rights,
                    "mask::" + rights,
                    "other::---",
                    "user:999:" + rights,
                    "user:998:" + rights,
                ]
            )
        assert argv[0] == "/usr/bin/systemctl" and argv[1] == "show"
        overrides = {}
        if argv[-1] == "ap-worker-publisher.service":
            overrides = {
                "DropInPaths": doctor.NETWORK_DROPIN,
                "IPAddressAllow": job["github_ipv4"] + "/32",
            }
        return helpers.unit_response(argv, overrides)

    def metadata(path, **kwargs):
        if path == "/sys/fs/bpf":
            return SimpleNamespace(st_mode=stat.S_IFDIR)
        return real_lstat(path, **kwargs)

    monkeypatch.setattr(doctor, "query", query)
    monkeypatch.setattr(os, "lstat", metadata)
    return SimpleNamespace(
        doctor=doctor,
        observer=observer,
        root=root,
        paths=paths,
        record=record,
        job=job,
        query=query,
        write=write,
        helpers=helpers,
    )


def save_record(network):
    network.paths[network.doctor.NETWORK_APPROVAL].write_bytes(encoded(network.record))


def test_exact_authorized_dropin_is_configured_but_never_bpf_proof(network):
    n = network
    assert n.observer.units() == ("CONFIGURED", "verified_effective_unit_settings")
    assert n.observer.bpf() == ("NOT_RUN", "bpf_attachment_evidence_missing")
    observed = n.helpers.GoodObservations()
    observed.units, observed.bpf = n.observer.units, n.observer.bpf
    first = n.doctor.report(observed)
    assert first == n.doctor.report(observed)
    assert first["status"] == "BLOCKED" and not first["launch_allowed"]
    assert first["host_evidence"] == "HOST_NOT_RUN"
    assert first["runtime"] == "LIVE_NO_GO" and first["gate_73"] == "BLOCKED"
    assert first["subscription"] == "SUBSCRIPTION_ISOLATION_BLOCKED"
    assert first["checks"]["bpf"]["state"] == "NOT_RUN"
    wire = json.dumps(first)
    assert n.job["github_ipv4"] not in wire
    assert n.record["job_sha256"] not in wire
    assert "READY_FOR_SUPERVISED_PUBLISHING" not in wire
    schema = json.loads((ROOT / "docs/worker-doctor.schema.json").read_text())
    assert set(first["checks"]) == set(schema["properties"]["checks"]["required"])
    for check in first["checks"].values():
        assert (
            check["reason"] in schema["$defs"]["check"]["properties"]["reason"]["enum"]
        )


def test_no_dropin_and_no_approval_keep_inert_default(network, monkeypatch):
    n = network
    n.paths[n.doctor.NETWORK_APPROVAL].unlink()
    n.paths[n.doctor.NETWORK_DROPIN].unlink()
    n.paths[n.doctor.NETWORK_DROPIN].parent.rmdir()
    monkeypatch.setattr(
        n.doctor,
        "query",
        lambda argv: (
            n.query(argv)
            if argv[0] == "/usr/bin/getfacl"
            else n.helpers.unit_response(argv)
        ),
    )
    assert n.observer.units()[0] == "CONFIGURED"
    with pytest.raises(n.doctor.Blocked, match="bpf_egress_policy_missing"):
        n.observer.bpf()


@pytest.mark.parametrize("missing", ["approval", "dropin", "machine", "job"])
def test_missing_required_record_cannot_be_approved(network, missing):
    n = network
    path = {
        "approval": n.doctor.NETWORK_APPROVAL,
        "dropin": n.doctor.NETWORK_DROPIN,
        "machine": "/etc/machine-id",
        "job": n.doctor.NETWORK_JOB,
    }[missing]
    n.paths[path].unlink()
    with pytest.raises((n.doctor.Blocked, FileNotFoundError)):
        n.observer.units()
    assert n.observer._network_verified is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("extra", "SECRET"),
        ("schema", "unknown"),
        ("authority", "model_pass"),
        ("job_sha256", "0" * 64),
        ("machine_id_sha256", "0" * 64),
        ("dropin_sha256", "0" * 64),
        ("peer_cert_sha256", "0" * 64),
        ("issued_at", True),
        ("expires_at", 1000),
        ("issued_at", 1001),
        ("issued_at", 1),
        ("expires_at", 0),
    ],
)
def test_unknown_stale_or_mismatched_approval_blocks(network, field, value):
    n = network
    n.record[field] = value
    save_record(n)
    with pytest.raises(n.doctor.Blocked):
        n.observer.units()
    assert n.observer._network_verified is None


@pytest.mark.parametrize(
    "peer",
    [
        "",
        "github.com",
        "140.82.112.5/32",
        "140.82.112.0/24",
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.2",
        "192.0.2.1",
        "224.0.0.1",
        "::1",
        "2001:4860:4860::8888",
        "140.82.112.5 140.82.112.6",
        "140.82.112.5\nExecStart=/evil",
    ],
)
def test_only_single_explicit_public_ipv4_is_expressible(network, peer):
    network.record["github_ipv4"] = peer
    save_record(network)
    with pytest.raises((network.doctor.Blocked, ValueError)):
        network.observer.units()


@pytest.mark.parametrize(
    "payload",
    [
        b"[Service]\nIPAddressAllow=any\n",
        b"[Service]\nIPAddressAllow=0.0.0.0/0\n",
        b"[Service]\nIPAddressAllow=140.82.112.5/24\n",
        b"[Service]\nIPAddressAllow=140.82.112.6/32\n",
        b"[Service]\nIPAddressAllow=\nIPAddressAllow=140.82.112.5/32\nExecStart=/evil\n",
    ],
)
def test_modified_dropin_is_not_accepted_even_if_operator_hash_matches(
    network, payload
):
    n = network
    n.paths[n.doctor.NETWORK_DROPIN].write_bytes(payload)
    n.record["dropin_sha256"] = sha(payload)
    save_record(n)
    with pytest.raises(n.doctor.Blocked, match="network_binding_mismatch"):
        n.observer.units()


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "DropInPaths",
            "/run/systemd/system/ap-worker-publisher.service.d/override.conf",
        ),
        ("DropInPaths", ""),
        ("DropInPaths", "EXTRA"),
        ("IPAddressAllow", "140.82.112.6/32"),
        ("IPAddressAllow", "140.82.112.5/32 140.82.112.6/32"),
        ("IPAddressAllow", "0.0.0.0/0"),
        ("IPAddressAllow", ""),
        ("IPAddressDeny", ""),
        ("SocketBindDeny", ""),
        ("RestrictAddressFamilies", "AF_INET AF_INET6"),
        ("NoNewPrivileges", "no"),
        ("ActiveState", "active"),
    ],
)
def test_effective_properties_must_equal_exact_closed_expectation(
    network, monkeypatch, field, value
):
    n = network

    def query(argv):
        text = n.query(argv)
        if (
            argv[0] == "/usr/bin/systemctl"
            and argv[-1] == "ap-worker-publisher.service"
        ):
            replacement = (
                n.doctor.NETWORK_DROPIN + " /tmp/extra.conf"
                if value == "EXTRA"
                else value
            )
            text = "\n".join(
                field + "=" + replacement if line.startswith(field + "=") else line
                for line in text.splitlines()
            )
        return text

    monkeypatch.setattr(n.doctor, "query", query)
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.units()


def test_signer_dropin_is_always_rejected(network, monkeypatch):
    n = network

    def query(argv):
        text = n.query(argv)
        if argv[-1] == "ap-worker-publisher-signer.service":
            text = text.replace(
                "DropInPaths=", "DropInPaths=" + n.doctor.NETWORK_DROPIN
            )
        return text

    monkeypatch.setattr(n.doctor, "query", query)
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.units()


@pytest.mark.parametrize("which", ["approval", "dropin", "job", "machine"])
@pytest.mark.parametrize("defect", ["symlink", "hardlink", "write", "setid"])
def test_real_input_metadata_and_aliases_fail_closed(network, which, defect):
    n = network
    path = n.paths[
        {
            "approval": n.doctor.NETWORK_APPROVAL,
            "dropin": n.doctor.NETWORK_DROPIN,
            "job": n.doctor.NETWORK_JOB,
            "machine": "/etc/machine-id",
        }[which]
    ]
    if defect == "symlink":
        path.unlink()
        path.symlink_to("/never-read-private-sentinel")
    elif defect == "hardlink":
        os.link(path, path.with_name(path.name + ".alias"))
    else:
        path.chmod(0o666 if defect == "write" else 0o4644)
    with pytest.raises((n.doctor.Blocked, OSError)):
        n.observer.units()


@pytest.mark.parametrize(
    "attribute",
    [
        "security.capability",
        "system.posix_acl_access",
        "system.posix_acl_default",
        "system.nfs4_acl",
    ],
)
def test_approval_has_no_acl_or_capabilities(network, monkeypatch, attribute):
    n = network
    real = os.listxattr
    inode = n.paths[n.doctor.NETWORK_APPROVAL].stat().st_ino
    monkeypatch.setattr(
        os,
        "listxattr",
        lambda fd: [attribute] if os.fstat(fd).st_ino == inode else real(fd),
    )
    with pytest.raises(n.doctor.Blocked, match="unsafe_attributes"):
        n.observer.units()


def test_foreign_owner_rejected(network, monkeypatch):
    n = network
    real = os.fstat
    inode = n.paths[n.doctor.NETWORK_DROPIN].stat().st_ino

    def changed(fd):
        value = real(fd)
        if value.st_ino == inode:
            fields = {
                name: getattr(value, name)
                for name in dir(value)
                if name.startswith("st_")
            }
            fields["st_uid"] = os.getuid() + 1
            return SimpleNamespace(**fields)
        return value

    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(n.doctor.Blocked, match="unsafe_metadata"):
        n.observer.units()


@pytest.mark.parametrize("kind", ["job", "dropin", "approval", "expiry", "effective"])
def test_drift_between_units_and_bpf_invalidates_correlation(
    network, monkeypatch, kind
):
    n = network
    n.observer.units()
    if kind == "expiry":
        monkeypatch.setattr(n.doctor.time, "time", lambda: 1100)
    elif kind == "effective":
        monkeypatch.setattr(
            n.doctor,
            "query",
            lambda argv: (
                n.query(argv)
                if argv[0] == "/usr/bin/getfacl"
                else n.helpers.unit_response(argv)
            ),
        )
    else:
        path = n.paths[
            {
                "job": n.doctor.NETWORK_JOB,
                "dropin": n.doctor.NETWORK_DROPIN,
                "approval": n.doctor.NETWORK_APPROVAL,
            }[kind]
        ]
        # Byte-identical replacement is still a changed object, not same approval.
        data, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
        path.rename(path.with_name(path.name + ".preserved"))
        path.write_bytes(data)
        path.chmod(mode)
    with pytest.raises(n.doctor.Blocked):
        n.observer.bpf()


def test_ancestor_replacement_during_read_is_detected(network, monkeypatch):
    n = network
    real_read = os.read
    ancestor = n.paths[n.doctor.NETWORK_APPROVAL].parent

    def changed(fd, limit):
        data = real_read(fd, limit)
        if data.startswith(b'{"authority"'):
            ancestor.rename(ancestor.with_name("preserved"))
            ancestor.mkdir()
            (ancestor / "publisher-network.json").write_bytes(data)
        return data

    monkeypatch.setattr(os, "read", changed)
    with pytest.raises(n.doctor.Blocked, match="network_observation_changed"):
        n.observer.units()


def test_failed_recheck_clears_prior_correlation(network, monkeypatch):
    n = network
    n.observer.units()
    monkeypatch.setattr(n.doctor.time, "time", lambda: 1100)
    with pytest.raises(n.doctor.Blocked):
        n.observer.units()
    assert n.observer._network_verified is None


def test_bpf_cannot_skip_successful_units_verification(network):
    with pytest.raises(network.doctor.Blocked, match="network_verification_required"):
        network.observer.bpf()


@pytest.mark.parametrize(
    "name", ["extra.conf", "README", "50-agent-platform-network.conf.bak"]
)
def test_extra_physical_dropin_entries_block_even_if_not_loaded(network, name):
    n = network
    (n.paths[n.doctor.NETWORK_DROPIN].parent / name).write_bytes(b"unreviewed")
    with pytest.raises(n.doctor.Blocked, match="network_approval_invalid"):
        n.observer.units()


@pytest.mark.parametrize("target", ["/etc/ap-publisher", "/etc/ap-publisher/job.json"])
def test_job_acl_cannot_grant_extra_principals(network, monkeypatch, target):
    n = network

    def query(argv):
        result = n.query(argv)
        if argv[0] == "/usr/bin/getfacl" and argv[-1] == target:
            result += "\nuser:1001:r--"
        return result

    monkeypatch.setattr(n.doctor, "query", query)
    with pytest.raises(n.doctor.Blocked, match="config_acl_invalid"):
        n.observer.units()


@pytest.mark.parametrize(
    "defect", ["duplicate", "malformed", "not_canonical", "oversize"]
)
def test_approval_wire_is_bounded_canonical_and_duplicate_free(network, defect):
    n = network
    raw = encoded(n.record)
    if defect == "duplicate":
        raw = raw.replace(b"{", b'{"schema":"AP-WORKER-NETWORK/1",', 1)
    elif defect == "malformed":
        raw = b"{bad"
    elif defect == "not_canonical":
        raw = json.dumps(n.record, indent=2).encode()
    else:
        raw += b" " * 65536
    n.paths[n.doctor.NETWORK_APPROVAL].write_bytes(raw)
    with pytest.raises((n.doctor.Blocked, ValueError)):
        n.observer.units()


def test_stale_manager_cache_is_rejected(network, monkeypatch):
    n = network

    def query(argv):
        return n.query(argv).replace("NeedDaemonReload=no", "NeedDaemonReload=yes")

    monkeypatch.setattr(n.doctor, "query", query)
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.units()


def test_read_permission_denied_is_not_operator_approval(network, monkeypatch):
    n = network

    def denied(*_args, **_kwargs):
        raise PermissionError("SECRET")

    monkeypatch.setattr(n.doctor, "network_read", denied)
    observed = n.helpers.GoodObservations()
    observed.units, observed.bpf = n.observer.units, n.observer.bpf
    report = n.doctor.report(observed)
    assert report["checks"]["units"] == {
        "state": "NOT_RUN",
        "reason": "observation_denied",
    }
    assert report["checks"]["bpf"]["state"] == "NOT_RUN"
    assert not report["launch_allowed"] and "SECRET" not in json.dumps(report)


@pytest.mark.parametrize("field", ["st_uid", "st_gid"])
def test_record_foreign_identity_is_rejected(network, monkeypatch, field):
    n = network
    original = os.fstat
    inode = n.paths[n.doctor.NETWORK_APPROVAL].stat().st_ino

    def observed(fd):
        value = original(fd)
        if value.st_ino == inode:
            fields = {
                name: getattr(value, name)
                for name in dir(value)
                if name.startswith("st_")
            }
            fields[field] += 1
            return SimpleNamespace(**fields)
        return value

    monkeypatch.setattr(os, "fstat", observed)
    with pytest.raises(n.doctor.Blocked, match="unsafe_metadata"):
        n.observer.units()


def test_mutation_while_manager_is_observed_cannot_be_cached(network, monkeypatch):
    n = network
    changed = False

    def query(argv):
        nonlocal changed
        result = n.query(argv)
        if argv[0] == "/usr/bin/systemctl" and not changed:
            changed = True
            path = n.paths[n.doctor.NETWORK_DROPIN]
            data = path.read_bytes()
            # Distinct inode: deterministic even on coarse timestamp filesystems.
            path.rename(path.with_name("preserved.conf"))
            path.write_bytes(data)
            path.chmod(0o644)
            path.with_name("preserved.conf").unlink()
        return result

    monkeypatch.setattr(n.doctor, "query", query)
    with pytest.raises(n.doctor.Blocked, match="network_observation_changed"):
        n.observer.units()
    assert n.observer._network_verified is None


def test_unknown_peer_cannot_reuse_approved_job(network):
    n = network
    peer = "140.82.112.6"  # Fabricated distinct public literal, not endpoint evidence.
    dropin = n.doctor.network_dropin(peer)
    n.paths[n.doctor.NETWORK_DROPIN].write_bytes(dropin)
    n.record.update(github_ipv4=peer, dropin_sha256=sha(dropin))
    save_record(n)
    with pytest.raises(n.doctor.Blocked, match="network_binding_mismatch"):
        n.observer.units()


def test_normal_getfacl_trailing_blank_line_is_not_an_extra_acl(network, monkeypatch):
    n = network

    def query(argv):
        text = n.query(argv)
        return text + "\n\n" if argv[0] == "/usr/bin/getfacl" else text

    monkeypatch.setattr(n.doctor, "query", query)
    assert n.observer.units()[0] == "CONFIGURED"
    assert n.observer.bpf() == ("NOT_RUN", "bpf_attachment_evidence_missing")


DENY_ORDERS = ("0.0.0.0/0 ::/0", "::/0 0.0.0.0/0")
INVALID_DENY = (
    "",
    "0.0.0.0/0",
    "::/0",
    "0.0.0.0/0 0.0.0.0/0",
    "::/0 ::/0",
    "0.0.0.0/0 ::/0 ::/0",
    "::/0 0.0.0.0/0 0.0.0.0/0",
    "0.0.0.0/0 ::/0 192.0.2.1/32",
    "any",
    "any ::/0",
    "0/0 ::/0",
    "0.0.0.0/0 0:0:0:0:0:0:0:0/0",
    "0.0.0.0/1 ::/0",
    "0.0.0.0/0 ::/1",
)


def deny_query(network, value, approved=True, **overrides):
    """Vary only explicit publisher properties; retain signer/ACL responses."""
    base = network.query if approved else network.helpers.unit_response
    changes = {"IPAddressDeny": value} | overrides

    def query(argv):
        text = base(argv)
        if (
            argv[0] == "/usr/bin/systemctl"
            and argv[-1] == "ap-worker-publisher.service"
        ):
            rows = [line.split("=", 1) for line in text.splitlines()]
            text = "\n".join(k + "=" + changes.get(k, v) for k, v in rows)
        return text

    return query


def unconfigure_network(network):
    network.paths[network.doctor.NETWORK_APPROVAL].unlink()
    network.paths[network.doctor.NETWORK_DROPIN].unlink()
    network.paths[network.doctor.NETWORK_DROPIN].parent.rmdir()


@pytest.mark.parametrize("approved", [False, True], ids=["inert", "approved"])
@pytest.mark.parametrize(
    "value", DENY_ORDERS, ids=["ipv4-first", "worker01-ipv6-first"]
)
def test_deny_prefix_order_is_not_an_egress_or_bpf_authorization(
    network, monkeypatch, approved, value
):
    n = network
    if not approved:
        unconfigure_network(n)
    monkeypatch.setattr(n.doctor, "query", deny_query(n, value, approved))
    assert n.observer.units() == ("CONFIGURED", "verified_effective_unit_settings")
    if approved:
        assert n.observer.bpf() == ("NOT_RUN", "bpf_attachment_evidence_missing")
    else:
        with pytest.raises(n.doctor.Blocked, match="bpf_egress_policy_missing"):
            n.observer.bpf()


@pytest.mark.parametrize("approved", [False, True], ids=["inert", "approved"])
@pytest.mark.parametrize("value", INVALID_DENY)
def test_deny_requires_exactly_two_distinct_canonical_default_prefixes(
    network, monkeypatch, approved, value
):
    n = network
    if not approved:
        unconfigure_network(n)
    monkeypatch.setattr(n.doctor, "query", deny_query(n, value, approved))
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.units()
    assert n.observer._network_verified is None


@pytest.mark.parametrize("value", INVALID_DENY)
def test_bpf_rechecks_deny_cardinality_and_canonical_membership(
    network, monkeypatch, value
):
    n = network
    n.observer.units()
    monkeypatch.setattr(n.doctor, "query", deny_query(n, value))
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.bpf()


@pytest.mark.parametrize(
    "field,value",
    [
        ("DropInPaths", ""),
        ("DropInPaths", "EXTRA"),
        ("IPAddressAllow", "140.82.112.5/32 140.82.112.6/32"),
        ("SocketBindDeny", ""),
        ("RestrictAddressFamilies", "AF_INET AF_INET6"),
        ("NeedDaemonReload", "yes"),
    ],
)
def test_ipv6_first_deny_does_not_relax_other_exact_properties(
    network, monkeypatch, field, value
):
    n = network
    if value == "EXTRA":
        value = n.doctor.NETWORK_DROPIN + " /run/foreign.conf"
    monkeypatch.setattr(
        n.doctor, "query", deny_query(n, DENY_ORDERS[1], **{field: value})
    )
    with pytest.raises(n.doctor.Blocked, match="unit_constraints_rejected"):
        n.observer.units()
