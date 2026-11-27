# PUB-11 worker01 isolated recovery rehearsal

**STOP on worker01.** A fresh root and nested systemd 257 PID 1 are plausible,
but no approved launcher can currently demonstrate equivalent isolation while
preserving the exact recovery profiles, role labels and per-unit BPF enforcement.
Exact offline recovery remains **NOT_TESTED**. PUB-10 live-unit rehearsal remains
**BLOCKED**. The smallest viable exact-unit alternative is one temporary,
disconnected Debian 13 amd64 VM under [PUB-09](worker01-recovery-host-rehearsal.md).
Reuse it sequentially from a clean image for independent fixtures. PUB-10 requires
separate approval and a fresh fixture. Source simulations can proceed independently.

Subject to independent review, the plan below defines what an alternate target
would have to demonstrate. It carries no authority to run it. No installed
candidate changes, host profile changes, production generation spend, or GitHub
traffic are in scope. #183 remains open, #73 and #168 remain gated, and
#169/#108 remain LIVE NO-GO.

## Evidence and feasibility

Source baseline is `19848a974084cd8cef1c681e5fedb526c0cf192a`. The installed
candidate is `0.1.0-9~git7b5f0506998341bd3b2bf8524d6240a78033fa23`, source tree
`fdb1218e0bc15fbfe0b63656c9bf42eaabeb0cc4`, archive SHA256
`13477bf9782aa4899440b9c98dedfbfda6f64f06b650315685c346d157e8f292`.
The protected archive stays in operator custody. #183 records Debian 13 amd64,
systemd 257, recovery units loaded and idle, recovery profiles absent, the opt-in
unit absent, and frozen historical state preserved during installation and
maintenance restoration. The earlier combined #183 probe used adapted paths and
units. [Post-install review](https://github.com/TechTradeExpress/Agent-Platform/issues/183#issuecomment-7203188631)
and [restoration record](https://github.com/TechTradeExpress/Agent-Platform/issues/183#issuecomment-7203268589).

| Boundary | Required equivalence and current disposition |
| --- | --- |
| Fresh root, namespaces and PID 1 | A chroot or systemd RootDirectory leaves the host manager in charge. A booted private mount/PID/user/network/IPC/UTS/cgroup namespace can provide a distinct manager, but still shares worker01's kernel. Require disjoint, preapproved host UID/GID maps for inner root and both roles, private mount propagation and procfs, fresh /run, isolated minimal devices, no inherited file descriptors, host mounts, host manager bus or routes. No existing approved launcher or image attestation has been shown. NOT_TESTED. |
| nspawn or LXC | A launcher name establishes no guarantees. Reject identity mapping, unsafe capabilities, writable host sysfs/cgroups, credential forwarding, host integrations and an unconfined host-root payload. Verify the full effective launcher configuration and process tree. NOT_TESTED. |
| AppArmor | A mount or user namespace does not create a policy namespace. Require independently provisioned private AppArmor policy scope, audited host-side confinement and exact compiled policy including pinned Debian includes. The role compares /proc/self/attr/current byte-for-byte with its bare profile name plus ` (enforce)`. Namespace-relative and host-side views can differ, and a stacked label can break that check. Capture both views and verify exact labels, enforcing transitions, path mediation and signals from the manager under the declared policy. Namespaced loading requires a supported, authorized control path. STOP on a renamed, stacked-but-incompatible, complain-mode or missing label, or any need to touch global policy. |
| cgroup v2 and BPF | A writable delegated child subtree can support resource controls, but it does not grant the privileges needed to load and attach cgroup BPF. The nested manager may omit filtering where it cannot attach. Require actual effective IPv4/IPv6 ingress/egress and bind programs on the role cgroups, including inherited programs, plus traffic tests. A parent deny-all is useful outer containment and cannot prove per-unit filtering. No approved mechanism is evidenced. STOP if it requires initial-user-namespace privileges for the payload, writable ancestor/sibling cgroups or relaxed policy. |
| PID 1 credentials | A real inner system manager must resolve exact paths inside the new root and copy only declared leaves into each service's read-only credential mount. Check mount identity and ACL or accepted UID-owned fallback under remapping. Direct file injection, granting role read access to sources or setting CREDENTIALS_DIRECTORY by hand invalidates the proof. NOT_TESTED. |
| Availability | Require funded disk, inode and memory headroom, bounded I/O, CPU, PIDs, journal size and elapsed time at the outer boundary. No headroom or containment evidence is available. NOT_TESTED. |

References for operator review include
[systemd 257 service isolation and credential semantics](https://freedesktop.org/software/systemd/man/257/systemd.exec.html),
[AppArmor policy namespace semantics](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorNamespaces),
and [kernel cgroup v2 delegation and containment](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Operator preflight (read-only)

Run individually from the established operator session on worker01. Capture
exit status and errors locally. Report missing tools, unreadable data and
absent paths separately. Do not obtain additional access to fill a gap. Retain
only approved redacted results. Use no tracing of secret-bearing processes and
no module imports. This inventory is point-in-time evidence, so it cannot prove
effective maintenance exclusion or nested enforcement.

```sh
date -u +%FT%TZ
hostname
uname -smr
cat /etc/debian_version
systemctl --version
dpkg-query -W -f='${Package} ${Architecture} ${Version} ${Status}\n' agent-platform-worker
dpkg --verify agent-platform-worker
dpkg --audit
command -v systemd-nspawn lxc-start apparmor_parser bpftool nft getfacl
cat /sys/module/apparmor/parameters/enabled
cat /sys/kernel/security/lsm
cat /sys/kernel/security/apparmor/profiles
stat -fc '%T' /sys/fs/cgroup
findmnt -no FSTYPE,OPTIONS,PROPAGATION -T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
grep -E '^CONFIG_(USER_NS|PID_NS|NET_NS|CGROUPS|CGROUP_BPF|BPF_SYSCALL|SECURITY_APPARMOR)=' "/boot/config-$(uname -r)"
getent passwd ap-publisher ap-publisher-signer
id ap-publisher
id ap-publisher-signer
df -Pk /var/lib /run
df -Pi /var/lib /run
grep -E '^(MemAvailable|SwapFree):' /proc/meminfo
systemctl --system list-jobs --no-pager
systemctl --system show --all --no-pager \
  --property=Id,Names,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,Result,ExecMainStatus,MainPID,ControlPID,Job,ControlGroup,User,Group,SupplementaryGroups,AppArmorProfile,PrivateNetwork,IPAddressAllow,IPAddressDeny,RestrictAddressFamilies,SocketBindDeny,Restart,LoadCredential,NetworkNamespacePath \
  ap-worker-publisher.service ap-worker-publisher-signer.service \
  ap-worker-publisher-recovery.service ap-worker-publisher-recovery-signer.service \
  ap-worker-publisher-recovery-live.service
```

If bpftool is readable in the established context, use `bpftool cgroup tree
/sys/fs/cgroup effective` locally to inventory attachments. Correlate IDs to
the recorded cgroups. Never infer enforcement from declarations, build flags
or an empty/permission-denied listing. Do not use feature probes that load BPF.

For metadata only, run the following with the same paths before and after any
future authorized activity. Inspect each parent for links before inspecting
children. Missing recovery fixture paths on the host are expected and must stay
missing. A present production key is a hard collision for any host-root
rehearsal. Store credential metadata comparisons locally as match/differ/unreadable.

```sh
for p in /etc/ap-publisher /etc/ap-publisher-keys /etc/ap-publisher-keys/worker.pem \
  /etc/ap-publisher-recovery-169 /var/lib/ap-publisher /var/lib/ap-publisher-signer \
  /var/lib/ap-publisher-recovery /var/lib/ap-publisher-recovery-169-publisher \
  /var/lib/ap-publisher-recovery-169-signer /run/ap-publisher-signer \
  /run/ap-publisher-signer/app-jwt /run/ap-publisher-recovery-169-grants \
  /run/ap-publisher-recovery-169-live /run/ap-publisher-recovery-169-artifact \
  /run/ap-publisher-recovery-169-signer /run/ap-publisher-recovery-169-publisher \
  /run/credentials/ap-worker-publisher-recovery.service \
  /run/credentials/ap-worker-publisher-recovery-signer.service \
  /run/credentials/ap-worker-publisher-recovery-live.service \
  /run/netns/ap-worker-publisher-recovery-live
do
  namei -l -- "$p"
done
# After reviewing the namei output, repeat this command for each approved path.
stat --printf='%F %a %u:%g %d:%i %h %s %y %z %n\n' -- "$reviewed_leaf"
```

On the separately retained custody inventory, review the exact leaf paths and
ACLs with `getfacl -p -- "$reviewed_leaf"` after link checks. Verify the existing
six approved nonsecret frozen-state checks locally against the operator's
retained manifest. Inspect each manifest entry before running any checksum
command. Never read or hash a key, JWT, token, credential leaf or credential
packet. Compare unit fragments, allowlist, journals and archive only where
already classified as nonsecret by custody. Missing custody or inventory means
STOP. Compare the complete loaded policy inventory and historical effective
unit metadata without exporting unrelated entries.

With the protected candidate under operator custody on the review system, use
`namei -l -- "$candidate"`, `stat -- "$candidate"`,
`sha256sum -- "$candidate"`, `dpkg-deb --field "$candidate" Package Version
Architecture` and `dpkg-deb --contents "$candidate"`. Verify root-owned,
non-writable ancestors and singly linked archive against the pinned identity.
Check the independently retained provenance and the exact role files against
the package. No package extraction on worker01 is required for preflight.

## Consolidated execution plan for separate authorization

1. **Review and fence.** Require one signed-off target-specific plan naming
   image, launcher, confinement and BPF attachment mechanism, observer and
   operator, exact approved archive and scope, probe method, resource budget,
   deadline, paths, cgroup and cleanup identities. Record a read-only baseline
   and prove continuous exclusion of competing manager calls, profile changes,
   automation and custody writers. A flock alone cannot exclude them. Keep the
   historical failed Publisher and inactive Signer untouched. If containment
   would require changing worker01 host policy or exposing host state, stop
   before creating a fixture and move to the disposable VM procedure.
2. **Establish the outer boundary before boot.** Build from a pinned clean
   Debian 13 amd64 rootfs with a minimal target and no automatic role
   activation. Verify the protected rev9 package then extract into the fresh
   root with dpkg-deb (no maintainer scripts on worker01). Record the exact
   packaged files and distribution dependency/include digests. Within the
   fixture, provision only the package-required users, directories, systemd dependencies and ACLs
   from the reviewed package contract. Reject stale jobs, aliases, drop-ins,
   symlinks, unexpected files or inherited credentials. Check that a synthetic
   host-side sentinel outside the root, host bus and sibling cgroups are
   unreachable. For offline recovery allow no NIC, veth, routes or host socket
   forwarding. Before launch require measured headroom and enforce proposed
   ceilings of 1 GiB memory, 96 tasks, one CPU, 4 GiB disk (including a 32 MiB
   journal budget), bounded storage I/O and 10 minutes per case. Lower ceilings
   only if compatible with exact units. The exact role limits remain in force.
3. **Generate each fixture from scratch.** Use a deterministic fabricated Git
   parent/tree/commit and bounded AP-WP/1 graph, fake repository/installation
   evidence and disposable RSA App key generated within the new root. Generate
   independent synthetic approval and observer keys in a custody context
   separate from both roles. Use a fresh launch ID, bounded expiry, per-case
   ledger and new journal identities. Preserve the compiled case/generation
   strings inside the fixture because the roles validate them. Scope their
   meaning to the synthetic root and synthetic trust anchors. Never clone a
   worker disk or copy production evidence, keys, trust stores or ledger. Use
   fabrications under the historical paths for denial tests.
4. **Stage and launch.** Reuse the construction and verification in
   `worker_publish_generation.dispatch`, `worker_publish_pre_spend`,
   `worker_publish_recovery_paths` and `tests/test_worker_publish_generation.py`
   as the fixture-builder specification. Independently review the exact future
   fixture harness before approval. The stock `recovery-handoff` operator
   requires pinned frozen v4 and must refuse fabricated v4. For the positive
   role test, synthesize the canonical signed observation, spent approval,
   independent pre-spend receipt and per-role grants in the existing formats.
   Retain pre-spend externally to the fixture and use exclusive, fsynced
   writes, with no regenerated grant on a lost response.
   Stage root-private grant sources at
   `/run/ap-publisher-recovery-169-grants/{signer,publisher}.json` (directory
   0700, leaves 0600), synthetic pin at
   `/etc/ap-publisher-recovery-169/approval-pin` and synthetic App key at
   `/etc/ap-publisher-keys/worker.pem` (root:root 0600). Stage the separate
   candidate channel at `/run/ap-publisher-recovery-169-artifact/candidate.json`
   (root:root 0440, exactly both role UID read ACLs). Bind its inode/device and
   bytes to the grant. Use fresh role-owned 0600 journals in private directories.
   Hold the live controller's POSIX lock on the create-only liveness leaf
   `/run/ap-publisher-recovery-169-live` (root:root 0644, 64-byte launch ID).
   Start the exact recovery Signer through inner PID 1 only. Verify durable
   terminal journal and same-launch output, then bind its result and journal
   to the signed Publisher grant. Start the exact offline Publisher via the
   same manager. No test transport in the deployed wrapper. Require
   `HANDOFF_VERIFIED` and `publication=DISABLED`, with zero peer events.
5. **Collect positive and negative evidence.** For actual invocation IDs/PIDs,
   record fragment bytes, exact manager properties, namespace identities,
   cgroup lineage and attached programs, effective AppArmor labels, capability
   sets, no-new-privileges, credential mount/ACL metadata and intended
   journal/output writes. Use the actual runtime path to prove reads from
   PID 1's copies (`handoff`, `approval-pin`, and Signer-only `app-key`).
   Test denial of cross-role copies, staging, direct key source, historical
   paths, host sentinels and cross-role state. Demonstrate kernel policy on
   synthetic accesses where DAC would permit them, and independently verify DAC
   role denial. For both roles demonstrate IPv4/IPv6 refusal, absence of
   packets and effective address/bind programs. AF_UNIX-only refusal alone
   cannot prove BPF caused a denial. Correlate attributed audit and probe
   evidence to the relevant layer. Preapprove probes and distinguish actual
   service evidence from a helper running with altered unit, label, process
   context or cgroup. If necessary negatives cannot be observed without
   adaptation, they remain NOT_TESTED for the exact unit, and the gate stays
   blocked.
6. **Faults, one clean fixture per case.** Test missing/invalid ACL, altered
   grant/handoff or artifact identity, expired grant, duplicate start with
   retained state, lost controller before claim, after durable UNKNOWN,
   and after durable terminal write before acknowledgment. Expect refusal
   before claim where appropriate, no reconstructed lease or replay, and
   preserved spent/ambiguous records. Test failed file and directory fsyncs
   with reviewed fault injection in synthetic tests and label adapted
   results accordingly. Offline Publisher has no remote UNKNOWN operation.
   Exercise before-send UNKNOWN, lost response and revocation boundaries only
   in the injected offline transport test or the separately approved PUB-10
   fixture. A controlled loss of a fixture process cannot prove power-loss
   durability. Never crash or reboot worker01.
7. **Contain and retire.** Record UTC, target/image, boot and namespace
   identities, binaries/package/source pins, effective manager and kernel
   evidence, case IDs, run order, redacted journal phase/sequence and
   durability observations, expected/actual outcomes, observer and approval
   references, and PASS/FAIL/NOT_TESTED/STOP per boundary. Retain no secret
   bytes or secret digests in logs, repo or outbox. On drift, lost reply,
   unexpected PID, journal ambiguity, cap breach or deadline, stop dispatch
   and quarantine. Under explicit cleanup authority, stop only the inventoried
   fixture manager/processes through their verified handles and confirm its
   cgroup is empty. Release only owned fixture namespace/mount/policy handles
   after checking identities, descendants, mount propagation and external
   references. Delete only the manifest-owned private fixture directory on
   the same expected filesystem once unmounted. No global cleanup, no
   overwrite, no unlink of an uncertain or pre-existing path. Preserve
   redacted evidence and consumed synthetic ledger across cleanup. Repeat
   the preflight and custody comparisons under exclusion. A missing
   post-check, mismatch or unowned residual requires human reconciliation
   before ending maintenance. Secret metadata comparisons cannot prove
   credential-byte identity.

## Separate PUB-10 live-unit rehearsal

Follow the [PUB-10 runbook](worker01-recovery-live-publisher.md) in its approved
disposable VM. The opt-in live unit is outside rev9. Use exact opt-in source
wrapper, unit and profile with only the runbook's single numeric
`IPAddressAllow=<synthetic IPv4>/32` substitution, plus the unchanged
Signer. Bind the existing signed egress-policy fields to effective PID 1 values,
boot ID, namespace device/inode and retained kernel evidence. The synthetic
observer signs the policy and the synthetic operator authorizes the distinct
live grant. With a new disconnected fixture, connect only the publisher netns
and the synthetic HTTPS peer. Use no uplink, DNS forwarding, host bridge,
NAT, or proxy. Trust a test CA only in the fixture, with a server cert for
`api.github.com` and local routing to the numeric test peer. Verify canonical
SNI and TLS validation plus wrong CA, hostname and connected peer failures.

Load and verify default-deny input/output/forward nft rules exclusively in the
publisher namespace. Require the one TCP/443 peer and established replies.
Prove effective cgroup BPF and actual namespace packet outcomes from the
declared role boundary: approved peer on TCP/443 passes, same peer on another
port and another IPv4 on 443 fail, UDP/DNS and IPv6 fail, and Signer has no IP
access. Include decoy listeners where needed to distinguish a policy denial
from no listener or no route. Verify readback and revocation against the
scripted peer only, and require durable UNKNOWN before each synthetic effect.
A live-unit synthetic success has no GitHub publication meaning. If these
checks need relaxed profiles, host nft changes or an adapted unit, retain
BLOCKED. The PUB-10 disposable VM gate and all production admission and
release gates continue to apply.
