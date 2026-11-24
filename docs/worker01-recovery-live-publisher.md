# PUB-10 worker01 recovery Publisher

**SOURCE_ONLY / NOT_EXECUTED / LIVE NO-GO.** The Debian rev. 9 candidate
installs the existing network-denied recovery Publisher and Signer. The
opt-in unit, executable, AppArmor profile and nftables template are review
inputs under `packaging/worker-publisher/opt-in/`. They are outside package
installation. Exact-unit rehearsal under #183 and release custody under #168
are separate gates. This runbook requires separate operator authorization
before any host action or real credential use.

## Prepare and verify the opt-in boundary

1. Pin the clean source HEAD/tree, rev. 9 candidate version, package digests,
   installed predecessor and extracted package contents. Follow the upgrade
   and v4 preservation procedure in
   [PUB-09](worker01-recovery-host-rehearsal.md). First rehearse the exact
   separate live unit and unchanged Signer in an approved disposable VM with
   synthetic inputs and a test-only HTTPS peer. Use an isolated route for the
   numeric peer and a synthetic CA trusted only inside the disconnected VM. Keep real keys, JWTs, tokens and
   v4 data out of the rehearsal. A simulated wire never establishes live
   GitHub success.
2. Under maintenance exclusion, prevent all other privileged starts,
   namespace/cgroup changes, firewall reloads, credential staging writes and
   competing controller invocations until the result is retained. The
   controller flock coordinates cooperating processes. Verify idle units,
   cgroups and queues and pin package-owned Python sources, distinct users,
   profiles and existing journal identities. Preserve the v4 units, allowlist
   and journals. Use only the empty, explicitly approved recovery journals.
3. Review and provision the dedicated network namespace at
   `/run/netns/ap-worker-publisher-recovery-live` under root custody. Use
   dedicated routing and apply `recovery-egress.nft` **inside that namespace**,
   replacing the documentation IPv4 with the independently approved job peer.
   Require default-deny input/output/forward, one outgoing TCP destination
   IPv4 and port 443, and established replies from that peer and port. Disable
   IPv6 and exclude extra interfaces, routes, tunnels, NAT/redirect rules and
   shared/untrusted processes that could undermine this boundary. Check the
   resulting namespace and effective nftables hooks, policies and rules.
   Systemd IP filtering alone does not filter ports.
4. Review the opt-in source files. After separate approval, deploy the wrapper
   to `/usr/libexec/ap-worker-publisher-recovery-live`, the profile to
   `/etc/apparmor.d/ap-worker-publisher-recovery-live`, and the unit to
   `/etc/systemd/system/ap-worker-publisher-recovery-live.service`. Use
   root-owned, non-writable-by-service paths. Add exactly one
   `IPAddressAllow=<approved IPv4>/32` in the unit fragment. Load the enforcing
   profile and reload PID 1 configuration within the approved window. Admit
   neither drop-ins/aliases nor a broad allowed peer. The Signer retains its
   existing private network, AF_UNIX-only restriction and deny-network profile.
5. Verify in the same service/cgroup and AppArmor boundary, with synthetic
   credentials, that approved TCP/443 alone passes. Deny the same peer on
   another port, another IPv4 on 443, UDP/DNS, IPv6, direct local networking,
   alternate credential access and any Signer IP traffic. Verify TLS uses
   system CA validation and SNI for `api.github.com` at the selected IPv4,
   including failure on an incorrect hostname, CA or connected peer. There is
   no leaf pin in the homelab contract. Confirm the units remain one-shot with
   restart disabled. Record kernel evidence, actual PID 1 values, namespace
   device/inode and boot ID. Require exact live-unit proof and confirm the
   kernel rules remain fenced through the attempt.

## Authorize one attempt

1. Independently obtain the fresh GitHub observer report and selected
   installation evidence per [PUB-09](worker01-recovery-host-rehearsal.md).
   Require main, protected rules and App separation, absent exact feature
   ref/PR, intended open Issue, exact job/artifact/base, and external custody.
   The existing `create-draft` signature and pre-spend alone apply to the
   offline handoff unless the separate live grant is also issued.
2. The independently pinned observer signs canonical `live-egress-policy.json`
   with purpose `recovery-egress-policy`. Retain its detached
   `live-egress-policy.sig` with the case inputs. The record schema is
   `AP-worker01-recovery-egress/1`. Use the exact fields from `verify_policy`,
   including job and observer report SHA256, unit, generation, IPv4, port 443,
   `tcp/ipv4`, denied Signer network, boot ID, namespace stat device/inode,
   PID 1 SHA256, retained kernel evidence SHA256, and UTC epoch `at`/`expires`.
   The PID 1 digest hashes the canonical JSON property map from
   `check_live_unit` (literal values, no added newline) on the reviewed host.
   Pin the observer public key independently from the approval key. Sign
   only after inspecting the underlying kernel and PID 1 evidence. A digest
   in a signed record cannot itself observe firewall enforcement.
3. If separately authorized to publish this exact job, invoke the existing
   foreground operator command `recovery-handoff --request-live` with the
   required snapshot and continuity SHA256 arguments. The option requests
   signed live admission. PID 1 values and the namespace must match before
   pre-spend and again before starting the live unit. The external custodian
   spends the fixed generation in its existing store; retain that store
   independently of Worker snapshots. The Signer takes the existing signed
   grant and emits the same protected handoff.
4. Inspect the exact `recovery-publisher-live` challenge, including job,
   artifact, HEAD/ref, App/installation, policy/peer, signature purpose,
   launch, expiry, pre-spend, and terminal Signer evidence. Require a direct
   approval for that exact challenge before using the external ledger helper's
   `--grant-role publisher-live`. The helper records the exact challenge with
   exclusive creation and confirms durability before signing. A lost reply
   consumes the allowance. Keep the key on the external custody side. Only
   the signature crosses the response channel. An offline grant, bare flag,
   environment or staging file has no live authority.
5. Keep controller liveness through unit completion. The recovery role
   verifies the signed handoff, enforced process profile, namespace identity,
   time bounds and liveness before I/O. PID 1 passes a read-only boot ID copy
   because the live role retains the PID-only procfs mount. The existing Publisher journals
   UNKNOWN before each effect, checks authority before sending, and attempts
   revocation of a known installation token even if the grant expires.
   There is no recovery-path retry or automated reconciliation.

## Record the result

- **DISABLED** is an offline handoff. It carries no publication result.
- **STOP** is a blocked admission or a confirmed role stop before its journal
  recorded a publication attempt. Preserve spent evidence.
- **UNKNOWN** covers unresolved start or journal evidence, incompletely
  confirmed effects, failed readback and failed revocation. Quarantine the
  generation and investigate read-only. Never repeat an uncertain action.
- **DRAFT_VERIFIED** requires successful role exit and a matching durable
  terminal journal, including the Draft and revoke confirmations. The engine
  re-reads the Draft state, exact repo/base/ref/HEAD, App/Bot author and
  native Issue link. Record the observed PR number and SHA, sanitized
  admission/evidence digests and operator disposition. Human-only merge and
  the separate review policy still apply.

Record the effective identity/namespace, packet and journal metadata, and
verification outcomes without credential contents. Stop on unexpected processes,
config drift, unsigned/expired/mismatched approval, a lost controller, journal
ambiguity, or any preexisting ref/PR. Host, privileged and live checks for this
source change are **NOT_RUN**.
