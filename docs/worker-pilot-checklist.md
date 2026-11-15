# Future Worker pilot: separate operator decisions, no activation authorization

This is a review checklist for #108, not a deployment command or approval.
PKG-05 does not install packages on worker01/worker02, change permissions, log in,
start services, access credentials or publish to GitHub. HOST_NOT_RUN / LIVE_NO_GO.

1. First obtain a human decision for **worker01 only** identifying the exact host,
   artifact hashes, source commit, requested installation/configuration actions,
   disposable target repository/feature branch and stop/rollback owner. Record
   authenticated approval separately from any AI report. No consent transfers to
   worker02. Retain the exact independently reviewed source HEAD and CI evidence.
2. On an approved disposable Debian 13 amd64 testbed complete both-role APT/dpkg
   and separate PKG-03R installer acceptance before any real host. Check dependencies,
   existing UID 999/GID 989, independent signer IDs, lifecycle/recovery and protected
   state retention. Record actual execution vs modeled tests vs NOT_RUN separately.
3. Inventory the host without opening private homes/auth stores or exporting keys.
   Capture existing account/state/journal anchor metadata through the authorized
   owner. Require quiescence and independently retained continuity evidence; do
   not reconstruct missing history, copy journals or share keys between workers.
4. Verify the approved .deb version/source SHA, exact .deb SHA-256, acquisition
   source and upstream Codex URL/tag/pin/archive/binary hashes. Inspect the trusted
   install record and absolute effective path. Resolve PATH collisions explicitly;
   do not delete personal Codex or chmod arbitrary binaries. Install and configure
   are distinct authorized actions, never implied by the diagnostic.
5. Retain the closed doctor's report with its SHA-256, versioned evidence envelope
   below, unknowns and NOT_RUN checks. Obtain independent evidence of effective
   systemd limits, real per-process enforce attachment and cgroup BPF/fixed egress,
   negative DAC/MAC/proc/FD/env/memory access, journal continuity and reboot recovery.
   No synthetic/local PASS can replace this. Missing evidence means STOP.
6. Independently authenticate the worker's exact App/bot/installation and selected
   target, actual grants and protected-main/App merge denial. Revalidate source
   pins (worker01 App 5748674 / installation 181691110; worker02 App 5748675 /
   installation 181691061) against authoritative observations. Do not place a PEM,
   token or signer handle in the report, agent home, source checkout or artifact.
7. Only a further exact-action human approval can allow a one-shot supervised
   disposable App-authored Draft pilot. Preserve AP-WP/1 CAS, human authorization,
   UNKNOWN-before-effect, readback and revocation. No native run/resume, automatic
   Ready, merge, force push, main mutation or automatic retry is permitted.
8. Review worker01's actual evidence and STOPs independently. Only then seek a
   **new explicit worker02 decision**, repeating every gate with its own App,
   identities, hashes, state and evidence. Worker01 success never proves worker02.

## Redacted evidence envelope (future review record, not readiness input)

Record schema `AP-WORKER-PILOT-EVIDENCE/1`, exact approved host alias and human
decision reference; observation method/time/collector provenance; full source
HEAD/tree, package versions and SHA-256 plus acquisition source and manifest hash;
Codex release URL/tag, reviewed lock/pin/archive/binary hashes, effective absolute
path and shadow status; Python/Git/systemd/AppArmor/kernel versions; numeric role
UID/GIDs and separation; nonsecret state/receipt digest and independent anchor
reference; authenticated App/bot/installation IDs, grants and target; effective
systemd/AppArmor/BPF and negative-isolation evidence references/digests; doctor
report SHA-256; per-check VERIFIED/BLOCKED/NOT_RUN and uncertainties; scope/expiry
of human approval; exact action/readback/revocation outcomes; STOP reason and
rollback owner/decision. Never embed auth payloads, private journal data, home
paths or credential contents. A reference to missing evidence is NOT_RUN.
This envelope is not parsed or trusted by the PKG-05 executable.

STOP on any mismatch, pending transaction, unknown/incomplete journal/receipt,
missing anchor, shadowed executable, foreign identity, invalid ACL, missing or
unattached profile, unverified BPF, stale authorization, permission ambiguity,
uncertain network effect or inability to revoke. Preserve evidence and quiescence;
never auto-repair, retry publication or erase UNKNOWN. A separately approved
rollback may restore reviewed compatible package/tool bytes only after schema and
continuity review. It must retain identities, journals, anchors and uncertainty;
Codex rollback uses only PKG-03R's intact verified version store. Incompatible
state, partial recovery or unknown external effects require human reconciliation.
