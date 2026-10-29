# Offline Telegram operator-console prototype — Issue #38

`agent_platform.telegram_console` is a disabled-by-default, offline Python API.
It accepts bounded synthetic updates and returns safe diagnostic responses.
There is no bot token, Telegram client, send operation, CLI command, polling,
webhook, listener, daemon, scheduler or action dispatcher. `FakeInbox` delivers
one scripted update only when explicitly called. Existing notifier/outbox,
HOLD, recovery, queue, publisher and execution contracts remain unchanged.
Native subscription execution still fails closed at exit 13.

## Boundaries and supported input

The trusted controller supplies an immutable `Policy`: repository ID/canonical
name, expected numeric bot ID, up to eight exact `Principal(sender, chat)` pairs,
optional explicitly selected status Issue, maximum age (1–300 seconds) and
`enabled=False` by default. Sender/chat IDs are positive integers below 2^52;
booleans, strings, groups and negative channel IDs are rejected. Pairs cannot be
mixed to synthesize another authorized caller. No username, display name, Issue
text or message content establishes authority.

`BotContext` is a **separately trusted fake-frontend assertion** of bot ID and
exact policy hash. It is never extracted from Update JSON. Numeric allowlisting
checks the claimed synthetic identity; it is NOT cryptographic authentication
of Telegram, a device or a human. Anyone who can forge JSON and that trusted
context could impersonate an allowlisted identity. The future authenticated
transport/controller channel must establish their origin independently. A
matching bot token or sender ID alone cannot authorize sensitive actions.
Types and hashes are consistency checks, not signatures or process isolation.

The parser deliberately supports a minimal **synthetic subset**, not all live
Bot API updates. UTF-8 JSON is limited to 8 KiB; duplicate keys, nonfinite numbers,
unknown fields/types and malformed encodings fail closed. There is exactly one
`message` or `callback_query` beside `update_id`. User objects contain exactly
`id` and boolean `is_bot`; chat objects contain exactly `id` and `type=private`.
Names/usernames and all other profile fields are outside this prototype. A
future live adapter needs separate schema review; do not silently drop unknown
security metadata to make real payloads fit.

Command messages contain exactly message_id, date, from, chat and text. They
must be authored by a non-bot allowlisted sender in its exact private chat.
Forwarded, edited, anonymous, channel, inline, service and multi-type updates are
rejected, including otherwise valid commands carrying extra fields.
The entire grammar is:

| Command | Result |
| --- | --- |
| `/help` | Fixed allowlisted help text |
| `/status` | Supplied trusted status snapshot of the policy-selected Issue |
| `/queue` | Supplied trusted advisory queue snapshot |
| `/issue N` | Supplied trusted status snapshot of exactly N |

N is ASCII decimal, 1–2,147,483,647, without signs/leading zeros. No arguments,
whitespace expansion, bot suffix, shell expression, URL, prompt or unknown
command is accepted. There is no active pause/hold/resume/approve/merge command.

The trusted caller supplies `now`; the gateway never starts a clock or timer.
Message dates must be positive bounded integer Unix seconds, not in the future
and no older than policy.max_age. A backwards clock relative to durable replay
evidence blocks. No inferred reset time or automatic wait exists.

## Read-only evidence and responses

`collect_reports` explicitly reuses `task_status.inspect_local` and optional
`queue.plan` with trusted admission pins/snapshots. It performs only their
existing non-creating host-lock and bounded read-only Git checks, never gh,
Codex, account/session access or state repair. Exact repository and admission
pins must agree with validated local status. Unknown/missing/conflicting state
becomes an unavailable view. Queue collection remains offline and advisory.

The resulting frozen `Reports` contains only Issue numbers and allowlisted
recorded phases/queue classifications. A caller-provided dict, wrong repository
or absent report produces fixed unavailable/needs_human output. Raw reports,
paths, session IDs, Issue prose, events, errors and logs never enter responses.
The collector and report delivery are trusted controller responsibilities; do
not deserialize reports from the transport/repository/model. Code compromised
inside the trusted process could fabricate typed receipts; no stronger claim
is made. The collector does not make separate status/queue reads atomic.

Responses are at most 1 KiB, plain fixed text plus bounded numbers/enums, with
`action_authorized=false`, `launch_allowed=false`, `resume_authorized=false`
and `mode=offline_fake`. RUNNING is explicitly recorded, with live activity
unknown. Queue data is explicitly a recorded advisory snapshot, not live GitHub
or permission to start. No Markdown/HTML interpretation, external links, prompts,
account identifiers, auth paths or raw exception prose is emitted. The existing
notifier's trusted lifecycle events are not fabricated to send console replies.

## Replay evidence and crash behavior

Explicit `Gateway.initialize(context, last_update_id=..., now=...)` is a separate
trusted offline bootstrap operation, never a Telegram command. It requires the
existing fixed host mutex and a genuinely absent bot directory. No automatic
creation of that mutex or reinitialization/adoption of an existing/empty/partial
directory is allowed. The operator supplies the initial high-water mark; the
first incoming packet cannot choose/reset it.

The only persistent namespace is
`~/.local/state/agent-platform-console/<bot-id>/`, derived from trusted
prepare.HOME, with private 0700 directories and 0600 regular single-link files.
The replay record binds the exact policy and immutable callback-registry hash,
highest admitted update ID, canonical request digest, monotonic observed clock,
generation, last response outcome and up to 16 consumed token hashes. It stores
no raw messages, tokens, callback/task contents or response logs. The shared
16 KiB storage limit and bounded directory scan apply.

Each admitted update ID must strictly exceed the durable cursor. Duplicates,
changed content under the same ID, lower/reordered IDs and restart replays are
suppressed. Old IDs remain rejected without an unbounded history. Telegram's
possible ID discontinuities, clock rollback, policy/registry changes, lost files
or exhausting one-use evidence require human reconciliation, never an inferred
reset. Unauthorized/malformed packets do not advance the cursor. This policy
intentionally sacrifices availability to avoid replay ambiguity.

The existing **non-creating host mutex** serializes all journal reads/writes.
Missing/busy/unsafe locks block. Before returning a response, the gateway uses
the shared atomic storage writer to durably record a separate pending intent,
then replace/fsync and reread the cursor. Only that invocation's verified marker
is removed after the cursor is durable; the directory is fsynced. Failures leave
pending/temporary evidence, which blocks all later handling/reinitialization.
No orphan is repaired or removed automatically. Failure after successful cursor
commit can suppress a reply rather than repeat processing. Exactly-once network
delivery is not claimed. No token timer, eviction, retry loop or cleanup API exists.

Symlinks, hardlinks, foreign ownership, unsafe permissions, malformed/oversized
records, unexpected files, changing metadata or lock replacement fail closed.
These are protected local-store assumptions, not rollback-resistant hardware:
privileged/same-UID compromise or rollback/removal of the entire trusted store
cannot be proven absent offline. Future deployment needs independent integrity,
backup/reconciliation and isolation review. Task checkpoints/guards, HOLD records,
Git refs and notifier state are never modified by the gateway.

## Callbacks: one-use proposals, no confirmation authority

Synthetic callback queries contain exactly id, from, message, chat_instance and
data. Their message must be from the expected bot in the exact private chat.
Data is a single 64-byte lowercase hex opaque token, never a command/URL/action.
There is no inline-mode support. Callback queries have no independent click-date
in this subset; the bot message's age is checked conservatively. Fresh message
metadata is not proof of fresh human intent.

A separately trusted `CallbackIntent` binds token, numeric principal, bot ID,
future operation (pause/hold/resume/approve), exact `CurrentTask`, issued_at and
expiry (at most 300 seconds). CurrentTask reuses RecoveryReference: repository/
Issue identity, scope/revision/provenance/base SHA, checkpoint digest/generation,
execution and session UUIDs, plus exact HEAD SHA. The immutable registry is
pinned at bootstrap; changing any binding under an existing token blocks, even
after restart. Registry issuance/update is not implemented here.

Only an exact matching, unexpired trusted current-state receipt may produce
`dry_run_only`; it still has no action authority. Matched callers consume their
known token before receiving the result, including when state/expiry conflicts.
A swapped caller cannot consume another principal's token. Token reuse is
suppressed even with a higher update ID or changed registry attempt. Consumed
history is never evicted. Unknown/expired/swapped callbacks cannot change HOLD,
recover, resume, approve, publish or merge. Synthetic token fixtures do not prove
secure live issuance; a future issuer must provide unpredictable tokens, durable
immutable intent binding and independent per-action approval/fresh validation.

## Threat model and later deployment prerequisites

| Threat | Boundary / limitation |
| --- | --- |
| Compromised Telegram account/device | Read-only access is still possible under that identity; no sensitive operation is enabled. Future actions need independent approval and local policy, not chat possession alone. |
| Stolen bot token | Can expose messages or impersonate the bot; keep it only in an isolated low-privilege frontend. It is not maintainer/GitHub/Codex authority. No token exists here. |
| Forged sender/chat/bot metadata | Strict schema, numeric pairs and separate trusted context reject mismatches; JSON itself provides no origin authenticity. Future authenticated IPC/transport provenance is mandatory. |
| Replay, delays, clock rollback or outages | Freshness, monotonic cursor, one-use hashes and durable pending intent block ambiguity. Reordered/lost replies may need human attention; no automatic retries or scheduling. |
| Callback swapping/cross-Issue confusion | Exact immutable task/scope/SHA/generation/session/operation registry binding; dry-run only and no token remapping. |
| Command/model/shell injection | Exact four-command grammar; no dispatcher, shell, prompts or raw text forwarding. |
| Spoofed reports or local-state tampering | Trusted collector and exact existing admission checks; safe enum projection, private replay store and stable rereads. Same-process/privileged compromise remains outside this prototype. |
| Telegram platform visibility | Bot conversations are visible to Telegram and potentially account/token holders; private chat is not a confidential control plane. Return minimal nonsecret facts. |

Before any separately approved live integration: independently review schema and
transport provenance, OS/process/UID/FD/network separation, secret handling,
trusted clock, serialization/backpressure/rate limits, replay bootstrap and
manual reconciliation. Fixed-origin verified-HTTPS long polling would require
explicit deployment approval, bounded requests and carefully ordered durable
offsets; no polling loop is provided. A webhook would require separately approved
HTTPS hosting, verified secret_token headers, producer validation, limits and
protected IPC; no public endpoint is provided. Neither approach may give the
frontend Codex auth, GitHub write credentials or administrator access.

Any later active command service requires separate per-operation governance,
explicit maintainer opt-in, fresh admission/checkpoint/session/recovery/ref and
kernel-isolation validation. Human-only GitHub merge and subscription isolation
blocks remain binding. Offline parser/fake tests are not authenticated Telegram,
OS confinement, live delivery, model inference or production-readiness evidence.
