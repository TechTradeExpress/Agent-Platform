# Offline Telegram notification module — Issue #37

This milestone provides typed events, fixed presentation, a private durable outbox
and a scripted fake Bot API adapter. It adds **no CLI command, lifecycle hook,
HTTP client, token input, real sender, polling/webhook endpoint or daemon**.
Nothing imports it from the runner, status or publisher. Integration is disabled
by default. Enabling `Preferences` enables only explicit **offline queue/fake**
operations; it cannot activate Telegram delivery or native Codex execution.

## Trusted events, not model instructions

`NotificationEvent` is a frozen, slotted schema with a closed `Kind` vocabulary:
accepted/blocked, start intent, checkpoint progress, paused/failed/needs-human,
review requested, Draft PR created, CI result, independent review completed,
Ready and human-merged. It carries canonical numeric repository/Issue/PR identity,
approved scope digest, exact base/head SHA, checkpoint phase/generation or CI/
review result, and a trusted evidence digest. No message/title/body/URL/command,
reviewer/label/token, local path or arbitrary exception field exists.

`checkpoint_event(admission, source, record, kind=...)` reuses existing typed
admission and checkpoint/lifecycle validators. It derives only kinds compatible
with the validated phase. The **trusted controller** must supply stable admitted
source/checkpoint snapshots obtained under existing lock/private-storage checks;
this pure factory does not read GitHub, disk or native sessions, and must never
be fed model/repository/chat JSON. A recorded STARTING means intent, and RUNNING
means a recorded checkpoint; neither proves a live process. Failed-turn events
come only from validated PAUSED evidence, not parsed provider-error prose.

`GitHubEvidence` is a separately trusted collector's assertion about an exact
repository, PR, SHA and receipt digest. Review-completed and human-merge kinds
require explicit independent-review/human-merge assertions. CI supports PASS,
FAIL or CANCELLED; independent review supports PASS or CHANGES_REQUIRED. The
collector must actually verify Draft/Ready/merge state, current exact SHA, human
actor, review independence and optional public-repository visibility. These are
as-of-observation receipts, not live remote freshness; a future sender must
revalidate visibility and recipient policy before releasing any real message. No raw
GitHub response parser or remote collector is added in this milestone.

Frozen types and syntactic validation are **not authentication or attestations**.
Trusted Python code can fabricate an instance; this API is not a way to turn
model content into trusted facts. Authenticating collector/orchestrator handoff
and preventing the worker from modifying the service/outbox remain deployment
prerequisites. Do not infer trust from an Issue description, Git output, chat
message, model PASS claim, label alone or arbitrary saved event file.

## Safe formatting and preferences

`format_event` returns `SafeNotification`; its text is a computed fixed template,
not a free-text constructor argument. Messages are ASCII and <=768 UTF-8 bytes.
They disclose only numeric repository/Issue/PR IDs, fixed state/result phrases
and checkpoint generation. Repository names, commit/scope/evidence hashes,
branch/worktree/CODEX_HOME, session UUIDs, usage, prompts, logs, exceptions and
repository contents are omitted. The internal event retains hashes for binding,
not for rendering. There is no Markdown/HTML parse mode or supplied entity list.

Links are off by default. Only when both operator preferences enable links and
trusted GitHub evidence confirms the repository is public does the formatter
construct canonical `https://github.com/OWNER/REPO/issues/N` and `/pull/N` links.
No arbitrary URL is accepted, followed or redirected. Local checkpoint events
cannot assert public visibility. Numeric chat IDs are operator-controlled,
positive, strictly integer and <2**52; usernames/groups/channel destinations and
booleans are rejected. Positive IDs alone do not prove chat ownership/privacy;
a future live deployment must verify the private chat independently.

Preferences require explicit enabled flag, chat binding and repository-ID
allowlist. Default severities are milestones, blocking/errors and review;
progress is opt-in. Minimum send interval is 1–3,600 seconds (default 5), progress
enqueue interval 30–86,400 seconds (default 60), and attempts 1–3 (default 3).
Disabled operations return without touching storage or transport. Policy and
chat binding are pinned in the queue; changing them requires separately reviewed
migration/reconciliation, never automatic retargeting of old notifications.

## Bounded durable outbox

`Outbox` uses a separate fixed sibling store:
`~/.local/state/agent-platform-notifications/{outbox.lock,outbox.json}`.
It never modifies task checkpoints, execution guards, sessions or the host mutex.
The trusted operator must keep this store outside all worker mounts/worktrees.
There is no path flag or destination path sourced from event/repository data.

Only explicit enabled `initialize()` creates owner-only directories (0700), its
single-link mutex (0600), and an empty queue. Existing unsafe permissions/owners,
symlinks, hardlinks, unexpected files, malformed schema, unfinished atomic-write
files and lost queue/mutex pairs block; they are never repaired or deleted.
`initialize` is idempotent only for the same complete valid queue/binding.
Missing mutex with an existing queue is refused **before creating a replacement**.
Missing queue with an existing mutex is not reinitialized as an empty history.

A separate nonblocking flock serializes queue calls. Reads/writes reuse existing
private-file validation, <=16 KiB JSON limit, duplicate-key/nonfinite rejection,
expected-record comparison, same-directory temporary file, file fsync, atomic
replace and directory fsync. Path/descriptor identity is checked around reads
and mutex use. Failures leave recovery evidence; no cleanup API is provided.
The filesystem and trusted same-UID callers must honor these constraints; this
is not OS isolation, tamper-proof storage or power-loss proof on unaudited media.

At most **16 entries** are retained, including delivered/unknown tombstones.
Capacity or byte-limit exhaustion blocks new events without eviction. History
cannot grow unbounded or silently lose deduplication on restart. There is no
prune/reset/epoch rotation; a future reviewed retention workflow is necessary
for long-running deployment. Deleting or rolling back the whole store defeats
local historical deduplication and is not a supported recovery operation.

Logical idempotency binds schema, repository/Issue, kind, approved scope, exact
SHA, checkpoint phase/generation or PR/result. Refreshed receipt hashes and
visibility do not create another notification for the same logical fact. The
queue key additionally binds chat ID; a separate complete-event SHA-256 detects
stored-event drift. Neither hash is a signature or remote exactly-once guarantee.

Both the queue schema and reports explicitly carry `mode=offline_fake`. Delivered
means a validated **simulated** acknowledgement, never live Telegram evidence.
A future live sender must use separately reviewed mode/ledger handling and cannot
reinterpret this fake delivery history as actual delivery.

Persistent outcomes are **pending**, **delivered**, **unknown**:

1. `enqueue(event, now=...)` filters preferences, suppresses duplicates and
   throttles progress before durable insertion. It never sends anything.
2. `attempt_once(key, fake, now=...)` makes **at most one** fake adapter call. It
   first persists `unknown/dispatch_intent`, attempt count and rate budget.
3. A validated matching private-chat acknowledgement becomes delivered. Timeout,
   transport exception, 5xx/redirect/malformed/mismatched reply or crash remains
   unknown; later calls require reconciliation and never resend that key.
4. Confirmed 429 rejection persists bounded retry-after and a queue-wide rate
   barrier. Definitely-not-sent fake failures use 30/60/120-second backoff.
   A new explicit call is required at/after the due time; there is no sleep,
   scheduler or retry loop. Confirmed 400/401/403 rejections are non-retryable.
5. Stored delivered keys remain deduplicated on restart. Failed outcome persistence
   leaves the prior durable unknown intent (or interrupted-write marker).

`now` is an explicit trusted integer clock input for deterministic policy/tests;
rollback below the persisted clock blocks. The future trusted service must supply
its own reviewed clock, never model/chat timestamps. Rate limiting is conservative
and global to this queue. `snapshot()` and frozen `Report` return only fixed
statuses/categories, key, attempts and due time, never messages, chat ID, paths
or raw reply/exception text. No successful send/ack implies a run, PR write or
recovery authorization.

## Fake transport and evidence

The logical request fixes HTTPS origin `https://api.telegram.org`, method
`sendMessage`, five-second timeout contract and no redirects. Payload is JSON
with numeric chat ID, computed text, disabled previews, content protection and
paid broadcasting explicitly false. It has no token-bearing URL/header, parse
mode, entities, callbacks or remote-control payload. `FakeTelegram` accepts only
<=32 scripted reply/fault values and records <=32 logical requests; it performs
no HTTP. Reply parsing is <=8 KiB, strict JSON, exact private-chat/payload binding
and positive message ID. Raw error descriptions are discarded. These protocol
choices are checked against [Telegram's official Bot API documentation](https://core.telegram.org/bots/api#sendmessage)
and [response parameters](https://core.telegram.org/bots/api#responseparameters).
Timeout/fault scripts are classification tests, not real HTTP timeout evidence.

The outbox **accepts exactly the shipped fake class**, rejecting arbitrary
transports and subclasses. `Transport` documents the future narrow interface;
it does not enable a real adapter. No token is requested from environment, files,
BotFather or an operator. Offline tests inject synthetic checkpoints/GitHub facts,
private scratch storage, faults, fsync/replace failures and fabricated replies.
They are distinct from live notification, service isolation and deployment proof.

## Separate future live-enablement gate

Live delivery needs a separately approved Issue/operator deployment and an
independent security review of the trusted service, event collector, bounded HTTP
adapter, TLS/origin/no-redirect enforcement, storage durability and retention.
The operator must independently provision a numeric private-chat allowlist,
notification/subscription opt-in, rate/privacy preferences, and a BotFather token
in an audited secret store with rotation/revocation procedures. Never place that
token, a GitHub-write credential or administrator capability in Codex, its
worktree, task mounts, notification text, errors or logs. Network egress must be
minimal and separate from untrusted tools. Bot messages are not an end-to-end
encrypted secret store; content protection is not a confidentiality guarantee.

No live sender is shipped/enabled, and this module cannot accept inbound commands,
webhooks, polling or process control. Issue #38 remains separate. Codex CLI and
ChatGPT subscription remain the intended engine/funding path; all existing native,
subscription, publisher and artifact/confinement gates stay unchanged.
