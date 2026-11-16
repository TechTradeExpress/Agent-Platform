# HAR-03: Claude parser and offline continuation contract

**SOURCE_ONLY / OFFLINE_ONLY / HOST_NOT_RUN / LIVE_NO_GO.**
[Issue #133](https://github.com/TechTradeExpress/Agent-Platform/issues/133)
adds a parser, not a CLI integration. Stacked base: published HAR-02 PR #140
`b27aa56d81408b233f44a3d81d729a6d595f6a18`, parent
`733160b8db95de9a6eefebc5394bcc339705fa87`, tree
`95471e7d844b3d4e186188ab7eb739805eac8a4f`. HAR-01–07 remain unmerged.
A future separately authorized Draft targets `feature/issue-132-harness-admission`.
This delivery is local-only. No other worktree or real host is changed.

Read with [ADR 008](multi-harness-architecture.md),
[HAR-01 schema](harness-contract.schema.json),
[HAR-02](harness-admission.md) and [native quarantine](execution.md).
The new module is explicitly SOURCE_ONLY in the closed manifest: neither
Control, Worker P0/P1 nor Publisher may import or ship it. Exactly two Debian
packages remain. Codex code/flags, harness selection and capability matrix are
unchanged. No product launcher, argv builder, run/resume, SDK dependency, provider
client, auth read, permission callback, fallback, service or writer is added.

## Exact target and evidence limits

The selected **research target is official Claude Code 2.1.295**, release tag
[v2.1.295](https://github.com/anthropics/claude-code/releases/tag/v2.1.295),
source-reference commit `602df92bf481ed904533e95c09f740f40aab5aed`.
The [immutable changelog reference](https://raw.githubusercontent.com/anthropics/claude-code/602df92bf481ed904533e95c09f740f40aab5aed/CHANGELOG.md)
confirms that release, including its print-mode background-output changes.
This is not an executable artifact/source-equivalence or installation pin.
No vendor binary, SDK package, login, API call or CLI command was used.

[AP-CLAUDE-EVENTS/1 profile](claude-adapter-contract.json) is a **project-owned
closed subset**, not a vendor-issued wire schema. Official sources researched:

- [CLI reference](https://code.claude.com/docs/en/cli-reference): modes, output flags,
  explicit ID/resume/fork behavior. Flags are reference data, never generated argv.
- [Programmatic CLI](https://code.claude.com/docs/en/headless): framing, failures,
  denials, subagent routing, interrupted/background work and bare-mode constraints.
- [Official TypeScript protocol reference](https://code.claude.com/docs/en/agent-sdk/typescript):
  native message field shapes only. Reading this reference does not use the SDK,
  establish CLI/SDK authorization equivalence or approve product orchestration.
- [Streaming payload reference](https://platform.claude.com/docs/en/build-with-claude/streaming):
  nested text delta grammar only; no Messages API request/client is implemented.

The documentation pages are mutable and were inspected on 2026-11-16. They are
not a frozen v2.1.295 schema. No version-pinned complete wire schema was located;
an attempted versioned SDK type-file URL returned 404 and was not used as evidence.
Consequently exact-binary compatibility remains **UNVERIFIED / NOT_RUN**.
Version-qualified field introductions in the reference constrain the selected
subset, but do not prove historical presence of every optional field. Unknown
fields/types, other versions or unsupported features are rejected, not guessed.
Future HAR-04/HAR-07 must verify exact approved binary/corpus and official support
before any production use. The HAR-01 Claude capability row stays unverified.

Every recording under `tests/fixtures/claude/` is labelled
`SYNTHETIC_NOT_CAPTURED`: documented shapes, fabricated IDs/values, deliberately
restricted empty metadata maps. They are not recordings of v2.1.295, an account,
a real permission denial or a live kill/reap. The independent process fixture,
quiescence assertion, UUID restriction and canonical lifecycle mapping are **our
synthetic/policy assumptions**, never vendor guarantees.

## Supported and rejected surfaces

| Surface | Official description / conservative project handling |
| --- | --- |
| Interactive `claude` | Terminal-oriented interaction; no stable TTY parser provided. Interactive bytes cannot be treated as JSON completion |
| `claude -p` | Programmatic CLI, documented as an SDK-facing mode. This does not authorize subscription-funded product automation; HAR-05 still decides eligibility |
| `json` | One final result object; strict whole-document decoder, no stream inferred from an array or concatenated JSON |
| `stream-json` | JSONL native messages. The profile requires final newline, one init, ordered assistant/tool messages and one terminal result; startup error-only result is a separate admitted shape |
| Partial output | Text-only message/block/delta/stop sequence and full-assistant text digest must agree. Thinking, input-JSON tool deltas, pings and other variants are unsupported, never silently consumed |
| Tool use/results | Correlate known IDs, reject orphan/duplicate replies and unresolved calls. No request is executed. Tool-error text is discarded; `is_error` alone is not a permission-denial classification |
| Denial | Structured denial event and final denial inventory are correlated. A denial never permits success or an automatic approval/retry |
| Auth/limit | Closed native error tags and structured rejection events only. No string matching of result/error prose, account readiness, reset prediction, extra-usage purchase or API fallback |
| Resume/fork | Vendor resume may search by ID/name/path; this profile accepts only an independently pinned typed Claude session. No latest/name/path search. Vendor fork changes the native ID; this profile rejects fork/ID substitution |
| Subagents/background | Recognized parent/task/run correlations are checked, including stale task notifications. Any background/subagent observation keeps effect completion UNKNOWN, even after a completed notification |
| SIGTERM | Documentation describes exit 143 and an unfinished turn; it also describes exit hooks and background/MCP limitations. We infer no universal side-effect rollback/death from that behavior. Every cancellation/timeout remains UNKNOWN |
| `--bare` | Documented auth/config behavior differs from normal personal subscription use. It is not an approved subscription-compatible confinement profile and no bare-mode command is produced |

A structurally valid message can still be outside this profile. Unknown hooks,
plugins, MCP discovery, replayed-user messages, optional future fields, multi-result
background loops and alternate output variants fail closed. The profile does not
follow a display client's permissive ignore-new-fields advice. Generic bounded
content islands (`input`, usage maps, structured output) remain opaque, untrusted
JSON; no control is inferred from their keys or values. Their depth/size is bounded.

## Parser and redacted common output

`parse(raw: bytes, context: Context, *, output_format='stream-json', process=None)`
accepts only an already captured bounded in-memory byte string. It opens no file,
socket, process, session store or stderr. There is no blocking iterator or callback.
Import/construction are inert. Decoder exceptions and vendor prose never escape
into reports; raw text, tool input/output, model names, cwd, auth source, costs,
account fields, UUIDs and private output paths are discarded before diagnostics.
Only fixed categories, public binding pins and namespaced digests are returned.

Protocol verdict and operation outcome are independent:

- **PASS**: the supported protocol was complete and internally consistent.
  Without independent effect evidence, normal result + exit 0 is still UNKNOWN.
- **FAIL**: malformed, duplicate, replayed, foreign, out-of-order, unsupported,
  oversized or incomplete input; no partial success. Operation outcome UNKNOWN.
- **UNKNOWN**: effects cannot be established, including denied/pending tools,
  authentication/limit errors, interruption and background work. Canonical output
  is NEEDS_HUMAN with the closed HAR-01 reason; no retry or resume permission.

`ProcessFixture` is a distinct typed, versioned **fabricated capture witness**,
bound to assignment and full raw-stream SHA-256. It carries EOF, process status,
termination and UNKNOWN/FIXTURE_QUIESCENT only. A dict, native payload, wrong hash,
HOST_PASS label or changed evidence is rejected. Only matching, complete,
non-background, closed native success plus this independent synthetic quiescence
and successful process exit may project COMPLETED. Exact known error plus the
same quiescence/exit-1 control may project PAUSED. These are fixture observations,
not actual process evidence or stored task-state transitions. No trusted production
witness producer exists; real host evidence always stays HOST_NOT_RUN.

`AP-CLAUDE-REPORT/1` has a closed field/reason inventory. Normalized terminal
`AP-HEVENT/1` and namespaced `AP-HSESSION/1` match HAR-01. Context supplies the next
sequence (>=3) after an externally owned STARTING/RUNNING prefix; the parser does
not invent or persist that prefix from model text. Reports cannot be applied as
execution authority. Repeated offline parsing is deterministic and consumes no
operation; real sequence/replay persistence and independent continuity are deferred.

## Session and continuation binding

`ClaudeSession` is a frozen, versioned typed reference with full HAR-02 worker
binding, exact assignment digest, public session reference and protected native
ID (excluded from repr). Canonical lowercase UUID v4 is a restrictive **project
policy**, not an assertion that every vendor session uses that grammar. A UUID's
syntax does not identify its provider. Only the Claude type plus full binding
establishes the offline namespace; a Codex UUID/event is never a substitute.

`Context` independently pins assignment, worker/enrollment, epoch, config/parser/
capability/instruction/isolation digests and full prior event-digest inventory.
It rejects cross-harness or stale bindings before accepting vendor bytes. Native
output cannot change these pins. Context and process witness are revalidated and
hashed before/after parsing; drift discards the projected records.

`ContinuationIntent` compares exact previous Claude session and assignment,
new assignment, unchanged full binding, task authority/model/account pins,
nonzero exact checkpoint and reconciled PAUSED outcome. The new assignment must
be distinct, and the next session must retain the same protected native ID.
It cannot produce argv, read a checkpoint or grant resume. New admission/freshness,
HAR-02 replay policy, authenticated history and process-death proof still apply;
none is bypassed by this necessary comparison. Unknown state, another provider,
worker, boot/epoch, policy, account or forked ID blocks. No cross-host session copy.

## Resource and security bounds

| Bound | Fixed profile limit |
| --- | --- |
| One JSON object/line | 16 KiB |
| Complete capture | 1 MiB |
| Native events / retained event IDs | 512, no eviction |
| JSON nesting | 8, quote-aware checked before decoding |
| JSON nodes / collection items | 4096 / 256 per event |
| Text field / tool-task-message correlations | 8192 characters / 128 of each |
| Parser wall budget | 2 seconds, checked between bounded events and after parsing |
| Synthetic capture duration | 15 seconds; exceeding it is RESOURCE_LIMIT |

Transport capture, kernel limits, authentication and durable state are not
implemented. A parser budget cannot contain a malicious process that was never
launched here. Native stderr is not accepted or retained. Quota/cost remain
UNAVAILABLE; process status is distinct from the permanent runtime exit 13 gate.

Tests cover synthetic normal JSON/JSONL and text deltas, tool denial/error, auth,
limit, cancellation, lost tool/result, invalid IDs, malformed/deep/oversized JSON,
duplicate/reordered/replayed events, injection, worker epoch/harness mismatch,
cross-provider resume and gate/package regressions. Keep root AGENTS.md as the
single instruction document; add no CLAUDE.md or copies. Actual AGENTS loading,
CLI compatibility, subscription entitlement, host isolation, cancellation/death,
all live sessions and hosted CI for this local-only HEAD remain NOT_RUN.
