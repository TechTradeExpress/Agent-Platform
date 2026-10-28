# Deferred operator-only subscription smoke procedure

**BLOCKED by ADR 001. Do not run a model turn with this increment.**
`agent-platform subscription` is only a blocked diagnostic, not a launcher. This
procedure is a future acceptance checklist after complete tool isolation is
independently demonstrated and a supported subscription adapter exists. Do not
substitute the old API broker, raw auth.json mounts or unrestricted host exec.

Prerequisites: exact reviewed Agent Platform/Codex artifact SHA, admissible runtime,
complete external-tool mediation proof on a real kernel, credential-store/session
separation audit, no API-key/credit fallback and a dedicated disposable repository
with an explicitly human-approved Issue. Preserve every existing task/session.
No real account or auth material is accessed by CI or this coding task.

1. The human separately authorizes login to the selected ChatGPT account/workspace
   and subscription usage. Only that human performs supported browser/device login
   in the private trusted credential domain and inspects their own login status.
   Do not copy or export auth caches, tokens, URLs, cookies or keyring contents.
2. Independently verify a tool can neither see the auth/store/native sessions nor
   inspect parent memory/proc/fds, contact host network/keyring/GitHub/SSH, change
   checkpoint/refs or escape workspace writes. Use fabricated canaries first;
   never test credential isolation by printing actual secret material.
3. Revalidate admission, clean initial task, mutex and identity. Immediately before
   a single account-consuming turn, the human explicitly confirms the exact
   disposable task/account and the approved subscription-only invocation.
   There is deliberately no executable launch command here until an adapter has
   passed review; do not improvise one from the pinned CLI's help.
4. Record only exact UUID, safe lifecycle/result codes and expected fixture edits.
   Verify known completion, then a separately approved known failed/PAUSED turn.
   Ambiguous exit is NEEDS_HUMAN; do not manufacture PAUSED or edit checkpoints.
5. Human separately authorizes same-UUID resume after fresh admission and native
   session integrity checks. Preserve tracked/staged/untracked fixture edits.
   Verify no account/backend switch; never select --last or retry unknown state.
6. In separately authorized private tests, verify refresh, revocation, logout/
   re-auth, concurrent refresh, cancellation and restart persistence. No token
   or account details enter reports. Auth uncertainty blocks rather than falling
   back to API billing or another identity/session.
7. Human checks official dashboard or /status manually if usage is unavailable.
   A known PAUSED can be held manually; do not infer reset times from model prose,
   scrape sessions/cookies or schedule automatic waiting/resume.

Redacted report fields: exact source/artifact SHA, pinned version, offline tests,
real kernel/complete tool mediation, auth-mode/refresh/session outcomes, known
lifecycle states, blockers and LIVE_NOT_RUN/PASS/FAIL. Never store prompts, model
responses, tokens, account identifiers, native transcripts, raw stderr or access
URLs. Keep offline PASS separate from live evidence. Preserve guards/sessions and
verify descendants stopped before human reconciliation; no automatic cleanup,
credential movement, rollback or delivery is authorized. Independent review and
human-only merge remain separate from any authorization to consume subscription
usage or change host policy.
