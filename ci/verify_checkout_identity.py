"""CI-01: bind a Debian package run to its actual checkout.

Runs in the unprivileged workflow after ``actions/checkout`` as step
``verify_checkout``; every later step requires its outcome ``success``. It
reads only the event name, ref, SHA, event payload and the checked-out commit
graph; it never reads secrets, makes no network call and writes only the
evidence file named on the command line, and only after a successful check.

* ``push``: the checkout must be exactly the pushed commit.
* ``pull_request``: the checkout must be GitHub's synthetic merge result
  ``refs/pull/<n>/merge`` whose two parents are exactly the event's base SHA
  (first) and head SHA (second). Tree equality, the event name or a run
  ``head_sha`` alone never count. A mismatch, stale or ambiguous graph fails.

The record attests the checkout identity only (``scope``). Its ``status``
CI_ONLY and ``release`` NOT_RELEASED classify this workflow-level evidence, not
any package: embedded package provenance is unchanged, so ordinary candidates
built from the checkout, including a synthetic merge commit, keep build_kind
candidate, ci_only false and release_authorized false. Their class and source
identity, not this record, keep them out of release and custody admission
(docs/debian-package.md). The record is not a validation result either: only
the job conclusion is.
"""

import argparse
import json
import os
import re
import subprocess
import sys

SCHEMA = "AP-CI-CHECKOUT-EVIDENCE/1"
SHA = re.compile(r"[0-9a-f]{40}")


class Rejected(Exception):
    """Evidence is missing, stale, mismatched or ambiguous."""


def _sha(value, name):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise Rejected(f"{name}_not_full_lowercase_sha")
    return value


def _text(value, name):
    if not isinstance(value, str) or not value or len(value) > 255:
        raise Rejected(f"{name}_missing")
    return value


def verify(event_name, ref, github_sha, event, head, parents, tree):
    """Pure decision over observed facts; returns the evidence record."""
    github_sha = _sha(github_sha, "github_sha")
    head = _sha(head, "checkout_head")
    tree = _sha(tree, "checkout_tree")
    parents = [_sha(p, "checkout_parent") for p in parents]
    if head != github_sha:
        raise Rejected("checkout_head_differs_from_event_sha")
    record = {
        "schema": SCHEMA,
        "scope": "checkout_identity_only",
        "status": "CI_ONLY",
        "release": "NOT_RELEASED",
        "event": event_name,
        "ref": _text(ref, "ref"),
        "checkout_sha": head,
        "checkout_tree": tree,
        "checkout_parents": parents,
    }
    if event_name == "push":
        if not ref.startswith(("refs/heads/", "refs/tags/")):
            raise Rejected("push_ref_invalid")
        if event.get("after") != github_sha:
            raise Rejected("push_after_differs_from_checkout")
        record["mode"] = "exact_head"
        return record
    if event_name != "pull_request":
        raise Rejected("event_not_supported")
    pr = event.get("pull_request")
    if not isinstance(pr, dict) or type(event.get("number")) is not int:
        raise Rejected("pull_request_event_incomplete")
    base, pr_head = pr.get("base"), pr.get("head")
    if not isinstance(base, dict) or not isinstance(pr_head, dict):
        raise Rejected("pull_request_event_incomplete")
    base_sha = _sha(base.get("sha"), "event_base_sha")
    head_sha = _sha(pr_head.get("sha"), "event_head_sha")
    if ref != f"refs/pull/{event['number']}/merge":
        raise Rejected("checkout_ref_is_not_the_pull_request_merge_ref")
    if len(parents) != 2:
        raise Rejected("checkout_is_not_a_two_parent_merge_commit")
    if parents != [base_sha, head_sha]:
        raise Rejected("merge_parents_differ_from_event_base_and_head")
    if github_sha in (base_sha, head_sha):
        raise Rejected("checkout_is_not_a_synthetic_merge_result")
    record.update(
        {
            "mode": "synthetic_merge_result",
            "pull_request": event["number"],
            "event_base_sha": base_sha,
            "event_head_sha": head_sha,
            "base_ref": _text(base.get("ref"), "base_ref"),
            "head_ref": _text(pr_head.get("ref"), "head_ref"),
        }
    )
    return record


def _git(*args):
    out = subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True, timeout=60
    )
    return out.stdout.strip()


def observe():
    """Read actual facts from the checkout and the runner-provided event."""
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
        event = json.load(handle)
    fields = _git("rev-list", "--parents", "-n", "1", "HEAD").split()
    return {
        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "github_sha": os.environ.get("GITHUB_SHA", ""),
        "event": event,
        "head": _git("rev-parse", "--verify", "HEAD^{commit}"),
        "parents": fields[1:],
        "tree": _git("rev-parse", "--verify", "HEAD^{tree}"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", required=True)
    parser.add_argument("--github-env", default=os.environ.get("GITHUB_ENV"))
    args = parser.parse_args(argv)
    try:
        record = verify(**observe())
    except (
        Rejected,
        KeyError,
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ) as e:
        reason = e.args[0] if isinstance(e, Rejected) else type(e).__name__
        print(f"CHECKOUT_EVIDENCE_REJECTED: {reason}", file=sys.stderr)
        return 1
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write(text)
    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as handle:
            handle.write(f"AP_VERIFIED_CHECKOUT_SHA={record['checkout_sha']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
