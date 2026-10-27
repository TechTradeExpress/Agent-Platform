"""Read-only GitHub Issue admission. All remote data is untrusted."""

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from agent_platform.process import CommandError, read_command

PAGE_SIZE = 20
MAX_PAGES = 3
MAX_REQUESTS = 128
TOTAL_TIMEOUT = 60
REQUEST_TIMEOUT = 5
OUTPUT_LIMIT = 2 * 1024 * 1024
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")


class AdmissionError(Exception):
    """Fixed diagnostics only; never include API data."""


def require(condition: bool) -> None:
    if not condition:
        raise AdmissionError("GitHub response is incomplete or ambiguous.")


def positive_int(value) -> bool:
    return type(value) is int and 0 < value < 2**63


def timestamp(value) -> datetime:
    require(isinstance(value, str))
    require(bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value)))
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise AdmissionError("GitHub response contains an invalid timestamp.") from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(value):
    raise AdmissionError("GitHub returned invalid JSON.")


class GitHub:
    """Only fixed GET requests within one validated repository; no retries."""

    def __init__(self, repository: str):
        self.prefix = f"repos/{repository}"
        self.requests = 0
        self.deadline = time.monotonic() + TOTAL_TIMEOUT

    def get(self, suffix: str = "", query: dict | None = None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= MAX_REQUESTS:
            raise AdmissionError("GitHub discovery exceeded its request or time limit.")
        self.requests += 1
        endpoint = self.prefix + suffix
        if query:
            endpoint += "?" + urlencode(query)
        env = {
            key: os.environ[key]
            for key in (
                "HOME",
                "XDG_CONFIG_HOME",
                "GH_CONFIG_DIR",
                "GH_TOKEN",
                "GITHUB_TOKEN",
            )
            if key in os.environ
        }
        env.update(
            {
                "PATH": os.defpath,
                "LC_ALL": "C",
                "GH_PROMPT_DISABLED": "1",
                "GH_NO_UPDATE_NOTIFIER": "1",
                "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
            }
        )
        try:
            raw = read_command(
                [
                    "gh",
                    "api",
                    "--hostname",
                    "github.com",
                    "--method",
                    "GET",
                    "--include",
                    "--header",
                    "Accept: application/vnd.github+json",
                    "--header",
                    "X-GitHub-Api-Version: 2022-11-28",
                    endpoint,
                ],
                Path("/"),
                env,
                timeout=min(REQUEST_TIMEOUT, remaining),
                limit=OUTPUT_LIMIT,
            )
        except CommandError:
            raise AdmissionError(
                "GitHub read failed; check gh, authentication, network and limits."
            ) from None
        try:
            text = raw.decode("utf-8").replace("\r\n", "\n")
            header, body = text.split("\n\n", 1)
            lines = header.splitlines()
            require(bool(re.fullmatch(r"HTTP/[\d.]+ 200(?: OK)?", lines[0])))
            headers = {}
            for line in lines[1:]:
                key, value = line.split(":", 1)
                key = key.lower()
                # Only pagination is consumed. Other headers may legitimately repeat.
                if key == "link":
                    require(key not in headers)
                    headers[key] = value.strip()
            data = json.loads(
                body, object_pairs_hook=unique_object, parse_constant=invalid_constant
            )
            return data, headers.get("link")
        except (UnicodeError, ValueError, IndexError, RecursionError):
            raise AdmissionError(
                "GitHub returned malformed JSON or HTTP metadata."
            ) from None

    def pages(self, suffix: str, filters: dict | None = None) -> list:
        items = []
        for page in range(1, MAX_PAGES + 1):
            query = {**(filters or {}), "per_page": PAGE_SIZE, "page": page}
            batch, link = self.get(suffix, query)
            require(isinstance(batch, list) and len(batch) <= PAGE_SIZE)
            items.extend(batch)
            next_page = False
            if link is not None:
                relations = {}
                for part in link.split(","):
                    match = re.fullmatch(
                        r'\s*<([^<>]+)>; rel="(next|last|prev|first)"\s*', part
                    )
                    require(match is not None)
                    url, relation = match.groups()
                    require(relation not in relations)
                    parsed = urlsplit(url)
                    require(
                        parsed.scheme == "https" and parsed.netloc == "api.github.com"
                    )
                    require(
                        parsed.path.casefold()
                        == ("/" + self.prefix + suffix).casefold()
                    )
                    require(not parsed.fragment)
                    values = parse_qs(parsed.query, strict_parsing=True)
                    number = values.pop("page", [])
                    require(len(number) == 1 and number[0].isdigit())
                    number = int(number[0])
                    require(number > 0)
                    expected = {
                        key: [str(value)]
                        for key, value in query.items()
                        if key != "page"
                    }
                    require(values == expected)
                    relations[relation] = number
                next_page = "next" in relations
                if next_page:
                    require(relations["next"] == page + 1 and len(batch) == PAGE_SIZE)
                require(relations.get("last", page) >= page)
                require(relations.get("last", page) == page or next_page)
                require(relations.get("prev", page - 1) == page - 1)
                require(relations.get("first", 1) == 1)
            if not next_page:
                require(len(batch) < PAGE_SIZE)
                return items
        raise AdmissionError(
            "GitHub pagination limit reached; history or discovery is incomplete."
        )


def identity(api: GitHub, repository: str) -> tuple[int, str]:
    data, _ = api.get()
    require(isinstance(data, dict) and positive_int(data.get("id")))
    name = data.get("full_name")
    require(isinstance(name, str) and name.casefold() == repository.casefold())
    return data["id"], name


def issue_snapshot(data, number: int, repository: str) -> dict:
    require(isinstance(data, dict) and positive_int(data.get("id")))
    require(type(data.get("number")) is int and data["number"] == number)
    require(isinstance(data.get("repository_url"), str))
    require(isinstance(data.get("url"), str))
    require(
        data["repository_url"].casefold()
        == f"https://api.github.com/repos/{repository}".casefold()
    )
    require(
        data["url"].casefold()
        == f"https://api.github.com/repos/{repository}/issues/{number}".casefold()
    )
    require(data.get("state") in ("open", "closed"))
    require(isinstance(data.get("title"), str) and len(data["title"]) <= 1024)
    require(data.get("body") is None or isinstance(data.get("body"), str))
    require(isinstance(data.get("labels"), list))
    labels = []
    for label in data["labels"]:
        require(isinstance(label, dict) and isinstance(label.get("name"), str))
        labels.append(label["name"].casefold())
    require(len(labels) == len(set(labels)))
    timestamp(data.get("updated_at"))
    return {
        key: data.get(key)
        for key in (
            "id",
            "number",
            "state",
            "title",
            "body",
            "updated_at",
        )
    } | {"labels": sorted(labels), "pr": "pull_request" in data}


def has_scope(body: str | None) -> bool:
    # A deliberately conservative local format, not model-based interpretation.
    match = re.search(r"(?im)^## Scope\s*\n(.*?)(?=^## |\Z)", body or "", re.S)
    if not match:
        return False
    scope = match[1].strip()
    if re.search(r"\b(TODO|TBD|whatever|something|figure it out)\b", scope, re.I):
        return False
    return any(
        re.fullmatch(
            r"\s*(?:[-*]|\d+\.)\s+(?:Implement|Add|Fix|Remove|Update|Create|Document|Test)"
            r"\s+\S[^\n]{30,}",
            line,
            re.I,
        )
        for line in scope.splitlines()
    )


def exclusion(issue: dict) -> str | None:
    if issue["pr"]:
        return "not_issue"
    if issue["state"] != "open":
        return "closed"
    if {"agent:working", "needs:human"} & set(issue["labels"]):
        return "blocked_label"
    if "agent:ready" not in issue["labels"]:
        return "missing_ready_label"
    if not has_scope(issue["body"]):
        return "missing_explicit_scope"
    return None


def provenance(events: list, trusted: set[str]) -> tuple:
    seen = set()
    previous_time = None
    ready_time = None
    ready = False
    actor = None
    snapshot = []
    for event in events:
        require(isinstance(event, dict) and positive_int(event.get("id")))
        require(event["id"] not in seen)
        seen.add(event["id"])
        created = timestamp(event.get("created_at"))
        require(previous_time is None or created >= previous_time)
        previous_time = created
        kind = event.get("event")
        require(isinstance(kind, str))
        snapshot.append((event["id"], kind, created))
        if kind not in {"labeled", "unlabeled"}:
            continue
        label = event.get("label")
        require(isinstance(label, dict) and isinstance(label.get("name"), str))
        if label["name"].casefold() != "agent:ready":
            continue
        require(ready_time is None or created > ready_time)
        ready_time = created
        require(ready != (kind == "labeled"))
        ready = kind == "labeled"
        who = event.get("actor")
        require(isinstance(who, dict) and isinstance(who.get("login"), str))
        require(LOGIN.fullmatch(who["login"]) is not None)
        actor = who["login"]
        snapshot.append((label["name"], actor))
    require(ready and actor is not None)
    if actor.casefold() not in trusted:
        return None, "untrusted_ready_actor", snapshot
    return actor, None, snapshot


def safe_title(title: str) -> str:
    for key in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(key)
        if token:
            title = title.replace(token, "[redacted]")
    title = re.sub(r"\b[A-Za-z][A-Za-z0-9+.-]*://\S+", "[url]", title)
    title = re.sub(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)", "[redacted]", title
    )
    return "".join(c if c.isprintable() else " " for c in title)[:200]


def validate_candidate(api: GitHub, repository: str, number: int, trusted: set[str]):
    suffix = f"/issues/{number}"
    data, _ = api.get(suffix)
    issue = issue_snapshot(data, number, repository)
    reason = exclusion(issue)
    actor = None
    verified = None
    if reason is None:
        verified = provenance(api.pages(suffix + "/events"), trusted)
        actor, reason, _ = verified
        # Re-read the entire bounded history, not just the last page, so a
        # removal/relabel between identical label snapshots cannot pass.
        require(provenance(api.pages(suffix + "/events"), trusted) == verified)
    current, _ = api.get(suffix)
    require(issue_snapshot(current, number, repository) == issue)
    return issue, actor, reason, verified


def candidate(api: GitHub, repository: str, number: int, trusted: set[str]) -> dict:
    issue, actor, reason, _ = validate_candidate(api, repository, number, trusted)
    return {
        "number": number,
        "title": safe_title(issue["title"]),
        "trusted_actor": actor,
        "eligible": reason is None,
        "reason": reason or "eligible",
    }


def discover(
    repository: str, actors: list[str], number: int | None = None
) -> tuple[dict, int]:
    require(all(LOGIN.fullmatch(actor) is not None for actor in actors))
    require(number is None or positive_int(number))
    result = {
        "repository": repository,
        "candidates": [],
        "status": "no_work",
        "reason": "no_eligible_issues",
    }
    if not actors:
        result["reason"] = "missing_trusted_actors"
        return result, 9
    trusted = {actor.casefold() for actor in actors}
    api = GitHub(repository)
    repo_id, canonical = identity(api, repository)
    result["repository"] = canonical
    if number is not None:
        numbers = [number]
    else:
        data = api.pages(
            "/issues",
            {
                "state": "open",
                "labels": "agent:ready",
                "sort": "created",
                "direction": "asc",
            },
        )
        numbers = []
        for item in data:
            require(isinstance(item, dict) and positive_int(item.get("number")))
            numbers.append(item["number"])
        require(len(numbers) == len(set(numbers)))
    candidates = [candidate(api, canonical, item, trusted) for item in sorted(numbers)]
    require(identity(api, repository) == (repo_id, canonical))
    result["candidates"] = (
        candidates if number else [c for c in candidates if c["eligible"]]
    )
    if any(c["eligible"] for c in result["candidates"]):
        result.update(status="eligible", reason="eligible_issues")
        return result, 0
    return result, 9
