"""Offline model of the workflow YAML subset and GitHub Actions step conditions.

Test support for CI-01 only: not shipped, not a general YAML parser and not an
Actions runner. A real GitHub Actions run remains the only live evidence.

``load_workflow`` accepts the block-YAML subset used by the Debian package
workflow and raises ``ValueError`` on anything else (tabs, CR, whitespace-only
lines, document markers, anchors, aliases, tags, quoted or folded scalars, flow
mappings, indentless or nested sequences, duplicate keys, empty values, ``: ``
inside a plain scalar, YAML 1.1 yes/no/on/off and non-integer numeric-looking
scalars), so semantic tests fail closed instead of guessing.

``run_steps`` evaluates step ``if`` conditions with GitHub's documented rules
(docs.github.com/en/actions/reference/workflows-and-actions/expressions and
.../contexts, ``steps`` context):

* "A default status check of success() is applied unless you include one of
  these functions" (success, failure, always, cancelled);
* success() "Returns true when all previous steps have succeeded"; failure()
  "Returns true when any previous step of a job fails"; cancelled() "Returns
  true if the workflow was canceled"; always() returns true "even when
  canceled";
* ``steps.<id>.outcome`` is the result "before continue-on-error is applied",
  ``conclusion`` the result after it; values are success, failure, cancelled
  or skipped.

Only ``!``, ``&&``, ``||``, parentheses, the four status functions and
``steps.<id>.outcome|conclusion ==|!= '<value>'`` are accepted. ``!`` directly
before a comparison is rejected: Actions binds it to the operand, not the
comparison. A condition may read only an earlier step that has an ``id``.
"""

import re

STATUS_FUNCTIONS = ("success", "failure", "always", "cancelled")
STEP_RESULTS = ("success", "failure", "cancelled", "skipped")

_KEY = re.compile(r"([A-Za-z0-9_-]+):(?: (.*))?\Z")
_AMBIGUOUS = {"y", "n", "yes", "no", "on", "off", "null", "~", "true", "false"}
_NUMERIC_LOOKING = re.compile(r"[-+.0-9_:eE]+")
_TOKEN = re.compile(
    r"\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\))"
    r"|(?P<status>success|failure|always|cancelled)\(\)"
    r"|(?P<step>steps\.[A-Za-z_][A-Za-z0-9_-]*\.(?:outcome|conclusion))"
    r"|'(?P<literal>[a-z]+)')"
)


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _skip(lines, index):
    while index < len(lines) and (
        not lines[index] or lines[index].lstrip(" ").startswith("#")
    ):
        index += 1
    return index


def _strip_comment(text):
    if text.startswith("#"):
        return ""
    cut = text.find(" #")
    return (text if cut < 0 else text[:cut]).rstrip(" ")


def _scalar(text, index):
    where = f"line {index + 1}"
    if not text or text[0] in "!&*{}[]|>'\"%@`#?,:- ":
        raise ValueError(f"{where}: unsupported scalar {text[:1]!r}")
    if ": " in text or text.endswith(":") or " #" in text:
        raise ValueError(f"{where}: ambiguous plain scalar")
    if text in ("true", "false"):
        return text == "true"
    if text.lower() in _AMBIGUOUS:
        raise ValueError(f"{where}: ambiguous YAML 1.1 scalar {text!r}")
    if re.fullmatch(r"0|[1-9][0-9]*", text):
        return int(text)
    if _NUMERIC_LOOKING.fullmatch(text):
        raise ValueError(f"{where}: numeric-looking scalar {text!r}")
    return text


def _flow(text, index):
    if not text.endswith("]") or text.count("[") != 1 or text.count("]") != 1:
        raise ValueError(f"line {index + 1}: unsupported flow sequence")
    parts = [part.strip(" ") for part in text[1:-1].split(",")]
    if not all(re.fullmatch(r"[A-Za-z0-9_./-]+", part) for part in parts):
        raise ValueError(f"line {index + 1}: unsupported flow sequence item")
    return [_scalar(part, index) for part in parts]


def _literal(lines, index, parent):
    block, indent, cursor = [], None, index + 1
    while cursor < len(lines):
        line = lines[cursor]
        if line:
            current = _indent(line)
            if indent is None:
                if current <= parent:
                    break
                indent = current
            if current < indent:
                break
            block.append(line[indent:])
        else:
            block.append("")
        cursor += 1
    while block and block[-1] == "":
        block.pop()
    if not block:
        raise ValueError(f"line {index + 1}: empty literal block")
    return "\n".join(block) + "\n", cursor


def _node(lines, index, indent):
    content = lines[index][indent:]
    if content == "-" or content.startswith("- "):
        return _sequence(lines, index, indent)
    return _mapping(lines, index, indent)


def _mapping(lines, index, indent):
    result = {}
    while True:
        index = _skip(lines, index)
        if index == len(lines) or _indent(lines[index]) < indent:
            return result, index
        if _indent(lines[index]) > indent:
            raise ValueError(f"line {index + 1}: unexpected indentation")
        match = _KEY.match(lines[index][indent:])
        if match is None:
            raise ValueError(f"line {index + 1}: unsupported mapping entry")
        key = match.group(1)
        rest = _strip_comment((match.group(2) or "").lstrip(" "))
        if key in result:
            raise ValueError(f"line {index + 1}: duplicate key {key!r}")
        if rest == "|":
            result[key], index = _literal(lines, index, indent)
        elif rest.startswith("["):
            result[key], index = _flow(rest, index), index + 1
        elif rest:
            result[key], index = _scalar(rest, index), index + 1
        else:
            child = _skip(lines, index + 1)
            if child == len(lines) or _indent(lines[child]) <= indent:
                raise ValueError(f"line {index + 1}: empty or indentless value")
            result[key], index = _node(lines, child, _indent(lines[child]))


def _sequence(lines, index, indent):
    items = []
    while True:
        index = _skip(lines, index)
        if index == len(lines) or _indent(lines[index]) < indent:
            return items, index
        content = lines[index][indent:]
        if _indent(lines[index]) > indent or not content.startswith("- "):
            raise ValueError(f"line {index + 1}: unsupported sequence entry")
        body = content[2:]
        if not body or body[0] in " -":
            raise ValueError(f"line {index + 1}: empty or nested sequence item")
        if _KEY.match(body):
            lines[index] = " " * (indent + 2) + body
            item, index = _mapping(lines, index, indent + 2)
        else:
            item, index = _scalar(_strip_comment(body), index), index + 1
        items.append(item)


def load_workflow(text):
    """Load the supported block-YAML subset; raise ValueError otherwise."""
    if "\t" in text or "\r" in text:
        raise ValueError("tab or carriage return")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for index, line in enumerate(lines):
        if line and not line.strip(" "):
            raise ValueError(f"line {index + 1}: whitespace-only line")
    start = _skip(lines, 0)
    if start == len(lines) or _indent(lines[start]):
        raise ValueError("document is not a top-level block mapping")
    document, end = _mapping(lines, start, 0)
    if end != len(lines):
        raise ValueError(f"line {end + 1}: trailing content")
    return document


def _tokens(expression):
    tokens, position = [], 0
    expression = expression.rstrip()
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if match is None:
            raise ValueError(f"unsupported expression {expression[position:]!r}")
        tokens.append((match.lastgroup, match.group(match.lastgroup)))
        position = match.end()
    return tokens


def _or(tokens):
    node, tokens = _and(tokens)
    while tokens and tokens[0] == ("op", "||"):
        right, tokens = _and(tokens[1:])
        node = ("or", node, right)
    return node, tokens


def _and(tokens):
    node, tokens = _unary(tokens)
    while tokens and tokens[0] == ("op", "&&"):
        right, tokens = _unary(tokens[1:])
        node = ("and", node, right)
    return node, tokens


def _unary(tokens):
    if tokens and tokens[0] == ("op", "!"):
        if len(tokens) > 1 and tokens[1][0] == "step":
            raise ValueError("'!' before a step comparison; use parentheses")
        operand, tokens = _unary(tokens[1:])
        return ("not", operand), tokens
    return _primary(tokens)


def _primary(tokens):
    if not tokens:
        raise ValueError("incomplete expression")
    (kind, value), rest = tokens[0], tokens[1:]
    if (kind, value) == ("op", "("):
        node, rest = _or(rest)
        if not rest or rest[0] != ("op", ")"):
            raise ValueError("unbalanced parentheses")
        return node, rest[1:]
    if kind == "status":
        return ("status", value), rest
    if kind == "step":
        if (
            len(rest) < 2
            or rest[0] not in (("op", "=="), ("op", "!="))
            or rest[1][0] != "literal"
        ):
            raise ValueError("a step result must be compared with a literal")
        if rest[1][1] not in STEP_RESULTS:
            raise ValueError(f"unknown step result {rest[1][1]!r}")
        _, step_id, field = value.split(".")
        return ("compare", step_id, field, rest[0][1], rest[1][1]), rest[2:]
    raise ValueError(f"unexpected token {value!r}")


def _walk(node):
    yield node
    if node[0] in ("not", "and", "or"):
        for child in node[1:]:
            yield from _walk(child)


def parse_condition(text):
    """Return a step condition with GitHub's implicit success() applied."""
    if text is None:
        return ("status", "success")
    if type(text) is not str:
        raise ValueError("condition is not a string")
    expression = text.strip()
    if expression.startswith("${{"):
        if (
            not expression.endswith("}}")
            or expression.count("${{") != 1
            or expression.count("}}") != 1
        ):
            raise ValueError("unsupported expression wrapper")
        expression = expression[3:-2]
    elif "${{" in expression or "}}" in expression:
        raise ValueError("unsupported expression wrapper")
    node, rest = _or(_tokens(expression))
    if rest:
        raise ValueError(f"unexpected token {rest[0][1]!r}")
    if not any(part[0] == "status" for part in _walk(node)):
        node = ("and", ("status", "success"), node)
    return node


def _evaluate(node, state):
    kind = node[0]
    if kind == "status":
        return {
            "always": True,
            "cancelled": state["cancelled"],
            "failure": state["failed"],
            "success": not state["failed"] and not state["cancelled"],
        }[node[1]]
    if kind == "not":
        return not _evaluate(node[1], state)
    if kind == "and":
        return _evaluate(node[1], state) and _evaluate(node[2], state)
    if kind == "or":
        return _evaluate(node[1], state) or _evaluate(node[2], state)
    _, step_id, field, operator, value = node
    return (state["steps"][step_id][field] == value) == (operator == "==")


def step_label(step):
    return step.get("name") or step["uses"].split("@", 1)[0]


def run_steps(steps, *, fail=(), cancel=None):
    """Return the labels of the steps that execute, in order.

    Steps labelled in ``fail`` fail when they execute; the run is cancelled
    while the step labelled ``cancel`` executes (that step ends cancelled).
    """
    labels = [step_label(step) for step in steps]
    unknown = (set(fail) | ({cancel} if cancel else set())) - set(labels)
    if len(set(labels)) != len(labels) or unknown:
        raise ValueError(f"duplicate or unknown step labels {sorted(unknown)}")
    ids = [step["id"] for step in steps if "id" in step]
    if len(set(ids)) != len(ids) or not all(
        type(i) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", i) for i in ids
    ):
        raise ValueError("duplicate or invalid step id")
    state = {"failed": False, "cancelled": False, "steps": {}}
    executed = []
    for step, label in zip(steps, labels, strict=True):
        condition = parse_condition(step.get("if"))
        for part in _walk(condition):
            if part[0] == "compare" and part[1] not in state["steps"]:
                raise ValueError(f"{label}: reads unknown or later step {part[1]!r}")
        if _evaluate(condition, state):
            executed.append(label)
            if label == cancel:
                outcome, state["cancelled"] = "cancelled", True
            else:
                outcome = "failure" if label in fail else "success"
        else:
            outcome = "skipped"
        conclusion = outcome
        if outcome == "failure" and step.get("continue-on-error") is True:
            conclusion = "success"
        if conclusion == "failure":
            state["failed"] = True
        if "id" in step:
            state["steps"][step["id"]] = {"outcome": outcome, "conclusion": conclusion}
    return executed
