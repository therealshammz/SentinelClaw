"""
Sigma-subset reader (P2-14).

Converts Sigma YAML detection rules (sigma spec v1 subset, as
maintained by SigmaHQ) into SentinelClaw's internal rule format so the
deterministic rule engine evaluates them over the same evidence records.

Design constraints:

* No new runtime dependencies (PyYAML is already a project dependency).
* Every conversion failure raises :class:`SigmaRuleError` carrying a
  stable ``reason_code``; importers skip the offending rule and keep
  going so one bad rule never breaks a 3000+ rule import (P1-9
  isolation).
* Converted rules pass ``rule_engine.validate_rule`` unchanged and only
  use the engine's native operators.

Supported logsource mapping
===========================

Sigma identifies its data source with ``logsource.category`` /
``logsource.product`` / ``logsource.service``. SentinelClaw evidence is
tagged with one of its own categories, so conversion maps:

============================  ================  =========================
Sigma logsource               Internal category Notes
============================  ================  =========================
category: process_creation    process           product windows or linux
category: network_connection  network
category: file_event          file
category: logon_failure       windows_event     Security log logons
category: logon_success       windows_event     Security log logons
category: auditd              log
category: syslog (+service)   auth/log          sshd/sudo -> auth;
                                                auditd/syslog -> log
(no category) service:
  security / sysmon           windows_event     EventID-style rules
  sshd / sudo / su            auth
  auditd / syslog             log
============================  ================  =========================

``logsource.product`` gates the rule to an OS: ``windows`` becomes
``os: [windows]``, ``linux`` becomes ``os: [linux]``, and any other
product (for example ``macos``) skips the rule because the engine has
no evidence schema for it.

Supported field-name mapping
============================

Sigma field names are translated to the keys of the matching internal
evidence record. A rule referencing a field that has no entry in the
table for its category is skipped (reason ``unmapped-field``); it is
never silently matched against the wrong key:

===================  ====================  =============
Sigma field          Internal field        Category
===================  ====================  =============
Image                executable            process
CommandLine          command_line          process
ParentImage          parent_name           process
ProcessId            pid                   process
ParentProcessId      ppid                  process
User                 username              process
EventID              event_id              windows_event
Channel              source                windows_event
Computer             computer              windows_event
Message              message_data          windows_event
RecordNumber         record_number         windows_event
DestinationIp        remote_address.ip     network
DestinationPort      remote_address.port   network
SourceIp             local_address.ip      network
SourcePort           local_address.port    network
TargetFilename       path                  file
msg / message        message               auth, log
program              program               auth, log
user / username      username              auth, log
===================  ====================  =============

Supported condition grammar
===========================

``detection`` blocks hold named ``selection`` / ``filter`` maps; each
``Field: value`` entry adds an AND-ed condition. Lists of values mean
OR (any-of) unless ``|all`` forces AND. The ``condition`` expression
grammar is:

.. code-block:: text

    expr      := or_expr
    or_expr   := and_expr ( "or" and_expr )*
    and_expr  := unary ( "and" unary )*
    unary     := "not" unary | "(" expr ")" | predicate
    predicate := name | name "*" | ("1 of" | "all of") name ["*"]
    name      := any detection-block name, or "them"

``1 of <prefix>*`` and ``1 of them`` compile to an OR of the matched
blocks; ``all of <prefix>*`` and ``all of them`` compile to an AND.
Only ``1 of`` and ``all of`` counts are supported.

Supported value modifiers
=========================

A field key may carry ``|``-joined modifiers:

* ``field|contains``        -> ``contains`` operator
* ``field|startswith``      -> ``startswith`` (native engine operator)
* ``field|endswith``        -> ``endswith`` (native engine operator)
* ``field|re``              -> ``matches`` (case-insensitive regex)
* ``field|cidr``            -> ``cidr`` (ipaddress; IP-in-network test)
* ``field|fieldref``        -> ``fieldref`` (value names a sibling field)
* ``field|exists``          -> ``exists``
* ``field|lt|gt|lte|gte``   -> less_than/greater_than/less_or_equal/
                               greater_or_equal
* ``|all``                  -> every list value becomes its own AND-ed
                               condition
* ``|any``                  -> explicit default any-of list semantics

Plain values default to ``equals``. Values containing ``*`` / ``?``
wildcards are compiled to ``matches`` regexes (anchored for plain
equals, prefix/suffix anchored for startswith/endswith, unanchored for
contains), which preserves Sigma wildcard semantics. String matching is
case-insensitive, mirroring Sigma's own comparisons; converted regexes
therefore carry a ``(?i)`` prefix.

Out of scope (the rule is skipped with a warning; see
``SUPPORTED_SUBSET.md``):

* Sigma v2 correlation rules (top-level ``correlation:``) and
  ``$placeholder`` values.
* ``keywords:``-only detections (they have no field anchor).
* Value-transform modifiers: ``|base64``, ``|utf16le``, ``|utf16be``,
  ``|wide``, ``|windash``, ``|compress``, ``|expand``.
* Multi-count conditions such as ``2 of selection_*``.
* Products other than windows/linux, unmapped logsource blocks, and
  unmapped fields.
"""

from __future__ import annotations

import logging
import re
from typing import Any, NoReturn

import yaml

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Mapping tables (documented in the module docstring and in
# sentinelclaw/sigma/SUPPORTED_SUBSET.md)
# --------------------------------------------------------------------------

LOGSOURCE_CATEGORY_MAP = {
    "process_creation": "process",
    "network_connection": "network",
    "file_event": "file",
    "file_change": "file",
    "logon_failure": "windows_event",
    "logon_success": "windows_event",
    "auditd": "log",
    # ``syslog`` alone needs the service to pick a destination (see
    # LOGSOURCE_SERVICE_MAP); without one it stays unsupported.
}

LOGSOURCE_SERVICE_MAP = {
    "sshd": "auth",
    "sudo": "auth",
    "su": "auth",
    "security": "windows_event",
    "security-auditing": "windows_event",
    "sysmon": "windows_event",
    "auditd": "log",
    "syslog": "log",
}

PRODUCT_OS_MAP = {
    "windows": ["windows"],
    "linux": ["linux"],
}

SEVERITY_MAP = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

STATUS_MAP = {
    "stable": "proven",
    "test": "experimental",
    "experimental": "experimental",
    "deprecated": "deprecated",
}

# Sigma rules carry no confidence; derive a conservative value from the
# rule level so the engine's required field is populated.
CONFIDENCE_BY_LEVEL = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
}

SUPPORTED_MODIFIERS = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "re",
        "cidr",
        "fieldref",
        "exists",
        "all",
        "any",
        "lt",
        "lte",
        "gt",
        "gte",
    }
)

MODIFIER_OPERATORS = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "matches",
    "cidr": "cidr",
    "fieldref": "fieldref",
    "exists": "exists",
    "lt": "less_than",
    "lte": "less_or_equal",
    "gt": "greater_than",
    "gte": "greater_or_equal",
}

FIELD_MAP = {
    "process": {
        "Image": "executable",
        "CommandLine": "command_line",
        "ParentImage": "parent_name",
        "ProcessId": "pid",
        "ParentProcessId": "ppid",
        "User": "username",
    },
    "windows_event": {
        "EventID": "event_id",
        "Channel": "source",
        "Computer": "computer",
        "Message": "message_data",
        "RecordNumber": "record_number",
    },
    "network": {
        "DestinationIp": "remote_address.ip",
        "DestinationPort": "remote_address.port",
        "SourceIp": "local_address.ip",
        "SourcePort": "local_address.port",
        "User": "username",
    },
    "file": {
        "TargetFilename": "path",
        "Image": "path",
    },
    "auth": {
        "msg": "message",
        "message": "message",
        "program": "program",
        "user": "username",
        "username": "username",
        "host": "ip",
    },
    "log": {
        "msg": "message",
        "message": "message",
        "program": "program",
        "user": "username",
        "username": "username",
        "host": "ip",
    },
}

_WILDCARD_RE = re.compile(r"[*?]")
_CASE_INSENSITIVE_PREFIX = "(?i)"

_REGEX_SPECIAL_CHARS = frozenset(r".^$+?{}[]\|()")

#: Operators whose match functions accept a list of values as any-of.
LISTABLE_OPERATORS = frozenset(
    {
        "equals",
        "contains",
        "startswith",
        "endswith",
        "matches",
        "cidr",
    }
)


def _escape_literal_segment(segment: str) -> str:
    """Escape only the regex metacharacters of a literal segment.

    ``re.escape`` also escapes spaces and other innocuous characters;
    the resulting ``\\ `` sequences are brittle across Python versions,
    so only the characters with regex meaning are escaped here.
    """
    return "".join(f"\\{char}" if char in _REGEX_SPECIAL_CHARS else char for char in segment)


class SigmaRuleError(Exception):
    """A single Sigma rule could not be converted (skip, do not abort).

    ``reason_code`` is a stable, coarse classifier importers aggregate
    for their skip summary (for example ``unmapped-field``); ``message``
    carries the human-readable detail.
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def _fail(
    reason_code: str,
    message: str,
) -> NoReturn:
    raise SigmaRuleError(
        reason_code,
        message,
    )


def resolve_category(
    logsource: Any,
) -> str | None:
    """Map a Sigma logsource block to an internal category or ``None``.

    Returns ``None`` when the logsource does not describe evidence the
    engine can evaluate; the caller skips the rule.
    """
    if not isinstance(
        logsource,
        dict,
    ):
        return None

    category = logsource.get("category")
    service = logsource.get("service")

    mapped = None

    if category is not None:
        mapped = LOGSOURCE_CATEGORY_MAP.get(str(category).lower())

    if mapped is None and service is not None:
        mapped = LOGSOURCE_SERVICE_MAP.get(str(service).lower())

    if mapped is None and category is not None and str(category).lower() == "syslog":
        # A bare syslog category without a refining service defaults to
        # the generic log category.
        mapped = "log"

    return mapped


def resolve_os_values(
    logsource: Any,
) -> list[str] | None:
    """Map a logsource product to an ``os`` list (``None`` means all)."""
    if not isinstance(
        logsource,
        dict,
    ):
        return None

    product = logsource.get("product")

    if product is None:
        return None

    product_name = str(product).lower()

    if product_name not in PRODUCT_OS_MAP:
        _fail(
            "unsupported-product",
            f"logsource.product {product_name!r} is not supported",
        )

    return PRODUCT_OS_MAP[product_name]


def map_sigma_field(
    field_name: str,
    internal_category: str,
) -> str:
    """Translate a Sigma field name to an internal evidence key."""
    mapped = FIELD_MAP.get(
        internal_category,
        {},
    ).get(field_name)

    if mapped is None:
        _fail(
            "unmapped-field",
            f"field {field_name!r} has no mapping for category {internal_category!r}",
        )

    return mapped


def _wildcard_body(
    value: str,
) -> str:
    """Escape the literal parts of a Sigma wildcard string.

    ``*`` becomes ``.*`` and ``?`` becomes ``.``; literal characters are
    regex-escaped individually.
    """
    pieces = []
    literal: list[str] = []

    for char in value:
        if char in "*?":
            if literal:
                pieces.append(_escape_literal_segment("".join(literal)))
                literal = []

            pieces.append(".*" if char == "*" else ".")
        else:
            literal.append(char)

    if literal:
        pieces.append(_escape_literal_segment("".join(literal)))

    return "".join(pieces)


def _wildcard_regex(
    value: str,
    anchor_start: bool,
    anchor_end: bool,
) -> str:
    """Compile a wildcard value into a case-insensitive regex string."""
    body = _wildcard_body(value)

    if anchor_start:
        body = "^" + body

    if anchor_end:
        body += "$"

    return _CASE_INSENSITIVE_PREFIX + body


def _value_has_wildcards(value: Any) -> bool:
    if isinstance(value, str):
        return _WILDCARD_RE.search(value) is not None

    if isinstance(value, list):
        return any(
            isinstance(item, str) and _WILDCARD_RE.search(item) is not None for item in value
        )

    return False


def _regex_for_operator(
    value: str,
    operator: str,
) -> str:
    """Build the engine ``matches`` pattern for a wildcard value."""
    if operator == "equals":
        return _wildcard_regex(
            value,
            True,
            True,
        )

    if operator == "startswith":
        return _wildcard_regex(
            value,
            True,
            False,
        )

    if operator == "endswith":
        return _wildcard_regex(
            value,
            False,
            True,
        )

    return _wildcard_regex(
        value,
        False,
        False,
    )


class ConditionBuilder:
    """Parse one detection ``Field|mod1|mod2: value`` key."""

    def __init__(
        self,
        raw_key: str,
        internal_category: str,
    ) -> None:
        parts = raw_key.split("|")
        self.field_name = parts[0]
        self.modifiers = parts[1:]
        self.internal_category = internal_category
        self.operator = "equals"
        self.base_modifier: str | None = None

        if not self.field_name:
            _fail(
                "unsupported-field",
                f"empty field name in detection key {raw_key!r}",
            )

        unsupported = sorted(set(self.modifiers) - SUPPORTED_MODIFIERS)

        if unsupported:
            _fail(
                "unsupported-modifier",
                f"unsupported modifier(s) {unsupported} on field {self.field_name!r}",
            )

        if "all" in self.modifiers and "any" in self.modifiers:
            _fail(
                "unsupported-modifier",
                f"field {self.field_name!r} mixes 'all' and 'any'",
            )

        base = [modifier for modifier in self.modifiers if modifier not in {"all", "any"}]

        if len(base) > 1:
            _fail(
                "unsupported-modifier",
                f"cannot combine modifiers {self.modifiers} on field {self.field_name!r}",
            )

        if base:
            self.base_modifier = base[0]

            if base[0] not in MODIFIER_OPERATORS:
                _fail(
                    "unsupported-modifier",
                    f"unsupported modifier {base[0]!r} on field {self.field_name!r}",
                )

            self.operator = MODIFIER_OPERATORS[base[0]]


def _compile_field_value(
    builder: ConditionBuilder,
    value: Any,
) -> list[dict]:
    """Compile one ``field: value`` pair into engine condition nodes.

    Every returned node is AND-ed with its siblings. A plain list value
    collapses into one any-of condition (the engine treats lists as
    any-of), while ``|all`` splits the list into one AND-ed condition
    per entry.
    """
    internal_field = map_sigma_field(
        builder.field_name,
        builder.internal_category,
    )

    operator = builder.operator
    values = value if isinstance(value, list) else [value]

    if operator == "fieldref":
        if len(values) != 1 or not isinstance(values[0], str):
            _fail(
                "unsupported-value",
                f"fieldref on {builder.field_name!r} needs exactly one field name",
            )

        referenced = map_sigma_field(
            values[0],
            builder.internal_category,
        )

        return [
            {
                "field": internal_field,
                "operator": "fieldref",
                "value": referenced,
            }
        ]

    if operator == "exists":
        return [
            {
                "field": internal_field,
                "operator": "exists",
                "value": None,
            }
        ]

    if value is None and operator == "equals":
        # A bare ``Field:`` entry means "the field exists" in Sigma.
        return [
            {
                "field": internal_field,
                "operator": "exists",
                "value": None,
            }
        ]

    expand_all = "all" in builder.modifiers

    wildcard_ok = operator in {
        "equals",
        "contains",
        "startswith",
        "endswith",
    }
    use_matches = wildcard_ok and _value_has_wildcards(value)

    emitted_operator = "matches" if use_matches else operator

    transformed: list[Any] = []

    for item in values:
        if item is None:
            _fail(
                "unsupported-value",
                f"null value on {builder.field_name!r} with modifier {operator!r}",
            )

        if not isinstance(item, (str, int, float, bool)):
            _fail(
                "unsupported-value",
                f"unsupported value type {type(item).__name__} on {builder.field_name!r}",
            )

        if isinstance(item, str) and item.startswith("$"):
            _fail(
                "placeholder",
                f"Sigma placeholder {item!r} is not supported",
            )

        if use_matches and isinstance(item, str):
            transformed.append(_regex_for_operator(item, operator))
            continue

        if builder.base_modifier == "re":
            pattern = str(item)

            if not pattern.startswith(_CASE_INSENSITIVE_PREFIX):
                pattern = _CASE_INSENSITIVE_PREFIX + pattern

            transformed.append(pattern)
            continue

        transformed.append(item)

    if expand_all:
        return [
            {
                "field": internal_field,
                "operator": emitted_operator,
                "value": item,
            }
            for item in transformed
        ]

    if len(transformed) == 1:
        return [
            {
                "field": internal_field,
                "operator": emitted_operator,
                "value": transformed[0],
            }
        ]

    # The engine's list operators are any-of over the list; numeric
    # comparisons cannot take a list, so OR them through a group node.
    if operator in LISTABLE_OPERATORS:
        return [
            {
                "field": internal_field,
                "operator": emitted_operator,
                "value": transformed,
            }
        ]

    return [
        {
            "any_of": [
                {
                    "field": internal_field,
                    "operator": emitted_operator,
                    "value": item,
                }
                for item in transformed
            ]
        }
    ]


def compile_detection_block(
    block: Any,
    block_name: str,
    internal_category: str,
) -> list[dict]:
    """Compile a named detection map into AND-ed engine conditions."""
    if not isinstance(block, dict):
        _fail(
            "invalid-detection",
            f"detection block {block_name!r} must be a mapping",
        )

    conditions: list[dict] = []

    for raw_key, value in block.items():
        builder = ConditionBuilder(
            raw_key,
            internal_category,
        )

        if isinstance(value, dict):
            _fail(
                "unsupported-value",
                f"mapping value for field {builder.field_name!r} is not supported",
            )

        conditions.extend(
            _compile_field_value(
                builder,
                value,
            )
        )

    if not conditions:
        _fail(
            "invalid-detection",
            f"detection block {block_name!r} compiled to no conditions",
        )

    return conditions


class ConditionParser:
    """Recursive-descent parser for the Sigma condition expression.

    Produces a raw AST of ``and`` / ``or`` / ``not`` / ``name`` / ``of``
    nodes; resolution against the detection blocks happens later in
    :class:`ExpressionCompiler`.
    """

    def __init__(self, expression: str) -> None:
        self.tokens = re.findall(r"[()]|[^\s()]+", expression)
        self.position = 0

    def peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None

        return self.tokens[self.position]

    def pop(self) -> str:
        if self.position >= len(self.tokens):
            _fail(
                "condition-syntax",
                "unexpected end of condition expression",
            )

        token = self.tokens[self.position]
        self.position += 1

        return token

    def parse(self) -> Any:
        if not self.tokens:
            _fail(
                "condition-syntax",
                "empty condition expression",
            )

        node = self.parse_or()

        if self.peek() is not None:
            _fail(
                "condition-syntax",
                f"trailing tokens in condition: {' '.join(self.tokens[self.position :])}",
            )

        return node

    def parse_or(self) -> Any:
        node = self.parse_and()

        while True:
            next_token = self.peek()

            if next_token is None or next_token.lower() != "or":
                break

            self.pop()
            node = {
                "or": [node, self.parse_and()],
            }

        return node

    def parse_and(self) -> Any:
        node = self.parse_unary()

        while True:
            next_token = self.peek()

            if next_token is None or next_token.lower() != "and":
                break

            self.pop()
            node = {
                "and": [node, self.parse_unary()],
            }

        return node

    def parse_unary(self) -> Any:
        token = self.peek()

        if token is None:
            _fail(
                "condition-syntax",
                "unexpected end of condition expression",
            )

        if token.lower() == "not":
            self.pop()

            return {"not": self.parse_unary()}

        if token == "(":
            self.pop()
            node = self.parse_or()

            if self.peek() != ")":
                _fail(
                    "condition-syntax",
                    "missing closing parenthesis in condition",
                )

            self.pop()

            return node

        if token.lower() in {"and", "or"}:
            _fail(
                "condition-syntax",
                f"unexpected {token!r} in condition",
            )

        return self.parse_predicate()

    def parse_predicate(self) -> Any:
        token = self.pop()
        lowered = token.lower()

        if lowered in {"all", "them"} or token.isdigit():
            if lowered == "them":
                _fail(
                    "condition-syntax",
                    "'them' must follow '1 of' or 'all of'",
                )

            if lowered == "all":
                count = "all"
            elif int(token) == 1:
                count = "any"
            else:
                _fail(
                    "condition-syntax",
                    f"only '1 of' and 'all of' are supported, got {token} of",
                )

            next_token = self.peek()

            if next_token is None or next_token.lower() != "of":
                _fail(
                    "condition-syntax",
                    "expected 'of' after count in condition",
                )

            self.pop()

            target = self.peek()

            if target is None:
                _fail(
                    "condition-syntax",
                    "expected detection name after 'of'",
                )

            self.pop()

            return {
                "of": count,
                "target": target,
            }

        if token.endswith("*"):
            _fail(
                "condition-syntax",
                f"wildcard name {token!r} must follow '1 of' or 'all of'",
            )

        return {"name": token}


class ExpressionCompiler:
    """Resolve a parsed condition AST against compiled detection blocks.

    Blocks are pre-compiled lists of engine condition nodes; a name
    reference expands to the block's nodes AND-ed together. The compiled
    output is an engine condition tree using only ``all_of`` /
    ``any_of`` / ``negated`` wrappers over flat conditions.
    """

    def __init__(self, blocks: dict[str, list[dict]]) -> None:
        self.blocks = blocks

    def detection_names(self) -> list[str]:
        return sorted(self.blocks)

    def block_node(self, name: str) -> Any:
        conditions = self.blocks.get(name)

        if conditions is None:
            _fail(
                "unknown-detection-reference",
                f"condition references unknown detection block {name!r}",
            )

        if len(conditions) == 1:
            return conditions[0]

        return {"all_of": list(conditions)}

    def resolve_target(self, target: str) -> list[Any]:
        lowered = target.lower()

        if lowered == "them":
            names = self.detection_names()
        elif target.endswith("*"):
            prefix = target[:-1]
            names = [name for name in self.detection_names() if name.startswith(prefix)]

            if not names:
                _fail(
                    "unknown-detection-reference",
                    f"condition references prefix {prefix!r} which matches no detection block",
                )
        else:
            names = [target]

        return [self.block_node(name) for name in names]

    def negate(self, node: Any) -> Any:
        copy = dict(node)

        if copy.get("negated"):
            del copy["negated"]
        else:
            copy["negated"] = True

        return copy

    def combine_all(self, nodes: list[Any]) -> Any:
        children: list[Any] = []

        for node in nodes:
            if isinstance(node, dict) and "all_of" in node and not node.get("negated"):
                children.extend(node["all_of"])
            else:
                children.append(node)

        if len(children) == 1:
            return children[0]

        return {"all_of": children}

    def combine_any(self, nodes: list[Any]) -> Any:
        children: list[Any] = []

        for node in nodes:
            if isinstance(node, dict) and "any_of" in node and not node.get("negated"):
                children.extend(node["any_of"])
            else:
                children.append(node)

        if len(children) == 1:
            return children[0]

        return {"any_of": children}

    def compile(self, node: Any) -> Any:
        if isinstance(node, dict) and "name" in node:
            return self.block_node(node["name"])

        if isinstance(node, dict) and "of" in node:
            nodes = self.resolve_target(node["target"])

            if node["of"] == "any":
                return self.combine_any(nodes)

            return self.combine_all(nodes)

        if isinstance(node, dict) and "not" in node:
            return self.negate(self.compile(node["not"]))

        if isinstance(node, dict) and "and" in node:
            return self.combine_all([self.compile(item) for item in node["and"]])

        if isinstance(node, dict) and "or" in node:
            return self.combine_any([self.compile(item) for item in node["or"]])

        _fail(
            "condition-syntax",
            f"cannot compile condition node {node!r}",
        )

    def rule_conditions(self, node: Any) -> list[dict]:
        """Flatten the compiled tree to the engine's top-level list.

        A root ``all_of`` group without negation becomes the implicit
        top-level AND list; any other shape stays as a single nested
        node so the engine evaluates it correctly.
        """
        root = self.compile(node)

        if isinstance(root, dict) and "all_of" in root and not root.get("negated"):
            return list(root["all_of"])

        return [root]


def _string_list(data: dict, key: str) -> list[str] | None:
    value = data.get(key)

    if not isinstance(value, list):
        return None

    return [str(item) for item in value]


def _emit_rule_metadata(data: dict, rule: dict) -> None:
    """Copy optional Sigma provenance metadata onto the internal rule."""
    tags = data.get("tags")

    if isinstance(tags, list):
        attack_techniques = []

        for tag in tags:
            tag_text = str(tag).strip()

            if tag_text.startswith("attack."):
                suffix = tag_text[len("attack.") :]

                if re.fullmatch(r"t\d{4}(\.\d{3})?", suffix):
                    attack_techniques.append("T" + suffix[1:])

        if attack_techniques:
            rule["mitre"] = {
                "technique": attack_techniques[0],
            }

        rule["tags"] = [str(tag) for tag in tags]

    falsepositives = _string_list(
        data,
        "falsepositives",
    )

    if falsepositives is not None:
        rule["falsepositives"] = falsepositives

    references = _string_list(
        data,
        "references",
    )

    if references is not None:
        rule["references"] = references

    for key in ("author", "date", "modified"):
        if key in data and data[key] is not None:
            rule[key] = str(data[key])

    logsource = data.get("logsource")

    if isinstance(logsource, dict):
        rule["sigma_logsource"] = {str(key): logsource[key] for key in sorted(logsource)}


def convert_sigma_rule(data: Any, source: str = "<sigma>") -> dict:
    """Convert one parsed Sigma rule document to the internal format.

    Raises :class:`SigmaRuleError` with a stable ``reason_code`` on any
    unsupported construct; callers skip the rule and continue.
    """
    if not isinstance(data, dict):
        _fail(
            "invalid-yaml",
            f"{source}: rule document must be a YAML mapping",
        )

    if "correlation" in data:
        _fail(
            "correlation-rule",
            f"{source}: Sigma v2 correlation rules are not supported",
        )

    rule_id = data.get("id")
    title = data.get("title")

    if not rule_id:
        _fail(
            "missing-id",
            f"{source}: rule has no 'id'",
        )

    if not title:
        _fail(
            "missing-title",
            f"{source}: rule has no 'title'",
        )

    logsource = data.get("logsource")

    internal_category = resolve_category(logsource)

    if internal_category is None:
        _fail(
            "unsupported-logsource",
            f"{source}: logsource {logsource!r} maps to no supported evidence category",
        )

    os_values = resolve_os_values(logsource)

    level = str(data.get("level", "medium")).lower()

    if level not in SEVERITY_MAP:
        _fail(
            "invalid-level",
            f"{source}: unknown Sigma level {level!r}",
        )

    status_value = data.get("status")

    if status_value is not None:
        status_name = str(status_value).lower()

        if status_name not in STATUS_MAP:
            _fail(
                "unsupported-status",
                f"{source}: unknown Sigma status {status_value!r}",
            )

    detection = data.get("detection")

    if not isinstance(detection, dict) or not detection:
        _fail(
            "invalid-detection",
            f"{source}: detection block is missing or empty",
        )

    if "keywords" in detection:
        _fail(
            "keywords",
            f"{source}: keyword-only detections are not supported",
        )

    condition_expression = detection.get("condition")

    if not isinstance(condition_expression, str):
        _fail(
            "invalid-detection",
            f"{source}: no string 'condition' in detection",
        )

    blocks: dict[str, list[dict]] = {}

    for name, block in detection.items():
        if name == "condition":
            continue

        blocks[str(name)] = compile_detection_block(
            block,
            str(name),
            internal_category,
        )

    ast = ConditionParser(condition_expression).parse()

    conditions = ExpressionCompiler(blocks).rule_conditions(ast)

    rule: dict[str, Any] = {
        "id": str(rule_id),
        "title": str(title),
        "description": str(data.get("description", "")),
        "category": internal_category,
    }

    if os_values is not None:
        rule["os"] = os_values

    rule.update(
        {
            "severity": SEVERITY_MAP[level],
            "confidence": CONFIDENCE_BY_LEVEL[level],
        }
    )

    if status_value is not None:
        rule["status"] = STATUS_MAP[str(status_value).lower()]

    rule["enabled"] = True

    _emit_rule_metadata(data, rule)

    rule["conditions"] = conditions

    return rule


def convert_sigma_text(
    text: str,
    source: str = "<sigma>",
) -> dict:
    """Parse and convert a Sigma rule from its raw YAML text."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaRuleError(
            "invalid-yaml",
            f"{source}: invalid YAML ({exc})",
        ) from exc

    return convert_sigma_rule(data, source)
