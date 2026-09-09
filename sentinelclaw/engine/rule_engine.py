import logging
import re
from pathlib import Path
from typing import Any

import yaml

from sentinelclaw.config.constants import VALID_SEVERITIES

logger = logging.getLogger(
    __name__
)

SUPPORTED_OPERATORS = frozenset(
    {
        "equals",
        "contains",
        "startswith",
        "endswith",
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
        "exists",
        "not_equals",
        "not_contains",
        "matches",
    }
)

VALID_RULE_CATEGORIES = frozenset(
    {
        "process",
        "network",
        "file",
        "windows_event",
        "log",
    }
)

REQUIRED_RULE_FIELDS = (
    "id",
    "title",
    "description",
    "category",
    "severity",
    "confidence",
    "conditions",
)


def load_rule_file(file_path: str | Path) -> list[dict]:
    path = Path(file_path)

    if not path.exists():
        return []

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError as exc:
        logger.warning(
            "Skipping rule file %s: invalid YAML (%s)",
            path,
            exc,
        )

        return []

    rules = data.get("rules", [])

    if not isinstance(rules, list):
        logger.warning(
            "Skipping rule file %s: top-level "
            "'rules' must be a list",
            path,
        )

        return []

    validated = []

    for index, rule in enumerate(rules):
        valid, reason = validate_rule(
            rule
        )

        if not valid:
            logger.warning(
                "Skipping rule %d in %s: %s",
                index,
                path,
                reason,
            )

            continue

        validated.append(
            rule
        )

    return validated


def load_rules_from_directory(
    directory: str | Path,
) -> list[dict]:
    rule_directory = Path(directory)

    if not rule_directory.exists():
        logger.debug(
            "Rules directory %s does not exist",
            rule_directory,
        )

        return []

    rule_files = [
        *sorted(
            rule_directory.glob("*.yaml")
        ),
        *sorted(
            rule_directory.glob("*.yml")
        ),
    ]

    if not rule_files:
        logger.debug(
            "No rule files found in %s",
            rule_directory,
        )

        return []

    rules = []
    loaded_any = False

    for file_path in rule_files:
        file_rules = load_rule_file(
            file_path
        )

        if file_rules:
            loaded_any = True

        rules.extend(
            file_rules
        )

    if not loaded_any:
        raise RuntimeError(
            "All rule files in "
            f"{rule_directory} failed to load"
        )

    logger.debug(
        "Loaded %d rule(s) from %s",
        len(rules),
        rule_directory,
    )

    return rules


def normalize_string(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        return " ".join(
            str(item)
            for item in value
        ).lower()

    return str(value).lower()


def get_nested_value(
    data: dict,
    field_path: str,
) -> Any:
    current: Any = data

    for part in field_path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def match_equals(
    actual,
    expected,
) -> bool:
    if isinstance(expected, list):
        actual_normalized = normalize_string(
            actual
        )

        return any(
            actual_normalized
            == normalize_string(item)
            for item in expected
        )

    return (
        normalize_string(actual)
        == normalize_string(expected)
    )


def match_contains(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            normalize_string(item)
            in actual_normalized
            for item in expected
        )

    return (
        normalize_string(expected)
        in actual_normalized
    )


def match_startswith(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            actual_normalized.startswith(
                normalize_string(item)
            )
            for item in expected
        )

    return actual_normalized.startswith(
        normalize_string(expected)
    )


def match_endswith(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            actual_normalized.endswith(
                normalize_string(item)
            )
            for item in expected
        )

    return actual_normalized.endswith(
        normalize_string(expected)
    )


def _searchable_text(value: Any) -> str:
    """Render a value as the case-preserved text regexes search on."""
    if isinstance(value, list):
        return " ".join(
            str(item)
            for item in value
        )

    if value is None:
        return ""

    return str(value)


def _regex_search(
    pattern: Any,
    text: str,
) -> bool:
    try:
        return (
            re.search(
                str(pattern),
                text,
            )
            is not None
        )
    except re.error as exc:
        logger.debug(
            "matches: invalid regex %r (%s)",
            pattern,
            exc,
        )

        return False


def match_matches(
    actual,
    expected,
) -> bool:
    """Return whether the actual value matches the regex pattern(s)."""
    actual_text = _searchable_text(
        actual
    )

    if isinstance(expected, list):
        return any(
            _regex_search(
                pattern,
                actual_text,
            )
            for pattern in expected
        )

    return _regex_search(
        expected,
        actual_text,
    )


def match_not_equals(
    actual,
    expected,
) -> bool:
    return not match_equals(
        actual,
        expected,
    )


def match_not_contains(
    actual,
    expected,
) -> bool:
    return not match_contains(
        actual,
        expected,
    )


def evaluate_condition(
    record: dict,
    condition: dict,
) -> bool:
    field = condition.get("field")
    operator = condition.get(
        "operator",
        "equals",
    )
    expected: Any = condition.get("value")

    if not field:
        return False

    actual = get_nested_value(
        record,
        field,
    )

    if operator == "equals":
        return match_equals(
            actual,
            expected,
        )

    if operator == "contains":
        return match_contains(
            actual,
            expected,
        )

    if operator == "startswith":
        return match_startswith(
            actual,
            expected,
        )

    if operator == "endswith":
        return match_endswith(
            actual,
            expected,
        )

    if operator == "matches":
        return match_matches(
            actual,
            expected,
        )

    if operator == "not_equals":
        return match_not_equals(
            actual,
            expected,
        )

    if operator == "not_contains":
        return match_not_contains(
            actual,
            expected,
        )

    if operator == "greater_than":
        try:
            return float(actual) > float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "greater_or_equal":
        try:
            return float(actual) >= float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "less_than":
        try:
            return float(actual) < float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "less_or_equal":
        try:
            return float(actual) <= float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            logger.debug(
                "less_or_equal: non-numeric "
                "comparison %r vs %r",
                actual,
                expected,
            )

            return False

    if operator == "exists":
        return actual is not None

    return False


def evaluate_rule(
    rule: dict,
    record: dict,
) -> bool:
    conditions = rule.get(
        "conditions",
        []
    )

    if not conditions:
        return False

    match_mode = (
        rule.get(
            "match",
            "all",
        )
        .lower()
    )

    results = [
        evaluate_condition(
            record,
            condition,
        )
        for condition in conditions
    ]

    if match_mode == "any":
        return any(results)

    return all(results)


def validate_condition(
    condition: Any,
) -> tuple[
    bool,
    str,
]:
    """Validate a single rule condition; return (ok, reason)."""
    if not isinstance(
        condition,
        dict,
    ):
        return (
            False,
            "condition must be a mapping",
        )

    field = condition.get("field")
    operator = condition.get(
        "operator",
        "equals",
    )

    if not field:
        return (
            False,
            "condition missing field 'field'",
        )

    if operator not in SUPPORTED_OPERATORS:
        return (
            False,
            f"unknown operator '{operator}'",
        )

    if "value" not in condition:
        return (
            False,
            "condition missing field 'value'",
        )

    if operator == "matches":
        patterns = (
            condition["value"]
            if isinstance(
                condition["value"],
                list,
            )
            else [
                condition["value"]
            ]
        )

        for pattern in patterns:
            try:
                re.compile(
                    str(pattern)
                )
            except re.error as exc:
                return (
                    False,
                    f"invalid regex {pattern!r}: {exc}",
                )

    return (
        True,
        "",
    )


def validate_rule(
    rule: Any,
) -> tuple[
    bool,
    str,
]:
    """Validate a rule; return (ok, reason)."""
    if not isinstance(
        rule,
        dict,
    ):
        return (
            False,
            "rule must be a mapping",
        )

    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            return (
                False,
                f"missing required field '{field}'",
            )

    severity = str(
        rule.get("severity", "")
    ).lower()

    if severity not in VALID_SEVERITIES:
        return (
            False,
            f"invalid severity '{rule.get('severity')}'",
        )

    category = str(
        rule.get("category", "")
    ).lower()

    if category not in VALID_RULE_CATEGORIES:
        return (
            False,
            f"invalid category '{rule.get('category')}'",
        )

    conditions = rule.get("conditions")

    if (
        not isinstance(
            conditions,
            list,
        )
        or not conditions
    ):
        return (
            False,
            "conditions must be a non-empty list",
        )

    for index, condition in enumerate(
        conditions
    ):
        valid, reason = validate_condition(
            condition
        )

        if not valid:
            return (
                False,
                f"condition {index}: {reason}",
            )

    return (
        True,
        "",
    )


PROMOTED_CONTEXT_FIELDS = (
    "pid",
    "process_name",
    "remote_ip",
    "remote_port",
    "timestamp",
)


def create_finding(
    rule: dict,
    record: dict,
) -> dict:
    finding = {
        "severity": rule.get(
            "severity",
            "info",
        ),
        "rule_id": rule.get(
            "id",
            "RULE-UNKNOWN",
        ),
        "title": rule.get(
            "title",
            "Rule matched",
        ),
        "description": rule.get(
            "description",
            "",
        ),
        "category": rule.get(
            "category",
            "unknown",
        ),
        "evidence": record,
    }

    # Promote entity context to the finding's top level so the
    # correlation engine can group YAML-rule findings the same way
    # it groups built-in detector findings. The full record stays
    # unchanged under "evidence" for reports and timeline fallback.
    for field in PROMOTED_CONTEXT_FIELDS:
        if field in record:
            finding[field] = record[field]

    if (
        "process_name" not in finding
        and rule.get("category") == "process"
    ):
        name = record.get("name")

        if name is not None:
            finding["process_name"] = name

    mitre = rule.get("mitre")

    if mitre:
        finding["mitre"] = mitre

    confidence = rule.get(
        "confidence"
    )

    if confidence is not None:
        finding["confidence"] = (
            confidence
        )

    return finding


def run_rules(
    rules: list[dict],
    records: list[dict],
    category: str | None = None,
) -> list[dict]:
    findings = []

    for rule in rules:
        if not rule.get(
            "enabled",
            True,
        ):
            continue

        rule_category = rule.get(
            "category"
        )

        if (
            category
            and rule_category != category
        ):
            continue

        for record in records:
            if evaluate_rule(
                rule,
                record,
            ):
                findings.append(
                    create_finding(
                        rule,
                        record,
                    )
                )

    logger.debug(
        "Rule engine produced %d finding(s) "
        "from %d record(s), category=%s",
        len(findings),
        len(records),
        category,
    )

    return findings
