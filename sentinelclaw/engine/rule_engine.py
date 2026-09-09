from pathlib import Path
from typing import Any

import yaml


def load_rule_file(file_path: str | Path) -> list[dict]:
    path = Path(file_path)

    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file) or {}

    rules = data.get("rules", [])

    if not isinstance(rules, list):
        return []

    return rules


def load_rules_from_directory(
    directory: str | Path,
) -> list[dict]:
    rule_directory = Path(directory)

    if not rule_directory.exists():
        return []

    rules = []

    for file_path in sorted(
        rule_directory.glob("*.yaml")
    ):
        rules.extend(
            load_rule_file(file_path)
        )

    for file_path in sorted(
        rule_directory.glob("*.yml")
    ):
        rules.extend(
            load_rule_file(file_path)
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
):
    current = data

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


def evaluate_condition(
    record: dict,
    condition: dict,
) -> bool:
    field = condition.get("field")
    operator = condition.get(
        "operator",
        "equals",
    )
    expected = condition.get("value")

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

    return findings
