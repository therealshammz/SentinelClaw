import sys

import pytest

from sentinelclaw.config.paths import get_rules_directory
from sentinelclaw.engine.rule_engine import (
    load_rule_file,
    load_rules_from_directory,
    run_rules,
    validate_rule,
)


def single_condition_rule(
    rule_id: str,
    field: str,
    operator: str,
    value: object,
) -> dict:
    return {
        "id": rule_id,
        "title": f"Rule {rule_id}",
        "description": "Synthetic operator test rule.",
        "category": "process",
        "severity": "medium",
        "confidence": "medium",
        "conditions": [
            {
                "field": field,
                "operator": operator,
                "value": value,
            }
        ],
    }


def triggered_ids(
    rules: list[dict],
    record: dict,
) -> set[str]:
    return {
        str(finding.get("rule_id"))
        for finding in run_rules(
            rules,
            [record],
            category="process",
        )
    }


def test_project_rules_load_successfully() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    assert isinstance(rules, list)
    assert len(rules) >= 1


def test_rule_ids_are_unique() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    rule_ids = [
        rule.get("id")
        for rule in rules
    ]

    assert None not in rule_ids
    assert len(rule_ids) == len(set(rule_ids))


def test_expected_rule_categories_exist() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    categories = {
        str(rule.get("category"))
        for rule in rules
    }

    assert "process" in categories
    assert "file" in categories

    on_windows = sys.platform.startswith(
        "win"
    )

    on_linux = sys.platform.startswith(
        "linux"
    )

    # windows_event rules are OS-gated to Windows (P1-10).
    if on_windows:
        assert "windows_event" in categories
    else:
        assert "windows_event" not in categories

    # auth and persistence categories exist only on Linux.
    if on_linux:
        assert "auth" in categories
        assert "persistence" in categories
    else:
        assert "auth" not in categories
        assert "persistence" not in categories


def test_encoded_powershell_synthetic_record_can_trigger_rule() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    record = {
        "pid": 4242,
        "ppid": 1000,
        "name": "powershell.exe",
        "parent_name": "cmd.exe",
        "username": "TEST\\analyst",
        "executable": (
            r"C:\Windows\System32\WindowsPowerShell"
            r"\v1.0\powershell.exe"
        ),
        "status": "running",
        "memory_percent": 0.1,
        "command_line": (
            "powershell.exe -EncodedCommand "
            "VABFAFMAVA=="
        ),
        "create_time": "2026-09-08T10:00:00+00:00",
    }

    findings = run_rules(
        rules,
        [record],
        category="process",
    )

    ids = {
        finding.get("rule_id")
        or finding.get("id")
        for finding in findings
    }

    assert "PROC-YAML-001" in ids


def test_yaml_process_finding_promotes_entity_context() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    record = {
        "pid": 7777,
        "ppid": 1000,
        "name": "powershell.exe",
        "parent_name": "cmd.exe",
        "command_line": (
            "powershell.exe -EncodedCommand VABFAFMAVA=="
        ),
        "create_time": "2026-09-08T10:00:00+00:00",
    }

    findings = run_rules(
        rules,
        [record],
        category="process",
    )

    matching = [
        finding
        for finding in findings
        if finding.get("rule_id") == "PROC-YAML-001"
    ]

    assert matching
    assert matching[0]["pid"] == 7777
    assert matching[0]["process_name"] == (
        "powershell.exe"
    )
    assert matching[0]["evidence"]["pid"] == 7777
    assert matching[0]["evidence"]["name"] == (
        "powershell.exe"
    )


def test_yaml_file_finding_does_not_promote_process_name() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    record = {
        "name": "suspicious.exe",
        "path": (
            "C:\\Users\\analyst\\Downloads\\"
            "suspicious.exe"
        ),
        "is_pe_file": True,
        "entropy": 7.9,
        "extension": ".exe",
    }

    findings = run_rules(
        rules,
        [record],
        category="file",
    )

    matching = [
        finding
        for finding in findings
        if finding.get("rule_id") == "FILE-YAML-001"
    ]

    assert matching
    assert "process_name" not in matching[0]
    assert matching[0]["evidence"]["name"] == (
        "suspicious.exe"
    )


def test_not_equals_operator_matches_when_different() -> None:
    rule = single_condition_rule(
        "OP-NEQ-001",
        "name",
        "not_equals",
        "powershell.exe",
    )

    assert triggered_ids(
        [rule],
        {"name": "cmd.exe"},
    ) == {"OP-NEQ-001"}


def test_not_equals_operator_no_match_when_equal() -> None:
    rule = single_condition_rule(
        "OP-NEQ-001",
        "name",
        "not_equals",
        "powershell.exe",
    )

    assert triggered_ids(
        [rule],
        {"name": "powershell.exe"},
    ) == set()


def test_not_contains_operator_matches_when_absent() -> None:
    rule = single_condition_rule(
        "OP-NC-001",
        "command_line",
        "not_contains",
        "-enc",
    )

    assert triggered_ids(
        [rule],
        {"command_line": "powershell -noprofile"},
    ) == {"OP-NC-001"}


def test_not_contains_operator_no_match_when_present() -> None:
    rule = single_condition_rule(
        "OP-NC-001",
        "command_line",
        "not_contains",
        "-enc",
    )

    assert triggered_ids(
        [rule],
        {"command_line": "powershell -enc abc"},
    ) == set()


def test_less_or_equal_matches_below_and_boundary() -> None:
    rule = single_condition_rule(
        "OP-LE-001",
        "memory_percent",
        "less_or_equal",
        0.5,
    )

    assert triggered_ids(
        [rule],
        {"memory_percent": 0.3},
    ) == {"OP-LE-001"}
    assert triggered_ids(
        [rule],
        {"memory_percent": 0.5},
    ) == {"OP-LE-001"}


def test_less_or_equal_no_match_above() -> None:
    rule = single_condition_rule(
        "OP-LE-001",
        "memory_percent",
        "less_or_equal",
        0.5,
    )

    assert triggered_ids(
        [rule],
        {"memory_percent": 0.7},
    ) == set()


def test_less_or_equal_coerces_numeric_strings() -> None:
    rule = single_condition_rule(
        "OP-LE-001",
        "memory_percent",
        "less_or_equal",
        "0.5",
    )

    assert triggered_ids(
        [rule],
        {"memory_percent": "0.4"},
    ) == {"OP-LE-001"}


def test_less_or_equal_non_numeric_is_no_match() -> None:
    rule = single_condition_rule(
        "OP-LE-001",
        "memory_percent",
        "less_or_equal",
        0.5,
    )

    assert triggered_ids(
        [rule],
        {"memory_percent": "high"},
    ) == set()


def test_matches_operator_matches_regex() -> None:
    rule = single_condition_rule(
        "OP-MAT-001",
        "command_line",
        "matches",
        r"powershell.*encoded",
    )

    assert triggered_ids(
        [rule],
        {"command_line": "powershell -encodedCommand x"},
    ) == {"OP-MAT-001"}


def test_matches_operator_is_case_sensitive() -> None:
    rule = single_condition_rule(
        "OP-MAT-001",
        "command_line",
        "matches",
        "^powershell",
    )

    assert triggered_ids(
        [rule],
        {"command_line": "POWERSHELL -noprofile"},
    ) == set()


def test_matches_operator_matches_any_list_pattern() -> None:
    rule = single_condition_rule(
        "OP-MAT-002",
        "command_line",
        "matches",
        ["secret", "shadow"],
    )

    assert triggered_ids(
        [rule],
        {"command_line": "run shadow task"},
    ) == {"OP-MAT-002"}


def test_unknown_operator_rule_is_skipped_with_warning(
    tmp_path,
    caplog,
) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "operators.yaml").write_text(
        "rules:\n"
        "  - id: BAD-OP-001\n"
        "    title: Bad operator\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: fuzzy\n"
        "        value: powershell.exe\n"
        "  - id: GOOD-OP-001\n"
        "    title: Good rule\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n",
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rules_from_directory(
            rule_directory
        )

    assert {
        rule.get("id")
        for rule in rules
    } == {"GOOD-OP-001"}
    assert any(
        "unknown operator" in record.message
        for record in caplog.records
    )


def test_malformed_yaml_file_is_skipped_with_warning(
    tmp_path,
    caplog,
) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "broken.yaml").write_text(
        ": not: [valid: [yaml",
        encoding="utf-8",
    )

    (rule_directory / "valid.yaml").write_text(
        "rules:\n"
        "  - id: GOOD-VALID-001\n"
        "    title: Good rule\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n",
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rules_from_directory(
            rule_directory
        )

    assert {
        rule.get("id")
        for rule in rules
    } == {"GOOD-VALID-001"}
    assert any(
        "Skipping rule file" in record.message
        for record in caplog.records
    )


def test_rule_missing_required_field_is_skipped(
    tmp_path,
    caplog,
) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "missing.yaml").write_text(
        "rules:\n"
        "  - id: MISS-001\n"
        "    title: No description here\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n"
        "  - id: OK-001\n"
        "    title: Fine\n"
        "    description: ok\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n",
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rules_from_directory(
            rule_directory
        )

    assert {
        rule.get("id")
        for rule in rules
    } == {"OK-001"}
    assert any(
        "missing required field" in record.message
        for record in caplog.records
    )


def test_matches_with_invalid_regex_rule_is_skipped(
    tmp_path,
    caplog,
) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "regex.yaml").write_text(
        "rules:\n"
        "  - id: BAD-REGEX-001\n"
        "    title: Bad regex\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: command_line\n"
        "        operator: matches\n"
        '        value: "("\n'
        "  - id: OK-REGEX-001\n"
        "    title: Fine\n"
        "    description: ok\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: command_line\n"
        "        operator: matches\n"
        '        value: "encoded"\n',
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rules_from_directory(
            rule_directory
        )

    assert {
        rule.get("id")
        for rule in rules
    } == {"OK-REGEX-001"}
    assert any(
        "invalid regex" in record.message
        for record in caplog.records
    )


def test_all_shipped_rules_load_and_validate() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    # The shipped rule set is OS-gated (P1-10): Linux loads the base
    # rules plus the Linux-only process/auth/persistence rules, while
    # other platforms load only the platform-agnostic rules.
    if sys.platform.startswith(
        "linux"
    ):
        expected = 19
    else:
        expected = 7

    assert len(rules) == expected


def test_all_rule_files_failing_raises(tmp_path) -> None:
    rule_directory = tmp_path / "rules"
    rule_directory.mkdir()

    (rule_directory / "broken.yaml").write_text(
        ": not: [valid: [yaml",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError):
        load_rules_from_directory(rule_directory)


def test_validate_rule_rejects_invalid_severity() -> None:
    rule = single_condition_rule(
        "X-001",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, severity="extreme")
    )

    assert not ok
    assert "invalid severity" in reason


def test_validate_rule_rejects_invalid_category() -> None:
    rule = single_condition_rule(
        "X-001",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, category="kernel")
    )

    assert not ok
    assert "invalid category" in reason


def test_load_rule_file_validates_individual_rules(
    tmp_path,
    caplog,
) -> None:
    rule_file = tmp_path / "mixed.yaml"

    rule_file.write_text(
        "rules:\n"
        "  - id: BAD-FIELD-001\n"
        "    title: Missing conditions\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "  - id: GOOD-FIELD-001\n"
        "    title: Good\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: powershell.exe\n",
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rule_file(rule_file)

    assert {
        rule.get("id")
        for rule in rules
    } == {"GOOD-FIELD-001"}


def test_validate_rule_accepts_optional_metadata() -> None:
    rule = single_condition_rule(
        "META-001",
        "name",
        "equals",
        "a",
    )
    rule.update(
        {
            "status": "experimental",
            "noisy": True,
            "falsepositives": "Legitimate admin automation.",
            "level_override": "critical",
            "enabled": True,
        }
    )

    ok, reason = validate_rule(rule)

    assert ok, reason


def test_validate_rule_accepts_falsepositives_list() -> None:
    rule = single_condition_rule(
        "META-002",
        "name",
        "equals",
        "a",
    )
    rule["falsepositives"] = [
        "Automation",
        "Admin scripts",
    ]

    ok, reason = validate_rule(rule)

    assert ok, reason


def test_validate_rule_rejects_unknown_status() -> None:
    rule = single_condition_rule(
        "META-003",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, status="madeup")
    )

    assert not ok
    assert "invalid status" in reason


def test_validate_rule_rejects_invalid_level_override() -> None:
    rule = single_condition_rule(
        "META-004",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, level_override="extreme")
    )

    assert not ok
    assert "invalid level_override" in reason


def test_validate_rule_rejects_invalid_noisy_type() -> None:
    rule = single_condition_rule(
        "META-005",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, noisy="yes")
    )

    assert not ok
    assert "noisy must be a boolean" in reason


def test_validate_rule_rejects_invalid_enabled_type() -> None:
    rule = single_condition_rule(
        "META-006",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, enabled="false")
    )

    assert not ok
    assert "enabled must be a boolean" in reason


def test_validate_rule_rejects_invalid_falsepositives() -> None:
    rule = single_condition_rule(
        "META-007",
        "name",
        "equals",
        "a",
    )

    ok, reason = validate_rule(
        dict(rule, falsepositives=[])
    )

    assert not ok
    assert "falsepositives" in reason


def test_unknown_status_rule_is_skipped_with_warning(
    tmp_path,
    caplog,
) -> None:
    rule_file = tmp_path / "status.yaml"

    rule_file.write_text(
        "rules:\n"
        "  - id: ST-001\n"
        "    title: Bad status\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    status: madeup\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: a\n",
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        rules = load_rule_file(rule_file)

    assert rules == []
    assert "invalid status" in caplog.text


def test_disabled_rule_skipped_at_load(
    tmp_path,
    caplog,
) -> None:
    rule_file = tmp_path / "disabled.yaml"

    rule_file.write_text(
        "rules:\n"
        "  - id: DIS-001\n"
        "    title: Disabled\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    enabled: false\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: a\n"
        "  - id: EN-001\n"
        "    title: Enabled\n"
        "    description: x\n"
        "    category: process\n"
        "    severity: high\n"
        "    confidence: high\n"
        "    enabled: true\n"
        "    conditions:\n"
        "      - field: name\n"
        "        operator: equals\n"
        "        value: a\n",
        encoding="utf-8",
    )

    with caplog.at_level("DEBUG"):
        rules = load_rule_file(rule_file)

    assert {
        rule.get("id")
        for rule in rules
    } == {"EN-001"}
    assert "Skipping disabled rule DIS-001" in caplog.text


def test_level_override_changes_finding_severity() -> None:
    rule = single_condition_rule(
        "OVR-001",
        "name",
        "equals",
        "malware.exe",
    )
    rule["severity"] = "medium"
    rule["level_override"] = "critical"

    findings = run_rules(
        [rule],
        [{"name": "malware.exe"}],
        category="process",
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_finding_severity_unchanged_without_override() -> None:
    rule = single_condition_rule(
        "OVR-002",
        "name",
        "equals",
        "malware.exe",
    )

    findings = run_rules(
        [rule],
        [{"name": "malware.exe"}],
        category="process",
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_all_shipped_rules_carry_quality_metadata() -> None:
    rules = load_rules_from_directory(
        get_rules_directory()
    )

    statuses = set()

    for rule in rules:
        status = rule.get("status")

        assert status in {
            "proven",
            "experimental",
        }
        assert isinstance(
            rule.get("enabled", True),
            bool,
        )

        statuses.add(status)

    assert "proven" in statuses

    if sys.platform.startswith("linux"):
        assert "experimental" in statuses

