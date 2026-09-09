from sentinelclaw.config.paths import get_rules_directory
from sentinelclaw.engine.rule_engine import (
    load_rules_from_directory,
    run_rules,
)


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
    assert "windows_event" in categories


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
