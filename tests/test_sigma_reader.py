"""Sigma-subset reader and import tests (P2-14).

Covers conversion of Sigma logsource/detection/condition constructs into
the internal rule format, firing of converted rules against the canned
conftest fixtures, the ``|cidr`` / ``|fieldref`` operators, per-rule
skip isolation, and the offline ``rules import --source`` flow. None of
these tests touch the network.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from sentinelclaw.config.paths import get_rules_directory
from sentinelclaw.engine.rule_engine import (
    load_rule_file,
    run_rules,
    validate_rule,
)
from sentinelclaw.sigma.importer import (
    ConversionSummary,
    convert_directory,
    import_into,
)
from sentinelclaw.sigma.reader import (
    SigmaRuleError,
    convert_sigma_text,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SIGMA_MIMIKATZ = """
title: Mimikatz execution via process creation
id: 20255a30-2e1d-4f0e-8b2c-7f1b2f4a6b21
status: test
description: Detects mimikatz (or mimikatz-adjacent credential tooling) starting.
level: high
tags:
    - attack.credential_access
    - attack.t1003.001
references:
    - https://github.com/gentilkiwi/mimikatz
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: mimikatz.exe
        CommandLine|contains:
            - privilege::debug
            - sekurlsa::logonpasswords
            - sekurlsa::wdigest
            - 'lsadump::'
            - 'kerberos::'
    condition: selection
"""

SIGMA_LOGON_FAILURE = """
title: Windows logon failure (EventID 4625)
id: b9b42a9e-3c26-4f3a-8f4e-6b4c4d1e2f01
status: stable
description: A Windows Security logon failure event was recorded.
level: medium
tags:
    - attack.credential_access
    - attack.t1110
falsepositives:
    - Legitimate users mistyping passwords.
logsource:
    category: logon_failure
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
"""

SIGMA_NETWORK_PORT = """
title: Network connection to suspicious remote port
id: c2b84f39-4e6e-4b99-9a1f-77c30a1b3c11
status: test
description: A process established a connection to a suspicious remote port.
level: medium
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 4444
            - 5555
    condition: selection
"""

SIGMA_SSHD = """
title: SSH failed password for invalid user
id: 7c67e8d1-5f0a-4c2b-9e6d-88f9a2b4d501
status: test
description: sshd reported a failed password attempt for a nonexistent account.
level: medium
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    category: syslog
    product: linux
    service: sshd
detection:
    selection:
        msg|contains: 'Failed password for invalid user'
    condition: selection
"""


def converted(
    text: str,
) -> dict:
    rule = convert_sigma_text(text)
    ok, reason = validate_rule(rule)

    assert ok, reason

    return rule


def run_category(
    rule: dict,
    records: list[dict],
    category: str,
) -> list[dict]:
    return run_rules(
        [rule],
        records,
        category=category,
    )


# ---------------------------------------------------------------------------
# (a) process_creation conversion fires on the canned process fixture
# ---------------------------------------------------------------------------


def test_process_creation_sample_fires_on_canned_processes(
    sample_processes,
) -> None:
    rule = converted(SIGMA_MIMIKATZ)

    assert rule["category"] == "process"
    assert rule["os"] == ["windows"]
    assert rule["severity"] == "high"
    assert rule["confidence"] == "high"
    assert rule["status"] == "experimental"
    assert rule["mitre"] == {"technique": "T1003.001"}

    findings = run_category(
        rule,
        sample_processes,
        "process",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == rule["id"]
    assert findings[0]["pid"] == 1337
    assert findings[0]["process_name"] == "mimikatz.exe"


def test_process_creation_contains_requires_any_list_value() -> None:
    rule = converted(SIGMA_MIMIKATZ)

    benign = {
        "name": "mimikatz.exe",
        "command_line": ["mimikatz.exe", "coffee"],
        "executable": "C:\\tools\\mimikatz.exe",
    }

    assert run_category(rule, [benign], "process") == []


# ---------------------------------------------------------------------------
# (b) logon_failure conversion fires on the canned windows event fixture
# ---------------------------------------------------------------------------


def test_logon_failure_fires_on_canned_windows_events(
    sample_windows_events,
) -> None:
    rule = converted(SIGMA_LOGON_FAILURE)

    assert rule["category"] == "windows_event"
    assert rule["os"] == ["windows"]

    findings = run_category(
        rule,
        sample_windows_events,
        "windows_event",
    )

    assert len(findings) == 3
    assert all(finding["rule_id"] == rule["id"] for finding in findings)
    assert all(finding["evidence"]["event_id"] == 4625 for finding in findings)


def test_logon_failure_does_not_fire_on_other_events(
    sample_windows_events,
) -> None:
    rule = converted(SIGMA_LOGON_FAILURE)
    events = [event for event in sample_windows_events if event["event_id"] != 4625]

    assert run_category(rule, events, "windows_event") == []


# ---------------------------------------------------------------------------
# (c) |cidr modifier (ip in / out of network)
# ---------------------------------------------------------------------------


def test_cidr_rule_fires_when_ip_inside_network() -> None:
    rule = converted(
        """
title: External address probe
id: 90000000-0000-0000-0000-000000000001
level: low
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp|cidr:
            - 10.0.0.0/8
            - 192.168.0.0/16
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "remote_address.ip",
            "operator": "cidr",
            "value": ["10.0.0.0/8", "192.168.0.0/16"],
        }
    ]

    inside = {
        "local_address": {"ip": "10.0.0.1", "port": 1234},
        "remote_address": {"ip": "192.168.55.7", "port": 80},
    }

    assert len(run_category(rule, [inside], "network")) == 1


def test_cidr_rule_does_not_fire_when_ip_outside_network() -> None:
    rule = converted(
        """
title: External address probe
id: 90000000-0000-0000-0000-000000000002
level: low
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp|cidr: 10.0.0.0/8
    condition: selection
"""
    )

    outside = {
        "remote_address": {"ip": "203.0.113.9", "port": 80},
    }

    assert run_category(rule, [outside], "network") == []


# ---------------------------------------------------------------------------
# (d) |fieldref modifier
# ---------------------------------------------------------------------------


def test_fieldref_rule_compares_sibling_fields() -> None:
    rule = converted(
        """
title: Command line mirrors image
id: 90000000-0000-0000-0000-000000000003
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|fieldref: Image
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "command_line",
            "operator": "fieldref",
            "value": "executable",
        }
    ]

    matching = {
        "command_line": "C:\\Windows\\run.exe",
        "executable": "C:\\Windows\\run.exe",
    }

    assert len(run_category(rule, [matching], "process")) == 1

    different = {
        "command_line": "C:\\Windows\\run.exe --go",
        "executable": "C:\\Windows\\run.exe",
    }

    assert run_category(rule, [different], "process") == []


# ---------------------------------------------------------------------------
# (e) unsupported constructs skip the rule with a warning; others load
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "reason_code"),
    [
        (
            """
title: Encoded command
id: 90000000-0000-0000-0000-000000000010
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|windash|contains: '-enc'
    condition: selection
""",
            "unsupported-modifier",
        ),
        (
            """
title: Encoded command
id: 90000000-0000-0000-0000-000000000011
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64: 'SQBuAHMAdABhAGwAbABlAHIA'
    condition: selection
""",
            "unsupported-modifier",
        ),
        (
            """
title: Keywords only
id: 90000000-0000-0000-0000-000000000012
level: low
logsource:
    category: syslog
    product: linux
detection:
    keywords:
        - Failed password
    condition: keywords
""",
            "keywords",
        ),
        (
            """
title: Correlation rule v2
id: 90000000-0000-0000-0000-000000000013
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: cmd.exe
    condition: selection
correlation:
    type: temporal
    rules:
        - 90000000-0000-0000-0000-000000000010
""",
            "correlation-rule",
        ),
        (
            """
title: Unknown product
id: 90000000-0000-0000-0000-000000000014
level: low
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: a
    condition: selection
""",
            "unsupported-product",
        ),
        (
            """
title: Placeholder value
id: 90000000-0000-0000-0000-000000000015
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: $some_var
    condition: selection
""",
            "placeholder",
        ),
        (
            """
title: Counted condition
id: 90000000-0000-0000-0000-000000000016
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: a.exe
    selection_2:
        Image|endswith: b.exe
    condition: 2 of selection_*
""",
            "condition-syntax",
        ),
    ],
)
def test_unsupported_sigma_constructs_raise_stable_reason(
    text,
    reason_code,
) -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(text)

    assert excinfo.value.reason_code == reason_code


def test_missing_id_and_title_are_skipped() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: No id
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "missing-id"

    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
id: 90000000-0000-0000-0000-000000000020
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "missing-title"


def test_unmapped_field_skips_rule() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Hashes
id: 90000000-0000-0000-0000-000000000021
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes: 'MD5=deadbeef'
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "unmapped-field"


# ---------------------------------------------------------------------------
# condition grammar: and/or/not, parentheses, '1 of'/'all of'
# ---------------------------------------------------------------------------


def test_condition_selection_and_not_filter_negates_atom() -> None:
    rule = converted(
        """
title: Cmdline legit filter
id: 90000000-0000-0000-0000-000000000030
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: cmd.exe
    filter:
        CommandLine|contains: legit
    condition: selection and not filter
"""
    )

    assert rule["conditions"] == [
        {
            "field": "executable",
            "operator": "endswith",
            "value": "cmd.exe",
        },
        {
            "field": "command_line",
            "operator": "contains",
            "value": "legit",
            "negated": True,
        },
    ]

    suspicious = {
        "name": "cmd.exe",
        "executable": "C:\\Windows\\cmd.exe",
        "command_line": ["cmd.exe", "/c", "evil"],
    }
    legit = {
        "name": "cmd.exe",
        "executable": "C:\\Windows\\cmd.exe",
        "command_line": ["cmd.exe", "/c", "legit backup"],
    }

    assert len(run_category(rule, [suspicious], "process")) == 1
    assert run_category(rule, [legit], "process") == []


def test_condition_not_selection_with_multi_atom_block() -> None:
    rule = converted(
        """
title: Everything but the backup agent
id: 90000000-0000-0000-0000-000000000031
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: cmd.exe
    filter:
        CommandLine|contains: legit
        User: 'NT AUTHORITY\\SYSTEM'
    condition: selection and not filter
"""
    )

    backup_agent = {
        "name": "cmd.exe",
        "executable": "C:\\Windows\\cmd.exe",
        "command_line": ["cmd.exe", "legit"],
        "username": "NT AUTHORITY\\SYSTEM",
    }
    same_command_other_user = {
        "name": "cmd.exe",
        "executable": "C:\\Windows\\cmd.exe",
        "command_line": ["cmd.exe", "legit"],
        "username": "TEST\\analyst",
    }

    assert run_category(rule, [backup_agent], "process") == []
    assert len(run_category(rule, [same_command_other_user], "process")) == 1


def test_condition_one_of_prefix_is_an_or() -> None:
    rule = converted(
        """
title: Multiple images
id: 90000000-0000-0000-0000-000000000032
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: mimikatz.exe
    selection_2:
        Image|endswith: procdump.exe
    condition: 1 of selection_*
"""
    )

    assert rule["conditions"] == [
        {
            "any_of": [
                {
                    "field": "executable",
                    "operator": "endswith",
                    "value": "mimikatz.exe",
                },
                {
                    "field": "executable",
                    "operator": "endswith",
                    "value": "procdump.exe",
                },
            ]
        }
    ]

    for name in ("mimikatz.exe", "procdump.exe"):
        assert (
            len(
                run_category(
                    rule,
                    [{"name": name, "executable": f"C:\\tools\\{name}"}],
                    "process",
                )
            )
            == 1
        )

    assert (
        run_category(
            rule,
            [{"name": "notepad.exe", "executable": "C:\\tools\\notepad.exe"}],
            "process",
        )
        == []
    )


def test_condition_or_with_compound_and_uses_nested_groups() -> None:
    rule = converted(
        """
title: Compound or
id: 90000000-0000-0000-0000-000000000033
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: wscript.exe
        CommandLine|contains: javascript
    selection_b:
        Image|endswith: cscript.exe
    condition: selection_a or selection_b
"""
    )

    assert rule["conditions"] == [
        {
            "any_of": [
                {
                    "all_of": [
                        {
                            "field": "executable",
                            "operator": "endswith",
                            "value": "wscript.exe",
                        },
                        {
                            "field": "command_line",
                            "operator": "contains",
                            "value": "javascript",
                        },
                    ]
                },
                {
                    "field": "executable",
                    "operator": "endswith",
                    "value": "cscript.exe",
                },
            ]
        }
    ]

    wscript_js = {
        "name": "wscript.exe",
        "executable": "C:\\Windows\\wscript.exe",
        "command_line": ["wscript.exe", "//e:javascript"],
    }
    cscript = {
        "name": "cscript.exe",
        "executable": "C:\\Windows\\cscript.exe",
        "command_line": ["cscript.exe"],
    }

    assert len(run_category(rule, [wscript_js], "process")) == 1
    assert len(run_category(rule, [cscript], "process")) == 1


def test_condition_parenthesized_mix() -> None:
    rule = converted(
        """
title: Parenthesized mix
id: 90000000-0000-0000-0000-000000000034
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: powershell.exe
    filter_quiet:
        CommandLine|contains: '-noprofile'
    filter_interactive:
        User|fieldref: Image
    condition: selection and not (filter_quiet or filter_interactive)
"""
    )

    rule_node = rule["conditions"]

    assert rule_node[0]["field"] == "executable"
    assert rule_node[1]["negated"] is True
    assert "any_of" in rule_node[1]

    plain_powershell = {
        "name": "powershell.exe",
        "executable": "C:\\Windows\\powershell.exe",
        "command_line": ["powershell.exe", "-enc", "abc"],
    }

    assert len(run_category(rule, [plain_powershell], "process")) == 1

    quiet_powershell = {
        "name": "powershell.exe",
        "executable": "C:\\Windows\\powershell.exe",
        "command_line": ["powershell.exe", "-NoProfile", "-enc", "abc"],
    }

    assert run_category(rule, [quiet_powershell], "process") == []


def test_condition_unknown_reference_is_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Dangling ref
id: 90000000-0000-0000-0000-000000000035
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection or missing_block
"""
        )

    assert excinfo.value.reason_code == "unknown-detection-reference"


def test_condition_missing_parenthesis_is_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Broken parens
id: 90000000-0000-0000-0000-000000000036
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: (selection
"""
        )

    assert excinfo.value.reason_code == "condition-syntax"


def test_all_of_them_requires_every_block() -> None:
    rule = converted(
        """
title: All images
id: 90000000-0000-0000-0000-000000000037
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: a.exe
    selection_2:
        Image|endswith: b.exe
    condition: all of them
"""
    )

    # ``all of them`` demands every block on the SAME record, so a
    # record satisfying only one block never matches.
    assert (
        len(
            run_category(
                rule,
                [
                    {
                        "name": "b.exe",
                        "executable": "C:\\tools\\b.exe",
                    }
                ],
                "process",
            )
        )
        == 0
    )

    rule_two_blocks = converted(
        """
title: All blocks on one record
id: 90000000-0000-0000-0000-000000000038
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: a.exe
    selection_2:
        CommandLine|contains: run
    condition: all of them
"""
    )

    complete = {
        "name": "a.exe",
        "executable": "C:\\tools\\a.exe",
        "command_line": "a.exe --run",
    }

    assert len(run_category(rule_two_blocks, [complete], "process")) == 1

    partial = {
        "name": "a.exe",
        "executable": "C:\\tools\\a.exe",
        "command_line": "a.exe --list",
    }

    assert run_category(rule_two_blocks, [partial], "process") == []


# ---------------------------------------------------------------------------
# modifiers: contains|all, wildcards, numeric comparisons, exists
# ---------------------------------------------------------------------------


def test_contains_all_expands_to_and_conditions() -> None:
    rule = converted(
        """
title: All flags
id: 90000000-0000-0000-0000-000000000040
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - --admin
            - --debug
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "command_line",
            "operator": "contains",
            "value": "--admin",
        },
        {
            "field": "command_line",
            "operator": "contains",
            "value": "--debug",
        },
    ]

    both = {"name": "tool.exe", "command_line": "tool.exe --admin --debug"}
    one = {"name": "tool.exe", "command_line": "tool.exe --admin"}

    assert len(run_category(rule, [both], "process")) == 1
    assert run_category(rule, [one], "process") == []


def test_wildcard_equals_becomes_anchored_regex() -> None:
    rule = converted(
        """
title: Wildcard image path
id: 90000000-0000-0000-0000-000000000041
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'C:\\Users\\*\\mimikatz.exe'
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "executable",
            "operator": "matches",
            "value": r"(?i)^C:\\Users\\.*\\mimikatz\.exe$",
        }
    ]

    hit = {
        "name": "mimikatz.exe",
        "executable": r"C:\Users\analyst\Downloads\mimikatz.exe",
    }
    miss = {
        "name": "mimikatz.exe",
        "executable": r"D:\mimikatz.exe",
    }

    assert len(run_category(rule, [hit], "process")) == 1
    assert run_category(rule, [miss], "process") == []


def test_sshd_wildcard_matches_fixture_style_message() -> None:
    rule = converted(SIGMA_SSHD)

    assert rule["category"] == "auth"
    assert rule["os"] == ["linux"]

    record = {
        "program": "sshd",
        "event_type": "failed_password",
        "username": "root",
        "ip": "203.0.113.9",
        "port": 22,
        "message": (
            "Sep  9 10:00:01 host sshd[1234]: Failed password for "
            "invalid user root from 203.0.113.9 port 22 ssh2"
        ),
    }

    findings = run_category(
        rule,
        [record],
        "auth",
    )

    assert len(findings) == 1

    accepted = {
        "program": "sshd",
        "event_type": "accepted_password",
        "username": "root",
        "message": (
            "Sep  9 10:01:00 host sshd[1234]: Accepted password for "
            "root from 203.0.113.9 port 22 ssh2"
        ),
    }

    assert run_category(rule, [accepted], "auth") == []


def test_regex_modifier_is_case_insensitive() -> None:
    rule = converted(
        """
title: Regex powershell
id: 90000000-0000-0000-0000-000000000042
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: '.*powershell.*-enc.*'
    condition: selection
"""
    )

    assert rule["conditions"][0]["value"] == "(?i).*powershell.*-enc.*"

    assert (
        len(
            run_category(
                rule,
                [
                    {
                        "name": "powershell.exe",
                        "command_line": "POWERSHELL.EXE -EnCodedCommand AAAA",
                    }
                ],
                "process",
            )
        )
        == 1
    )


def test_numeric_comparison_modifiers_compile() -> None:
    rule = converted(
        """
title: Big process id
id: 90000000-0000-0000-0000-000000000043
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessId|gt: 1000
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "pid",
            "operator": "greater_than",
            "value": 1000,
        }
    ]

    assert len(run_category(rule, [{"name": "x.exe", "pid": 5000}], "process")) == 1
    assert run_category(rule, [{"name": "x.exe", "pid": 500}], "process") == []


def test_bare_field_means_exists() -> None:
    rule = converted(
        """
title: Has command line
id: 90000000-0000-0000-0000-000000000044
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "command_line",
            "operator": "exists",
            "value": None,
        }
    ]

    assert (
        len(
            run_category(
                rule,
                [{"name": "x.exe", "command_line": "x.exe"}],
                "process",
            )
        )
        == 1
    )
    assert run_category(rule, [{"name": "x.exe"}], "process") == []


# ---------------------------------------------------------------------------
# logsource mapping coverage
# ---------------------------------------------------------------------------


def test_syslog_without_service_maps_to_log() -> None:
    rule = converted(
        """
title: Generic syslog
id: 90000000-0000-0000-0000-000000000050
level: low
logsource:
    category: syslog
    product: linux
detection:
    selection:
        msg|contains: kernel panic
    condition: selection
"""
    )

    assert rule["category"] == "log"
    assert rule["os"] == ["linux"]


def test_auditd_category_maps_to_log() -> None:
    rule = converted(
        """
title: Auditd
id: 90000000-0000-0000-0000-000000000051
level: low
logsource:
    category: auditd
    product: linux
detection:
    selection:
        msg|contains: syscall
    condition: selection
"""
    )

    assert rule["category"] == "log"


def test_file_event_maps_to_file_category() -> None:
    rule = converted(
        """
title: Dropped binary
id: 90000000-0000-0000-0000-000000000052
level: medium
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: .scr
    condition: selection
"""
    )

    assert rule["category"] == "file"
    assert rule["os"] == ["windows"]

    record = {"name": "evil.scr", "path": "C:\\Users\\x\\evil.scr"}

    assert len(run_category(rule, [record], "file")) == 1


def test_missing_logsource_is_skipped() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: No logsource
id: 90000000-0000-0000-0000-000000000053
level: low
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "unsupported-logsource"


def test_informational_level_maps_to_info_severity() -> None:
    rule = converted(
        """
title: Info level
id: 90000000-0000-0000-0000-000000000054
level: informational
status: deprecated
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
    )

    assert rule["severity"] == "info"
    assert rule["confidence"] == "low"
    assert rule["status"] == "deprecated"


# ---------------------------------------------------------------------------
# shipped sample rules mirror the conversion output exactly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sigma_text", "shipped_file", "rule_id"),
    [
        (SIGMA_MIMIKATZ, "sigma_windows_proc_creation_mimikatz.yaml", None),
        (SIGMA_LOGON_FAILURE, "sigma_windows_security_logon_failure.yaml", None),
        (SIGMA_NETWORK_PORT, "sigma_windows_network_connection_beacon_port.yaml", None),
        (SIGMA_SSHD, "sigma_linux_sshd_failed_password.yaml", None),
    ],
)
def test_shipped_sigma_samples_match_converter_output(
    sigma_text,
    shipped_file,
    rule_id,
) -> None:
    converted_rule = converted(sigma_text)

    shipped_path = get_rules_directory() / "sigma" / shipped_file

    shipped = yaml.safe_load(shipped_path.read_text(encoding="utf-8"))["rules"][0]

    comparable_keys = [
        "id",
        "title",
        "category",
        "os",
        "severity",
        "confidence",
        "status",
        "enabled",
        "mitre",
        "conditions",
    ]

    assert {key: shipped.get(key) for key in comparable_keys} == {
        key: converted_rule.get(key) for key in comparable_keys
    }


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux sigma rule is os-gated to linux",
)
def test_shipped_sigma_linux_rule_fires_through_directory_load() -> None:
    rules = load_rule_file(
        get_rules_directory() / "sigma" / "sigma_linux_sshd_failed_password.yaml"
    )

    assert len(rules) == 1

    record = {
        "program": "sshd",
        "event_type": "failed_password",
        "message": (
            "Sep  9 10:00:00 host sshd[42]: Failed password for "
            "invalid user admin from 10.0.0.9 port 22 ssh2"
        ),
    }

    findings = run_rules(
        rules,
        [record],
        category="auth",
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# (f) rules import --source over a small local SigmaHQ-style tree
# ---------------------------------------------------------------------------


def make_sigma_tree(
    root: Path,
) -> Path:
    rules_dir = root / "rules"

    windows = rules_dir / "windows" / "process_creation"
    windows.mkdir(parents=True)

    (windows / "proc_creation_win_tool.yml").write_text(
        SIGMA_MIMIKATZ,
        encoding="utf-8",
    )

    (windows / "proc_creation_win_bad.yml").write_text(
        """
title: Unsupported base64 rule
id: 90000000-0000-0000-0000-000000000090
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64: 'QQ=='
    condition: selection
""",
        encoding="utf-8",
    )

    linux = rules_dir / "linux" / "syslog"
    linux.mkdir(parents=True)

    (linux / "sshd_failed.yml").write_text(
        SIGMA_SSHD,
        encoding="utf-8",
    )

    return root


def test_import_into_converts_and_writes_identical_copies(
    tmp_path,
) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")
    sigma_rules = source / "rules"

    destination_a = tmp_path / "dest-a"
    destination_b = tmp_path / "dest-b"

    summary = import_into(
        sigma_rules,
        [destination_a, destination_b],
    )

    assert summary.converted_count == 2
    assert summary.skipped_count == 1
    assert summary.skipped.get("unsupported-modifier") == 1

    for destination in (destination_a, destination_b):
        converted_windows = (
            destination / "sigma" / "windows" / "process_creation" / "proc_creation_win_tool.yaml"
        )
        converted_linux = destination / "sigma" / "linux" / "syslog" / "sshd_failed.yaml"

        assert converted_windows.exists()
        assert converted_linux.exists()

        # No unsupported rules survive the conversion.
        assert not (
            destination / "sigma" / "windows" / "process_creation" / "proc_creation_win_bad.yaml"
        ).exists()

    # The two copies are byte-identical.
    for relative in (
        "sigma/windows/process_creation/proc_creation_win_tool.yaml",
        "sigma/linux/syslog/sshd_failed.yaml",
    ):
        assert (destination_a / relative).read_bytes() == (destination_b / relative).read_bytes()


def test_import_refresh_replaces_previous_tree(tmp_path) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")
    destination = tmp_path / "dest"

    import_into(
        source / "rules",
        [destination],
    )

    stale = destination / "sigma" / "stale.yaml"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text("rules: []\n", encoding="utf-8")

    import_into(
        source / "rules",
        [destination],
    )

    assert not stale.exists()


def test_converted_import_rules_load_and_fire(tmp_path) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")
    destination = tmp_path / "dest"

    import_into(
        source / "rules",
        [destination],
    )

    loaded = []

    for converted_file in (destination / "sigma").rglob("*.yaml"):
        loaded.extend(load_rule_file(converted_file))

    # Only the Linux-gated rule loads on this platform; the Windows
    # sigma rule is OS-gated and skipped here (P1-10 behaviour).
    expected_id = (
        "7c67e8d1-5f0a-4c2b-9e6d-88f9a2b4d501"
        if sys.platform.startswith("linux")
        else "20255a30-2e1d-4f0e-8b2c-7f1b2f4a6b21"
    )

    assert {rule.get("id") for rule in loaded} == {
        expected_id,
    }

    for rule in loaded:
        ok, reason = validate_rule(rule)

        assert ok, reason


def test_convert_directory_tallies_every_skip(tmp_path) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")

    summary = ConversionSummary()

    convert_directory(
        source / "rules",
        summary,
    )

    assert summary.converted_count == 2
    assert summary.skipped_count == 1


# ---------------------------------------------------------------------------
# (f-continued) offline CLI: sentinelclaw rules import --source --dest
# ---------------------------------------------------------------------------


def run_import_cli(
    *args: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinelclaw",
            "rules",
            "import",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=PROJECT_ROOT,
    )


def test_rules_import_cli_offline(tmp_path) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")
    destination = tmp_path / "dest"

    result = run_import_cli(
        "--source",
        str(source),
        "--dest",
        str(destination),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 converted, 1 skipped" in result.stdout
    assert "unsupported-modifier: 1" in result.stdout
    assert str(destination / "sigma") in result.stdout

    converted_files = list((destination / "sigma").rglob("*.yaml"))

    assert len(converted_files) == 2


def test_rules_import_cli_rejects_missing_source(tmp_path) -> None:
    result = run_import_cli(
        "--source",
        str(tmp_path / "nope"),
        "--dest",
        str(tmp_path / "dest"),
    )

    assert result.returncode == 1
    assert "Sigma" in result.stdout + result.stderr


def test_rules_import_with_zip_source(tmp_path) -> None:
    import zipfile

    source = make_sigma_tree(tmp_path / "sigma-src")

    archive_path = tmp_path / "sigma-release.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        for rule_file in (source / "rules").rglob("*.yml"):
            archive.write(
                rule_file,
                f"sigma-archive/{rule_file.relative_to(source)}",
            )

    destination = tmp_path / "dest"

    result = run_import_cli(
        "--source",
        str(archive_path),
        "--dest",
        str(destination),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 converted, 1 skipped" in result.stdout

    assert len(list((destination / "sigma").rglob("*.yaml"))) == 2


# ---------------------------------------------------------------------------
# additional edge coverage: importer helpers and error paths
# ---------------------------------------------------------------------------


def test_prepare_source_directory_rejects_other_files(
    tmp_path,
) -> None:
    from sentinelclaw.sigma.importer import (
        SigmaImportError,
        prepare_source_directory,
    )

    plain_file = tmp_path / "notes.txt"
    plain_file.write_text("hello", encoding="utf-8")

    with pytest.raises(SigmaImportError):
        prepare_source_directory(
            plain_file,
            tmp_path / "work",
        )


def test_prepare_source_directory_accepts_checkout_root(
    tmp_path,
) -> None:
    from sentinelclaw.sigma.importer import prepare_source_directory

    checkout = tmp_path / "sigma"
    (checkout / "rules" / "windows").mkdir(parents=True)

    (checkout / "rules" / "windows" / "x.yml").write_text(
        "title: X\nid: 1\nlevel: low\ndetection: {}\n",
        encoding="utf-8",
    )

    resolved = prepare_source_directory(
        checkout,
        tmp_path / "work",
    )

    assert resolved == checkout / "rules"


def test_extract_rules_directory_requires_rules_tree(
    tmp_path,
) -> None:
    import zipfile

    from sentinelclaw.sigma.importer import (
        SigmaImportError,
        extract_rules_directory,
    )

    empty_zip = tmp_path / "empty.zip"

    with zipfile.ZipFile(empty_zip, "w") as archive:
        archive.writestr("docs/readme.txt", "nothing here")

    with pytest.raises(SigmaImportError):
        extract_rules_directory(
            empty_zip,
            tmp_path / "work",
        )

    broken_zip = tmp_path / "broken.zip"
    broken_zip.write_bytes(b"not a zip")

    with pytest.raises(SigmaImportError):
        extract_rules_directory(
            broken_zip,
            tmp_path / "work",
        )


def test_download_release_zip_reports_network_failures(
    tmp_path,
    monkeypatch,
) -> None:
    import urllib.error
    import urllib.request

    from sentinelclaw.sigma.importer import (
        SigmaImportError,
        download_release_zip,
    )

    def exploding_open(*args, **kwargs):
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        exploding_open,
    )

    with pytest.raises(SigmaImportError):
        download_release_zip(
            "r2026-07-01",
            tmp_path / "out.zip",
        )


def test_import_into_deduplicates_destination_roots(
    tmp_path,
) -> None:
    source = make_sigma_tree(tmp_path / "sigma-src")
    destination = tmp_path / "dest"

    summary = import_into(
        source / "rules",
        [destination, destination],
    )

    assert summary.converted_count == 2

    written = list((destination / "sigma").rglob("*.yaml"))

    assert len(written) == 2


def test_convert_directory_default_summary_and_read_errors(
    tmp_path,
) -> None:
    from sentinelclaw.sigma.importer import convert_directory

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "binary.yml").write_bytes(b"\xff\xfe\x00\x01\x02")

    summary = convert_directory(rules_dir)

    assert summary.converted_count == 0
    assert summary.skipped.get("read-error") == 1


def test_reader_rejects_invalid_yaml_documents() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            ": not: [valid: [yaml",
        )

    assert excinfo.value.reason_code == "invalid-yaml"


def test_reader_rejects_non_mapping_document() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            "[a, b, c]",
        )

    assert excinfo.value.reason_code == "invalid-yaml"


def test_explicit_any_and_lte_modifiers_compile() -> None:
    rule = converted(
        """
title: Explicit any
id: 90000000-0000-0000-0000-000000000060
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith|any:
            - a.exe
            - b.exe
        ProcessId|lte: 9999
    condition: selection
"""
    )

    assert rule["conditions"][0]["value"] == ["a.exe", "b.exe"]

    assert rule["conditions"][1] == {
        "field": "pid",
        "operator": "less_or_equal",
        "value": 9999,
    }

    assert (
        len(
            run_category(
                rule,
                [{"name": "b.exe", "executable": "C:\\b.exe", "pid": 100}],
                "process",
            )
        )
        == 1
    )


def test_multi_modifier_combination_is_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Bad combo
id: 90000000-0000-0000-0000-000000000061
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|startswith: foo
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "unsupported-modifier"


def test_unknown_level_and_status_are_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Bad level
id: 90000000-0000-0000-0000-000000000062
level: apocalyptic
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "invalid-level"

    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Bad status
id: 90000000-0000-0000-0000-000000000063
level: low
status: mythical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
    condition: selection
"""
        )

    assert excinfo.value.reason_code == "unsupported-status"


def test_empty_detection_is_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: Empty detection
id: 90000000-0000-0000-0000-000000000064
level: low
logsource:
    category: process_creation
    product: windows
detection: {}
"""
        )

    assert excinfo.value.reason_code == "invalid-detection"


def test_missing_condition_is_rejected() -> None:
    with pytest.raises(SigmaRuleError) as excinfo:
        convert_sigma_text(
            """
title: No condition
id: 90000000-0000-0000-0000-000000000065
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: a.exe
"""
        )

    assert excinfo.value.reason_code == "invalid-detection"


def test_all_of_prefix_compiles_to_conjunction() -> None:
    rule = converted(
        """
title: All selections
id: 90000000-0000-0000-0000-000000000066
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: a.exe
    selection_2:
        Image|endswith: a.exe
    condition: all of selection_*
"""
    )

    assert rule["conditions"] == [
        {
            "field": "executable",
            "operator": "endswith",
            "value": "a.exe",
        },
        {
            "field": "executable",
            "operator": "endswith",
            "value": "a.exe",
        },
    ]


def test_one_of_them_or_across_all_blocks() -> None:
    rule = converted(
        """
title: One of them
id: 90000000-0000-0000-0000-000000000067
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: a.exe
    selection_b:
        Image|endswith: b.exe
    condition: 1 of them
"""
    )

    assert (
        len(
            run_category(
                rule,
                [{"name": "b.exe", "executable": "C:\\b.exe"}],
                "process",
            )
        )
        == 1
    )


def test_contains_wildcard_compiles_unanchored_regex() -> None:
    rule = converted(
        """
title: Wildcard contains
id: 90000000-0000-0000-0000-000000000068
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-enc*AAAA'
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "field": "command_line",
            "operator": "matches",
            "value": "(?i)-enc.*AAAA",
        }
    ]

    hit = {"name": "powershell.exe", "command_line": "powershell -enc X AAAA"}

    assert len(run_category(rule, [hit], "process")) == 1


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux sigma rule is os-gated to linux",
)
def test_sshd_shipped_rule_fires_on_syslog_prefixed_message() -> None:
    from sentinelclaw.config.paths import get_rules_directory

    rule = converted(SIGMA_SSHD)

    record = {
        "program": "sshd",
        "event_type": "failed_password",
        "message": (
            "Sep  9 10:00:00 host sshd[777]: Failed password for "
            "invalid user nobody from 10.1.1.1 port 40000 ssh2"
        ),
    }

    assert len(run_category(rule, [record], "auth")) == 1

    shipped = load_rule_file(
        get_rules_directory() / "sigma" / "sigma_linux_sshd_failed_password.yaml"
    )

    assert len(shipped) == 1

    assert run_category(shipped[0], [record], "auth") != []


def test_numeric_list_value_uses_any_of_group() -> None:
    rule = converted(
        """
title: Numeric list
id: 90000000-0000-0000-0000-000000000069
level: low
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ProcessId|gt:
            - 100
            - 900
    condition: selection
"""
    )

    assert rule["conditions"] == [
        {
            "any_of": [
                {
                    "field": "pid",
                    "operator": "greater_than",
                    "value": 100,
                },
                {
                    "field": "pid",
                    "operator": "greater_than",
                    "value": 900,
                },
            ]
        }
    ]

    assert len(run_category(rule, [{"name": "x.exe", "pid": 950}], "process")) == 1
    assert run_category(rule, [{"name": "x.exe", "pid": 50}], "process") == []
