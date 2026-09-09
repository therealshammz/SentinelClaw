"""
Centralized constants shared across the SentinelClaw package.

This module is intentionally a leaf: it must not import from any
other SentinelClaw package so that engines, detectors, reporters,
and models can all depend on it without creating import cycles.

Note: sentinelclaw/main.py still carries its own local incident-risk
weights and risk-level thresholds. main.py is out of scope for this
consolidation pass; those values remain duplicated there pending a
later migration.
"""

SEVERITY_ORDER = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)

SEVERITY_RANK = {
    severity: rank
    for rank, severity in enumerate(
        SEVERITY_ORDER
    )
}

VALID_SEVERITIES = frozenset(
    SEVERITY_ORDER
)

# P3-18: the machine-readable report schema. Every report dict emitted
# by ``run_scan`` and every scan-state record written to the data
# directory carries this version so parsers can detect schema changes.
REPORT_SCHEMA_VERSION = "1.0.0"

SEVERITY_SCORES = {
    "info": 0,
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 10,
}

RISK_LEVEL_THRESHOLDS = (
    (70, "critical"),
    (40, "high"),
    (20, "medium"),
    (1, "low"),
)


def risk_level_from_score(
    score: int,
) -> str:
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level

    return "informational"


MONITORED_PORTS = {
    23: "Telnet",
    4444: "Common reverse-shell/metasploit port",
    5555: "Common Android ADB/debugging port",
    6667: "Common IRC port",
}
