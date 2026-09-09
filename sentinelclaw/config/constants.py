"""
Centralized constants shared across the SentinelClaw package.

This module is intentionally a leaf: it must not import from any
other SentinelClaw package so that engines, detectors, reporters,
and models can all depend on it without creating import cycles.

P4-24: the risk-level thresholds, severity scores, confidence
multipliers, category modifiers and saturation rate below are the
single source of truth for the documented risk model implemented in
``sentinelclaw.models.risk`` (see its module docstring for the exact
formula and calibration rationale). main.py no longer carries its own
incident-risk weights.
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


# P4-24: risk-model v2 configuration. The severity base scores above
# are multiplied by the confidence multiplier and the category modifier
# to produce a finding's intrinsic risk contribution; a ranked list of
# contributions is then combined with geometric saturation (see
# ``sentinelclaw.models.risk`` for the documented formula).
#
# A finding without a parsed confidence level (``None`` or an unknown
# value) keeps the neutral multiplier 1.0 so pre-existing detections
# that do not carry confidence are not inflated or damped. Categories
# that are not listed (including the normalized ``unknown`` bucket and
# detector-specific buckets such as ``log``/``pcap``) keep the neutral
# modifier 1.0.
CONFIDENCE_RISK_MULTIPLIERS = {
    "low": 0.9,
    "medium": 1.1,
    "high": 1.3,
}

CATEGORY_RISK_MODIFIERS = {
    "process": 1.05,
    "network": 1.05,
    "persistence": 1.10,
    "file": 1.00,
    "windows_event": 0.95,
    "auth": 0.95,
}

# Geometric decay applied to each additional finding when a set of
# risk contributions is aggregated (ranked largest first): the k-th
# contribution keeps ``RISK_SATURATION_RATE ** (k - 1)`` of its value.
RISK_SATURATION_RATE = 0.95

RISK_SCORE_CAP = 100


MONITORED_PORTS = {
    23: "Telnet",
    4444: "Common reverse-shell/metasploit port",
    5555: "Common Android ADB/debugging port",
    6667: "Common IRC port",
}

# P4-21: top-level domains that are disproportionately abused for
# phishing, malware staging, and C2 rendezvous (cheap registrations,
# free subdomain providers, or freshly delegated ccTLDs). Matching is
# case-insensitive on the last DNS label of a query name. This is a
# documented indicator list, not a blocklist: legitimate uses exist.
SUSPICIOUS_DNS_TLDS = frozenset(
    {
        "cf",
        "download",
        "ga",
        "gq",
        "loan",
        "ml",
        "party",
        "racing",
        "science",
        "stream",
        "tk",
        "top",
        "win",
        "work",
        "xyz",
    }
)
