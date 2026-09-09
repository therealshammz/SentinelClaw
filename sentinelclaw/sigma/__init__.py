"""
Sigma-rule compatibility layer (P2-14).

This package converts the Sigma detection format (SigmaHQ / sigma spec
v1 subset) into SentinelClaw's internal rule format so imported rules
are evaluated by the deterministic rule engine over the same evidence.
Import itself is user-invoked and never runs during scans.
"""

from sentinelclaw.sigma.reader import (
    FIELD_MAP,
    LOGSOURCE_CATEGORY_MAP,
    LOGSOURCE_SERVICE_MAP,
    PRODUCT_OS_MAP,
    SigmaRuleError,
    convert_sigma_rule,
    convert_sigma_text,
)

__all__ = [
    "FIELD_MAP",
    "LOGSOURCE_CATEGORY_MAP",
    "LOGSOURCE_SERVICE_MAP",
    "PRODUCT_OS_MAP",
    "SigmaRuleError",
    "convert_sigma_rule",
    "convert_sigma_text",
]
