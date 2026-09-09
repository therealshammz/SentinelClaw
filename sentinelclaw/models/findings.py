"""Finding risk helpers (backward-compatible import site, P4-24).

Risk model v2 lives in ``sentinelclaw.models.risk``; this module keeps
re-exporting ``calculate_risk_score`` so existing call sites and tests
that imported it from ``models.findings`` keep working unchanged.
"""

from sentinelclaw.models.risk import (
    calculate_risk_score,
)

__all__ = [
    "calculate_risk_score",
]
