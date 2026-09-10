"""
Risk model v2 (P4-24): one documented, deterministic scoring model.

All risk scoring in SentinelClaw -- finding-level, incident-level and
the combined scan risk -- shares this single implementation. The
historical model summed raw severity points per finding and derived
incident contributions from a *different* weight table, merging the two
inconsistent strata with ``max()``. v2 replaces both weight tables with
one formula and applies it uniformly.

Intrinsic finding base score
----------------------------

A finding contributes an *intrinsic base score* before any
aggregation::

    base(f) = severity_score(f) * confidence_multiplier(f)
                                 * category_modifier(f)

where the three factors come from
``sentinelclaw.config.constants``:

* ``SEVERITY_SCORES`` -- info 0, low 1, medium 3, high 7, critical 10.
  The 0/1/3/7/10 spacing keeps single-signal behaviour identical to
  the historical model, so v2 is a strict calibration of the old
  additive scores for one finding.
* ``CONFIDENCE_RISK_MULTIPLIERS`` -- low 0.9, medium 1.1, high 1.3.
  A finding without a parsed confidence level (``None`` or an unknown
  value) keeps the neutral multiplier 1.0, so legacy findings that
  carry no confidence are neither inflated nor damped.
* ``CATEGORY_RISK_MODIFIERS`` -- direct-execution evidence categories
  amplify slightly (persistence 1.10, process/network 1.05, file 1.00)
  while circumstantial log evidence is damped (windows_event/auth
  0.95). Categories outside the table (including the normalized
  ``unknown`` bucket and detector buckets such as ``log``/``pcap``)
  keep the neutral modifier 1.0.

Aggregation with count saturation
---------------------------------

A set of contributions (all findings of a scan, or the member findings
of one incident) is aggregated by ranking the base scores largest
first and applying geometric decay to every additional signal::

    risk(V) = min(100, round( sum over k=1..n of v_k
                                   * SATURATION_RATE ** (k - 1) ))

with ``SATURATION_RATE = 0.95`` and each ``v_k`` a distinct ranked base
score. The k-th finding keeps 95% of the marginal risk of the (k-1)-th:
repeated or correlated signals still raise risk, but with diminishing
returns instead of the historical unbounded linear addition. Ten
identical critical findings score ~80 rather than 100, and twenty
identical critical findings still saturate at the
:data:`RISK_SCORE_CAP` of 100 (the historical cap test).

The decay is a property of the *aggregate*: a finding's own breakdown
(``finding_risk_breakdown``) reports its intrinsic base with
``saturation_applied`` false. Aggregation entry points are the only
place the saturation curve is applied.

Strata
------

* ``calculate_risk_score(findings)`` -- finding stratum.
* ``calculate_incident_risk(incidents)`` -- incident stratum. An
  incident restates its member findings, so each incident first gets
  the shared saturating aggregate over its *members* (never the
  historical max-of-severity weight), and the resulting per-incident
  scores are then combined with the same saturating aggregate across
  incidents.
* ``calculate_overall_risk(findings, incidents)`` -- the scan-level
  risk is ``max(finding stratum, incident stratum)``. Incidents are a
  derived, overlapping view of the same findings; adding the strata
  would double-count the underlying signals, so the larger stratum
  wins. Levels are mapped by ``risk_level_from_score`` against the
  shared ``RISK_LEVEL_THRESHOLDS`` (70 critical, 40 high, 20 medium,
  1 low, else informational).

Rounding is deterministic ``round()`` to integers at stratum level and
for a finding's standalone score; scores never go negative and are
capped at :data:`RISK_SCORE_CAP`.

Per-finding breakdown
---------------------

``finding_risk_breakdown`` returns::

    {"score": int, "level": str,
     "components": {"severity_score": int, "confidence": float,
                    "category_modifier": float,
                    "saturation_applied": false}}

``components["confidence"]`` is the applied numeric multiplier (1.0
when the finding carries no confidence level); the finding keeps its
raw confidence string alongside. ``saturation_applied`` is always
false for the standalone breakdown -- the geometric saturation curve
is only applied by the aggregation entry points above.
"""

from collections.abc import Iterable
from typing import Any

from sentinelclaw.config.constants import (
    CATEGORY_RISK_MODIFIERS,
    CONFIDENCE_RISK_MULTIPLIERS,
    RISK_SATURATION_RATE,
    RISK_SCORE_CAP,
    SEVERITY_SCORES,
    risk_level_from_score,
)


def confidence_multiplier(
    confidence: Any,
) -> float:
    """Return the risk multiplier for a finding's confidence level."""
    if confidence is None:
        return 1.0

    level = str(confidence).lower()

    return CONFIDENCE_RISK_MULTIPLIERS.get(
        level,
        1.0,
    )


def category_modifier(
    category: Any,
) -> float:
    """Return the risk modifier for a finding's category."""
    if category is None:
        return 1.0

    level = str(category).lower()

    return CATEGORY_RISK_MODIFIERS.get(
        level,
        1.0,
    )


def finding_base_score(
    finding: dict,
) -> float:
    """Intrinsic (pre-aggregation) risk contribution of one finding."""
    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).lower()

    base = float(
        SEVERITY_SCORES.get(
            severity,
            0,
        )
    )

    if base == 0:
        return 0.0

    return base * confidence_multiplier(
        finding.get("confidence")
    ) * category_modifier(
        finding.get("category")
    )


def saturating_score(
    contributions: Iterable[float],
) -> int:
    """Combine ranked risk contributions with geometric saturation.

    Contributions are sorted largest first; the k-th keeps
    ``SATURATION_RATE ** (k - 1)`` of its value so identical or
    correlated signals add diminishing marginal risk.
    """
    ranked = sorted(
        (
            float(value)
            for value in contributions
            if value > 0
        ),
        reverse=True,
    )

    total = 0.0
    decay = 1.0

    for value in ranked:
        total += value * decay
        decay *= RISK_SATURATION_RATE

    score = int(
        round(
            total
        )
    )

    return min(
        score,
        RISK_SCORE_CAP,
    )


def finding_risk_breakdown(
    finding: dict,
) -> dict:
    """Standalone risk view attached to every processed finding.

    The breakdown documents how the finding's intrinsic base score was
    derived; aggregation (``calculate_risk_score`` and friends) applies
    the saturation curve on top of these bases.
    """
    base = finding_base_score(
        finding
    )

    score = int(
        round(
            base
        )
    )

    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).lower()

    return {
        "score": score,
        "level": risk_level_from_score(
            score
        ),
        "components": {
            "severity_score": SEVERITY_SCORES.get(
                severity,
                0,
            ),
            "confidence": confidence_multiplier(
                finding.get("confidence")
            ),
            "category_modifier": category_modifier(
                finding.get("category")
            ),
            "saturation_applied": False,
        },
    }


def calculate_risk_score(
    findings: list[dict],
) -> dict:
    """Risk of a list of findings (shared finding-stratum entry point)."""
    score = saturating_score(
        finding_base_score(
            finding
        )
        for finding in findings
    )

    return {
        "score": score,
        "level": risk_level_from_score(
            score
        ),
    }


def _incident_members(
    incident: dict,
) -> list[dict]:
    members = incident.get(
        "findings",
        [],
    )

    if isinstance(
        members,
        list,
    ):
        return [
            item
            for item in members
            if isinstance(
                item,
                dict,
            )
        ]

    return []


def calculate_incident_risk(
    incidents: list[dict],
) -> dict:
    """Risk of the incident stratum.

    Each incident's risk is the shared saturating aggregate over its
    member findings (never a max-of-severity weight), and the incident
    scores are combined with the same saturating aggregate across
    incidents so overlapping correlation lenses add confirmation
    rather than duplicate the full finding risk.
    """
    incident_scores = (
        saturating_score(
            finding_base_score(
                member
            )
            for member in _incident_members(
                incident
            )
        )
        for incident in incidents
    )

    score = saturating_score(
        incident_scores
    )

    return {
        "score": score,
        "level": risk_level_from_score(
            score
        ),
    }


def calculate_overall_risk(
    findings: list[dict],
    incidents: list[dict],
) -> dict:
    """Combine the finding and incident strata into the scan risk.

    Incidents are a derived, overlapping view of the findings (their
    members are findings), so the strata are merged with ``max()``
    rather than added: adding would count the same signals twice.
    Both strata already share the identical scoring formula.
    """
    finding_risk = calculate_risk_score(
        findings
    )

    incident_risk = calculate_incident_risk(
        incidents
    )

    overall_score = max(
        finding_risk["score"],
        incident_risk["score"],
    )

    return {
        "score": overall_score,
        "level": risk_level_from_score(
            overall_score
        ),
        "finding_risk": finding_risk,
        "incident_risk": incident_risk,
    }
