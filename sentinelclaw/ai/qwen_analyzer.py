from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)


SYSTEM_INSTRUCTION = """
You are a defensive cybersecurity analyst assisting with SentinelClaw.

You must analyze only the evidence supplied to you.

Rules:
- Do not invent events, malware, users, IP ownership, or attack activity.
- Treat detections as indicators, not proof of compromise.
- Distinguish confirmed evidence from hypotheses.
- Explain likely benign alternatives where appropriate.
- Prioritize high-confidence, high-severity evidence.
- Use MITRE ATT&CK mappings only when present in the supplied data.
- Do not recommend destructive actions.
- Do not recommend deleting files, killing processes, changing registry
  settings, disabling security controls, or blocking addresses automatically.
- Recommend investigation and verification steps only.
- Keep the response concise and useful to a SOC analyst.

Return the assessment using these sections:

EXECUTIVE SUMMARY
KEY FINDINGS
CORRELATED ACTIVITY
MITRE ATT&CK
RISK ASSESSMENT
RECOMMENDED INVESTIGATION STEPS
""".strip()


def build_ai_payload(
    report: dict,
) -> dict:
    risk = report.get(
        "risk",
        {}
    )

    summary = report.get(
        "summary",
        {}
    )

    findings = report.get(
        "findings",
        {}
    ).get(
        "all",
        []
    )

    incidents = report.get(
        "incidents",
        []
    )

    timeline = report.get(
        "timeline",
        []
    )

    reduced_findings = []

    for finding in findings[:50]:
        reduced_findings.append(
            {
                "severity": finding.get(
                    "severity"
                ),
                "rule_id": finding.get(
                    "rule_id"
                ),
                "title": finding.get(
                    "title"
                ),
                "description": finding.get(
                    "description"
                ),
                "confidence": finding.get(
                    "confidence"
                ),
                "category": finding.get(
                    "category"
                ),
                "mitre": finding.get(
                    "mitre"
                ),
                "pid": finding.get(
                    "pid"
                ),
                "process_name": finding.get(
                    "process_name"
                ),
                "remote_ip": finding.get(
                    "remote_ip"
                ),
                "source": finding.get(
                    "source"
                ),
                "evidence": finding.get(
                    "evidence"
                ),
            }
        )

    reduced_incidents = []

    for incident in incidents[:20]:
        reduced_incidents.append(
            {
                "incident_id": incident.get(
                    "incident_id"
                ),
                "title": incident.get(
                    "title"
                ),
                "description": incident.get(
                    "description"
                ),
                "severity": incident.get(
                    "severity"
                ),
                "confidence": incident.get(
                    "confidence"
                ),
                "finding_count": incident.get(
                    "finding_count"
                ),
                "related_rule_ids": incident.get(
                    "related_rule_ids"
                ),
                "related_pids": incident.get(
                    "related_pids"
                ),
                "related_ips": incident.get(
                    "related_ips"
                ),
                "mitre": incident.get(
                    "mitre"
                ),
            }
        )

    reduced_timeline = []

    for event in timeline[:50]:
        reduced_timeline.append(
            {
                "timestamp": event.get(
                    "timestamp"
                ),
                "event_type": event.get(
                    "event_type"
                ),
                "severity": event.get(
                    "severity"
                ),
                "title": event.get(
                    "title"
                ),
                "rule_id": event.get(
                    "rule_id"
                ),
                "incident_id": event.get(
                    "incident_id"
                ),
                "pid": event.get(
                    "pid"
                ),
                "process_name": event.get(
                    "process_name"
                ),
                "remote_ip": event.get(
                    "remote_ip"
                ),
            }
        )

    return {
        "scan": report.get(
            "scan",
            {}
        ),
        "risk": risk,
        "summary": summary,
        "findings": reduced_findings,
        "incidents": reduced_incidents,
        "timeline": reduced_timeline,
        "collector_status": report.get(
            "collector_status",
            {}
        ),
    }


def build_prompt(
    report: dict,
) -> str:
    payload = build_ai_payload(
        report
    )

    evidence_json = json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    return (
        SYSTEM_INSTRUCTION
        + "\n\n"
        + "SENTINELCLAW EVIDENCE:\n"
        + evidence_json
        + "\n\n"
        + "Analyze the supplied evidence."
    )


def query_ollama(
    prompt: str,
    model: str | None = None,
    timeout: int | None = None,
) -> str:
    settings = get_settings()

    resolved_model = (
        model
        if model is not None
        else settings.ollama_model
    )

    resolved_timeout = (
        timeout
        if timeout is not None
        else settings.ollama_timeout
    )

    request_body = {
        "model": resolved_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    encoded_body = json.dumps(
        request_body
    ).encode(
        "utf-8"
    )

    request = urllib.request.Request(
        settings.ollama_url,
        data=encoded_body,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=resolved_timeout,
        ) as response:
            body = response.read().decode(
                "utf-8"
            )

    except urllib.error.URLError as exc:
        logger.warning(
            "Ollama request failed for model %s: %s",
            resolved_model,
            exc,
        )

        raise RuntimeError(
            "Could not connect to Ollama. "
            "Make sure Ollama is running."
        ) from exc

    except TimeoutError as exc:
        raise RuntimeError(
            "The Ollama request timed out."
        ) from exc

    try:
        result: dict[str, Any] = (
            json.loads(
                body
            )
        )

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Ollama returned invalid JSON."
        ) from exc

    response_text = result.get(
        "response"
    )

    if not response_text:
        error = result.get(
            "error"
        )

        if error:
            raise RuntimeError(
                f"Ollama error: {error}"
            )

        raise RuntimeError(
            "Ollama returned no analysis."
        )

    return str(
        response_text
    ).strip()


def analyze_report_with_qwen(
    report: dict,
    model: str | None = None,
) -> dict:
    settings = get_settings()

    resolved_model = (
        model
        if model is not None
        else settings.ollama_model
    )

    prompt = build_prompt(
        report
    )

    analysis = query_ollama(
        prompt=prompt,
        model=resolved_model,
    )

    return {
        "model": resolved_model,
        "analysis": analysis,
    }
