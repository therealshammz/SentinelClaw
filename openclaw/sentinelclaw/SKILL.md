---
name: sentinelclaw
description: Local defensive cybersecurity analysis using the SentinelClaw CLI.
---

# SentinelClaw

Use SentinelClaw for defensive, read-only cybersecurity analysis of the local system.

SentinelClaw is installed as a Python CLI command and should be invoked using:

```text
sentinelclaw
```

Do not assume a specific installation directory, Windows username, virtual environment path, or Python executable.

Do not kill processes, delete files, modify registry settings, change firewall rules, modify system configuration, or perform remediation automatically.

## Available commands

### Security dashboard

Run:

```text
sentinelclaw dashboard
```

Use this when the user wants a concise overview of the current security posture.

For additional evidence:

```text
sentinelclaw dashboard --verbose
```

### Full security scan

Run:

```text
sentinelclaw scan
```

Use this when the user asks to scan the computer, investigate suspicious activity, inspect the system, or perform a security review.

The deterministic SentinelClaw detection pipeline should be treated as the primary source of security evidence.

### AI-assisted investigation

Run:

```text
sentinelclaw investigate
```

Use this when the user explicitly wants SentinelClaw's optional local AI investigation.

The AI layer is an investigation assistant. It must not be treated as the primary detection engine.

AI conclusions must be checked against the deterministic SentinelClaw findings.

If Ollama or the configured local model is unavailable, do not treat that as failure of SentinelClaw's core security analysis. Use the deterministic scan instead.

### Generate report

Run:

```text
sentinelclaw report
```

Use this when the user asks for a saved security assessment report.

SentinelClaw can generate JSON, text, and HTML reports.

To request a specific format:

```text
sentinelclaw report --format json
sentinelclaw report --format text
sentinelclaw report --format html
sentinelclaw report --format all
```

### System information

Run:

```text
sentinelclaw system
```

Use this for basic local system information relevant to an investigation.

### Running processes

Run:

```text
sentinelclaw processes
```

Use this to inspect currently running processes and process-related security indicators.

### Network connections

Run:

```text
sentinelclaw network
```

Use this to inspect current network connections and network-related security indicators.

### Windows Security events

Run:

```text
sentinelclaw windows-events
```

Use this to inspect supported Windows Security Event Log activity.

Access to the Windows Security log may require an elevated Administrator session.

If the collector cannot access the Security log, explain the permission issue rather than treating the collector failure as evidence of malicious activity.

### Analyze a file

Run:

```text
sentinelclaw file "<path>"
```

Use this when the user asks to analyze a specific local file.

Treat file findings as indicators requiring validation.

Do not delete, quarantine, modify, or execute the analyzed file.

### Analyze a PCAP

Run:

```text
sentinelclaw pcap "<path>"
```

Use this when the user asks to analyze an existing packet capture.

PCAP support is optional. If the required PCAP dependency is unavailable, explain that PCAP support must be installed rather than treating it as a security failure.

Do not initiate offensive network activity or automatically interact with systems identified in the capture.

### Correlated incidents

Run:

```text
sentinelclaw incidents
```

Use this when the user wants to review SentinelClaw's correlated security incidents.

Correlation is investigative context and does not automatically prove compromise.

### Investigation timeline

Run:

```text
sentinelclaw timeline
```

Use this when the user wants to reconstruct the chronological sequence of detected security activity.

### Detection rules

Run:

```text
sentinelclaw rules
```

Use this to inspect the detection rules currently available to SentinelClaw.

## Analysis rules

Treat SentinelClaw findings as evidence, not proof of compromise.

When presenting a security finding, explain:

- what was detected
- its severity
- why the rule triggered
- the supporting evidence
- possible benign explanations
- what the user should investigate or verify next

Do not claim malware, intrusion, persistence, credential theft, command-and-control activity, or compromise unless the available evidence supports that conclusion.

Informational findings should not be presented as threats.

A suspicious process name, executable location, network connection, monitored port, unsigned executable, high-entropy file, or individual Windows event is not by itself proof of malicious activity.

Prefer deterministic SentinelClaw evidence over AI speculation.

Clearly distinguish confirmed observations from interpretations or hypotheses.

If SentinelClaw reports a collector error, permission problem, unavailable optional dependency, or unavailable AI service, describe it as an operational limitation rather than a security finding.

## Safety boundaries

SentinelClaw is a defensive and read-only analysis tool.

Do not automatically:

- terminate processes
- delete or quarantine files
- execute suspicious files
- modify the Windows registry
- modify firewall rules
- modify user accounts
- disable services
- change system security settings
- install persistence
- exploit systems
- perform credential attacks
- perform destructive remediation

Investigation and verification steps should remain defensive and authorized.

## Response style

Prefer concise SOC-style summaries.

Prioritize critical and high-severity findings first, followed by medium, low, and informational findings when relevant.

Clearly separate:

1. observed evidence
2. assessment
3. recommended verification steps

Do not overwhelm the user with raw JSON unless they explicitly request structured output.
