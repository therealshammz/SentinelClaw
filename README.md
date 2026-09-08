# SentinelClaw

**SentinelClaw** is a local, defensive cybersecurity analysis CLI for Windows and Linux.

It collects and analyzes security-relevant system data, normalizes detections, correlates related findings into incidents, builds investigation timelines, calculates risk scores, analyzes PCAP files, and generates security assessment reports.

SentinelClaw can optionally use a locally running **Qwen model through Ollama** to explain deterministic scan results.

> SentinelClaw is designed for defensive security, investigation, education, and authorized analysis. Its core detection engine does not depend on AI.

---

## Features

- Local system security scanning
- Running process analysis
- Network connection analysis
- Windows Security Event Log analysis
- File security analysis
- Text log analysis
- Offline PCAP analysis
- YAML-based detection rules
- Finding normalization and deduplication
- Incident correlation
- Security timeline generation
- Risk scoring
- MITRE ATT&CK mappings
- JSON, text, and HTML reports
- Optional local Qwen analysis through Ollama
- Terminal security dashboard
- OpenClaw integration
- No cloud dependency for core detection

---

## Architecture

```text
Security Data
     |
     v
Collectors / File Input
     |
     v
Analyzers
     |
     v
Detectors + YAML Rules
     |
     v
Finding Processor
     |
     v
Correlation Engine
     |
     +--------------------+
     |                    |
     v                    v
Risk Engine          Timeline Engine
     |                    |
     +---------+----------+
               |
               v
        Reports / Console
               |
               v
      Optional Local Qwen
```

The deterministic security pipeline operates independently from the AI layer.

AI is used as an optional investigation assistant rather than as the primary detection mechanism.

---

## Requirements

### Supported Python

Python 3.11 or newer.

### Primary Platforms

- Windows 10
- Windows 11
- Linux

Some functionality is platform-specific.

Windows Security Event Log collection requires Windows and may require an elevated terminal.

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd SentinelClaw
```

Create a virtual environment:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install SentinelClaw in editable mode:

```bash
python -m pip install -e .
```

Verify the installation:

```bash
sentinelclaw --help
```

---

## Optional PCAP Support

PCAP analysis uses Scapy.

Install SentinelClaw with PCAP support:

```bash
python -m pip install -e ".[pcap]"
```

Then analyze a capture:

```bash
sentinelclaw pcap path/to/capture.pcap
```

SentinelClaw performs offline PCAP analysis and does not require packet capture privileges for existing capture files.

Depending on the operating system and Scapy configuration, additional packet-capture components may be required for functionality beyond SentinelClaw's offline analysis workflow.

---

## Development Installation

Install the development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the automated test suite:

```bash
pytest
```

For detailed output:

```bash
pytest -v
```

---

## Quick Start

Run the terminal dashboard:

```bash
sentinelclaw dashboard
```

Show additional evidence:

```bash
sentinelclaw dashboard --verbose
```

Run the complete deterministic scan:

```bash
sentinelclaw scan
```

Display a compact summary:

```bash
sentinelclaw summary
```

Show correlated incidents:

```bash
sentinelclaw incidents
```

Display the investigation timeline:

```bash
sentinelclaw timeline
```

Show loaded detection rules:

```bash
sentinelclaw rules
```

---

## Commands

### System Information

```bash
sentinelclaw system
```

Collects basic local system information.

### Process Analysis

```bash
sentinelclaw processes
```

Collects information about running processes.

Process detections can identify indicators such as suspicious execution locations, unusual parent-child relationships, suspicious PowerShell arguments, and selected living-off-the-land behavior.

A detection is an indicator for investigation and does not by itself prove malicious activity.

### Network Analysis

```bash
sentinelclaw network
```

Examines current network connections.

SentinelClaw can identify security-relevant network indicators such as connections involving monitored ports.

Network findings should be validated before being treated as malicious.

### Windows Security Events

```bash
sentinelclaw windows-events
```

Analyzes selected Windows Security Event Log records.

Monitored events include security-relevant activity such as:

- Failed logons
- Explicit credential use
- Special privilege assignment
- Process creation
- Service installation
- Account creation
- Group membership changes
- Account lockouts
- Security audit log clearing

Access to the Windows Security log may require Administrator privileges.

If access is denied, launch PowerShell, Windows Terminal, or VS Code as Administrator and run SentinelClaw again.

### Text Log Analysis

```bash
sentinelclaw logs path/to/file.log
```

Analyzes supported text log input.

### File Analysis

```bash
sentinelclaw file path/to/file.exe
```

File analysis can examine indicators including:

- SHA-256
- File metadata
- MIME information
- Entropy
- PE signatures
- Authenticode status
- Executable location
- Suspicious double extensions
- Script file types

Machine-readable output:

```bash
sentinelclaw file path/to/file.exe --json
```

### PCAP Analysis

```bash
sentinelclaw pcap path/to/capture.pcap
```

PCAP analysis includes:

- Protocol statistics
- Source and destination IPs
- Destination ports
- Network flows
- TCP scan indicators
- UDP scan indicators
- Monitored-port detections
- High-volume flow indicators

PCAP findings represent investigation signals rather than automatic proof of compromise.

---

## Security Dashboard

```bash
sentinelclaw dashboard
```

The dashboard provides a compact SOC-style overview containing information such as:

```text
SENTINELCLAW SECURITY DASHBOARD

RISK
Overall Risk : LOW
Risk Score   : 6/100

SCAN SUMMARY
Processes
Connections
Windows Events
Findings
Incidents

PRIORITIZED FINDINGS
...
```

Use:

```bash
sentinelclaw dashboard --verbose
```

for additional evidence and context.

---

## Detection Rules

SentinelClaw supports external YAML detection rules.

The default rule categories include:

```text
process
file
windows_event
```

Example rule structure:

```yaml
id: PROC-EXAMPLE-001
title: Example Process Detection
category: process
severity: medium
description: Example defensive process rule.

conditions:
  - field: name
    operator: equals
    value: powershell.exe
```

Rules should identify observable security indicators rather than assume malicious intent without supporting evidence.

---

## Finding Processing

Raw detections are passed through SentinelClaw's finding processor.

The processor handles:

- Severity normalization
- Confidence normalization
- Evidence normalization
- MITRE metadata normalization
- Duplicate detection
- Finding merging
- Deterministic ordering

This reduces repeated alerts before correlation and reporting.

---

## Incident Correlation

SentinelClaw attempts to correlate related security findings into higher-level incidents.

Examples include:

- Multiple suspicious findings involving the same process
- Process and network activity sharing relevant context
- Related MITRE ATT&CK activity

Correlation increases investigative context but does not automatically prove that an intrusion occurred.

---

## Timeline

Run:

```bash
sentinelclaw timeline
```

SentinelClaw builds a chronological investigation timeline from findings and correlated incidents when timestamps are available.

This helps reconstruct the order of security-relevant activity.

---

## Risk Scoring

SentinelClaw uses deterministic severity-based risk scoring.

Findings and correlated incidents contribute to the overall assessment.

Risk levels include:

```text
INFORMATIONAL
LOW
MEDIUM
HIGH
CRITICAL
```

The risk score is intended for prioritization.

It should not be interpreted as a mathematical probability that a system is compromised.

---

## Reports

Generate all report formats:

```bash
sentinelclaw report
```

SentinelClaw supports:

```text
JSON
Text
HTML
```

Generate a specific format:

```bash
sentinelclaw report --format html
```

Other examples:

```bash
sentinelclaw report --format json
sentinelclaw report --format text
sentinelclaw report --format all
```

Reports include security assessment information such as:

- Overall risk
- Executive assessment
- Scan statistics
- Prioritized observations
- Findings
- Correlated incidents
- Timeline events
- Collector status
- Investigation recommendations
- Methodology and limitations

Generated reports are stored in the configured report directory.

The report directory can be overridden using:

```text
SENTINELCLAW_REPORT_DIR
```

---

## Optional Local AI Investigation

SentinelClaw's core security engine does **not** require AI.

The architecture is:

```text
SentinelClaw
├── Deterministic scan → AI not required
└── AI investigation   → optional Ollama/Qwen
```

The AI layer receives results produced by SentinelClaw's deterministic analysis pipeline and provides an analyst-oriented explanation.

It does not replace the underlying detection engine.

---

## Ollama Setup

Install Ollama separately.

After Ollama is installed, download a compatible Qwen model.

Example:

```bash
ollama pull qwen3:14b
```

Verify it is available:

```bash
ollama list
```

Then run:

```bash
sentinelclaw investigate
```

The default model is:

```text
qwen3:14b
```

A different installed Ollama model can be selected with:

```bash
sentinelclaw investigate --model MODEL_NAME
```

For example:

```bash
sentinelclaw investigate --model qwen3:14b
```

If Ollama is unavailable, the deterministic SentinelClaw scan remains usable.

---

## AI Security Model

SentinelClaw follows a separation-of-responsibility model:

```text
Python detection engine
        |
        | produces evidence
        v
Structured findings
        |
        v
Correlation + risk + timeline
        |
        v
Optional Qwen analysis
```

The deterministic engine identifies observable indicators.

The AI layer is intended to:

- Summarize evidence
- Explain findings
- Assist investigation
- Identify relationships in supplied evidence
- Suggest defensive verification steps

The AI layer should not invent evidence or treat an indicator as confirmed malware without supporting data.

AI output is advisory.

---

## Environment Variables

SentinelClaw supports path overrides using environment variables.

### Detection Rules

```text
SENTINELCLAW_RULES_DIR
```

### Reports

```text
SENTINELCLAW_REPORT_DIR
```

### Data

```text
SENTINELCLAW_DATA_DIR
```

These can be used when integrating SentinelClaw into custom environments.

---

## Windows Launcher

The repository includes:

```text
sentinelclaw.bat
```

It can be used from the project directory on Windows.

Example:

```powershell
.\sentinelclaw.bat dashboard
```

If the project's virtual environment exists, the launcher uses it automatically.

Otherwise it attempts to use the system Python installation.

After package installation, the preferred command is:

```bash
sentinelclaw
```

---

## OpenClaw Integration

SentinelClaw includes an OpenClaw skill definition for local integration.

The integration is intended to expose defensive SentinelClaw analysis through OpenClaw while keeping the underlying security operations read-only.

The skill must not automatically:

- Kill processes
- Delete files
- Modify the registry
- Modify firewall rules
- Perform remediation
- Execute destructive actions

SentinelClaw should provide evidence and investigation context while leaving consequential remediation decisions to the operator.

---

## Project Structure

```text
SentinelClaw/
│
├── sentinelclaw/
│   ├── ai/
│   ├── config/
│   ├── detectors/
│   ├── engine/
│   ├── models/
│   ├── reporting/
│   ├── tools/
│   ├── ui/
│   └── utils/
│
├── rules/
├── tests/
├── data/
├── reports/
├── openclaw/
│
├── pyproject.toml
├── requirements.txt
├── sentinelclaw.bat
└── README.md
```

---

## Testing

SentinelClaw includes automated tests for core components including:

- Risk scoring
- Finding processing
- Correlation
- Timeline generation
- YAML rule execution
- CLI behavior

Run:

```bash
pytest -v
```

A release should not be considered validated unless the automated test suite passes.

---

## Security Philosophy

SentinelClaw is intentionally designed around several principles.

**Deterministic detection first**

Security findings should originate from observable data and deterministic rules whenever possible.

**AI is optional**

Failure or absence of the local AI model must not disable core security analysis.

**Evidence before conclusions**

Suspicious behavior is treated as an investigation indicator rather than automatic proof of compromise.

**Local-first operation**

Core analysis is designed to run locally without requiring cloud services.

**Read-only analysis**

SentinelClaw focuses on collection, detection, correlation, investigation, and reporting rather than automatic remediation.

---

## Limitations

SentinelClaw is not a replacement for an enterprise EDR, SIEM, antivirus product, or professional incident-response platform.

Current limitations may include:

- Detection rules can produce false positives.
- Windows Security Event Log access depends on permissions and auditing configuration.
- Network connections may be legitimate even when they match monitored indicators.
- PCAP scan heuristics do not by themselves prove reconnaissance or compromise.
- Some timestamps may originate from different system or event sources.
- Correlation is heuristic and should be reviewed by an analyst.
- Local AI output can contain incorrect interpretations.
- AI-generated conclusions must be validated against deterministic evidence.
- Platform-specific collectors may not be available on every operating system.

---

## Responsible Use

SentinelClaw is intended for:

- Defensive cybersecurity
- Security education
- SOC training
- Authorized system investigation
- Incident analysis
- Security research on systems and data you are permitted to analyze

Do not use SentinelClaw to access, interfere with, or analyze systems without authorization.

---

## Project Status

SentinelClaw is under active development.

Current major capabilities include:

```text
System collection
Process analysis
Network analysis
Windows Event Log analysis
File analysis
YAML detection rules
Finding normalization
Incident correlation
Timeline reconstruction
Local Qwen integration
PCAP analysis
Terminal dashboard
Report generation
Automated testing
OpenClaw integration
```

The project is being prepared for a clean-machine release validation and public repository release.
