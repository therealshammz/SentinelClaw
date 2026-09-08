# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

SentinelClaw is installed as an editable package. After cloning the repository:

```bash
# Install in development mode
python -m pip install -e .

# For PCAP support
python -m pip install -e ".[pcap]"

# For development dependencies (including pytest)
python -m pip install -e ".[dev]"
```

### Common Commands

- **Run complete scan (JSON output)**: `sentinelclaw scan`
- **Run scan with dashboard**: `sentinelclaw dashboard` or `sentinelclaw summary`
- **Run scan with AI investigation**: `sentinelclaw investigate` (requires Ollama with Qwen model)
- **Generate reports**: `sentinelclaw report` (generates JSON, text, and HTML formats)
- **Show system information**: `sentinelclaw system`
- **Show running processes**: `sentinelclaw processes`
- **Show network connections**: `sentinelclaw network`
- **Show Windows Security Events**: `sentinelclaw windows-events` (Windows only, requires admin privileges)
- **Analyze a file**: `sentinelclaw file <path>`
- **Analyze a PCAP file**: `sentinelclaw pcap <path>` (requires PCAP extra)
- **Analyze a log file**: `sentinelclaw logs <path>`
- **Show detection rules**: `sentinelclaw rules`
- **Show correlated incidents**: `sentinelclaw incidents`
- **Show investigation timeline**: `sentinelclaw timeline`

### Development Commands

- **Run test suite**: `pytest`
- **Run tests with verbose output**: `pytest -v`
- **Run a specific test**: `pytest tests/test_cli.py::test_function_name`

## Architecture

SentinelClaw follows a modular, layered architecture designed for defensive cybersecurity analysis:

### Core Layers (Deterministic Engine)

1. **Collectors / Tools** (`sentinelclaw/tools/`)
   - Collect raw system data: processes, network connections, Windows events, system info
   - Analyze files, logs, and PCAP captures
   - Platform-specific collectors (Windows Event Log requires admin)

2. **Detectors** (`sentinelclaw/detectors/`)
   - Apply built-in detection logic to collected data
   - Process detector: analyzes running processes for suspicious indicators
   - Network detector: examines network connections for monitored ports
   - Windows event detector: analyzes Security Event Log entries (Windows only)
   - File detector: examines file properties (entropy, signatures, etc.)
   - PCAP detector: analyzes network capture files for scan indicators

3. **Rule Engine** (`sentinelclaw/engine/rule_engine.py`)
   - Loads and executes YAML-based detection rules from `rules/` directory
   - Supports process, file, and Windows event rule categories
   - Rules define conditions using field operators (equals, contains, etc.)

4. **Finding Processor** (`sentinelclaw/engine/finding_processor.py`)
   - Normalizes and deduplicates raw detections
   - Handles severity/confidence normalization
   - Merges duplicate findings and applies deterministic ordering

5. **Correlation Engine** (`sentinelclaw/engine/correlation_engine.py`)
   - Groups related findings into higher-level incidents
   - Correlates by process, network activity, MITRE ATT&CK techniques, etc.

6. **Timeline Engine** (`sentinelclaw/engine/timeline_engine.py`)
   - Builds chronological investigation timeline from findings and incidents
   - Uses available timestamps to reconstruct event sequences

7. **Risk Engine** (`sentinelclaw/models/findings.py`)
   - Calculates risk scores based on finding severities and incident impacts
   - Uses deterministic severity-based scoring (0-100 scale)
   - Risk levels: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL

8. **Reporter** (`sentinelclaw/reporting/report_generator.py`)
   - Generates JSON, text, and HTML reports
   - Includes executive summary, statistics, findings, incidents, timeline
   - Provides investigation recommendations and methodology

### Optional AI Layer

- **Qwen Analyzer** (`sentinelclaw/ai/qwen_analyzer.py`)
  - Integrates with locally running Ollama instance
  - Provides analyst-oriented explanations of deterministic scan results
  - Does not replace detection engine; AI output is advisory only
  - Requires separate Ollama installation and Qwen model download

### Project Structure

```
SentinelClaw/
├── sentinelclaw/                 # Main Python package
│   ├── __init__.py
│   ├── main.py                   # CLI entry point
│   ├── ai/                       # Optional AI analysis (Ollama/Qwen)
│   ├── config/                   # Configuration and path management
│   ├── detectors/                # Detection logic for each data type
│   ├── engine/                   # Core processing engines (correlation, timeline, etc.)
│   ├── models/                   # Data models and risk scoring
│   ├── reporting/                # Report generation
│   ├── tools/                    # Data collection and analysis utilities
│   └── ui/                       # Console output formatting
├── rules/                        # YAML detection rules
├── tests/                        # Automated test suite
├── data/                         # Sample data (PCAP files, etc.)
├── reports/                      # Generated reports directory
├── openclaw/                     # OpenClaw skill definition
├── pyproject.toml                # Project configuration and dependencies
├── requirements.txt              # Legacy requirements file
├── sentinelclaw.bat              # Windows launcher script
├── README.md                     # Project documentation
└── LICENSE                       # MIT license
```

### Key Design Principles

- **Deterministic detection first**: Core security analysis does not depend on AI
- **AI is optional**: Local AI model failure does not disable core functionality
- **Evidence before conclusions**: Suspicious behavior treated as investigation indicators
- **Local-first operation**: Designed to run locally without cloud dependencies
- **Read-only analysis**: Focuses on collection, detection, correlation, investigation, reporting (no automatic remediation)

## Development Practices

- Tests are located in the `tests/` directory and follow the naming convention `test_*.py`
- The project uses pytest for testing with configuration in `pyproject.toml`
- Detection rules are YAML files in the `rules/` directory
- The package is installed in development mode using `pip install -e .`
- Platform-specific dependencies are handled via environment markers in `pyproject.toml`