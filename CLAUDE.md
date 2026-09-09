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

- **Run complete scan (JSON output)**: `sentinelclaw scan` (`--format json|jsonl`, `--json-raw`, `--since <ISO>`, `--last`)
- **Run scan with dashboard**: `sentinelclaw dashboard` or `sentinelclaw summary` (both `--verbose`)
- **Loop scans / watch for deltas**: `sentinelclaw watch` (`--interval N`, `--count N`)
- **Run scan with AI investigation**: `sentinelclaw investigate` (`--model <name>`; requires Ollama with Qwen model)
- **Generate reports**: `sentinelclaw report` (`--format json|text|html|csv|jsonl|all`, default `all` = json+text+html; `--json-raw`)
- **Show system information**: `sentinelclaw system`
- **Show running processes**: `sentinelclaw processes`
- **Show network connections**: `sentinelclaw network`
- **Show Windows Security Events**: `sentinelclaw windows-events` (Windows only, requires admin privileges)
- **Analyze an offline EVTX file**: `sentinelclaw evtx <path>` (`--json`, `--verbose`; requires `evtx` extra)
- **Analyze a file or directory**: `sentinelclaw file <path>` (`--json`, `--verbose`)
- **Analyze a PCAP file**: `sentinelclaw pcap <path>` (`--json`, `--verbose`; requires `pcap` extra)
- **Analyze a log file**: `sentinelclaw logs <path>` (`--json`, `--verbose`)
- **Show detection rules**: `sentinelclaw rules`
- **Import SigmaHQ rules**: `sentinelclaw rules import` (`--source`, `--release`, `--dest`)
- **Show correlated incidents**: `sentinelclaw incidents` (`--verbose`)
- **Show investigation timeline**: `sentinelclaw timeline`
- **Scan-state hunting**: `sentinelclaw history`, `diff` (`[id1 id2]` or `--last`), `search <keyword>` (`--state <id>`), `accounts`, `tree <incident_id>`, `stats`
- **Plugin demo**: `sentinelclaw sample-plugin`
- **Global flag**: `--debug` (show Python tracebacks)

### Development Commands

- **Run test suite**: `pytest`
- **Run tests with verbose output**: `pytest -v`
- **Run a specific test**: `pytest tests/test_cli.py::test_function_name`
- **Lint**: `ruff check .`
- **Type check**: `mypy sentinelclaw`
- **Rules sync check**: `python scripts/sync_rules.py --check`
- **Bump version**: `python scripts/bump_version.py --patch|--minor|--major [target]`
- **Build standalone binary**: `scripts/build_binary.sh` (Linux/macOS) or `.\scripts\build_binary.ps1` (Windows); requires the `[build]` extra

## Architecture

SentinelClaw follows a modular, layered architecture designed for defensive cybersecurity analysis:

### Core Layers (Deterministic Engine)

0. **Command Layer** (`sentinelclaw/commands/`)
   - Thin CLI command modules registered in `sentinelclaw/commands/__init__.py` (source of truth for the command inventory); `main.py` only builds the parser and dispatches
   - `_scan_core.py` hosts the scan pipeline shared by `scan`/`dashboard`/`summary`/`incidents`/`timeline`/`report`

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

### Scan-State Store & Hunting

- **State store** (`sentinelclaw/state/store.py`)
  - Appends one bounded record per `scan`/`watch` cycle to `scans.jsonl`
    under the resolved data directory (default `./data`)
  - Backs the hunting commands (`history`, `diff`, `search`, `accounts`,
    `tree`, `stats`)

### Sigma & Plugins

- **Sigma importer** (`sentinelclaw/sigma/`) converts SigmaHQ rules into
  the internal format (`rules import`); writes a `sigma/` tree into the
  rule directories
- **Plugin API** (`sentinelclaw/plugins/`) discovers third-party
  subcommands via the `sentinelclaw.detectors` entry-point group;
  `sample-plugin` is the built-in demo

### Project Structure

```
SentinelClaw/
├── sentinelclaw/                 # Main Python package
│   ├── __init__.py
│   ├── main.py                   # CLI entry point (thin; parser + dispatch)
│   ├── __main__.py               # `python -m sentinelclaw` entry
│   ├── ai/                       # Optional AI analysis (Ollama/Qwen)
│   ├── commands/                 # CLI command modules (command inventory source of truth)
│   ├── config/                   # Configuration and path management
│   ├── detectors/                # Detection logic for each data type
│   ├── engine/                   # Core processing engines (correlation, timeline, etc.)
│   ├── models/                   # Data models and risk scoring
│   ├── plugins/                  # Entry-point plugin discovery + sample plugin
│   ├── reporting/                # Report generation
│   ├── rules/                    # Packaged rule trees (yaml, sigma, yara)
│   ├── sigma/                    # SigmaHQ importer/reader
│   ├── state/                    # Scan-state store + hunting commands
│   ├── tools/                    # Data collection and analysis utilities
│   └── ui/                       # Console output formatting
├── rules/                        # Detection-rule source of truth (synced to package)
├── packaging/                    # PyInstaller spec + packaging docs
├── scripts/                      # sync_rules, bump_version, build_binary
├── tests/                        # Automated test suite
├── data/                         # Scan-state store and sample data
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
- The `[build]` extra installs PyInstaller for `packaging/sentinelclaw.spec` builds; see `packaging/README.md`
- Rules in `rules/` are the source of truth; `scripts/sync_rules.py` mirrors them into `sentinelclaw/rules/`
- Versions live only in `pyproject.toml`; use `scripts/bump_version.py` to change them
- i18n is deferred: all UI strings in `sentinelclaw/ui/console.py` are English-only