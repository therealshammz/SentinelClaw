# SentinelClaw Agent Guide

SentinelClaw is a local, read-only, defensive cybersecurity analysis CLI (Python >= 3.11, Windows/Linux). Core detection is deterministic; AI (Ollama/Qwen) is an optional advisory layer that must never gate or replace the deterministic pipeline. See `CLAUDE.md` for the fuller architecture reference; this file covers what changes how you work day-to-day.

## Setup

- `venv/` exists in the repo root (Python 3.14). Activate it or use `venv/bin/python -m ...` — plain `pytest` may resolve to a system Python without deps installed.
- Install editable: `python -m pip install -e .` — add `[pcap]` for scapy (PCAP analysis) or `[dev]` for pytest.
- `pyproject.toml` is the source of truth for deps; `requirements.txt` is legacy (no platform markers) — edit pyproject, not requirements.txt.
- No linter/typechecker/CI is configured. `pytest` is the only quality gate.
- Windows-only paths (pywin32 / Security Event Log) are guarded and import safely on Linux; tests run fully on Linux.

## Running

CLI entry point: `sentinelclaw` (console script) or `python -m sentinelclaw.main`. Global `--debug` re-raises exceptions with a traceback; without it, errors are pretty-printed and exit 1.

| Command | Purpose |
|---|---|
| `scan` | Full deterministic scan, machine-readable JSON on stdout |
| `dashboard` / `summary` | Scan + human-readable console output (`--verbose` for detail) |
| `system` / `processes` / `network` | Raw collectors with indicators |
| `file <path>` / `logs <path>` / `pcap <path>` | Analyze a single file, log, or capture (`--json`, `--verbose`) |
| `windows-events` | Windows only; needs elevated terminal |
| `report` | Write JSON/text/HTML to report dir (`--format json\|text\|html\|all`, default all) |
| `rules` / `incidents` / `timeline` | Show loaded rules / correlated incidents / timeline |
| `investigate` | Deterministic scan + AI analysis via Ollama; `--model` (default `qwen3:14b`) |

`investigate` talks to a hardcoded `http://127.0.0.1:11434/api/generate` (Ollama). Failure of Ollama/AI must be treated as an operational limitation, never a security finding.

## Paths and rules (gotchas)

- Runtime rules dir is **`sentinelclaw/rules/`** (in-package, per `config/paths.py`), **not** the repo-root `rules/`.
- `rules/` and `sentinelclaw/rules/` are both tracked and currently identical — a drift hazard. When adding/editing YAML rules, update both (pyproject ships the in-package copy as package-data).
- Rule YAML categories are only `process`, `file`, `windows_event` (see `process_rules.yaml` for structure: `id`/`severity`/`conditions` with `field`+`operator`+`value`). Network/PCAP/log detections are Python code in `detectors/`, not YAML.
- Default report/data dirs are **CWD-relative** (`./reports`, `./data`) — not repo-fixed. Running from elsewhere writes elsewhere. Env overrides: `SENTINELCLAW_RULES_DIR`, `SENTINELCLAW_REPORT_DIR`, `SENTINELCLAW_DATA_DIR`. `reports/` is gitignored.

## Testing

- `pytest` from repo root (config in pyproject: `testpaths = ["tests"]`). 29 tests, fast, no services/fixtures needed.
- Single test: `pytest tests/test_cli.py::test_rules_command_exits_successfully`.
- CLI tests spawn `python -m sentinelclaw.main` as a subprocess — they exercise the module entry path, not the installed script.
- PCAP fixture is committed at `data/pcaps/sentinelclaw_test.pcap`. `tests/create_test_pcap.py` (scapy-only helper, not part of the suite) regenerates it but uses a Windows-style backslash path literal — do not run it on Linux expecting it to overwrite the fixture.

## Upgrade tracking

Planned upgrade work is tracked in `UPGRADE_TRACKER.md` (per-item status, changelog, problem log — the source of truth while the upgrade program runs); `UPGRADE_PLAN.md` holds the rationale and landscape research. Update tracker statuses/logs when working on any planned item.

## Pipeline map

`tools/` (collectors: process, network, file/log/pcap analyzers, system info) → `detectors/` (raw signals) → `engine/rule_engine.py` (YAML rules) + `engine/finding_processor.py` (normalize/dedupe/sort) → `engine/correlation_engine.py` (incidents) → `engine/timeline_engine.py` → risk scoring in `models/findings.py` (0–100) → `reporting/report_generator.py` + `ui/console.py`. Optional AI: `ai/qwen_analyzer.py`.
