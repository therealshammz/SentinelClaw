# SentinelClaw Agent Guide

SentinelClaw is a local, read-only, defensive cybersecurity analysis CLI (Python >= 3.11, Windows/Linux). Core detection is deterministic; AI (Ollama/Qwen) is an optional advisory layer that must never gate or replace the deterministic pipeline. See `CLAUDE.md` for the fuller architecture reference; this file covers what changes how you work day-to-day.

## Setup

- `venv/` exists in the repo root (Python 3.14). Activate it or use `venv/bin/python -m ...` — plain `pytest` may resolve to a system Python without deps installed.
- Install editable: `python -m pip install -e .` — extras: `[dev]` (pytest/ruff/mypy/pytest-cov), `[pcap]` (scapy), `[evtx]` (python-evtx), `[yara]` (yara-python), `[build]` (pyinstaller). All optional extras degrade gracefully when missing (operational note, never a finding).
- `pyproject.toml` is the source of truth for deps; `requirements.txt` is legacy (no platform markers) — edit pyproject, not requirements.txt.
- Quality gates (all configured, run in CI): `ruff check .`, `mypy sentinelclaw`, `pytest --cov=sentinelclaw --cov-fail-under=30`. CI: GitHub Actions, Ubuntu + Windows × Python 3.11–3.13, plus a PyInstaller build job.
- Windows-only paths (pywin32 / Security Event Log) are guarded and import safely on Linux; tests run fully on Linux.

## Running

CLI entry point: `sentinelclaw` (console script) or `python -m sentinelclaw`. Global `--debug` re-raises exceptions with a traceback and enables DEBUG logging on stderr; without it, errors are pretty-printed and exit 1.

| Command | Purpose |
|---|---|
| `scan` | Full deterministic scan, JSON on stdout (`--format json\|jsonl`, `--json-raw`, `--since`, `--last`); writes a state record |
| `dashboard` / `summary` | Scan + human-readable console output (`--verbose` for detail) |
| `investigate` | Deterministic scan + AI analysis via Ollama; `--model` (default from config) |
| `report` | Write JSON/text/HTML/CSV/JSONL to report dir (`--format json\|text\|html\|csv\|jsonl\|all`, default all; `--json-raw`) |
| `rules` | Show loaded rules (with status/noisy metadata + counts); `rules import` pulls SigmaHQ rules |
| `history` / `diff` / `watch` | Scan-state store: list records / delta between records / interval loop |
| `search` / `accounts` / `tree` / `stats` | Hunt aids over the state store |
| `system` / `processes` / `network` | Raw collectors with indicators |
| `file <path\|dir>` / `logs <path>` / `pcap <path>` | Analyze a file (or directory, capped), log, or capture (`--json`, `--verbose`) |
| `windows-events` | Windows only; needs elevated terminal |
| `evtx <path>` | Offline `.evtx` analysis (needs `[evtx]` extra) |
| `timeline` / `incidents` | Show timeline / correlated incidents |
| `sample-plugin` | Demonstrates the plugin API (`sentinelclaw.detectors` entry points) |

`investigate` talks to Ollama (default `http://127.0.0.1:11434/api/generate`, configurable). Failure of Ollama/AI must be treated as an operational limitation, never a security finding.

## Configuration

Settings resolve with precedence: built-in defaults → optional TOML file (`SENTINELCLAW_CONFIG`, `./sentinelclaw.toml`, `~/.config/sentinelclaw/config.toml`) → `SENTINELCLAW_*` env vars (env wins). Full field/env table in `sentinelclaw/config/settings.py` docstring. Notable: thresholds (entropy, port-scan, flow, logon failures), event caps, Ollama URL/model/timeout/retries/budget, correlation window, report caps, intel bundle path, YARA rules dir.

## Paths and rules (gotchas)

- Runtime rules dir is **`sentinelclaw/rules/`** (in-package, per `config/paths.py`), **not** the repo-root `rules/`.
- `rules/` and `sentinelclaw/rules/` are both tracked and must stay byte-identical — CI enforces it. When adding/editing YAML rules, update both, or run `python scripts/sync_rules.py --sync` (source of truth: `rules/`). Sigma-converted rules live in `rules/sigma/` + `sentinelclaw/rules/sigma/`; YARA rules live only in `sentinelclaw/rules/yara/` (not twin-synced).
- Rule YAML categories: `process`, `file`, `windows_event`, `network`, `log`, `auth`, `persistence` (see `process_rules.yaml` for structure: `id`/`severity`/`conditions` with `field`+`operator`+`value`; optional `os` gating, `status`/`noisy`/`falsepositives`/`level_override`/`enabled` metadata). Operators: `equals`, `contains`, `not_equals`, `not_contains`, `less_or_equal`, `less_than`, `matches` (regex), `cidr`, `fieldref`, plus nested `any_of`/`all_of`/`negated` nodes (Sigma output). Malformed rules are skipped with a warning — one bad rule never aborts a scan.
- Default report/data dirs are **CWD-relative** (`./reports`, `./data`) — not repo-fixed. Running from elsewhere writes elsewhere. Env overrides: `SENTINELCLAW_RULES_DIR`, `SENTINELCLAW_REPORT_DIR`, `SENTINELCLAW_DATA_DIR`. `reports/` and `data/` are gitignored (except the committed PCAP fixture).

## Testing

- `pytest` from repo root (config in pyproject: `testpaths = ["tests"]`). 434 tests + 1 Windows-only skip, fast (~5s), no services/fixtures needed.
- Single test: `pytest tests/test_cli.py::test_rules_command_exits_successfully`.
- `tests/conftest.py` provides canned collector fixtures (`sample_processes`, `sample_connections`, `sample_windows_events`, `sample_pcap_data`, `rules_dir_tmp`, autouse `env_isolation`) — detectors/engines are testable without a live host. `tests/test_end_to_end.py` runs the full `run_scan` pipeline over fixtures.
- Optional-extra tests (scapy/evtx/yara/pefile) skip cleanly when the extra isn't installed — CI installs only `[dev]` + `[dev,pcap]`.
- CLI tests spawn `python -m sentinelclaw` as a subprocess — they exercise the module entry path, not the installed script.
- PCAP fixture is committed at `data/pcaps/sentinelclaw_test.pcap`. `tests/create_test_pcap.py` (scapy-only helper, not part of the suite) regenerates it but uses a Windows-style backslash path literal — do not run it on Linux expecting it to overwrite the fixture.

## Upgrade tracking

The upgrade program (31 items, phases 0–6) is **COMPLETE** (2026-09-09) — see `UPGRADE_TRACKER.md` for the full changelog and problem log, `UPGRADE_PLAN.md` for the original rationale. Trackers are historical; update them only when making further roadmap changes.

## Pipeline map

`tools/` (collectors: process, network, file/log/pcap/evtx analyzers, auth, persistence, system info, intel loader) → `detectors/` (raw signals) → `engine/rule_engine.py` (YAML + Sigma rules) + `engine/finding_processor.py` (normalize/dedupe/sort) → `engine/correlation_engine.py` (time-windowed incidents) → `engine/timeline_engine.py` → risk scoring in `models/risk.py` (weighted + saturation, 0–100) → `reporting/report_generator.py` + `ui/console.py`. Stateful layer: `state/store.py` (JSONL scan records) + `state/analytics.py` + `state/hunting.py`. Sigma: `sigma/reader.py` + `sigma/importer.py`. Plugins: `plugins/` (entry-point group `sentinelclaw.detectors`). CLI dispatch: `commands/` (registry + per-domain modules; `main.py` is a thin 154-line entry). Optional AI: `ai/qwen_analyzer.py` (hardened: retries, injection defenses, budgeted context).