# SentinelClaw Upgrade Tracker

Living work-tracking document for the SentinelClaw upgrade program.
Full rationale/landscape research: `UPGRADE_PLAN.md`. The plan below is the authoritative copy used for execution tracking.

**Last updated:** 2026-09-09

## How to use this file (update protocol)

- **Starting an item:** set status `IN PROGRESS` (one at a time per phase where possible).
- **Finishing an item:** mark `DONE` only when the acceptance criteria pass — tests run, scan verified. Add a dated entry to §5 Changelog.
- **Blocked item:** status `BLOCKED` + reason in §6 Problem log.
- **New problem/decision discovered mid-work:** append to §6 immediately with date + item id.
- Keep this file in sync with every code change related to the upgrade program; it is the coordinator's source of truth, not `UPGRADE_PLAN.md`.

## Status legend

`PENDING` — not started · `IN PROGRESS` — being worked · `DONE` — verified complete · `BLOCKED` — waiting on something · `CANCELLED` — no longer wanted

---

## 1. Progress summary

| Phase | Items | PENDING | IN PROGRESS | DONE | BLOCKED |
|---|---|---|---|---|---|
| 0 — Engineering foundations | 6 | 6 | 0 | 0 | 0 |
| 1 — Core correctness & Linux parity | 7 | 7 | 0 | 0 | 0 |
| 2 — Detection content & standard adjacency | 3 | 3 | 0 | 0 | 0 |
| 3 — Stateful hunting & analyst UX | 4 | 4 | 0 | 0 | 0 |
| 4 — Deeper detection & intelligence | 5 | 5 | 0 | 0 | 0 |
| 5 — AI advisory hardening | 3 | 3 | 0 | 0 | 0 |
| 6 — Distribution & ecosystem | 3 | 3 | 0 | 0 | 0 |
| **Total** | **31** | **31** | **0** | **0** | **0** |

Research groundwork (complete): codebase audit · landscape research · `UPGRADE_PLAN.md` proposal.

---

## 2. Phase 0 — Engineering foundations

Priority: P0 (quality gates first; unblocks everything). Goal: constants single-sourced, config file, logging, CI, dead code gone, test scaffold.

### P0-1 · Single source of truth for constants
- **Status:** PENDING · **Effort:** S
- **Goal:** One `constants.py`: severity ranks/scores, risk levels, monitored ports, thresholds. Delete duplicated severity tables (currently ×5: correlation_engine, finding_processor, timeline_engine, console, report_generator) and risk-level blocks (×3: findings.py, main.py ×2).
- **Acceptance:** grep proves single definition per constant; 29 existing tests still pass; behavior unchanged.

### P0-2 · Config file + settings
- **Status:** PENDING · **Effort:** M
- **Goal:** Implement `config/settings.py`: optional TOML config (rules dir, report/data dirs, thresholds, Ollama URL/model/timeout) layered over `SENTINELCLAW_*` env vars and defaults. First consumers: entropy 7.2 (file_detector.py:157), port-scan 20/100 (pcap_detector.py:28,33,94), flow 5000 (:232), failed-logon 5 (log_detector.py:43), max-events caps (main.py:249,917).
- **Acceptance:** settings loadable from file/env/default; detectors read thresholds from settings; tests with tmp config file.

### P0-3 · Logging
- **Status:** PENDING · **Effort:** S
- **Goal:** stdlib `logging` in collectors/detectors/engines (debug/warning to stderr); keep user-facing output on stdout via print/console.py. Currently zero `logging` usage anywhere.
- **Acceptance:** `--debug`-equivalent trace obtainable via log level; no behavior change in stdout output.

### P0-4 · CI + lint + typecheck
- **Status:** PENDING · **Effort:** S
- **Goal:** GitHub Actions: pytest on Ubuntu + Windows (exercises pywin32 guard), `ruff` (lint+format), `mypy` on `sentinelclaw/`, coverage report. No CI exists today.
- **Acceptance:** green pipeline on both OSes; lint/typecheck failures block merge.

### P0-5 · Dead code / entry cleanup
- **Status:** PENDING · **Effort:** S
- **Goal:** Wire up or delete unused `models.Finding` dataclass; fill or delete empty `utils/helpers.py` and `config/settings.py` (becomes P0-2); add `__main__.py` so `python -m sentinelclaw` works (tests currently use `python -m sentinelclaw.main`); sync or remove legacy `requirements.txt` (missing pywin32 platform marker).
- **Acceptance:** `python -m sentinelclaw --help` exits 0; no dead-code findings from ruff/coverage scan.

### P0-6 · Test scaffold
- **Status:** PENDING · **Effort:** M
- **Goal:** Coverage gate (>70% `sentinelclaw/`); `tests/conftest.py` with canned collector fixtures (deterministic process/network/windows-event dicts) so detectors are testable without a live host.
- **Acceptance:** coverage report ≥70% or per-module exception list; fixture-based unit tests land with Phase 1 detectors.

---

## 3. Phase 1 — Make the deterministic core correct and cross-platform

Priority: P1 (correctness first; Linux parity is the biggest capability gap).

### P1-7 · Fix correlation of YAML-rule findings ⚠ highest bug-fix value
- **Status:** PENDING · **Effort:** S
- **Problem:** `rule_engine.create_finding` (rule_engine.py:282–307) only copies severity/rule_id/title/description/category/evidence (+mitre/confidence). Correlation reads only top-level `pid`/`process_name`/`remote_ip` → all 13 YAML-rule findings can never join INC-PROC/INC-NET incidents.
- **Changes:** promote `pid`, `process_name`, `remote_ip`, `timestamp` to top level in `create_finding` (rule-evidence mapping: e.g., `condition.field == "pid"` → top-level). Respect `evidence` fallback in correlation/timeline (correlation_engine.py:226,319).
- **Acceptance:** test proving a YAML process rule finding + network finding on same pid → correlated incident.

### P1-8 · Time-window correlation
- **Status:** PENDING · **Effort:** M
- **Goal:** `correlation_engine` groups only findings inside a configurable window (default 24h); incidents get `first_seen`/`last_seen`. Today correlation ignores timestamps entirely.
- **Acceptance:** findings outside window don't correlate; incident carries window bounds.

### P1-9 · Rule engine v2
- **Status:** PENDING · **Effort:** M
- **Goal:** Add `not_equals`, `less_or_equal`, `matches` (regex), `not_contains`. Unknown operator ⇒ load-time validation error, not silent `False` (rule_engine.py:245). Validate rules at load (required fields, severities, categories, condition schema). **Per-rule isolation:** one malformed YAML ⇒ warning + skip, scan continues (today it aborts everything — main.py:1385).
- **Acceptance:** malformed-rule fixture logs warning, scan completes; new operators unit-tested; existing 13 rules still valid.

### P1-10 · Linux parity ⚠ biggest capability gap
- **Status:** PENDING · **Effort:** L
- **Goal:** Real Linux signal: (a) auth log detector (sshd failed/passwordless/root logins, sudo failures, journald `_COMM` filters); (b) persistence checks (cron jobs, systemd unit files, rc*, at); (c) Linux LOLBin detection (bash/sh/python/perl/curl/wget/nc with suspicious parents/args) replacing `.exe`/backslash assumptions with OS-agnostic path handling; (d) listening sockets + non-standard ports; (e) deleted-binary (`/proc/<pid>/exe` readlink) check. Add Linux rules to both `sentinelclaw/rules/` and `rules/`; gate rules by OS/category so Windows rules don't fire noise on Linux.
- **Acceptance:** on Linux, a simulated malicious process (e.g., curl|bash from temp) yields medium+ findings; Windows rules don't fire on Linux fixtures.

### P1-11 · Wire `logs <path>` into the finding pipeline
- **Status:** PENDING · **Effort:** M
- **Problem:** log_analyzer keyword grep (11 keywords) produces raw matches only — no findings, no severity, no rules, no correlation.
- **Changes:** log_analyzer output → structured events → detectors/rules → findings (auth-failure thresholds, keyword classes); participate in incidents/risk/reports.
- **Acceptance:** `sentinelclaw logs <fixture>` emits findings; end-to-end test.

### P1-12 · Streaming memory guards
- **Status:** PENDING · **Effort:** S
- **Problems:** entropy loads whole file (file_analyzer.py:21–39, OOM on large files); JSON report embeds all raw collectors (multi-MB); pcap iteration unbounded.
- **Changes:** chunked entropy; skip/size-cap flagged large files (config); report summarization — raw data only via dedicated dump/`--json-raw`.
- **Acceptance:** analyzing a >1GB sparse file peaks well under file size; report JSON bounded.

### P1-13 · End-to-end pipeline tests
- **Status:** PENDING · **Effort:** M
- **Goal:** Canned-data scan tests asserting: known finding set, dedupe, correlation incl. YAML findings, timeline order, risk score, JSON schema stability.
- **Acceptance:** one `run_scan`-level test over fixtures; covers items 7–9 regressions.

---

## 4. Phase 2 — Detection content & standard adjacency

Priority: P1/P2. Requires P1-9 first.

### P2-14 · Sigma-rule import layer (read-only compatibility)
- **Status:** PENDING · **Effort:** L
- **Goal:** Sigma-subset reader: selection/filter/condition with `and/or/not`; modifiers `|contains|all|any`, `|re`, `|startswith|endswith`, `|cidr`, `|fieldref`; logsource→category mapping — evaluated by rule_engine over the same evidence. Optional `pysigma` extra OR hand-rolled subset (keep deps minimal). New `rules import` command pulls a pinned SigmaHQ release (user-invoked). 3000+ rules content multiplier.
- **Out of scope (document):** Sigma v2 correlation rules, placeholders.
- **Acceptance:** sample SigmaHQ Windows/Linux rules (process_create, logon_failure) fire on fixtures; docs list supported subset.

### P2-15 · Rule quality fields
- **Status:** PENDING · **Effort:** S
- **Goal:** Hayabusa-style metadata: `status` (proven/experimental), `noisy` flag, `falsepositives` guidance, per-rule level tuning override, enabled-by-default toggle for noisy rules; `rules list` shows counts by status/category.
- **Acceptance:** metadata optional (old rules load fine); `rules` command output shows fields when present.

### P2-16 · Rules sync hygiene
- **Status:** PENDING · **Effort:** S
- **Problem:** `rules/` and `sentinelclaw/rules/` both tracked, identical today, runtime uses in-package copy — drift hazard (see AGENTS.md).
- **Changes:** script or CI check asserting equality; run in P0-4 CI.
- **Acceptance:** CI fails on drift; one-command sync helper.

---

## 5. Phase 3 — Stateful hunting & analyst UX

Priority: P2. Requires stable JSON schema (P1-13).

### P3-17 · Scan state store
- **Status:** PENDING · **Effort:** M
- **Goal:** JSONL/NDJSON scan records in data dir (finally uses `get_data_directory()`, today unused): timestamp, hostname, findings, incidents, risk. New commands: `history`, `diff` (new/closed findings vs baseline), `watch` (interval loop printing deltas, Ctrl-C clean); `scan --since`/`last`.
- **Acceptance:** two scans produce two records; `diff` shows delta correctly.

### P3-18 · Machine-friendly exports
- **Status:** PENDING · **Effort:** S
- **Goal:** `scan --format jsonl`; `report --format csv|jsonl`; stable JSON schema `version` field; findings/incidents top-level, not buried in raw collector dumps.
- **Acceptance:** schema version present; exports importable by jq/pandas.

### P3-19 · Hunt aids
- **Status:** PENDING · **Effort:** M
- **Goal:** `search <keyword>` over state; account/logon summary from windows events; process tree view for incident members (ppid chains); event-ID metrics-style stats.
- **Acceptance:** each command tested against canned state store.

### P3-20 · Report improvements
- **Status:** PENDING · **Effort:** M
- **Goal:** capped/paginated text report; HTML incident drill-down; rule provenance (status, source file) and MITRE coverage summary in reports.
- **Acceptance:** large-fixture report renders under cap; provenance fields present.

---

## 6. Phase 4 — Deeper detection & intelligence

Priority: P2. Independent of Phase 3; parallelizable.

### P4-21 · PCAP v2
- **Status:** PENDING · **Effort:** M
- **Goal:** per-flow timestamps on findings (PCAP findings today are untimestamped → sink to timeline bottom); DNS query capture (suspicious TLDs); TLS SNI extraction when layer present; RITA-style beaconing (flow regularity); packet/flow caps with progress; use collected-but-unused `tcp_flags`.
- **Acceptance:** fixture pcap yields timestamped findings; beaconing detector unit-tested.

### P4-22 · Windows events v2
- **Status:** PENDING · **Effort:** L
- **Goal:** offline `.evtx` analysis (python-evtx extra or Windows); System/PowerShell/App channels; formatted messages + parsed fields (TargetUserName, IpAddress, NewProcessId from 4688/4625/4720); event-ID expansion; PowerShell 4104 script-block logging when available.
- **Acceptance:** .evtx fixture (Windows-generated or committed sample) analyzed offline; 4625 finding carries target account/IP.

### P4-23 · File scanning v2
- **Status:** PENDING · **Effort:** M
- **Goal:** optional YARA (`yara-python` extra + rules dir) for `file`/scan; PE details via `pefile` extra on Windows; allow `file` on directories with caps.
- **Acceptance:** yara rule fixture fires; missing yara-python degrades gracefully (operational note, not finding).

### P4-24 · Risk model v2
- **Status:** PENDING · **Effort:** M
- **Goal:** documented weighted model: severity × confidence + count saturation + category modifiers; one shared implementation for findings/incidents (today inconsistent weights merged via `max()`); per-finding risk breakdown in JSON; thresholds in config.
- **Acceptance:** risk math documented + unit tests incl. saturation; old scores differ only where documented.

### P4-25 · Offline threat intel (optional, user-invoked)
- **Status:** PENDING · **Effort:** M
- **Goal:** STIX/OpenIOC bundle loader (hashes/IPs/domains) checked against collected process/file/network data. Local file/feed only — no phoning home.
- **Acceptance:** intel bundle fixture triggers finding on matching hash/IP.

---

## 7. Phase 5 — AI advisory hardening

Priority: P2/P3. Keeps the "failure = operational limitation" contract (AGENTS.md/CLAUDE.md invariant).

### P5-26 · Configurable + resilient Ollama client
- **Status:** PENDING · **Effort:** S
- **Problems:** `OLLAMA_URL` hardcoded 127.0.0.1:11434 (qwen_analyzer.py:9), model default hardcoded (:10), timeout 900s (:265 area), no retries, unbounded `response.read()`.
- **Changes:** config/env overrides (`SENTINELCLAW_OLLAMA_URL` etc.); connect+read timeout with progress; 1 retry w/ backoff; cap response bytes.
- **Acceptance:** unreachable server fails fast (<30s) with graceful "[AI UNAVAILABLE]"; URL from env honored.

### P5-27 · Prompt-injection defenses ⚠
- **Status:** PENDING · **Effort:** M
- **Problem:** hostile evidence (filenames, command lines, log lines) sent to model raw — prompt injection surface in a security tool.
- **Changes:** delimit + escape all untrusted evidence strings; neutralize instruction-like tokens; request strict JSON output (or `format: json`) and validate fields (never eval); fixtures with hostile evidence ("ignore previous instructions…") asserting no injection.
- **Acceptance:** injection fixture tests pass; evidence visibly delimited in payload.

### P5-28 · Budgeted context
- **Status:** PENDING · **Effort:** S
- **Goal:** total token budget (config); per-item evidence truncation with explicit markers; never send credential-like strings (filter `password=`-style args / secrets in command lines).
- **Acceptance:** oversized scan reaches budget cap, truncation markers present, no credential-shaped strings in payload.

---

## 8. Phase 6 — Distribution & ecosystem

Priority: P3. Only after stability.

### P6-29 · Packaging
- **Status:** PENDING · **Effort:** M
- **Goal:** PyInstaller/briefcase binaries per OS (Windows first — `sentinelclaw.bat` currently looks for `.venv` while docs say `venv`), signed releases, version bump automation.
- **Acceptance:** built binary runs `scan`/`report` on target OS.

### P6-30 · Plugin API / command extraction
- **Status:** PENDING · **Effort:** L
- **Problem:** main.py is 1415 lines — all dispatch + scan orchestration inline.
- **Changes:** extract `commands/` dispatch; detector/collector registration points for community modules.
- **Acceptance:** `main.py` < ~400 lines; sample external detector loads via entry point.

### P6-31 · Docs & i18n
- **Status:** PENDING · **Effort:** S
- **Goal:** update CLAUDE.md/README with new commands; command reference; optional i18n pass on `ui/console.py` strings (994 lines, all English).
- **Acceptance:** README/CLAUDE.md match `--help` inventory.

---

## 9. Execution order (dependencies)

```
Phase 0 (foundations)        → fast, unblocks everything
   └─ Phase 1 (correctness + Linux)  → before content growth
         └─ Phase 2 (Sigma import)   → needs P1-9 rule engine v2
              └─ Phase 3 (state/UX)  → needs P1-13 schema stability
                   └─ Phase 4 (deep detection)  ┐
                        └─ Phase 5 (AI hardening)┴→ independent, parallelizable
                              └─ Phase 6 (distribution) → last
```

**Starter batch (approved items, dispatch-ready):** P0-1 · P0-4 · P1-7

---

## 10. Changelog (completed work)

| Date | Item | What was done | Verified by |
|---|---|---|---|
| 2026-09-09 | (research) | Full codebase audit; landscape research (Hayabusa/osquery/Sigma/Wazuh); `UPGRADE_PLAN.md` proposal written | codebase review agent + web research |
| | | | |

## 11. Problem log (problems & decisions found along the way)

| Date | Item | Problem / decision | Impact | Resolution / status |
|---|---|---|---|---|
| 2026-09-09 | pre-existing | `rules/` ↔ `sentinelclaw/rules/` duplicated and tracked; runtime uses in-package copy only | drift hazard when editing rules | → P2-16 (CI equality check) |
| 2026-09-09 | pre-existing | `requirements.txt` lacks pywin32 platform marker pyproject has | Linux installs may try pywin32 | → P0-5 |
| 2026-09-09 | pre-existing | `ISSUES.md` / `SENTINELCLAW_VALIDATION_REPORT.md` describe the win32evtlog import bug — already fixed in git history (commit fcdffec) | stale docs mislead | update or archive docs |
| 2026-09-09 | pre-existing | `config/settings.py` 0 bytes; `utils/helpers.py` 0 lines; `models.Finding` unused; `get_data_directory()` unused | dead code / no config | → P0-2, P0-5 |
| 2026-09-09 | pre-existing | No CI, no lint/typecheck config; `pytest` sole gate | regressions slip through | → P0-4 |
| 2026-09-09 | pre-existing | YAML-rule findings can never correlate (top-level pid missing) | INC-PROC/INC-NET dead for all YAML rules | → P1-7 |
| 2026-09-09 | pre-existing | correlation ignores timestamps; timeline pushes untimestamped events to end silently | false grouping / misleading timeline | → P1-8 |
| 2026-09-09 | pre-existing | malformed YAML rule aborts whole scan | single bad rule = DoS of scanner | → P1-9 |
| 2026-09-09 | pre-existing | Windows-centric heuristics run unconditionally → near-zero Linux signal | Linux scans ~always informational | → P1-10 |
| 2026-09-09 | pre-existing | `log_analyzer` orphaned from pipeline; entropy reads whole file; pcap/AI iteration unbounded | OOM / orphaned feature | → P1-11, P1-12, P5-26/28 |
| | | | | |
