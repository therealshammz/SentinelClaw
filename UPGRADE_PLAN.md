# SentinelClaw — Upgrade & Improvement Plan

Status: **COMPLETE — fully implemented 2026-09-09** (all 31 items, phases 0–6, on branch `feat/upgrade-phase1`, PR #4). This document is the historical rationale and landscape research; the authoritative record of what was done is `UPGRADE_TRACKER.md`. Generated 2026-09-09 from a full codebase review + landscape comparison against Hayabusa (Yamato Security), osquery, SigmaHQ/pySigma, Wazuh, and Velociraptor.

**North star:** make SentinelClaw *the* credible local-first deterministic scanner it already claims to be: (1) detection output that is internally consistent and correct, (2) cross-platform signal parity (Linux is currently ~zero-signal), (3) an open, standard-adjacent rule format with a real rule library, (4) stateful hunt workflows (baseline, delta, timeline), and (5) a hardened, honest AI advisory layer.

**Hard constraints that must survive every change** (existing design contract):
- Read-only, defensive, local-first. No remediation, no network calls except optional user-invoked intel/AI.
- Deterministic pipeline is the source of truth; AI (Ollama/Qwen) advisory only, must never gate the scan.
- AI/collector/permission failures are operational limitations, never security findings.
- Windows/Linux support; pywin32 guarded; tests must run fully on Linux.
- `pytest` remains the only quality gate until CI is added (Phase 0).

---

## 1. Verified current state (baseline)

**Strengths to keep and build on**
- Clean layered architecture: `tools/` → `detectors/` → `rule_engine` + `finding_processor` → `correlation_engine` → `timeline_engine` → risk → `reporting/` + `ui/`.
- Deterministic, well-normalized finding pipeline with dedupe + deterministic ordering; 29 fast tests; graceful CLI error handling (`--debug`); safe HTML escaping; color gated on TTY/`NO_COLOR`.
- Good process-side heuristics (LOLBins, Office→script, encoded PowerShell) and MITRE tagging on rule findings.
- Honest AI integration: single hardcoded Ollama URL, advisory-only degradation.

**Highest-impact defects (from review; all verified in code)**
1. **YAML-rule findings never correlate** — `rule_engine.create_finding` (rule_engine.py:282–307) doesn't promote `pid`/`process_name`/`remote_ip` to top level; correlation only reads top-level fields → all 13 YAML rules are correlation-dead.
2. **No time windows in correlation** — findings correlate purely by PID/category/tactic, ignoring timestamps.
3. **Rule engine is weak**: no regex / negation / `not_equals` / `less_or_equal`; unknown operators silently return False; **one malformed YAML rule aborts the whole scan** (no rule isolation).
4. **Linux signal ≈ zero** — detectors and bundled rules are Windows-centric (`.exe`, backslash paths, Windows event IDs); Linux scans yield only informational NET-002/PROC-003 findings.
5. **No state persistence** — every command re-collects everything; no baseline/delta/history; `get_data_directory()` unused; `config/settings.py` empty.
6. **Risk scoring is naive additive severity** with duplicated threshold tables (3×), inconsistent finding-vs-incident weights, no confidence/category weighting.
7. **Windows events shallow**: 14 IDs, Security channel only, raw StringInserts (pipe-joined), no offline `.evtx`.
8. **`logs` analysis orphaned** — keyword grep, never becomes findings.
9. **PCAP shallow**: no DNS/TLS/payload/beacon checks; `tcp_flags` collected but unused; no per-packet caps on huge captures; findings carry no timestamps.
10. **AI layer**: 900s blocking timeout, no retries, unbounded response read, no prompt-injection defenses on hostile evidence text, hardcoded URL/model.
11. **OOM risks**: entropy loads whole file; JSON report embeds all raw collectors (multi-MB).
12. **Duplication/dead code**: severity tables ×5, `SUSPICIOUS_PORTS` ×2, unused `models.Finding` dataclass, empty `utils/helpers.py`, duplicated `rules/` vs `sentinelclaw/rules/`.
13. **Test coverage thin**: 29 tests, smoke-level CLI tests; zero coverage on detectors, tools, AI, reporting, UI, scan orchestration.
14. **No logging, no CI, no lint/type config**; no `__main__.py`; stale `requirements.txt` and docs drift.

---

## 2. Landscape: what comparable projects have that we don't

| Capability | osquery | Hayabusa | Sigma/pySigma | Wazuh | SentinelClaw today |
|---|---|---|---|---|---|
| Rule expressiveness (negation, regex, modifiers, condition algebra) | — (SQL) | full Sigma v2 incl. correlation | selection/filter/condition, `contains|all|any`, `|re`, `|cidr`, `|endswith` | — | equals/contains/startswith/endswith/comparisons, no negation, no regex |
| Rule library size + updates | packs | 4000+ Sigma rules, daily sync | 3000+ community rules | ~3000 rules | 13 bundled, no update path |
| Log field normalization | — | yes | pipelines | yes | partial (only normalize helpers) |
| Live + offline log sources | tables (live) | .evtx dirs/live | — | agent + logs | live Security channel only, no evtx |
| Cross-platform parity | Linux/mac/Win | Win/Linux/mac | n/a | Win/Linux/mac | Windows-centric |
| Linux auth/persistence signal | auditd/journald tables | — | linux product rules | logcollector + SCA | ~none |
| Host state DB / querying | SQL tables, osqueryi | — | — | indexer | none (one-shot scans) |
| Baselines / delta / watch mode | scheduled queries (osqueryd) | — | — | real-time agent | none |
| Timeline / CSV / JSONL output for external tools | — | CSV/JSON/JSONL timeline, profiles | — | indexer/dashboards | HTML/JSON/text, no CSV/JSONL, JSON embeds all raw |
| Hunt aids (keyword search, logon summary, process tree, stack analysis) | SQL | search/logon-summary/eid-metrics | — | dashboards | none |
| YARA/file scanning | yara tables | — | — | rootcheck | none |
| FIM / config assessment (CIS) | FIM events | — | — | SCA + FIM | none |
| Threat-intel enrichment (GeoIP/hash/IP feeds) | — | GeoIP enrich | — | intel feeds | none |
| Correlation with time windows / sequences | — | Sigma v2 correlation | correlation rules spec | real-time rule engine | PID grouping only, no time |
| Risk/level tuning | — | level-tuning per rule | level field | rule levels | fixed weights, no tuning |
| Config file | flags + conf | profile/config | — | ossec.conf | env vars only |
| Hardened optional-AI layer | — | — | — | — | advisory but unbounded/unhardened |

Other gaps visible in the ecosystem: packaged release binaries, versioned JSON schema for scan output, i18n, plugin/extensions API, per-rule provenance/status (proven vs noisy, cf. Hayabusa), scan-result diffing, and a `python -m sentinelclaw` entry.

---

## 3. Phased roadmap

Phases are ordered by dependency and value-per-effort. Every item lists: goal, key changes (files/dirs), and acceptance criteria. S/M/L effort estimates assume one focused session each; P0 = correctness, P1 = core value, P2 = differentiation, P3 = polish.

### Phase 0 — Engineering foundations (quality gates first; unblocks everything)
1. **Single source of truth for constants** — one `constants.py` (severity ranks/scores, risk levels, monitored ports, thresholds). Delete the 5 duplicated severity tables and 3 duplicated risk-level blocks. *(S)*
2. **Config file + settings** — implement `config/settings.py`: optional TOML config (rules dir, report/data dirs, thresholds, Ollama URL/model/timeout) layered over env vars (`SENTINELCLAW_*`) and defaults. First consumer: replace hardcoded entropy 7.2, scan 20/100, flow 5000, logon 5, max-events caps. *(M)*
3. **Logging** — add stdlib `logging` to collectors/detectors/engines (debug context, warnings to stderr); keep user-facing output on stdout print/console.py. *(S)*
4. **CI + lint + typecheck** — GitHub Actions: pytest on Ubuntu + Windows (pywin32 path), `ruff` (lint+format), `mypy` on `sentinelclaw/`; coverage report; commit-check on pushes. *(S)*
5. **Dead code / entry cleanup** — delete unused `models.Finding` or wire it up; fill or delete `utils/helpers.py`; add `__main__.py` so `python -m sentinelclaw` works; sync/remove `requirements.txt`. *(S)*
6. **Test scaffold** — coverage gate (>70% on `sentinelclaw/`), `tests/conftest.py` with canned collector fixtures (deterministic process/network/windows-event dicts) so detectors are testable without a live host. *(M)*

### Phase 1 — Make the deterministic core correct and cross-platform
7. **Fix correlation of YAML findings** — promote `pid`, `process_name`, `remote_ip`, `timestamp` to top-level fields in `rule_engine.create_finding` (schema on rule findings: `field: pid` mapping or evidence-promotion rules); add rule-engine tests proving INC-PROC/INC-NET correlation. *(S — highest bug-fix value in the codebase)*
8. **Time-window correlation** — `correlation_engine` accepts a window (default e.g. 24h via config) and only groups findings inside it; incident gets `first_seen`/`last_seen`. *(M)*
9. **Rule engine v2** — add `not_equals`, `less_or_equal`, `matches` (regex), `not_contains`, wildcard-aware `contains`; unknown operator ⇒ rule-load validation error, **not** silent False; validate rules at load (required fields, allowed severities/categories, condition schema) with per-rule isolation: malformed rule ⇒ warning + skip, scan continues. *(M)*
10. **Linux parity (biggest capability gap)** — new collectors/detectors for Linux reality:
    - `auth` log detector (sshd: failed/passwordless/root logins; sudo failures; journald `_COMM` filters)
    - persistence checks: cron jobs, systemd units (`systemctl list-unit-files`), `/etc/rc*`, at
    - process detector: detect Linux LOLBins (bash/sh/python/perl/curl/wget/nc) with suspicious parents/args; replace `.exe`/backslash assumptions with `Path.name`/`Path.parts` so rules are OS-agnostic
    - listening sockets + non-standard ports, `on_disk=0`-style deleted-binary check (psutil exposes exe; `/proc/<pid>/exe` readlink check)
    - ship Linux rules in `sentinelclaw/rules/` (and mirrored `rules/`), gate rule `category`+`os` so Windows rules don't fire noise on Linux and vice versa. *(L)*
11. **Wire `logs <path>` into the finding pipeline** — `log_analyzer` output becomes structured events → detectors/rules → findings with severity (auth-failure thresholds, keyword classes), so `file/logs` analysis participates in incidents/risk/reports. *(M)*
12. **Streaming memory guards** — chunked entropy (stream, don't slurp); skip/size-cap flagged large files (config); cap report embedding (summaries + counts, full raw data only via `--json-raw` or a dedicated dump command). *(S)*
13. **Test the pipeline end-to-end** — canned-data scan tests asserting: known finding set, dedupe, correlation incl. YAML findings, timeline order, risk score, JSON schema stability. *(M)*

### Phase 2 — Detection content & standard adjacency
14. **Sigma-rule import layer (read-only compatibility)** — implement a **Sigma-subset reader** (selection/filter/condition with `and/or/not`, modifiers `|contains|all|any`, `|re`, `|startswith|endswith`, `|cidr`, `|fieldref`; logsource→category mapping) evaluated by `rule_engine` over the same evidence; docs-only support for what's out of scope (correlation rules, placeholders). Keep native YAML format for defaults; add a `rules import` command pulling a pinned SigmaHQ ruleset release (user-invoked, offline-friendly after download). Reuse pySigma parsers if a `pysigma` optional extra is acceptable — otherwise hand-rolled subset keeps deps minimal. This is the single biggest content multiplier (3000+ Windows/Linux rules). *(L)*
15. **Rule quality fields** — adopt Hayabusa-style metadata: `status` (proven/experimental), `noisy` flag, `falsepositives` guidance, per-rule `level` tuning override in config, `enabled-by-default` for noisy rules; `rules list` shows counts by status/category. *(S)*
16. **Rules sync hygiene** — script or CI check asserting `rules/` == `sentinelclaw/rules/` (kills the drift hazard documented in AGENTS.md). *(S)*

### Phase 3 — Stateful hunting & analyst UX
17. **Scan state store** — write each scan to a JSONL/NDJSON record in the data dir (`get_data_directory()` finally used): timestamp, hostname, findings, incidents, risk. Commands `scan --since`/`last` read state; new commands: `history`, `diff` (baseline vs current: new/closed findings), `watch` (interval loop re-running scan + printing deltas; Ctrl-C clean). *(M)*
18. **Machine-friendly exports** — `scan --format jsonl`, `report --format csv|jsonl`; stable JSON schema version field; findings/incidents collections top-level (don't bury in raw collector dumps). *(S)*
19. **Hunt aids** — `search <keyword>` over last scan state (Hayabusa-style), `logon-summary`-ish account summary from windows events, process tree view for incident members (child-of relationships from ppid), `eid-metrics`-style event-count stats. *(M)*
20. **Report improvements** — paginated/capped text report; HTML report gets incident drill-down; include rule provenance (`status`, source file) and MITRE coverage summary. *(M)*

### Phase 4 — Deeper detection & intelligence
21. **PCAP v2** — per-flow timestamps into findings; DNS query capture (suspicious TLDs/rare queries), TLS SNI extraction when scapy layer present, beaconing detection (RITA-style: periodic flow regularity between host pairs), packet/flow caps w/ progress, `--json` output of new indicators. *(M)*
22. **Windows events v2** — optional offline `.evtx` analysis path (Windows or via `python-evtx` extra), System/PowerShell/App channels, formatted message rendering + parsed fields (TargetUserName, IpAddress, NewProcessId from 4688/4625/4720), event-ID expansion table, PowerShell 4104 script-block logging when available. *(L)*
23. **File scanning v2** — optional YARA integration (`yara-python` extra + rules dir) for `file` and scan of suspicious files; PE static details (imports, sections, entropy per-section) on Windows via pefile extra; allow `file` on directories with caps. *(M)*
24. **Risk model v2** — documented weighted model: severity × confidence (+ count saturation on repeated identical findings, category modifiers); single implementation shared by findings/incidents; expose per-finding risk breakdown in JSON so scoring is auditable; ship risk-level thresholds in config. *(M)*
25. **Offline threat-intel (optional, user-invoked)** — STIX/OpenIOC bundle loader (hashes/IPs/domains) + local check against collected process/file/network data; no phoning home — intel is a local file/feed. *(M)*

### Phase 5 — AI advisory hardening
26. **Configurable + resilient client** — URL/model/timeout from config/env (`SENTINELCLAW_OLLAMA_URL`); connect timeout + read timeout with progress output; 1 retry with backoff; cap response bytes; non-200/JSON handling already graceful — keep contract "failure = limitation". *(S)*
27. **Prompt-injection defenses (important for a security tool)** — wrap every untrusted evidence string in delimiters with escaping; strip/neutralize instruction-like tokens in evidence before sending; ask model to return strict JSON (or use `format: json` when available) then parse/validate fields (never `eval`); add test fixtures with hostile evidence ("ignore previous instructions…"). *(M)*
28. **Budgeted context** — enforce total-token budget (config), truncate per-item evidence with explicit markers, and never send raw credential-like strings (filter `password=`-style args) — a real risk for a tool that prints attacker-controlled content. *(S)*

### Phase 6 — Distribution & ecosystem (when the product is stable)
29. **Packaging** — `pyinstaller`/`briefcase` binaries per OS (Windows first, matching `sentinelclaw.bat` intent); signed releases; version bump automation. *(M)*
30. **Plugin API** — detector/collector registration points so community collectors don't fork main.py (main.py is already 1415 lines — extract `commands/` dispatch). *(L)*
31. **Docs & i18n** — architecture doc update, command reference, sample reports; optional i18n pass on `ui/console.py` strings. *(S)*

---

## 4. Recommended sequencing

```
Phase 0 (foundations)        → fast, unblocks everything, pure quality
   └─ Phase 1 (core correctness + Linux)   → must precede content growth
         └─ Phase 2 (Sigma import)         → content multiplier needs v2 engine (item 9)
              └─ Phase 3 (state/UX)        → needs stable schema (item 18) & store (17)
                   └─ Phase 4 (deep detection)   ┐
                        └─ Phase 5 (AI hardening)┴→ independent, parallelizable
                              └─ Phase 6 (distribution) → last, requires stability
```

Parallelizable now: Phase 0 items 1–6 (one session), item 7 (critical bug), items 10/11/22 (collectors) after the findings schema stabilizes.

## 5. First actions (if you say go)

1. Dispatch build: items **7** (correlation fix), **1** (constants), **4** (CI+ruff+mypy) — all independent, high value.
2. Then items **2** (config), **9** (rule engine v2), **13** (E2E tests) before any Sigma work.
3. Keep AGENTS.md/CLAUDE.md updated as invariants change (they already document the rules-dir duplication and venv workflow).
