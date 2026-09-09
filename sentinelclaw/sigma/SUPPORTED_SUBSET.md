# Sigma support in SentinelClaw (P2-14)

SentinelClaw ships a read-only, deterministic **Sigma subset reader**
(`sentinelclaw/sigma/reader.py`). It converts Sigma detection rules into
the internal rule format so the existing rule engine evaluates them over
the same evidence records. Importing rules never runs during scans: the
`sentinelclaw rules import` command is strictly user-invoked, and only
that command may touch the network (stdlib `urllib`, no new
dependencies).

This document lists exactly what the subset supports and what it
explicitly does **not**. Anything not listed here is skipped at
conversion time with a warning; a single unsupported rule never breaks
an import (per-rule isolation, P1-9).

## Getting the rules

```
sentinelclaw rules import                          # download pinned SigmaHQ release
sentinelclaw rules import --release r2026-07-01    # explicit tag
sentinelclaw rules import --source /path/to/sigma  # offline checkout dir
sentinelclaw rules import --source release.zip     # offline release zip
sentinelclaw rules import --dest /custom/rules     # write elsewhere
```

* Default download: `https://github.com/SigmaHQ/sigma/archive/refs/tags/r2026-07-01.zip`
  (pinned quarterly snapshot; override via `--release` or
  `SENTINELCLAW_SIGMA_RELEASE`).
* Converted rules are written to `<rules-dir>/sigma/`, mirroring the
  source layout, and to the repo's twin `rules/sigma/` copy when the
  runtime rules directory is the packaged one — both copies stay
  byte-identical so `scripts/sync_rules.py --check` passes.
* The runtime rule loader is recursive, so `sigma/` rules load like any
  other rule file and appear in `sentinelclaw rules`.
* Re-running an import refreshes (replaces) the previous `sigma/` tree.

## Logsource → internal category

| Sigma logsource | Internal category |
|---|---|
| `category: process_creation` | `process` |
| `category: network_connection` | `network` |
| `category: file_event` / `file_change` | `file` |
| `category: logon_failure` / `logon_success` | `windows_event` |
| `category: auditd` | `log` |
| `category: syslog` + `service: sshd/sudo` | `auth` |
| `category: syslog` (no service) | `log` |
| `service: security` / `sysmon` (no category) | `windows_event` |
| `service: sshd` / `sudo` / `su` (no category) | `auth` |
| `service: auditd` / `syslog` (no category) | `log` |
| anything else / missing | **skipped** (`unsupported-logsource`) |

OS gating: `product: windows` → `os: [windows]`, `product: linux` →
`os: [linux]`, no product → all platforms, any other product (e.g.
`macos`) → **skipped** (`unsupported-product`).

## Field mapping

Sigma field names are translated per category; an unmapped field skips
the rule (`unmapped-field`), it is never silently matched elsewhere:

| Sigma field | Internal field | Categories |
|---|---|---|
| `Image` | `executable` | process |
| `CommandLine` | `command_line` | process |
| `ParentImage` | `parent_name` | process |
| `ProcessId` / `ParentProcessId` | `pid` / `ppid` | process |
| `User` | `username` | process |
| `EventID` | `event_id` | windows_event |
| `Channel` | `source` | windows_event |
| `Computer` | `computer` | windows_event |
| `Message` | `message_data` | windows_event |
| `RecordNumber` | `record_number` | windows_event |
| `DestinationIp` / `DestinationPort` | `remote_address.ip` / `remote_address.port` | network |
| `SourceIp` / `SourcePort` | `local_address.ip` / `local_address.port` | network |
| `TargetFilename` | `path` | file |
| `msg` / `message` | `message` | auth, log |
| `program` | `program` | auth, log |
| `user` / `username` | `username` | auth, log |
| `host` | `ip` | auth, log |

## Detection blocks and condition grammar

* Named `selection` / `filter` maps under `detection:`; every
  `Field: value` entry is AND-ed with its siblings.
* Lists of values default to OR (any-of); `|all` turns the list into
  AND-ed conditions.
* Condition expression grammar:

```
expr      := or_expr
or_expr   := and_expr ( "or" and_expr )*
and_expr  := unary ( "and" unary )*
unary     := "not" unary | "(" expr ")" | predicate
predicate := name | name "*" | ("1 of" | "all of") name ["*"]
name      := any detection-block name, or "them"
```

* `1 of <prefix>*` / `1 of them` compile to OR; `all of <prefix>*` /
  `all of them` compile to AND. Only counts `1` and `all` are
  supported (`2 of ...` → **skipped**, `condition-syntax`).
* The engine's condition format was extended (P2-14) with nested
  `any_of` / `all_of` group nodes and a `negated` flag so arbitrary
  and/or/not trees survive conversion.

## Value modifiers

| Sigma modifier | Internal operator | Notes |
|---|---|---|
| *(none)* | `equals` | case-insensitive; wildcards `*`/`?` become an anchored `matches` regex |
| `|contains` | `contains` | wildcards become an unanchored `matches` regex |
| `|startswith` / `|endswith` | `startswith` / `endswith` | native engine operators |
| `|re` | `matches` | regex, prefixed `(?i)` (Sigma comparisons are case-insensitive) |
| `|cidr` | `cidr` | stdlib `ipaddress`; value is a CIDR string or list; any-of |
| `|fieldref` | `fieldref` | value names a sibling field; compared with normalized equality |
| `|exists` (or a bare `Field:`) | `exists` | field presence |
| `|lt` / `|lte` / `|gt` / `|gte` | `less_than` / `less_or_equal` / `greater_than` / `greater_or_equal` | numeric |
| `|all` / `|any` | — | list aggregation |

## Severity / status / metadata

* `level` → severity: `informational→info`, `low→low`, `medium→medium`,
  `high→high`, `critical→critical`.
* `status` → internal status: `stable→proven`, `test/experimental→experimental`,
  `deprecated→deprecated`.
* Confidence is derived from the level (Sigma rules carry none).
* `tags` are kept; `attack.t####(.###)` tags populate the `mitre`
  technique. `references`, `author`, `date`, `modified`,
  `falsepositives` and the raw `logsource` are preserved as metadata.

## Out of scope (rule is skipped with a warning)

* Sigma v2 correlation rules (top-level `correlation:`) —
  `correlation-rule`.
* `$placeholder` values — `placeholder`.
* `keywords:`-only detections — `keywords`.
* Value-transform modifiers: `|base64`, `|utf16le`, `|utf16be`,
  `|wide`, `|windash`, `|compress`, `|expand` — `unsupported-modifier`.
* Multi-count conditions (`2 of selection_*`) — `condition-syntax`.
* Unmapped fields, unmapped logsource blocks, unknown products,
  missing `id`/`title`, keyword-only blocks.

## Notes and known fidelity limits

* `Channel` maps to the record's `source` field; Sigma's `Security`
  channel constant therefore does not equal
  `Microsoft-Windows-Security-Auditing`. Rules filtering on
  `Channel` will not match SentinelClaw's Security records.
* `ParentImage` maps to `parent_name` (basename only), so `endswith`
  values with a leading path separator may not match.
* The reader is a compatibility layer, not a full Sigma backend:
  converted rules keep Sigma's intent but evaluate over SentinelClaw's
  normalized evidence shapes.