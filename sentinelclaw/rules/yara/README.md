# SentinelClaw YARA rules (optional, P4-23)

This directory holds optional YARA rules used by the `file` command
(and directory scans) when the `yara-python` package is installed:

```
pip install -e ".[yara]"
```

Rules here are NOT part of the YAML detection-rule twin-copy sync
(`rules/` <-> `sentinelclaw/rules/`); they live only inside the
package. Point `SENTINELCLAW_YARA_RULES_DIR` at another directory to
use your own rule set instead.

- Files must use the `.yar` or `.yara` extension.
- Each file is compiled independently: a broken rule is skipped with a
  warning and does not disable the remaining rules.
- A matched rule becomes a `YARA-001` finding. Its severity is taken
  from the rule's `severity` metadata when present (one of
  info/low/medium/high/critical), otherwise it defaults to `medium`.

The two rules below are minimal examples, not a detection set:
`SuspiciousPowerShellEncoded` mirrors the built-in encoded-PowerShell
indicator, and `EmbeddedExecutableMarker` demonstrates metadata-driven
severity.
