"""
Scan-state persistence and analyst analytics (P3-17, P3-19).

The :mod:`sentinelclaw.state.store` module persists bounded scan
records as JSONL under the resolved data directory, and
:mod:`sentinelclaw.state.analytics` provides the pure data functions
behind the stateful hunting commands (``history``, ``diff``,
``search``, ``accounts``, ``tree``, ``stats``).
"""
