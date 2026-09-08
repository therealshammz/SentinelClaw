from __future__ import annotations

import sys
from typing import TextIO


class ScanProgress:
    """
    Small terminal progress reporter.

    Progress is written to stderr so stdout can remain clean
    for structured output such as JSON.
    """

    def __init__(
        self,
        enabled: bool = True,
        total_steps: int = 6,
        stream: TextIO | None = None,
    ) -> None:
        self.enabled = enabled
        self.total_steps = total_steps
        self.current_step = 0
        self.stream = stream or sys.stderr

    def _write(self, message: str) -> None:
        if not self.enabled:
            return

        print(
            message,
            file=self.stream,
            flush=True,
        )

    def step(self, message: str) -> None:
        self.current_step += 1

        self._write(
            f"[{self.current_step}/{self.total_steps}] "
            f"{message}"
        )

    def warning(self, message: str) -> None:
        self._write(
            f"[WARNING] {message}"
        )

    def error(self, message: str) -> None:
        self._write(
            f"[ERROR] {message}"
        )

    def complete(self) -> None:
        self._write(
            "[+] Scan complete."
        )
