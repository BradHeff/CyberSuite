"""Orchestrates all checks in order and aggregates their findings."""

from __future__ import annotations

import time
import traceback

from .checks import ALL_CHECKS
from .model import Finding, ScanContext, Severity


class ScanRunner:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.shared: dict = {"cve_online": ctx.cve_online}
        self.findings: list[Finding] = []
        self.started: float = 0.0
        self.finished: float = 0.0

    def run(self) -> list[Finding]:
        self.started = time.time()
        checks = [cls(self.ctx, self.shared) for cls in ALL_CHECKS]
        total = len(checks)

        for idx, check in enumerate(checks):
            if self.ctx.cancelled():
                self.ctx.log("Scan cancelled by user.")
                break
            self.ctx.progress(-1.0, f"=== {check.title} ({idx + 1}/{total}) ===")
            try:
                produced = check.run() or []
                self.findings.extend(produced)
            except Exception:  # never let one check kill the whole run
                tb = traceback.format_exc(limit=3)
                f = Finding(
                    title=f"Check '{check.name}' failed to run",
                    severity=Severity.LOW,
                    detail=tb,
                    recommendation="This is a tool error, not necessarily a security issue. "
                                   "Please report it if it persists.",
                    check=check.name,
                )
                self.findings.append(f)
                self.ctx.emit(f)

        self.finished = time.time()
        self.ctx.progress(1.0, "Scan complete.")
        return self.findings

    # --- summary helpers ---------------------------------------------------
    def summary_counts(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def duration(self) -> float:
        return max(0.0, (self.finished or time.time()) - self.started)
