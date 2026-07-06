"""Base class and shared state for all checks.

Checks communicate results in two ways:
  * live, via ctx.emit(finding) so the GUI can stream them, and
  * in aggregate, via the return value of run() (also a list of Findings).

Some checks publish data for later checks by writing into `shared` (a plain
dict on the runner). For example NetworkDiscovery writes the live-host list that
PortScan consumes.
"""

from __future__ import annotations

from ..model import Finding, ScanContext, Severity


class Check:
    name: str = "check"
    title: str = "Unnamed check"
    description: str = ""

    def __init__(self, ctx: ScanContext, shared: dict):
        self.ctx = ctx
        self.shared = shared
        self.findings: list[Finding] = []

    # --- helpers -----------------------------------------------------------
    def add(
        self,
        title: str,
        severity: Severity,
        detail: str = "",
        recommendation: str = "",
        target: str = "",
    ) -> Finding:
        f = Finding(
            title=title,
            severity=severity,
            detail=detail,
            recommendation=recommendation,
            target=target,
            check=self.name,
        )
        self.findings.append(f)
        self.ctx.emit(f)
        return f

    def log(self, msg: str) -> None:
        self.ctx.log(f"[{self.name}] {msg}")

    def cancelled(self) -> bool:
        return self.ctx.cancelled()

    # --- to override -------------------------------------------------------
    def run(self) -> list[Finding]:
        raise NotImplementedError
