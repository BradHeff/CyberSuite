"""Core data model shared across all checks and the GUI/reporting layers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional


class Severity(IntEnum):
    """Ordered severity levels. Higher value == more urgent."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()

    @property
    def color(self) -> str:
        """Hex color used by the GUI and HTML report."""
        return {
            Severity.INFO: "#4a90d9",
            Severity.LOW: "#3aa657",
            Severity.MEDIUM: "#d9a020",
            Severity.HIGH: "#e07b2e",
            Severity.CRITICAL: "#d1372e",
        }[self]


@dataclass
class Finding:
    """A single observation produced by a check.

    A Finding is not necessarily a problem: INFO findings document what was
    seen. Anything MEDIUM or above carries a recommendation on how to fix it.
    """

    title: str
    severity: Severity
    detail: str = ""
    recommendation: str = ""
    target: str = ""          # e.g. "192.168.1.10:23" or "localhost"
    check: str = ""           # name of the producing check, filled in by runner
    created: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "severity_value": int(self.severity),
            "detail": self.detail,
            "recommendation": self.recommendation,
            "target": self.target,
            "check": self.check,
        }


# A progress callback receives (fraction_complete_0_to_1, human_message).
ProgressCb = Callable[[float, str], None]
# A finding callback is invoked live as each finding is produced.
FindingCb = Callable[[Finding], None]
# A cancel predicate returns True when the user has asked to stop.
CancelCb = Callable[[], bool]


@dataclass
class ScanContext:
    """Runtime knobs and callbacks handed to every check."""

    progress: ProgressCb = lambda frac, msg: None
    emit: FindingCb = lambda finding: None
    cancelled: CancelCb = lambda: False

    # Tunables (overridable from the GUI / config).
    tcp_timeout: float = 0.6
    max_threads: int = 128
    ports: Optional[list[int]] = None          # None -> use default risky-port list
    subnets: Optional[list[str]] = None         # None -> auto-detect
    intrusive: bool = False                     # gate slower / noisier probes
    internal_tests: bool = False                # gateway/network vuln tests (internal only)
    cve_online: bool = False                    # allow online CVE enrichment (opt-in)

    def log(self, msg: str) -> None:
        self.progress(-1.0, msg)                # -1 fraction == "just a log line"
