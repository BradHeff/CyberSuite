"""CyberSuite CLI.

python -m cybersuite              # launch the GUI (default)
python -m cybersuite --cli        # run a scan in the terminal
python -m cybersuite --cli --internal --subnet 192.168.1.0/24 --report out.html # run a scan in the terminal output to html
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, netutil, reporting
from .model import Finding, ScanContext, Severity
from .runner import ScanRunner


def _cli(args) -> int:
    def progress(frac, msg):
        if frac < 0 and (msg.startswith("===") or not args.quiet):
            print(msg)
        elif frac >= 0 and not args.quiet:
            print(f"\r{msg:<60}", end="", flush=True)

    def emit(f: Finding):
        if f.severity >= Severity.MEDIUM or args.verbose:
            print(f"\n[{f.severity.label.upper()}] {f.title}" 
                  + (f"  ({f.target})" if f.target else ""))
            if f.recommendation:
                print(f"    FIX: {f.recommendation}")

    subnets = None
    if args.subnet:
        subnets = [s.strip() for s in ",".join(args.subnet).split(",") if s.strip()]

    ctx = ScanContext(
        progress=progress,
        emit=emit,
        intrusive=not args.fast,
        internal_tests=args.internal,
        cve_online=args.online,
        subnets=subnets,
    )
    runner = ScanRunner(ctx)
    findings = runner.run()
    print()
    print("=" * 60)
    print("SUMMARY:", reporting.summary_line(findings))
    print(f"Duration: {runner.duration():.1f}s")

    if args.report:
        meta = {"Subnets": ", ".join(subnets or netutil.guess_local_subnets()) or "auto",
                "Findings": reporting.summary_line(findings)}
        data = (reporting.to_text(findings, meta) if args.report.lower().endswith(".txt")
                else reporting.to_html(findings, meta))
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(data)
        print(f"Report written to {args.report}")

    # Non-zero exit if anything HIGH+ was found (useful for scheduled runs).
    return 1 if any(f.severity >= Severity.HIGH for f in findings) else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cybersuite",
                                description="One-click network security auditor.")
    p.add_argument("--version", action="version", version=f"CyberSuite {__version__}")
    p.add_argument("--cli", action="store_true", help="run in the terminal instead of the GUI")
    p.add_argument("--subnet", action="append", metavar="CIDR",
                   help="target subnet(s); repeatable or comma-separated (default: auto-detect)")
    p.add_argument("--internal", action="store_true",
                   help="enable internal network & gateway vulnerability tests (internal IPs only)")
    p.add_argument("--online", action="store_true",
                   help="allow online CVE enrichment via the CIRCL API (opt-in)")
    p.add_argument("--fast", action="store_true", help="skip deeper/slower probes")
    p.add_argument("--report", metavar="PATH", help="write an HTML (.html) or text (.txt) report")
    p.add_argument("--verbose", action="store_true", help="print INFO findings too (CLI)")
    p.add_argument("--quiet", action="store_true", help="suppress progress output (CLI)")
    args = p.parse_args(argv)

    if args.cli:
        return _cli(args)

    try:
        from .gui import main as gui_main
    except Exception as exc:  # tkinter missing / no display
        print(f"Could not start the GUI ({exc}).", file=sys.stderr)
        print("Run a terminal scan instead with:  python -m cybersuite --cli", file=sys.stderr)
        return 2
    gui_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
