"""Tkinter GUI: one-click scanning with a live, color-coded output window.

Cross-platform (Linux/Windows). The scan runs on a worker thread; all UI updates
are marshalled back to the Tk main loop through a thread-safe queue.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import netutil, reporting, scope
from .model import Finding, ScanContext, Severity
from .runner import ScanRunner

APP_TITLE = "CyberSuite — Network Security Auditor"


class CyberSuiteGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("960x720")
        self.root.minsize(820, 560)

        self.msg_q: "queue.Queue[tuple]" = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel_flag = threading.Event()
        self.runner: ScanRunner | None = None
        self.findings: list[Finding] = []
        self._counts = {s: 0 for s in Severity}

        self._build_ui()
        self.root.after(80, self._drain_queue)

    # ---------------------------------------------------------------- UI build
    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        header = tk.Frame(self.root, bg="#12203a")
        header.pack(fill="x")
        tk.Label(header, text="🛡  CyberSuite", bg="#12203a", fg="white",
                 font=("Segoe UI", 18, "bold")).pack(side="left", padx=16, pady=12)
        tk.Label(header, text="One-click network security checks for your own network",
                 bg="#12203a", fg="#9db4d6", font=("Segoe UI", 10)).pack(side="left", pady=12)

        # --- options row ---
        opts = ttk.LabelFrame(self.root, text="Scan options")
        opts.pack(fill="x", padx=12, pady=(10, 4))

        row1 = ttk.Frame(opts)
        row1.pack(fill="x", padx=8, pady=6)
        ttk.Label(row1, text="Target subnet(s):").pack(side="left")
        self.subnet_var = tk.StringVar(value="auto")
        self.subnet_entry = ttk.Entry(row1, textvariable=self.subnet_var, width=42)
        self.subnet_entry.pack(side="left", padx=6)
        ttk.Label(row1, text="('auto' = detect; or e.g. 192.168.1.0/24,10.0.0.0/24)",
                  foreground="#667").pack(side="left")

        row2 = ttk.Frame(opts)
        row2.pack(fill="x", padx=8, pady=(0, 8))
        self.intrusive_var = tk.BooleanVar(value=True)
        self.internal_var = tk.BooleanVar(value=True)
        self.online_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text="Deeper probes (banners, weak-TLS)",
                        variable=self.intrusive_var).pack(side="left")
        ttk.Checkbutton(row2, text="Internal network & gateway vuln tests (internal only)",
                        variable=self.internal_var,
                        command=self._warn_internal).pack(side="left", padx=12)
        ttk.Checkbutton(row2, text="Online CVE lookup (sends versions to CIRCL)",
                        variable=self.online_var).pack(side="left")

        # --- controls ---
        ctrl = ttk.Frame(self.root)
        ctrl.pack(fill="x", padx=12, pady=4)
        self.scan_btn = tk.Button(ctrl, text="▶  Run Security Scan", command=self.start_scan,
                                  bg="#1f7a3d", fg="white", font=("Segoe UI", 12, "bold"),
                                  relief="flat", padx=18, pady=8, cursor="hand2")
        self.scan_btn.pack(side="left")
        self.stop_btn = tk.Button(ctrl, text="■ Stop", command=self.stop_scan,
                                  bg="#8a2b26", fg="white", font=("Segoe UI", 11),
                                  relief="flat", padx=12, pady=8, state="disabled", cursor="hand2")
        self.stop_btn.pack(side="left", padx=8)
        self.save_btn = tk.Button(ctrl, text="💾 Save Report", command=self.save_report,
                                  relief="flat", padx=12, pady=8, state="disabled", cursor="hand2")
        self.save_btn.pack(side="left", padx=4)
        self.clear_btn = tk.Button(ctrl, text="Clear", command=self.clear_output,
                                   relief="flat", padx=12, pady=8, cursor="hand2")
        self.clear_btn.pack(side="left")

        # --- summary chips ---
        self.summary = tk.Frame(self.root)
        self.summary.pack(fill="x", padx=12, pady=(2, 0))
        self.chip_labels: dict[Severity, tk.Label] = {}
        for s in reversed(list(Severity)):
            lbl = tk.Label(self.summary, text=f"{s.label}: 0", bg=s.color, fg="white",
                           font=("Segoe UI", 9, "bold"), padx=8, pady=2)
            lbl.pack(side="left", padx=3)
            self.chip_labels[s] = lbl

        # --- progress ---
        self.progress = ttk.Progressbar(self.root, mode="determinate", maximum=1.0)
        self.progress.pack(fill="x", padx=12, pady=6)
        self.status_var = tk.StringVar(value="Ready. Click “Run Security Scan”.")
        ttk.Label(self.root, textvariable=self.status_var, foreground="#445").pack(
            anchor="w", padx=14)

        # --- output window ---
        outframe = ttk.LabelFrame(self.root, text="Output / recommendations")
        outframe.pack(fill="both", expand=True, padx=12, pady=8)
        self.output = tk.Text(outframe, wrap="word", font=("Consolas", 10),
                              bg="#0f1420", fg="#d6dae2", insertbackground="#d6dae2")
        yscroll = ttk.Scrollbar(outframe, command=self.output.yview)
        self.output.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.output.pack(side="left", fill="both", expand=True)

        for s in Severity:
            self.output.tag_config(f"sev{s.value}", foreground=s.color)
        self.output.tag_config("head", foreground="#7fb3ff",
                               font=("Consolas", 10, "bold"))
        self.output.tag_config("dim", foreground="#7a8494")
        self.output.tag_config("fix", foreground="#8fd0a0")
        self.output.configure(state="disabled")

        self._append("Welcome to CyberSuite.\n", "head")
        self._append(
            "Only scan networks you own or are explicitly authorised to test.\n"
            "Click “Run Security Scan” to check this machine and your local network.\n\n", "dim")

    # ------------------------------------------------------------- UI helpers
    def _warn_internal(self):
        if self.internal_var.get():
            messagebox.showinfo(
                "Internal-only tests",
                "Gateway and network vulnerability tests will run ONLY against private, "
                "internal (RFC1918) addresses and your default gateway.\n\n"
                "Public/internet addresses are automatically refused. Use these tests "
                "only on equipment you administer.")

    def _append(self, text: str, tag: str | None = None):
        self.output.configure(state="normal")
        self.output.insert("end", text, tag or ())
        self.output.see("end")
        self.output.configure(state="disabled")

    def _set_chip(self, sev: Severity, n: int):
        self.chip_labels[sev].config(text=f"{sev.label}: {n}")

    # --------------------------------------------------------------- scanning
    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        self.findings = []
        self._counts = {s: 0 for s in Severity}
        for s in Severity:
            self._set_chip(s, 0)
        self.clear_output()
        self.cancel_flag.clear()
        self.progress["value"] = 0
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.save_btn.config(state="disabled")

        subnets = self._parse_subnets()
        ctx = ScanContext(
            progress=lambda frac, msg: self.msg_q.put(("progress", frac, msg)),
            emit=lambda f: self.msg_q.put(("finding", f)),
            cancelled=self.cancel_flag.is_set,
            intrusive=self.intrusive_var.get(),
            internal_tests=self.internal_var.get(),
            cve_online=self.online_var.get() and self.intrusive_var.get(),
            subnets=subnets,
        )
        self._scan_started = time.time()
        self._append(f"Scan started {time.strftime('%Y-%m-%d %H:%M:%S')}\n", "head")
        if subnets:
            self._append(f"Target subnets: {', '.join(subnets)}\n\n", "dim")
        else:
            self._append("Target subnets: auto-detect\n\n", "dim")

        self.runner = ScanRunner(ctx)
        self.worker = threading.Thread(target=self._run_worker, daemon=True)
        self.worker.start()

    def _parse_subnets(self) -> list[str] | None:
        raw = self.subnet_var.get().strip()
        if not raw or raw.lower() == "auto":
            return None
        subs = [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]
        # Safety: if internal tests are on, silently drop any public subnet.
        if self.internal_var.get():
            kept = [s for s in subs if scope.is_internal_subnet(s)]
            dropped = [s for s in subs if s not in kept]
            if dropped:
                self.msg_q.put(("progress", -1.0,
                                f"Ignoring non-internal subnet(s): {', '.join(dropped)}"))
            return kept or None
        return subs or None

    def _run_worker(self):
        try:
            self.runner.run()
            self.msg_q.put(("done", None))
        except Exception as exc:  # pragma: no cover - defensive
            self.msg_q.put(("error", str(exc)))

    def stop_scan(self):
        self.cancel_flag.set()
        self.status_var.set("Stopping… (finishing current probe)")
        self.stop_btn.config(state="disabled")

    # ------------------------------------------------------------ queue drain
    def _drain_queue(self):
        try:
            while True:
                item = self.msg_q.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, frac, msg = item
                    if frac >= 0:
                        self.progress["value"] = frac
                    self.status_var.set(msg)
                    if frac < 0 and msg.startswith("==="):
                        self._append(f"\n{msg}\n", "head")
                    elif frac < 0:
                        self._append(f"  · {msg}\n", "dim")
                elif kind == "finding":
                    self._render_finding(item[1])
                elif kind == "done":
                    self._on_done()
                elif kind == "error":
                    self._append(f"\nScan error: {item[1]}\n", "sev3")
                    self._on_done()
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    def _render_finding(self, f: Finding):
        self.findings.append(f)
        self._counts[f.severity] += 1
        self._set_chip(f.severity, self._counts[f.severity])
        tag = f"sev{f.severity.value}"
        self._append(f"[{f.severity.label.upper()}] ", tag)
        self._append(f"{f.title}\n", tag)
        if f.target:
            self._append(f"        target: {f.target}\n", "dim")
        for line in f.detail.splitlines():
            if line.strip():
                self._append(f"        {line}\n", "dim")
        if f.recommendation:
            self._append(f"        → FIX: {f.recommendation}\n", "fix")

    def _on_done(self):
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.save_btn.config(state="normal" if self.findings else "disabled")
        self.progress["value"] = 1.0
        dur = time.time() - getattr(self, "_scan_started", time.time())
        actionable = sum(1 for f in self.findings if f.severity >= Severity.MEDIUM)
        self._append(
            f"\n=== Scan finished in {dur:.1f}s — "
            f"{actionable} issue(s) need attention, "
            f"{len(self.findings)} finding(s) total ===\n", "head")
        self.status_var.set(
            f"Done. {reporting.summary_line(self.findings)}. "
            f"{'Save the report for your records.' if actionable else 'Looks healthy.'}")

    # --------------------------------------------------------------- reports
    def save_report(self):
        if not self.findings:
            return
        path = filedialog.asksaveasfilename(
            title="Save CyberSuite report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("Text report", "*.txt")],
            initialfile=time.strftime("cybersuite-report-%Y%m%d-%H%M%S.html"))
        if not path:
            return
        meta = {
            "Host": netutil.local_ipv4_addresses() and netutil.local_ipv4_addresses()[0] or "?",
            "Subnets": ", ".join(self._parse_subnets() or netutil.guess_local_subnets()) or "auto",
            "Findings": reporting.summary_line(self.findings),
        }
        try:
            if path.lower().endswith(".txt"):
                data = reporting.to_text(self.findings, meta)
            else:
                data = reporting.to_html(self.findings, meta)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
            messagebox.showinfo("Report saved", f"Report written to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))

    def clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")


def main():
    root = tk.Tk()
    CyberSuiteGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
