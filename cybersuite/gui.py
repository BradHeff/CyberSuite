"""Tkinter GUI: one-click scanning with a live, color-coded output window.

Cross-platform (Linux/Windows). Uses ttkbootstrap for a modern look with the
project's 'heffelhoffui' theme; degrades gracefully to plain ttk if
ttkbootstrap is not installed. The scan runs on a worker thread; all UI updates
are marshalled back to the Tk main loop through a thread-safe queue.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk  # ttk.Combobox/Style used in both paths

from . import netutil, reporting, scope, theme
from .model import Finding, ScanContext, Severity
from .runner import ScanRunner

# --- optional ttkbootstrap ------------------------------------------------
# ttkbootstrap themes the standard ttk styles globally, so plain ttk widgets
# still pick up the active theme. We use tb.* widgets (which accept 'bootstyle')
# when available and fall back to tkinter.ttk otherwise.
#
# ttkbootstrap's package __init__ does `from ttkbootstrap.themes.user import
# USER_THEMES`. In some installs that file is owned by root / unreadable (e.g.
# it was written by the theme designer under sudo), which makes the whole import
# fail for a normal user. We pre-seed sys.modules with a harmless stub for that
# submodule so the locked file is never read; our own themes are registered
# separately via theme.register_user_themes().
def _load_ttkbootstrap():
    import sys
    import types
    name = "ttkbootstrap.themes.user"
    if name not in sys.modules:
        stub = types.ModuleType(name)
        stub.USER_THEMES = {}
        sys.modules[name] = stub
    import ttkbootstrap as _tb
    return _tb


try:
    tb = _load_ttkbootstrap()
    HAVE_TB = theme.register_user_themes()
except Exception:  # pragma: no cover - fallback path (e.g. ttkbootstrap missing)
    tb = None
    HAVE_TB = False

APP_TITLE = "CyberSuite — Network Security Auditor"


def _widget(kind: str, parent, bootstyle=None, **kw):
    """Create a ttkbootstrap/ttk widget, passing bootstyle only when supported."""
    if HAVE_TB:
        cls = getattr(tb, kind)
        if bootstyle is not None:
            kw["bootstyle"] = bootstyle
        return cls(parent, **kw)
    cls = getattr(ttk, kind)
    return cls(parent, **kw)


class CyberSuiteGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("980x740")
        self.root.minsize(840, 580)

        # Resolve the active palette (theme colors when ttkbootstrap is present).
        self.colors = self._resolve_colors()

        self.msg_q: "queue.Queue[tuple]" = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel_flag = threading.Event()
        self.runner: ScanRunner | None = None
        self.findings: list[Finding] = []
        self._counts = {s: 0 for s in Severity}

        self._build_ui()
        self.root.after(80, self._drain_queue)

    # ---------------------------------------------------------------- palette
    def _resolve_colors(self) -> dict:
        if HAVE_TB:
            c = self.root.style.colors
            return {
                "bg": c.bg,
                "fg": c.fg,
                "primary": c.primary,
                "success": c.success,
                "info": c.info,
                "secondary": c.secondary,
                "inputbg": c.inputbg,
                "selectfg": c.selectfg,
                "selectbg": c.selectbg,
            }
        # Fallback palette (approximates heffelhoffui).
        return {
            "bg": "#ffffff",
            "fg": "#282828",
            "primary": "#115740",
            "success": "#1d966f",
            "info": "#27c995",
            "secondary": "#5a6472",
            "inputbg": "#f2f2f0",
            "selectbg": "#115740",
            "selectfg": "#ffffff",
        }

    @staticmethod
    def _mix(c1: str, c2: str, t: float) -> str:
        """Blend two '#rrggbb' colors; t=0 -> c1, t=1 -> c2. Falls back to c1."""
        try:
            a = tuple(int(c1[i:i + 2], 16) for i in (1, 3, 5))
            b = tuple(int(c2[i:i + 2], 16) for i in (1, 3, 5))
        except (ValueError, IndexError):
            return c1
        return "#%02x%02x%02x" % tuple(
            round(a[i] + (b[i] - a[i]) * t) for i in range(3)
        )

    # ---------------------------------------------------------------- UI build
    def _build_ui(self):
        if not HAVE_TB:
            try:
                ttk.Style().theme_use("clam")
            except tk.TclError:
                pass

        # --- header banner (uses theme primary color) ---
        header = tk.Frame(self.root, bg=self.colors["primary"])
        header.pack(fill="x")
        self.header = header
        self.header_labels = [
            tk.Label(header, text="🛡  CyberSuite", bg=self.colors["primary"],
                     fg=self.colors["selectfg"], font=("Segoe UI", 18, "bold")),
            tk.Label(header, text="One-click network security checks — Horizon Christian School",
                     bg=self.colors["primary"], fg=self.colors["selectfg"],
                     font=("Segoe UI", 10)),
        ]
        self.header_labels[0].pack(side="left", padx=16, pady=12)
        self.header_labels[1].pack(side="left", pady=12)

        # theme picker on the right of the header
        self.theme_var = tk.StringVar(value=theme.APP_THEME)
        # if HAVE_TB:
        #     self._theme_lbl = tk.Label(header, text="Theme:", bg=self.colors["primary"],
        #                                fg=self.colors["selectfg"], font=("Segoe UI", 9))
        #     self._theme_lbl.pack(side="right", pady=12)
        #     picker = ttk.Combobox(header, textvariable=self.theme_var, width=16,
        #                           state="readonly", values=theme.theme_names())
        #     picker.pack(side="right", padx=8, pady=12)
        #     picker.bind("<<ComboboxSelected>>", self._on_theme_change)

        # --- options ---
        opts = _widget("Labelframe", self.root, text="Scan options")
        opts.pack(fill="x", padx=12, pady=(10, 4))

        row1 = _widget("Frame", opts)
        row1.pack(fill="x", padx=8, pady=6)
        _widget("Label", row1, text="Target subnet(s):").pack(side="left")
        self.subnet_var = tk.StringVar(value="auto")
        _widget("Entry", row1, textvariable=self.subnet_var, width=42).pack(side="left", padx=6)
        _widget("Label", row1,
                text="('auto' = detect; or e.g. 192.168.4.0/24,10.10.60.0/24)").pack(side="left")

        row2 = _widget("Frame", opts)
        row2.pack(fill="x", padx=8, pady=(0, 8))
        self.intrusive_var = tk.BooleanVar(value=True)
        self.internal_var = tk.BooleanVar(value=True)
        self.online_var = tk.BooleanVar(value=False)
        _widget("Checkbutton", row2, text="Deeper probes (banners, weak-TLS)",
                variable=self.intrusive_var, bootstyle="round-toggle").pack(side="left")
        _widget("Checkbutton", row2,
                text="Internal network & gateway vuln tests (internal only)",
                variable=self.internal_var, command=self._warn_internal,
                bootstyle="round-toggle").pack(side="left", padx=12)
        _widget("Checkbutton", row2, text="Online CVE lookup (sends versions to CIRCL)",
                variable=self.online_var, bootstyle="round-toggle").pack(side="left")

        # --- controls ---
        ctrl = _widget("Frame", self.root)
        ctrl.pack(fill="x", padx=12, pady=6)
        self.scan_btn = _widget("Button", ctrl, text="▶  Run Security Scan",
                                command=self.start_scan, bootstyle="success",
                                width=22)
        self.scan_btn.pack(side="left")
        self.stop_btn = _widget("Button", ctrl, text="■ Stop", command=self.stop_scan,
                                bootstyle="danger", state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.save_btn = _widget("Button", ctrl, text="💾 Save Report",
                                command=self.save_report, bootstyle="info-outline",
                                state="disabled")
        self.save_btn.pack(side="left", padx=4)
        self.clear_btn = _widget("Button", ctrl, text="Clear", command=self.clear_output,
                                 bootstyle="secondary-outline")
        self.clear_btn.pack(side="left")

        # --- summary chips (explicit severity colors so they match the report) ---
        self.summary = tk.Frame(self.root, bg=self.colors["fg"])
        self.summary.pack(fill="x", padx=12, pady=(2, 0))
        self.chip_labels: dict[Severity, tk.Label] = {}
        for s in reversed(list(Severity)):
            lbl = tk.Label(self.summary, text=f"{s.label}: 0", bg=s.color, fg="white",
                           font=("Segoe UI", 9, "bold"), padx=8, pady=2)
            lbl.pack(side="left", padx=3)
            self.chip_labels[s] = lbl

        # --- progress ---
        self.progress = _widget("Progressbar", self.root, mode="determinate",
                                maximum=1.0, bootstyle="success-striped")
        self.progress.pack(fill="x", padx=12, pady=6)
        self.status_var = tk.StringVar(value="Ready. Click “Run Security Scan”.")
        _widget("Label", self.root, textvariable=self.status_var).pack(anchor="w", padx=14)

        # --- output window ---
        outframe = _widget(
            "Labelframe",
            self.root,
            text="Output / recommendations",
        )
        outframe.pack(fill="both", expand=True, padx=12, pady=8)
        self.output = tk.Text(outframe, wrap="word", font=("Consolas", 10),
                              bg=self.colors["inputbg"], fg=self.colors["fg"],
                              insertbackground=self.colors["fg"], relief="flat",
                              padx=6, pady=6)
        yscroll = _widget("Scrollbar", outframe, command=self.output.yview)
        self.output.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.output.pack(side="left", fill="both", expand=True)
        self._configure_text_tags()
        self.output.configure(state="disabled")

        self._append("Welcome to CyberSuite.\n", "head")
        self._append(
            "Only scan networks you own or are explicitly authorised to test.\n"
            "Click “Run Security Scan” to check this machine and your local network.\n\n", "info")

    def _configure_text_tags(self):
        for s in Severity:
            self.output.tag_config(f"sev{s.value}", foreground=s.color)
        self.output.tag_config("head", foreground=self.colors["primary"],
                               font=("Consolas", 10, "bold"))
        # "dim" is muted-but-readable: blend the main text color 40% toward the
        # output background. This stays legible on light themes (heffelhoffui's
        # cream window) and dark themes alike, unlike the theme's very pale
        # 'secondary' color which washed out on a light background.
        self.output.tag_config(
            "dim", foreground=self._mix(self.colors["fg"], self.colors["inputbg"], 0.30))
        self.output.tag_config("fix", foreground=self.colors["success"])

    # ------------------------------------------------------------- theming
    def _on_theme_change(self, _event=None):
        if not HAVE_TB:
            return
        name = self.theme_var.get()
        try:
            self.root.style.theme_use(name)
        except tk.TclError:
            return
        # Re-resolve palette and restyle the hand-colored (non-ttk) widgets.
        self.colors = self._resolve_colors()
        self.summary.configure(bg=self.colors["bg"])
        self.output.configure(bg=self.colors["inputbg"], fg=self.colors["fg"],
                              insertbackground=self.colors["fg"])
        self._configure_text_tags()
        # Recolor the header banner to the new theme's primary color.
        self.header.configure(bg=self.colors["primary"])
        for lbl in self.header_labels:
            lbl.configure(bg=self.colors["primary"], fg=self.colors["selectfg"])
        if hasattr(self, "_theme_lbl"):
            self._theme_lbl.configure(bg=self.colors["primary"], fg=self.colors["selectfg"])
        self.status_var.set(f"Theme changed to '{name}'.")

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
        self._append(f"Target subnets: {', '.join(subnets) if subnets else 'auto-detect'}\n\n",
                     "dim")

        self.runner = ScanRunner(ctx)
        self.worker = threading.Thread(target=self._run_worker, daemon=True)
        self.worker.start()

    def _parse_subnets(self) -> list[str] | None:
        raw = self.subnet_var.get().strip()
        if not raw or raw.lower() == "auto":
            return None
        subs = [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]
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
        self._show_summary_window()

    # --------------------------------------------------- completion summary
    def _show_summary_window(self):
        """Pop up a focused summary of the action items and their fixes."""
        # Most-severe first; only MEDIUM+ are "issues" that carry a fix.
        actionable = sorted(
            (f for f in self.findings if f.severity >= Severity.MEDIUM),
            key=lambda f: (-int(f.severity), f.check, f.target, f.title),
        )
        n = len(actionable)

        # Replace any summary window left open from a previous scan.
        prev = getattr(self, "_summary_win", None)
        if prev is not None:
            try:
                prev.destroy()
            except tk.TclError:
                pass

        win = tk.Toplevel(self.root)
        self._summary_win = win
        win.title("Scan Complete")
        win.configure(bg=self.colors["bg"])
        win.transient(self.root)

        # --- header banner (theme primary color) ---
        head = tk.Frame(win, bg=self.colors["primary"])
        head.pack(fill="x")
        tk.Label(head, text=f"🛡  Scan Complete — {n} Issue{'' if n == 1 else 's'} Found",
                 bg=self.colors["primary"], fg=self.colors["selectfg"],
                 font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        sub = ("Everything below needs attention — each item includes a fix."
               if n else "No medium-or-higher issues were found. Looks healthy. 🎉")
        tk.Label(head, text=sub, bg=self.colors["primary"], fg=self.colors["selectfg"],
                 font=("Segoe UI", 10)).pack(anchor="w", padx=16, pady=(0, 12))

        # --- severity stat chips (counts across the whole scan) ---
        stats = tk.Frame(win, bg=self.colors["bg"])
        stats.pack(fill="x", padx=12, pady=(10, 2))
        for s in reversed(list(Severity)):
            tk.Label(stats, text=f"{s.label}: {self._counts[s]}", bg=s.color, fg="white",
                     font=("Segoe UI", 9, "bold"), padx=8, pady=2).pack(side="left", padx=3)

        # --- scrollable list of fixes ---
        body = _widget("Labelframe", win, text="Recommended fixes")
        body.pack(fill="both", expand=True, padx=12, pady=8)
        txt = tk.Text(body, wrap="word", font=("Consolas", 10),
                      bg=self.colors["inputbg"], fg=self.colors["fg"],
                      relief="flat", padx=8, pady=8)
        sb = _widget("Scrollbar", body, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)

        for s in Severity:
            txt.tag_config(f"sev{s.value}", foreground=s.color, font=("Consolas", 10, "bold"))
        txt.tag_config("dim", foreground=self._mix(self.colors["fg"], self.colors["inputbg"], 0.30))
        txt.tag_config("fix", foreground=self.colors["success"])

        if not actionable:
            txt.insert("end", "Nothing to fix. Keep systems patched and re-scan periodically.\n", "dim")
        else:
            for i, f in enumerate(actionable, 1):
                txt.insert("end", f"{i}. [{f.severity.label.upper()}] ", f"sev{f.severity.value}")
                txt.insert("end", f"{f.title}\n", f"sev{f.severity.value}")
                if f.target:
                    txt.insert("end", f"        target: {f.target}\n", "dim")
                fix = f.recommendation or "(no specific fix recorded — investigate this host manually)"
                txt.insert("end", f"        → FIX: {fix}\n\n", "fix")
        txt.configure(state="disabled")

        # --- buttons ---
        btns = _widget("Frame", win)
        btns.pack(fill="x", padx=12, pady=(0, 12))
        _widget("Button", btns, text="💾 Save Report", command=self.save_report,
                bootstyle="info").pack(side="left")
        ok = _widget("Button", btns, text="OK", command=win.destroy,
                     bootstyle="success", width=12)
        ok.pack(side="right")

        # Enter or Escape (or the OK button) dismisses the window.
        win.bind("<Return>", lambda _e: win.destroy())
        win.bind("<Escape>", lambda _e: win.destroy())

        # Size and center over the main window.
        ww, wh = 720, 600
        win.update_idletasks()
        rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
        rw, rh = self.root.winfo_width(), self.root.winfo_height()
        x = rx + max(0, (rw - ww) // 2)
        y = ry + max(0, (rh - wh) // 3)
        win.geometry(f"{ww}x{wh}+{x}+{y}")
        win.minsize(560, 420)
        win.lift()
        ok.focus_set()

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
        my = netutil.local_ipv4_addresses()
        meta = {
            "Host": my[0] if my else "?",
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
    if HAVE_TB:
        root = tb.Window(themename=theme.APP_THEME)
    else:
        root = tk.Tk()
    CyberSuiteGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
