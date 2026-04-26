"""
main.py - CIS Benchmark Audit Tool GUI

Tkinter interface for running Linux / Windows CIS audits,
displaying results in a colour-coded table, and generating reports.
"""

import json
import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

from audits import linux, windows
from reports.generator import generate_html_report


# ── Paths ───────────────────────────────────────────────────────
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


class AuditApp:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CIS Benchmark Audit Tool")
        self.root.geometry("900x560")
        self.root.minsize(720, 440)
        self.root.configure(bg="#1e1e2e")

        self._last_results: list[dict[str, str]] = []

        self._build_header()
        self._build_toolbar()
        self._build_table()
        self._build_footer()

    # ── Header ──────────────────────────────────────────────────
    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg="#1e1e2e")
        header.pack(fill="x", pady=(18, 4))

        tk.Label(
            header,
            text="🛡  CIS Benchmark Audit Tool",
            font=("Segoe UI", 18, "bold"),
            fg="#cdd6f4", bg="#1e1e2e",
        ).pack()

        tk.Label(
            header,
            text="Run security audits based on CIS benchmarks",
            font=("Segoe UI", 10),
            fg="#6c7086", bg="#1e1e2e",
        ).pack()

    # ── Toolbar ─────────────────────────────────────────────────
    def _build_toolbar(self) -> None:
        bar = tk.Frame(self.root, bg="#1e1e2e")
        bar.pack(fill="x", padx=20, pady=(12, 6))

        btn_style = {
            "font": ("Segoe UI", 11, "bold"),
            "relief": "flat",
            "cursor": "hand2",
            "padx": 18, "pady": 6,
        }

        self.btn_linux = tk.Button(
            bar, text="▶  Run Linux Audit",
            bg="#a6e3a1", fg="#1e1e2e",
            activebackground="#94e2d5",
            command=lambda: self._run_audit("linux"),
            **btn_style,
        )
        self.btn_linux.pack(side="left", padx=(0, 10))

        self.btn_windows = tk.Button(
            bar, text="▶  Run Windows Audit",
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            command=lambda: self._run_audit("windows"),
            **btn_style,
        )
        self.btn_windows.pack(side="left")

        self.status_label = tk.Label(
            bar, text="", font=("Segoe UI", 10),
            fg="#f9e2af", bg="#1e1e2e",
        )
        self.status_label.pack(side="right")

    # ── Results Table ───────────────────────────────────────────
    def _build_table(self) -> None:
        container = tk.Frame(self.root, bg="#1e1e2e")
        container.pack(fill="both", expand=True, padx=20, pady=(6, 6))

        columns = ("check_name", "status", "details")
        self.tree = ttk.Treeview(
            container, columns=columns,
            show="headings", selectmode="browse",
        )

        self.tree.heading("check_name", text="Check Name", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("details", text="Details", anchor="w")

        self.tree.column("check_name", width=220, minwidth=150)
        self.tree.column("status", width=80, minwidth=60, anchor="center")
        self.tree.column("details", width=420, minwidth=200)

        # Row colour tags
        self.tree.tag_configure("pass", background="#a6e3a1", foreground="#1e1e2e")
        self.tree.tag_configure("fail", background="#f38ba8", foreground="#1e1e2e")

        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Style the treeview for dark theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="#313244",
                        foreground="#cdd6f4",
                        fieldbackground="#313244",
                        font=("Segoe UI", 10),
                        rowheight=28)
        style.configure("Treeview.Heading",
                        background="#45475a",
                        foreground="#cdd6f4",
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#585b70")])

    # ── Footer ──────────────────────────────────────────────────
    def _build_footer(self) -> None:
        footer = tk.Frame(self.root, bg="#1e1e2e")
        footer.pack(fill="x", padx=20, pady=(0, 14))

        self.btn_report = tk.Button(
            footer, text="📄  Generate Report",
            font=("Segoe UI", 11, "bold"),
            bg="#cba6f7", fg="#1e1e2e",
            activebackground="#b4befe",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._generate_report,
        )
        self.btn_report.pack(side="right")

        self.summary_label = tk.Label(
            footer, text="No audit run yet",
            font=("Segoe UI", 10),
            fg="#6c7086", bg="#1e1e2e",
        )
        self.summary_label.pack(side="left")

    # ── Audit Runner ────────────────────────────────────────────
    def _run_audit(self, os_type: str) -> None:
        """Run the selected audit in a background thread."""
        self._set_buttons_enabled(False)
        self.status_label.config(text=f"Running {os_type} audit…")

        def task() -> None:
            try:
                if os_type == "linux":
                    results = linux.run_all_checks()
                else:
                    results = windows.run_all_checks()

                self.root.after(0, lambda: self._display_results(results, os_type))
            except Exception as exc:
                self.root.after(0, lambda: self._show_error(str(exc)))

        threading.Thread(target=task, daemon=True).start()

    def _display_results(self, results: list[dict[str, str]], os_type: str) -> None:
        """Populate the treeview with audit results."""
        # Clear previous rows
        for row in self.tree.get_children():
            self.tree.delete(row)

        self._last_results = results
        pass_count = 0

        for item in results:
            tag = "pass" if item["status"] == "PASS" else "fail"
            if tag == "pass":
                pass_count += 1

            self.tree.insert("", "end", values=(
                item["check_name"],
                item["status"],
                item["details"],
            ), tags=(tag,))

        total = len(results)
        self.summary_label.config(
            text=f"{os_type.capitalize()} audit: {pass_count}/{total} passed"
        )
        self.status_label.config(text="✓ Complete")
        self._set_buttons_enabled(True)

        # Auto-save JSON results
        self._save_results_json(results, os_type)

    def _show_error(self, message: str) -> None:
        self.status_label.config(text="✗ Error")
        self._set_buttons_enabled(True)
        messagebox.showerror("Audit Error", message)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.btn_linux.config(state=state)
        self.btn_windows.config(state=state)
        self.btn_report.config(state=state)

    # ── Save / Report ───────────────────────────────────────────
    def _save_results_json(self, results: list[dict[str, str]], os_type: str) -> None:
        """Save audit results to the results/ directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{os_type}_audit_{timestamp}.json"
        filepath = os.path.join(RESULTS_DIR, filename)

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)

    def _generate_report(self) -> None:
        """Generate an HTML audit report and open it in the browser."""
        if not self._last_results:
            messagebox.showwarning("No Data", "Run an audit first before generating a report.")
            return

        try:
            report_path = generate_html_report(self._last_results)
            messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")

            # Open the report in the default browser
            import webbrowser
            webbrowser.open(f"file:///{report_path}")
        except Exception as exc:
            messagebox.showerror("Report Error", str(exc))


def main() -> None:
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
