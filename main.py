"""
main.py - CIS Benchmark Audit Tool GUI

Tkinter interface for running Linux / Windows CIS audits,
displaying results in a colour-coded table, and generating reports.
"""

import json
import os
import logging
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox, filedialog
from reports.generator import generate_html_report

#  Logging Configuration 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("CIS-Audit")


#  Paths 
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

        logger.info("Initializing CIS Audit Tool GUI...")
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

        self.btn_windows = tk.Button(
            bar, text="▶  Run Windows Audit",
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            command=lambda: self._run_audit("windows"),
            **btn_style,
        )
        self.btn_windows.pack(side="left")

        # Add filter
        filter_frame = tk.Frame(bar, bg="#1e1e2e")
        filter_frame.pack(side="left", padx=(20, 0))
        tk.Label(filter_frame, text="Filter:", bg="#1e1e2e", fg="#cdd6f4", font=("Segoe UI", 11)).pack(side="left")
        
        self.filter_var = tk.StringVar(value="All")
        self.filter_cb = ttk.Combobox(
            filter_frame, textvariable=self.filter_var, state="readonly", width=15, font=("Segoe UI", 10)
        )
        self.filter_cb["values"] = ("All", "Critical", "Non-Critical", "Must Fix")
        self.filter_cb.pack(side="left", padx=(5, 0))
        self.filter_cb.bind("<<ComboboxSelected>>", self._apply_filter)

        self.status_label = tk.Label(
            bar, text="", font=("Segoe UI", 10),
            fg="#f9e2af", bg="#1e1e2e",
        )
        self.status_label.pack(side="right")

    # ── Results Table ───────────────────────────────────────────
    def _build_table(self) -> None:
        container = tk.Frame(self.root, bg="#1e1e2e")
        container.pack(fill="both", expand=True, padx=20, pady=(6, 6))

        columns = ("check_name", "status", "severity", "impact", "details")
        self.tree = ttk.Treeview(
            container, columns=columns,
            show="headings", selectmode="browse",
        )

        self.tree.heading("check_name", text="Check Name", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("severity", text="Severity", anchor="center")
        self.tree.heading("impact", text="Impact", anchor="center")
        self.tree.heading("details", text="Details", anchor="w")

        self.tree.column("check_name", width=250, minwidth=200)
        self.tree.column("status", width=100, minwidth=80, anchor="center")
        self.tree.column("severity", width=100, minwidth=80, anchor="center")
        self.tree.column("impact", width=120, minwidth=100, anchor="center")
        self.tree.column("details", width=500, minwidth=300)

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
                        font=("Segoe UI", 12),
                        rowheight=40)
        style.configure("Treeview.Heading",
                        background="#45475a",
                        foreground="#cdd6f4",
                        font=("Segoe UI", 12, "bold"))
        style.map("Treeview", background=[("selected", "#585b70")])

    # ── Footer ──────────────────────────────────────────────────
    def _build_footer(self) -> None:
        footer = tk.Frame(self.root, bg="#1e1e2e")
        footer.pack(fill="x", padx=20, pady=(0, 14))

        self.btn_report = tk.Button(
            footer, text="📄  Generate HTML",
            font=("Segoe UI", 11, "bold"),
            bg="#cba6f7", fg="#1e1e2e",
            activebackground="#b4befe",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._generate_report,
        )
        self.btn_report.pack(side="right")

        self.btn_pdf = tk.Button(
            footer, text="📄 Generate PDF",
            font=("Segoe UI", 11, "bold"),
            bg="#f5c2e7", fg="#1e1e2e",
            activebackground="#f5e0dc",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._generate_pdf,
        )
        self.btn_pdf.pack(side="right", padx=(0, 10))

        self.btn_csv = tk.Button(
            footer, text="📊 Export CSV",
            font=("Segoe UI", 11, "bold"),
            bg="#f9e2af", fg="#1e1e2e",
            activebackground="#f2cdcd",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._export_csv,
        )
        self.btn_csv.pack(side="right", padx=(0, 10))

        self.btn_clear = tk.Button(
            footer, text="🗑 Clear",
            font=("Segoe UI", 11, "bold"),
            bg="#f38ba8", fg="#1e1e2e",
            activebackground="#eba0ac",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._clear_table,
        )
        self.btn_clear.pack(side="left", padx=(10, 0))

        self.btn_autofix = tk.Button(
            footer, text="⚙️ Open Settings",
            font=("Segoe UI", 11, "bold"),
            bg="#a6e3a1", fg="#1e1e2e",
            activebackground="#89dceb",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._auto_fix_issue,
        )
        self.btn_autofix.pack(side="left", padx=(10, 0))

        self.btn_fix = tk.Button(
            footer, text="🔧 Guide/Fix",
            font=("Segoe UI", 11, "bold"),
            bg="#fab387", fg="#1e1e2e",
            activebackground="#f9e2af",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._fix_issue,
        )
        self.btn_fix.pack(side="left", padx=(10, 0))

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
        msg = f"Starting {os_type} audit..."
        self.status_label.config(text=msg)
        logger.info(msg)

        def task() -> None:
            try:
                from audits import windows
                results = windows.run_all_checks()

                logger.info(f"Successfully retrieved {len(results)} results for {os_type}")
                self.root.after(0, lambda: self._display_results(results, os_type))
            except Exception as exc:
                logger.error(f"Audit failed: {exc}")
                self.root.after(0, lambda: self._show_error(str(exc)))

        threading.Thread(target=task, daemon=True).start()

    def _display_results(self, results: list[dict[str, str]], os_type: str) -> None:
        """Populate the treeview with audit results."""
        self._last_results = results
        self._apply_filter()
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
        self.btn_windows.config(state=state)
        self.btn_report.config(state=state)
        self.btn_pdf.config(state=state)
        self.btn_csv.config(state=state)
        self.btn_clear.config(state=state)
        self.btn_fix.config(state=state)

    # ── Save / Report ───────────────────────────────────────────
    def _save_results_json(self, results: list[dict[str, str]], os_type: str) -> None:
        """Save audit results to the results/ directory."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{os_type}_audit_{timestamp}.json"
        filepath = os.path.join(RESULTS_DIR, filename)

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        logger.info(f"Auto-saved JSON results to {filepath}")

    def _generate_report(self) -> None:
        """Generate an HTML audit report and open it in the browser."""
        if not self._last_results:
            logger.warning("Attempted to generate report with no data")
            messagebox.showwarning("No Data", "Run an audit first before generating a report.")
            return

        try:
            logger.info("Generating HTML report...")
            report_path = generate_html_report(self._last_results)
            logger.info(f"Report generated successfully at {report_path}")
            messagebox.showinfo("Report Generated", f"Report saved to:\n{report_path}")

            # Open the report in the default browser
            import webbrowser
            logger.info(f"Opening report in default browser...")
            file_url = Path(report_path).as_uri()
            webbrowser.open(file_url)
        except Exception as exc:
            logger.error(f"Report generation failed: {exc}")
            messagebox.showerror("Report Error", str(exc))

    def _generate_pdf(self) -> None:
        """Generate a PDF audit report."""
        if not self._last_results:
            logger.warning("Attempted to generate PDF report with no data")
            messagebox.showwarning("No Data", "Run an audit first before generating a report.")
            return

        try:
            from reports.generator import generate_pdf_report
            logger.info("Generating PDF report...")
            report_path = generate_pdf_report(self._last_results)
            logger.info(f"PDF Report generated successfully at {report_path}")
            messagebox.showinfo("Report Generated", f"PDF saved to:\n{report_path}")

            import webbrowser
            logger.info(f"Opening report in default browser...")
            file_url = Path(report_path).as_uri()
            webbrowser.open(file_url)
        except Exception as exc:
            logger.error(f"PDF generation failed: {exc}")
            messagebox.showerror("Report Error", str(exc))

    def _export_csv(self) -> None:
        """Export results to a simple CSV file."""
        if not self._last_results:
            logger.warning("Attempted to export CSV with no data")
            messagebox.showwarning("No Data", "Run an audit first before exporting.")
            return

        import csv
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"windows_audit_{timestamp}.csv"
        filepath = os.path.join(RESULTS_DIR, filename)

        try:
            with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["Check Name", "Status", "Details"])
                for item in self._last_results:
                    writer.writerow([item["check_name"], item["status"], item["details"]])
            
            logger.info(f"Exported CSV to {filepath}")
            messagebox.showinfo("Export Successful", f"CSV saved to:\n{filepath}")
        except Exception as exc:
            logger.error(f"CSV export failed: {exc}")
            messagebox.showerror("Export Error", str(exc))

    def _clear_table(self) -> None:
        """Clear all results from the table."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._last_results = []
        self.summary_label.config(text="Table cleared")
        self.status_label.config(text="")
        logger.info("Cleared results table")

    def _apply_filter(self, event=None) -> None:
        if not hasattr(self, '_last_results') or not self._last_results:
            return
            
        filter_val = getattr(self, 'filter_var', None)
        if filter_val:
            filter_val = filter_val.get()
        else:
            filter_val = "All"
            
        # Clear UI table only
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        pass_count = 0
        total_shown = 0
            
        for item in self._last_results:
            severity = item.get("severity", "")
            status = item.get("status", "")
            
            show = False
            if filter_val == "All":
                show = True
            elif filter_val == "Critical" and severity == "Critical":
                show = True
            elif filter_val == "Non-Critical" and severity != "Critical":
                show = True
            elif filter_val == "Must Fix" and status == "FAIL" and severity == "Critical":
                show = True
                
            if show:
                tag = "pass" if status == "PASS" else "fail"
                if tag == "pass":
                    pass_count += 1
                total_shown += 1
                
                self.tree.insert(
                    "", "end",
                    values=(
                        item["check_name"],
                        item["status"],
                        item.get("severity", ""),
                        item.get("impact", ""),
                        item["details"],
                    ),
                    tags=(tag,)
                )
                
        if total_shown > 0:
            self.summary_label.config(
                text=f"Showing: {total_shown} checks | Passed: {pass_count} | Failed: {total_shown - pass_count}"
            )

    def _auto_fix_issue(self) -> None:
        """Attempts to automatically fix the selected issue via PowerShell."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Select an Issue", "Please select a failed check from the table first.")
            return
            
        item_data = self.tree.item(selected_item[0])
        check_name = item_data["values"][0]
        status = item_data["values"][1]
        
        if status == "PASS":
            messagebox.showinfo("Already Passed", f"{check_name} is already secure.")
            return
            
        # Define setting pages / URIs for each check
        setting_pages = {
            "Minimum Password Length": "secpol.msc",
            "Account Lockout Threshold": "secpol.msc",
            "Firewall All Profiles": "control firewall.cpl",
            "Guest Account Disabled": "lusrmgr.msc",
            "AutoRun Disabled": "ms-settings:autoplay",
            "Lock Screen on Wake": "ms-settings:lockscreen",
            "Windows Defender Enabled": "windowsdefender:",
            "Remote Desktop Disabled": "ms-settings:remotedesktop",
            "Audit Logon Events": "secpol.msc",
            "BitLocker on C:": "control /name Microsoft.BitLockerDriveEncryption",
            "UAC Enabled": "UserAccountControlSettings.exe",
            "SMBv1 Disabled": "optionalfeatures.exe",
            "Windows Update Active": "ms-settings:windowsupdate",
            "PowerShell Execution Policy": "powershell.exe",
            "Administrator Account Renamed": "lusrmgr.msc",
        }
        
        if check_name not in setting_pages:
            messagebox.showwarning("Manual Fix Required", f"No settings page available for '{check_name}'. Please use the 'Guide/Fix' button to see the manual instructions.")
            return
            
        target_page = setting_pages[check_name]
        
        import os
        try:
            logger.info(f"Opening settings page for {check_name}: {target_page}")
            os.startfile(target_page)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open settings page: {e}")

    def _fix_issue(self) -> None:
        """Redirects to Microsoft Guide for fixing the selected issue."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Select an Issue", "Please select a failed check from the table first.")
            return
            
        item_data = self.tree.item(selected_item[0])
        check_name = item_data["values"][0]
        
        urls = {
            "Minimum Password Length": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length",
            "Account Lockout Threshold": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold",
            "Firewall All Profiles": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-defender-firewall/turn-on-windows-defender-firewall",
            "Guest Account Disabled": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status",
            "AutoRun Disabled": "https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
            "Lock Screen on Wake": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit",
            "Windows Defender Enabled": "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows",
            "Remote Desktop Disabled": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
            "Audit Logon Events": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon-events",
            "BitLocker on C:": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
            "UAC Enabled": "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works",
            "SMBv1 Disabled": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            "Windows Update Active": "https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wufb",
            "PowerShell Execution Policy": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies",
            "Administrator Account Renamed": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-rename-administrator-account",
        }
        
        target_url = urls.get(check_name, "https://learn.microsoft.com/en-us/windows/security/")
        
        logger.info(f"Redirecting to specific guide for {check_name}: {target_url}")
        import webbrowser
        try:
            success = webbrowser.open_new_tab(target_url)
            if not success:
                raise RuntimeError("webbrowser.open returned False")
        except Exception as e:
            logger.error(f"Failed to open browser: {e}")
            # If the browser fails to open automatically, show a popup so the user can copy it manually
            import tkinter as tk
            
            popup = tk.Toplevel(self.root)
            popup.title("Guide URL")
            popup.geometry("600x150")
            popup.configure(bg="#1e1e2e")
            
            tk.Label(popup, text="We couldn't open your browser automatically.", fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 11)).pack(pady=(15, 5))
            tk.Label(popup, text="Please copy and paste this URL into your browser:", fg="#cdd6f4", bg="#1e1e2e", font=("Segoe UI", 10)).pack()
            
            url_entry = tk.Entry(popup, width=70, font=("Segoe UI", 10))
            url_entry.insert(0, target_url)
            url_entry.config(state="readonly")
            url_entry.pack(pady=10)
            
            tk.Button(popup, text="Close", command=popup.destroy, bg="#f38ba8", fg="#1e1e2e", font=("Segoe UI", 10, "bold"), relief="flat").pack()

def main() -> None:
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
