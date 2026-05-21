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
        self.root.geometry("950x580")
        self.root.minsize(760, 460)
        self.root.configure(bg="#1e1e2e")

        import platform
        self.current_os = platform.system().lower()
        logger.info(f"Initializing CIS Audit Tool GUI... Host OS detected: {self.current_os}")
        self._last_results: list[dict[str, str]] = []

        self._build_header()
        self._build_toolbar()
        self._build_table()
        self._build_footer()

    def _add_hover_effect(self, btn, normal_bg, hover_bg) -> None:
        """Helper to bind modern hover transitions on buttons."""
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg) if btn["state"] != "disabled" else None)
        btn.bind("<Leave>", lambda e: btn.config(bg=normal_bg) if btn["state"] != "disabled" else None)

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

        # Dynamic premium platform badge
        os_name = "Windows" if self.current_os == "windows" else "Linux" if self.current_os == "linux" else self.current_os.capitalize()
        badge_color = "#89b4fa" if self.current_os == "windows" else "#a6e3a1"
        
        badge_frame = tk.Frame(header, bg=badge_color, padx=12, pady=4)
        badge_frame.pack(pady=(6, 0))
        
        tk.Label(
            badge_frame,
            text=f"💻  {os_name} Host Active",
            font=("Segoe UI", 9, "bold"),
            fg="#1e1e2e", bg=badge_color,
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

        os_name = "Windows" if self.current_os == "windows" else "Linux" if self.current_os == "linux" else "Host"
        self.btn_run_bg = "#89b4fa" if self.current_os == "windows" else "#a6e3a1"
        self.btn_run_hover = "#74c7ec" if self.current_os == "windows" else "#89dceb"

        self.btn_windows = tk.Button(
            bar, text=f"▶  Run {os_name} Audit",
            bg=self.btn_run_bg, fg="#1e1e2e",
            activebackground=self.btn_run_hover,
            command=lambda: self._run_audit(self.current_os),
            **btn_style,
        )
        self.btn_windows.pack(side="left")
        self._add_hover_effect(self.btn_windows, self.btn_run_bg, self.btn_run_hover)

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
        self._add_hover_effect(self.btn_report, "#cba6f7", "#b4befe")

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
        self._add_hover_effect(self.btn_pdf, "#f5c2e7", "#f5e0dc")

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
        self._add_hover_effect(self.btn_csv, "#f9e2af", "#f2cdcd")

        self.btn_clear = tk.Button(
            footer, text="🗑 Clear",
            font=("Segoe UI", 11, "bold"),
            bg="#f38ba8", fg="#1e1e2e",
            activebackground="#eba0ac",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._clear_table,
        )
        self.btn_clear.pack(side="left")
        self._add_hover_effect(self.btn_clear, "#f38ba8", "#eba0ac")

        autofix_text = "⚙️ Open Config" if self.current_os == "linux" else "⚙️ Open Settings"
        self.btn_autofix = tk.Button(
            footer, text=autofix_text,
            font=("Segoe UI", 11, "bold"),
            bg="#a6e3a1", fg="#1e1e2e",
            activebackground="#89dceb",
            relief="flat", cursor="hand2",
            padx=18, pady=6,
            command=self._auto_fix_issue,
        )
        self.btn_autofix.pack(side="left", padx=(10, 0))
        self._add_hover_effect(self.btn_autofix, "#a6e3a1", "#89dceb")

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
        self._add_hover_effect(self.btn_fix, "#fab387", "#f9e2af")

        self.summary_label = tk.Label(
            footer, text="No audit run yet",
            font=("Segoe UI", 10),
            fg="#6c7086", bg="#1e1e2e",
        )
        self.summary_label.pack(side="left", padx=(15, 0))

    # ── Audit Runner ────────────────────────────────────────────
    def _run_audit(self, os_type: str) -> None:
        """Run the selected audit in a background thread."""
        self._set_buttons_enabled(False)
        msg = f"Starting {os_type} audit..."
        self.status_label.config(text=msg)
        logger.info(msg)

        def task() -> None:
            try:
                if os_type == "linux":
                    from audits import linux
                    results = linux.run_all_checks()
                else:
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
                        item.get("check_name", "Unknown"),
                        item.get("status", "FAIL"),
                        item.get("severity", "Medium"),
                        item.get("impact", "System-Wide"),
                        item.get("details", "")
                    ),
                    tags=(tag,)
                )
                
        # Update summary label
        if total_shown > 0:
            pass_rate = (pass_count / total_shown) * 100
            self.summary_label.config(text=f"Total: {total_shown} | Passed: {pass_count} ({pass_rate:.1f}%)")
        else:
            self.summary_label.config(text="No checks match the filter")

    def _open_path_or_url(self, target: str) -> None:
        """Opens a file path, directory, or URL in a cross-platform manner."""
        import platform
        import subprocess
        import webbrowser
        
        if target.startswith("http://") or target.startswith("https://"):
            webbrowser.open_new_tab(target)
            return

        system = platform.system().lower()
        try:
            if system == "windows":
                os.startfile(target)
            elif system == "darwin":
                subprocess.run(["open", target], check=True)
            else:  # Linux, FreeBSD, etc.
                subprocess.run(["xdg-open", target], check=True)
            logger.info(f"Successfully opened cross-platform target: {target}")
        except Exception as e:
            logger.error(f"Failed to open '{target}': {e}")
            messagebox.showerror("Error", f"Failed to open '{target}':\n{e}")

    def _auto_fix_issue(self) -> None:
        """Attempts to automatically open settings/config file for the selected issue."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Select an Issue", "Please select an issue from the table first.")
            return
            
        item_data = self.tree.item(selected_item[0])
        check_name = item_data["values"][0]
        status = item_data["values"][1]
        
        if status == "PASS":
            messagebox.showinfo("Already Passed", f"'{check_name}' is already secure.")
            return
            
        windows_pages = {
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

        linux_pages = {
            "Minimum Password Length": "/etc/security/pwquality.conf",
            "Password Expiration": "/etc/login.defs",
            "SSH Root Login Disabled": "/etc/ssh",
            "SSH Password Authentication": "/etc/ssh",
            "Firewall All Profiles": "/etc/default",
            "Windows Update Active": "/etc/apt/apt.conf.d",
            "AutoRun Disabled": "/etc/sysctl.conf",
            "Windows Defender Enabled": "/etc/apparmor.d",
            "Guest Account Disabled": "/etc/passwd",
            "Umask Configuration": "/etc/login.defs",
            "Lock Screen on Wake": "/etc/security/limits.conf",
            "Audit Logon Events": "/etc/audit",
            "BitLocker on C:": "/tmp",
            "Remote Desktop Disabled": "/etc/modprobe.d",
            "Sudo Security": "/etc/sudoers.d",
            "UAC Enabled": "/etc/sudoers",
            "SMBv1 Disabled": "/etc/samba",
            "Administrator Account Renamed": "/etc/passwd",
        }

        pages = linux_pages if self.current_os == "linux" else windows_pages
        
        if check_name not in pages:
            messagebox.showwarning("Manual Fix Required", f"No config page shortcut mapped for '{check_name}'. Please click 'Guide/Fix' to see the manual instructions.")
            return
            
        target = pages[check_name]
        self._open_path_or_url(target)

    def _fix_issue(self) -> None:
        """Opens a premium, in-app security guide dialog with instructions and clipboard action."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showinfo("Select an Issue", "Please select a check from the table first.")
            return
            
        item_data = self.tree.item(selected_item[0])
        check_name = item_data["values"][0]
        status = item_data["values"][1]
        severity = item_data["values"][2]
        impact = item_data["values"][3]
        details = item_data["values"][4]

        # Detailed local guides catalog
        windows_guides = {
            "Minimum Password Length": {
                "desc": "Enforces passwords to be at least 14 characters, preventing brute-force and dictionary attacks.",
                "fix": "Run secpol.msc -> Account Policies -> Password Policy -> Double-click 'Minimum password length' -> Set to 14 or higher."
            },
            "Account Lockout Threshold": {
                "desc": "Locks accounts temporarily after multiple failed login attempts to thwart automated brute forcing.",
                "fix": "Run secpol.msc -> Account Policies -> Account Lockout Policy -> Set 'Account lockout threshold' to 5 or fewer attempts."
            },
            "Firewall All Profiles": {
                "desc": "Ensures the system firewall is actively filtering inbound/outbound packets across Domain, Public, and Private environments.",
                "fix": "Open 'control firewall.cpl' -> Click 'Turn Windows Defender Firewall on or off' -> Enable Firewall for all profiles."
            },
            "Guest Account Disabled": {
                "desc": "Disables default anonymous guest privileges to stop unauthorized users from accessing system resources.",
                "fix": "Run lusrmgr.msc -> Users -> Double-click 'Guest' -> Check 'Account is disabled'."
            },
            "AutoRun Disabled": {
                "desc": "Disables AutoRun behavior to block physical vector attacks like infected USB key drops.",
                "fix": "Open Registry Editor -> HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer -> Set NoDriveTypeAutoRun to 255 (DWORD)."
            },
            "Lock Screen on Wake": {
                "desc": "Requires password validation upon system wake-up to maintain session integrity when leaving your machine unattended.",
                "fix": "Open Settings -> Accounts -> Sign-in options -> Set 'Require sign-in' to 'Every Time'."
            },
            "Windows Defender Enabled": {
                "desc": "Maintains real-time host protection active to continually intercept, scan, and block malware payloads.",
                "fix": "Open Windows Security -> Virus & threat protection -> Manage settings -> Set 'Real-time protection' to ON."
            },
            "Remote Desktop Disabled": {
                "desc": "Disables remote desktop services to shrink the network attack surface from network brute-forcing.",
                "fix": "Open Settings -> System -> Remote Desktop -> Toggle 'Remote Desktop' to OFF."
            },
            "Audit Logon Events": {
                "desc": "Enables successful/failed logon event logs to generate security audit trails.",
                "fix": "Run secpol.msc -> Local Policies -> Audit Policy -> Set 'Audit logon events' to Success and Failure."
            },
            "BitLocker on C:": {
                "desc": "Protects system disk data with full-drive AES encryption in case of physical drive theft.",
                "fix": "Search 'BitLocker' in Start menu -> Click 'Turn on BitLocker' on C: drive -> Keep recovery keys safe."
            },
            "UAC Enabled": {
                "desc": "Requires confirmation prompts before allowing execution of system-altering operations.",
                "fix": "Run UserAccountControlSettings.exe -> Drag slider to the default third notch (Notify me only when apps try to make changes)."
            },
            "SMBv1 Disabled": {
                "desc": "Disables the highly insecure, deprecated legacy SMBv1 protocol to block remote exploit vectors (e.g. WannaCry).",
                "fix": "Run optionalfeatures.exe -> Scroll down to 'SMB 1.0/CIFS File Sharing Support' -> Uncheck and click OK -> Restart PC."
            },
            "Windows Update Active": {
                "desc": "Forces system automatic package installations to keep Windows secure against zero-day vulnerabilities.",
                "fix": "Open Settings -> Windows Update -> Check for updates -> Enable automatic installs and updates."
            },
            "PowerShell Execution Policy": {
                "desc": "Restricts PowerShell script execution scopes to safe parameters (RemoteSigned or Restricted).",
                "fix": "Open PowerShell as Administrator and run:\nSet-ExecutionPolicy RemoteSigned -Force"
            },
            "Administrator Account Renamed": {
                "desc": "Renames default built-in 'Administrator' to protect against default credentials brute forcing.",
                "fix": "Run lusrmgr.msc -> Users -> Right-click default 'Administrator' -> Click 'Rename' and enter a custom username."
            }
        }

        linux_guides = {
            "Minimum Password Length": {
                "desc": "Enforces a minimum password length policy of 14 characters to prevent credential cracking.",
                "fix": "Edit /etc/security/pwquality.conf and add/modify:\nminlen = 14\n\nOr edit /etc/login.defs and set:\nPASS_MIN_LEN 14"
            },
            "Password Expiration": {
                "desc": "Requires users to change credentials every 90 days to shrink active exposure periods.",
                "fix": "Edit /etc/login.defs and configure:\nPASS_MAX_DAYS 90"
            },
            "SSH Root Login Disabled": {
                "desc": "Disables SSH remote login as 'root' to enforce credential accountability and local logging.",
                "fix": "Edit /etc/ssh/sshd_config and set:\nPermitRootLogin no\n\nThen restart SSH daemon:\nsudo systemctl restart ssh"
            },
            "SSH Password Authentication": {
                "desc": "Disables vulnerable SSH password prompts to mandate highly secure key-based remote authentication.",
                "fix": "Edit /etc/ssh/sshd_config and configure:\nPasswordAuthentication no\n\nThen restart SSH service:\nsudo systemctl restart ssh"
            },
            "Firewall All Profiles": {
                "desc": "Ensures the system runs an active local firewall wrapper to drop unauthorized network connections.",
                "fix": "For UFW (Ubuntu/Debian):\nsudo ufw enable\n\nFor Firewalld (RHEL/CentOS):\nsudo systemctl enable --now firewalld"
            },
            "Windows Update Active": {
                "desc": "Configures automatic package updates to deploy system and security patches daily without manual latency.",
                "fix": "For APT (Debian/Ubuntu):\nsudo apt install unattended-upgrades\nsudo dpkg-reconfigure --priority=low unattended-upgrades\n\nFor DNF (RHEL/CentOS):\nsudo dnf install dnf-automatic\nsudo systemctl enable --now dnf-automatic-install.timer"
            },
            "AutoRun Disabled": {
                "desc": "Address Space Layout Randomization (ASLR) randomizes process memory structures to block buffer overflow exploits.",
                "fix": "Enable ASLR permanently, edit /etc/sysctl.conf and add:\nkernel.randomize_va_space = 2\n\nApply immediately:\nsudo sysctl -p"
            },
            "Windows Defender Enabled": {
                "desc": "Enforces AppArmor or SELinux Mandatory Access Controls to secure host processes against filesystem privilege escalation.",
                "fix": "For AppArmor (Debian/Ubuntu):\nsudo systemctl enable --now apparmor\n\nFor SELinux (RHEL/CentOS):\nsudo setenforce 1\n(Edit /etc/selinux/config to set SELINUX=enforcing)"
            },
            "Guest Account Disabled": {
                "desc": "Confirms that only the legitimate 'root' user possesses UID 0 superuser status on the system.",
                "fix": "Scan /etc/passwd and inspect accounts with UID 0. Remove unauthorized UID 0 accounts:\nsudo userdel <username>"
            },
            "Umask Configuration": {
                "desc": "Enforces default file permissions of 027 or tighter to block standard users from reading newly created group/other files.",
                "fix": "Edit /etc/login.defs and add/update:\nUMASK 027"
            },
            "Lock Screen on Wake": {
                "desc": "Configures core dumps restrictions system-wide to prevent sensitive application RAM credentials from caching on disks.",
                "fix": "Edit /etc/security/limits.conf and add:\n* hard core 0\n\nOr edit /etc/sysctl.conf:\nfs.suid_dumpable = 0"
            },
            "Audit Logon Events": {
                "desc": "Integrates kernel system activity and authorization logging via auditd to generate security access trails.",
                "fix": "Install and enable audit daemon:\nsudo apt install auditd && sudo systemctl enable --now auditd\n\nOr on RHEL:\nsudo dnf install audit && sudo systemctl enable --now auditd"
            },
            "BitLocker on C:": {
                "desc": "Sets the sticky bit permission (+t) on world-writable storage areas to prevent users from deleting others' files.",
                "fix": "Set sticky bits on tmp systems:\nsudo chmod +t /tmp\nsudo chmod +t /var/tmp"
            },
            "Remote Desktop Disabled": {
                "desc": "Blacklists the kernel driver module for usb-storage devices to prevent local physical usb keys data extraction.",
                "fix": "Disable usb-storage driver module, add to /etc/modprobe.d/usb-storage.conf:\nblacklist usb-storage\ninstall usb-storage /bin/true"
            },
            "Sudo Security": {
                "desc": "Enforces complete password verification for every sudo action, eliminating insecure NOPASSWD user settings.",
                "fix": "Edit sudoers safely using visudo:\nsudo visudo\n\nLocate and comment/delete any lines containing 'NOPASSWD:'."
            },
            "UAC Enabled": {
                "desc": "Mandates that all privilege escalations run within a verified, interactive TTY screen.",
                "fix": "Open /etc/sudoers using visudo:\nsudo visudo\n\nEnsure this line is uncommented and present:\nDefaults requiretty"
            },
            "SMBv1 Disabled": {
                "desc": "Ensures the vulnerable legacy SMBv1 networking daemon is closed or blocked to avoid ransomware spreads.",
                "fix": "Disable the samba share server service:\nsudo systemctl disable --now smbd\n\nOr edit /etc/samba/smb.conf [global]:\nserver min protocol = SMB2"
            },
            "Administrator Account Renamed": {
                "desc": "Eliminates generic administration names 'admin' and 'administrator' from passwd to disable standard brute force scans.",
                "fix": "Rename generic admin account usernames:\nsudo usermod -l <custom_username> admin"
            }
        }

        guides = linux_guides if self.current_os == "linux" else windows_guides
        guide = guides.get(check_name, {
            "desc": "No detailed description currently loaded.",
            "fix": "Please check standard CIS benchmarks for local OS configurations."
        })

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
        fallback_url = "https://learn.microsoft.com/en-us/windows/security/" if self.current_os == "windows" else "https://www.cisecurity.org/benchmark/distribution_independent_linux"
        target_url = urls.get(check_name, fallback_url)

        # ── GUI Guided Window Creation (Catppuccin Theme) ─────────────────
        popup = tk.Toplevel(self.root)
        popup.title(f"🛡  Remediation Guide — {check_name}")
        popup.geometry("680x520")
        popup.minsize(580, 440)
        popup.configure(bg="#1e1e2e")
        popup.transient(self.root)
        popup.grab_set()

        # 1. Header Frame
        header = tk.Frame(popup, bg="#1e1e2e")
        header.pack(fill="x", padx=25, pady=(20, 10))

        tk.Label(
            header,
            text=check_name,
            font=("Segoe UI", 16, "bold"),
            fg="#cdd6f4", bg="#1e1e2e"
        ).pack(anchor="w")

        meta_frame = tk.Frame(header, bg="#1e1e2e")
        meta_frame.pack(fill="x", pady=(6, 0))

        # Severity indicators
        sev_colors = {"Critical": "#f38ba8", "High": "#fab387", "Medium": "#f9e2af", "Low": "#a6e3a1"}
        sev_color = sev_colors.get(severity, "#cdd6f4")
        
        tk.Label(
            meta_frame,
            text=f" Severity: {severity.upper()} ",
            font=("Segoe UI", 9, "bold"),
            fg="#1e1e2e", bg=sev_color,
            padx=6, pady=2
        ).pack(side="left")

        # Status badge
        status_color = "#a6e3a1" if status == "PASS" else "#f38ba8"
        tk.Label(
            meta_frame,
            text=f" Status: {status} ",
            font=("Segoe UI", 9, "bold"),
            fg="#1e1e2e", bg=status_color,
            padx=6, pady=2
        ).pack(side="left", padx=(10, 0))

        # Impact category
        tk.Label(
            meta_frame,
            text=f"Impact: {impact}",
            font=("Segoe UI", 9, "bold"),
            fg="#6c7086", bg="#1e1e2e"
        ).pack(side="right")

        # 2. Main content container
        content_frame = tk.Frame(popup, bg="#1e1e2e")
        content_frame.pack(fill="both", expand=True, padx=25, pady=5)

        tk.Label(
            content_frame, text="Security Context / Vulnerability Details",
            font=("Segoe UI", 10, "bold"),
            fg="#bac2de", bg="#1e1e2e"
        ).pack(anchor="w", pady=(8, 4))

        desc_box = tk.Text(
            content_frame, font=("Segoe UI", 10),
            fg="#a6adc8", bg="#181825",
            relief="flat", height=4, wrap="word"
        )
        desc_box.pack(fill="x")
        desc_box.insert("1.0", guide["desc"] + f"\n\nDetails reported: {details}")
        desc_box.config(state="disabled")

        tk.Label(
            content_frame, text="Step-by-Step Security Remediation",
            font=("Segoe UI", 10, "bold"),
            fg="#a6e3a1", bg="#1e1e2e"
        ).pack(anchor="w", pady=(12, 4))

        remed_box = tk.Text(
            content_frame, font=("Consolas", 10),
            fg="#cdd6f4", bg="#313244",
            relief="flat", borderwidth=8, wrap="word"
        )
        remed_box.pack(fill="both", expand=True)
        remed_box.insert("1.0", guide["fix"])
        remed_box.config(state="disabled")

        # 3. Actions Button Footer
        btn_bar = tk.Frame(popup, bg="#1e1e2e")
        btn_bar.pack(fill="x", padx=25, pady=(15, 20))

        # Clipboard helper
        def copy_remed():
            popup.clipboard_clear()
            popup.clipboard_append(guide["fix"])
            popup.update() # Keeps clipboard persistent
            messagebox.showinfo("Copied", "Remediation commands successfully copied to clipboard!", parent=popup)

        btn_style = {
            "font": ("Segoe UI", 10, "bold"),
            "relief": "flat",
            "cursor": "hand2",
            "padx": 14, "pady": 5,
        }

        # Close
        btn_close = tk.Button(btn_bar, text="Close", bg="#f38ba8", fg="#1e1e2e", activebackground="#eba0ac", command=popup.destroy, **btn_style)
        btn_close.pack(side="right")
        self._add_hover_effect(btn_close, "#f38ba8", "#eba0ac")

        # Open Config
        autofix_text = "⚙️ Open Config" if self.current_os == "linux" else "⚙️ Open Settings"
        btn_cfg = tk.Button(
            btn_bar, text=autofix_text,
            bg="#a6e3a1", fg="#1e1e2e",
            activebackground="#89dceb",
            command=lambda: [popup.destroy(), self._auto_fix_issue()],
            **btn_style
        )
        btn_cfg.pack(side="left")
        self._add_hover_effect(btn_cfg, "#a6e3a1", "#89dceb")

        # Copy Instructions
        btn_copy = tk.Button(btn_bar, text="📋 Copy Code", bg="#89b4fa", fg="#1e1e2e", activebackground="#74c7ec", command=copy_remed, **btn_style)
        btn_copy.pack(side="left", padx=(10, 0))
        self._add_hover_effect(btn_copy, "#89b4fa", "#74c7ec")

        # More Info (Online)
        btn_online = tk.Button(
            btn_bar, text="🌍 Online Guide",
            bg="#cba6f7", fg="#1e1e2e",
            activebackground="#b4befe",
            command=lambda: self._open_path_or_url(target_url),
            **btn_style
        )
        btn_online.pack(side="left", padx=(10, 0))
        self._add_hover_effect(btn_online, "#cba6f7", "#b4befe")

def main() -> None:
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
