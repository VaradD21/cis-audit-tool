import json
import os
import logging
import threading
import platform
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, messagebox, filedialog
from reports.generator import generate_html_report
from audits.guides import WINDOWS_GUIDES, LINUX_GUIDES, URLS

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("CIS-Audit")

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "results"))
os.makedirs(RESULTS_DIR, exist_ok=True)

THEMES = {
    "dark": {
        "bg": "#1e1e2e",
        "fg": "#cdd6f4",
        "card": "#313244",
        "accent": "#cba6f7",
        "text_mute": "#6c7086",
        "badge_bg": "#313244",
        "btn_run": "#89b4fa" if platform.system().lower() == "windows" else "#a6e3a1",
        "btn_run_hover": "#74c7ec" if platform.system().lower() == "windows" else "#89dceb",
        "tree_bg": "#313244",
        "tree_fg": "#cdd6f4",
        "tree_hdr": "#45475a"
    },
    "light": {
        "bg": "#eff1f5",
        "fg": "#4c4f69",
        "card": "#e6e9ef",
        "accent": "#7287fd",
        "text_mute": "#8c8fa1",
        "badge_bg": "#ccd0da",
        "btn_run": "#1e66f5",
        "btn_run_hover": "#04a5e5",
        "tree_bg": "#ffffff",
        "tree_fg": "#4c4f69",
        "tree_hdr": "#dce0e8"
    }
}

class AuditApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CIS Benchmark Audit Tool")
        self.root.geometry("1000x620")
        self.root.minsize(800, 500)
        
        self.current_os = platform.system().lower()
        self.dark_mode = True
        self._last_results = []
        
        self._build_interface()
        self.apply_theme()

    def _build_interface(self) -> None:
        self.header = tk.Frame(self.root)
        self.header.pack(fill="x", pady=(15, 5))

        self.lbl_title = tk.Label(self.header, text="🛡  CIS Benchmark Audit Tool", font=("Segoe UI", 16, "bold"))
        self.lbl_title.pack()

        self.lbl_sub = tk.Label(self.header, text="Run security hardening audits dynamically based on official CIS baselines", font=("Segoe UI", 10))
        self.lbl_sub.pack(pady=(2, 0))

        # Dynamic Host System Inspector
        os_info = "Windows" if self.current_os == "windows" else "Linux" if self.current_os == "linux" else platform.system()
        badge_color = "#89b4fa" if self.current_os == "windows" else "#a6e3a1"
        host_name = platform.node()
        kernel = platform.release()
        
        self.badge = tk.Frame(self.header, bg=badge_color, padx=12, pady=4)
        self.badge.pack(pady=8)
        self.badge.is_badge = True
        
        tk.Label(
            self.badge, 
            text=f"💻  {os_info} Host Active: {host_name} ({kernel})", 
            font=("Segoe UI", 9, "bold"), 
            fg="#1e1e2e", bg=badge_color
        ).pack()

        # Toolbar & Filter
        self.toolbar = tk.Frame(self.root)
        self.toolbar.pack(fill="x", padx=20, pady=(10, 5))

        btn_style = {"font": ("Segoe UI", 10, "bold"), "relief": "flat", "cursor": "hand2", "padx": 15, "pady": 5}
        
        os_label = "Windows" if self.current_os == "windows" else "Linux"
        self.btn_windows = tk.Button(self.toolbar, text=f"▶  Run {os_label} Audit", command=lambda: self._run_audit(self.current_os), **btn_style)
        self.btn_windows.pack(side="left")

        # Live Filter Combobox
        filter_frame = tk.Frame(self.toolbar)
        filter_frame.pack(side="left", padx=(20, 0))
        
        self.lbl_filter = tk.Label(filter_frame, text="Filter:", font=("Segoe UI", 10))
        self.lbl_filter.pack(side="left")

        self.filter_var = tk.StringVar(value="All")
        self.filter_cb = ttk.Combobox(filter_frame, textvariable=self.filter_var, state="readonly", width=12, font=("Segoe UI", 10))
        self.filter_cb["values"] = ("All", "Critical", "Non-Critical", "Must Fix")
        self.filter_cb.pack(side="left", padx=(5, 0))
        self.filter_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        # Live Search Bar
        self.lbl_search = tk.Label(filter_frame, text="Search:", font=("Segoe UI", 10))
        self.lbl_search.pack(side="left", padx=(15, 0))
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(filter_frame, textvariable=self.search_var, font=("Segoe UI", 10), width=16)
        self.search_entry.pack(side="left", padx=(5, 0))
        self.search_var.trace_add("write", lambda *args: self._apply_filter())

        # Theme Switcher Button
        self.btn_theme = tk.Button(self.toolbar, text="🌓 Theme", command=self.toggle_theme, **btn_style)
        self.btn_theme.pack(side="right")

        self.status_label = tk.Label(self.toolbar, text="", font=("Segoe UI", 10, "italic"))
        self.status_label.pack(side="right", padx=(0, 15))

        # Results Grid View
        self.table_container = tk.Frame(self.root)
        self.table_container.pack(fill="both", expand=True, padx=20, pady=5)

        columns = ("check_name", "status", "severity", "impact", "details")
        self.tree = ttk.Treeview(self.table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("check_name", text="Check Name", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("severity", text="Severity", anchor="center")
        self.tree.heading("impact", text="Impact", anchor="center")
        self.tree.heading("details", text="Details", anchor="w")

        self.tree.column("check_name", width=220, minwidth=180)
        self.tree.column("status", width=90, minwidth=80, anchor="center")
        self.tree.column("severity", width=90, minwidth=80, anchor="center")
        self.tree.column("impact", width=120, minwidth=100, anchor="center")
        self.tree.column("details", width=420, minwidth=250)

        self.tree.tag_configure("pass", background="#a6e3a1", foreground="#1e1e2e")
        self.tree.tag_configure("fail", background="#f38ba8", foreground="#1e1e2e")

        self.scrollbar = ttk.Scrollbar(self.table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Footer Actions Panel
        self.footer = tk.Frame(self.root)
        self.footer.pack(fill="x", padx=20, pady=(5, 15))

        self.btn_report = tk.Button(self.footer, text="📄 HTML Report", command=self._generate_report, **btn_style)
        self.btn_report.pack(side="right")

        self.btn_pdf = tk.Button(self.footer, text="📄 PDF Report", command=self._generate_pdf, **btn_style)
        self.btn_pdf.pack(side="right", padx=(0, 10))

        self.btn_csv = tk.Button(self.footer, text="📊 CSV Export", command=self._export_csv, **btn_style)
        self.btn_csv.pack(side="right", padx=(0, 10))

        self.btn_clear = tk.Button(self.footer, text="🗑 Clear", command=self._clear_table, **btn_style)
        self.btn_clear.pack(side="left")

        self.btn_autofix = tk.Button(self.footer, text="⚙️ Open Settings", command=self._auto_fix_issue, **btn_style)
        self.btn_autofix.pack(side="left", padx=(10, 0))

        self.btn_fix = tk.Button(self.footer, text="🔧 Guide / Fix", command=self._fix_issue, **btn_style)
        self.btn_fix.pack(side="left", padx=(10, 0))

        # Batch Script Exporter Button
        self.btn_export_script = tk.Button(self.footer, text="📦 Export Fix Script", command=self._export_fix_script, **btn_style)
        self.btn_export_script.pack(side="left", padx=(10, 0))

        self.summary_label = tk.Label(self.footer, text="System idle. Ready to audit.", font=("Segoe UI", 9))
        self.summary_label.pack(side="left", padx=(15, 0))

    def _add_hover_effect(self, btn, normal_bg, hover_bg) -> None:
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg) if btn["state"] != "disabled" else None)
        btn.bind("<Leave>", lambda e: btn.config(bg=normal_bg) if btn["state"] != "disabled" else None)

    def toggle_theme(self) -> None:
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def apply_theme(self) -> None:
        theme = THEMES["dark"] if self.dark_mode else THEMES["light"]
        self.root.configure(bg=theme["bg"])

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background=theme["tree_bg"],
                        foreground=theme["tree_fg"],
                        fieldbackground=theme["tree_bg"],
                        font=("Segoe UI", 10),
                        rowheight=35)
        style.configure("Treeview.Heading",
                        background=theme["tree_hdr"],
                        foreground=theme["fg"],
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", theme["accent"])])

        def apply_colors(widget):
            widget_class = widget.winfo_class()
            
            # Badge frames bypass normal backgrounds
            if hasattr(widget, "is_badge"):
                return

            if widget_class in ("Frame", "Labelframe"):
                widget.configure(bg=theme["bg"])
            elif widget_class == "Label":
                widget.configure(bg=theme["bg"], fg=theme["fg"])
            elif widget_class == "Entry":
                widget.configure(bg=theme["tree_bg"], fg=theme["tree_fg"], insertbackground=theme["fg"])
            elif widget_class == "Button":
                if widget not in (self.btn_windows, self.btn_clear):
                    widget.configure(bg=theme["card"], fg=theme["fg"], activebackground=theme["accent"], activeforeground="#1e1e2e")
                    self._add_hover_effect(widget, theme["card"], theme["accent"])

            for child in widget.winfo_children():
                apply_colors(child)

        apply_colors(self.root)
        
        # Explicit styles for highlight actions
        self.btn_windows.configure(bg=theme["btn_run"], fg="#1e1e2e", activebackground=theme["btn_run_hover"])
        self._add_hover_effect(self.btn_windows, theme["btn_run"], theme["btn_run_hover"])
        
        self.btn_clear.configure(bg="#f38ba8", fg="#1e1e2e", activebackground="#eba0ac")
        self._add_hover_effect(self.btn_clear, "#f38ba8", "#eba0ac")
        
        self.lbl_title.configure(fg=theme["accent"])
        self.lbl_sub.configure(fg=theme["text_mute"])
        self.summary_label.configure(fg=theme["text_mute"])
        self.status_label.configure(fg=theme["accent"])

        autofix_text = "⚙️ Open Config" if self.current_os == "linux" else "⚙️ Open Settings"
        self.btn_autofix.configure(text=autofix_text)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.btn_windows.config(state=state)
        self.btn_report.config(state=state)
        self.btn_pdf.config(state=state)
        self.btn_csv.config(state=state)
        self.btn_clear.config(state=state)
        self.btn_fix.config(state=state)
        self.btn_autofix.config(state=state)
        self.btn_export_script.config(state=state)

    def _run_audit(self, os_type: str) -> None:
        self._set_buttons_enabled(False)
        self.status_label.config(text=f"Auditing system...")

        def thread_task() -> None:
            try:
                if os_type == "linux":
                    from audits import linux
                    results = linux.run_all_checks()
                else:
                    from audits import windows
                    results = windows.run_all_checks()
                self.root.after(0, lambda: self._display_results(results, os_type))
            except Exception as e:
                self.root.after(0, lambda: self._show_error(str(e)))

        threading.Thread(target=thread_task, daemon=True).start()

    def _display_results(self, results: list[dict[str, str]], os_type: str) -> None:
        self._last_results = results
        self._apply_filter()
        self.status_label.config(text="✓ Audit Complete")
        self._set_buttons_enabled(True)
        self._save_results_json(results, os_type)

    def _show_error(self, message: str) -> None:
        self.status_label.config(text="✗ Error")
        self._set_buttons_enabled(True)
        messagebox.showerror("Audit Error", message)

    def _save_results_json(self, results: list[dict[str, str]], os_type: str) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(RESULTS_DIR, f"{os_type}_audit_{timestamp}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Auto-saved results: {filepath}")

    def _apply_filter(self) -> None:
        if not self._last_results:
            return
        
        filter_val = self.filter_var.get()
        search_term = self.search_var.get().strip().lower()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        pass_count = 0
        total_shown = 0
            
        for item in self._last_results:
            severity = item.get("severity", "Medium")
            status = item.get("status", "FAIL")
            check_name = item.get("check_name", "Unknown")
            details = item.get("details", "")
            
            show = False
            if filter_val == "All":
                show = True
            elif filter_val == "Critical" and severity == "Critical":
                show = True
            elif filter_val == "Non-Critical" and severity != "Critical":
                show = True
            elif filter_val == "Must Fix" and status == "FAIL" and severity == "Critical":
                show = True
                
            if show and search_term:
                if search_term not in check_name.lower() and search_term not in details.lower():
                    show = False

            if show:
                tag = "pass" if status == "PASS" else "fail"
                if tag == "pass":
                    pass_count += 1
                total_shown += 1
                
                self.tree.insert(
                    "", "end",
                    values=(check_name, status, severity, item.get("impact", "System-Wide"), details),
                    tags=(tag,)
                )
                
        if total_shown > 0:
            rate = (pass_count / total_shown) * 100
            self.summary_label.config(text=f"Shown: {total_shown} | Passed: {pass_count} ({rate:.1f}%)")
        else:
            self.summary_label.config(text="No matching checks found")

    def _open_path_or_url(self, target: str) -> None:
        import subprocess
        import webbrowser
        
        if target.startswith("http://") or target.startswith("https://"):
            webbrowser.open_new_tab(target)
            return

        sys_name = platform.system().lower()
        try:
            if sys_name == "windows":
                os.startfile(target)
            elif sys_name == "darwin":
                subprocess.run(["open", target], check=True)
            else:
                subprocess.run(["xdg-open", target], check=True)
        except Exception as e:
            logger.error(f"Failed to open '{target}': {e}")
            messagebox.showerror("Error", f"Failed to open '{target}':\n{e}")

    def _auto_fix_issue(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Check", "Please select a security check from the grid first.")
            return
            
        check_name = self.tree.item(selected[0])["values"][0]
        status = self.tree.item(selected[0])["values"][1]
        
        if status == "PASS":
            messagebox.showinfo("Already Secure", f"'{check_name}' is already compliant.")
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
            messagebox.showwarning("Manual Hardening Required", f"No dynamic shortcut mapped for '{check_name}'. Please review manual Guide.")
            return
            
        self._open_path_or_url(pages[check_name])

    def _fix_issue(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Check", "Please select a security check from the grid first.")
            return
            
        item = self.tree.item(selected[0])
        check_name, status, severity, impact, details = item["values"]

        guides = LINUX_GUIDES if self.current_os == "linux" else WINDOWS_GUIDES
        guide = guides.get(check_name, {
            "desc": "Manual baseline security configuration recommended.",
            "fix": "Please check official vendor benchmarks for your local platform configuration."
        })
        
        fallback_url = "https://learn.microsoft.com/en-us/windows/security/" if self.current_os == "windows" else "https://www.cisecurity.org/"
        target_url = URLS.get(check_name, fallback_url)

        theme = THEMES["dark"] if self.dark_mode else THEMES["light"]

        # In-App Premium Remediation Wizard Dialog
        popup = tk.Toplevel(self.root)
        popup.title(f"Remediation Hardening Guide — {check_name}")
        popup.geometry("680x520")
        popup.minsize(580, 440)
        popup.configure(bg=theme["bg"])
        popup.transient(self.root)
        popup.grab_set()

        # Header Frame
        hdr = tk.Frame(popup, bg=theme["bg"])
        hdr.pack(fill="x", padx=25, pady=(20, 10))

        tk.Label(hdr, text=check_name, font=("Segoe UI", 15, "bold"), fg=theme["accent"], bg=theme["bg"]).pack(anchor="w")

        meta = tk.Frame(hdr, bg=theme["bg"])
        meta.pack(fill="x", pady=6)

        sev_colors = {"Critical": "#f38ba8", "High": "#fab387", "Medium": "#f9e2af", "Low": "#a6e3a1"}
        sev_color = sev_colors.get(severity, theme["accent"])
        
        tk.Label(meta, text=f" Severity: {severity.upper()} ", font=("Segoe UI", 9, "bold"), fg="#1e1e2e", bg=sev_color, padx=6, pady=2).pack(side="left")

        status_color = "#a6e3a1" if status == "PASS" else "#f38ba8"
        tk.Label(meta, text=f" Status: {status} ", font=("Segoe UI", 9, "bold"), fg="#1e1e2e", bg=status_color, padx=6, pady=2).pack(side="left", padx=10)

        tk.Label(meta, text=f"Impact Scope: {impact}", font=("Segoe UI", 9, "bold"), fg=theme["text_mute"], bg=theme["bg"]).pack(side="right")

        # Content Frame
        content = tk.Frame(popup, bg=theme["bg"])
        content.pack(fill="both", expand=True, padx=25, pady=5)

        tk.Label(content, text="Context & Vulnerability Details", font=("Segoe UI", 10, "bold"), fg=theme["fg"], bg=theme["bg"]).pack(anchor="w", pady=(8, 4))

        desc_box = tk.Text(content, font=("Segoe UI", 10), fg=theme["tree_fg"], bg=theme["tree_bg"], relief="flat", height=4, wrap="word")
        desc_box.pack(fill="x")
        desc_box.insert("1.0", f"{guide['desc']}\n\nSystem details reported: {details}")
        desc_box.config(state="disabled")

        tk.Label(content, text="Remediation Hardening Actions", font=("Segoe UI", 10, "bold"), fg=theme["accent"], bg=theme["bg"]).pack(anchor="w", pady=(12, 4))

        remed_box = tk.Text(content, font=("Consolas", 10), fg=theme["tree_fg"], bg=theme["tree_bg"], relief="flat", borderwidth=8, wrap="word")
        remed_box.pack(fill="both", expand=True)
        remed_box.insert("1.0", guide["fix"])
        remed_box.config(state="disabled")

        # Footer Actions Frame
        btn_bar = tk.Frame(popup, bg=theme["bg"])
        btn_bar.pack(fill="x", padx=25, pady=(15, 20))

        def copy_remed():
            popup.clipboard_clear()
            popup.clipboard_append(guide["fix"])
            popup.update()
            messagebox.showinfo("Clipboard", "Remediation hardening commands successfully copied to clipboard!", parent=popup)

        btn_style = {"font": ("Segoe UI", 9, "bold"), "relief": "flat", "cursor": "hand2", "padx": 12, "pady": 4}

        btn_close = tk.Button(btn_bar, text="Close", bg="#f38ba8", fg="#1e1e2e", activebackground="#eba0ac", command=popup.destroy, **btn_style)
        btn_close.pack(side="right")
        self._add_hover_effect(btn_close, "#f38ba8", "#eba0ac")

        btn_cfg = tk.Button(
            btn_bar, text="⚙️ Open Settings" if self.current_os == "windows" else "⚙️ Open Config",
            bg="#a6e3a1", fg="#1e1e2e", activebackground="#89dceb",
            command=lambda: [popup.destroy(), self._auto_fix_issue()],
            **btn_style
        )
        btn_cfg.pack(side="left")
        self._add_hover_effect(btn_cfg, "#a6e3a1", "#89dceb")

        btn_copy = tk.Button(btn_bar, text="📋 Copy Actions", bg="#89b4fa", fg="#1e1e2e", activebackground="#74c7ec", command=copy_remed, **btn_style)
        btn_copy.pack(side="left", padx=(10, 0))
        self._add_hover_effect(btn_copy, "#89b4fa", "#74c7ec")

        btn_online = tk.Button(
            btn_bar, text="🌍 Online baseline",
            bg="#cba6f7", fg="#1e1e2e", activebackground="#b4befe",
            command=lambda: self._open_path_or_url(target_url),
            **btn_style
        )
        btn_online.pack(side="left", padx=(10, 0))
        self._add_hover_effect(btn_online, "#cba6f7", "#b4befe")

    def _export_fix_script(self) -> None:
        if not self._last_results:
            messagebox.showinfo("No Data", "Run an audit first before compiling a hardening script.")
            return

        fails = [item for item in self._last_results if item.get("status") == "FAIL"]
        if not fails:
            messagebox.showinfo("Fully Compliant", "No failed audit checks found. System is secure!")
            return

        is_win = self.current_os == "windows"
        ext = ".ps1" if is_win else ".sh"
        
        # Compile executable script header
        header_text = (
            "#\n# Windows CIS Hardening Remediation Script\n"
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n#\n\n"
            if is_win else
            f"#!/usr/bin/env bash\n#\n# Linux CIS Hardening Remediation Script\n"
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n#\n\n"
        )

        script_content = header_text
        guides = LINUX_GUIDES if not is_win else WINDOWS_GUIDES
        
        for item in fails:
            check_name = item.get("check_name", "Unknown")
            guide = guides.get(check_name)
            if guide and "fix" in guide:
                script_content += f"# Hardening Action: {check_name}\n"
                script_content += f"{guide['fix']}\n\n"

        filepath = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("PowerShell Script" if is_win else "Shell Script", f"*{ext}")],
            initialfile=f"remediate_system{ext}"
        )
        
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8", newline="\n" if not is_win else None) as f:
                f.write(script_content)
            
            # For Linux, set execute permissions automatically
            if not is_win:
                try:
                    os.chmod(filepath, 0o755)
                except Exception:
                    pass

            messagebox.showinfo("Export Successful", f"Batch hardening script exported successfully:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save hardening script:\n{e}")

    def _generate_report(self) -> None:
        if not self._last_results:
            messagebox.showwarning("No Data", "Run an audit first before generating a report.")
            return

        try:
            report_path = generate_html_report(self._last_results)
            messagebox.showinfo("Success", f"Report saved:\n{report_path}")
            self._open_path_or_url(Path(report_path).as_uri())
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _generate_pdf(self) -> None:
        if not self._last_results:
            messagebox.showwarning("No Data", "Run an audit first before generating a report.")
            return

        try:
            from reports.generator import generate_pdf_report
            report_path = generate_pdf_report(self._last_results)
            messagebox.showinfo("Success", f"PDF saved:\n{report_path}")
            self._open_path_or_url(Path(report_path).as_uri())
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _export_csv(self) -> None:
        if not self._last_results:
            messagebox.showwarning("No Data", "Run an audit first before exporting.")
            return

        import csv
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(RESULTS_DIR, f"windows_audit_{timestamp}.csv")

        try:
            with open(filepath, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Check Name", "Status", "Details"])
                for item in self._last_results:
                    writer.writerow([item["check_name"], item["status"], item["details"]])
            messagebox.showinfo("Success", f"CSV exported:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _clear_table(self) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._last_results = []
        self.summary_label.config(text="Grid cleared")
        self.status_label.config(text="")

def main() -> None:
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
