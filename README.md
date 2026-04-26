# 🛡 CIS Benchmark Audit Tool

A lightweight, cross-platform security auditing tool that checks your system against **CIS (Center for Internet Security) benchmarks**. It runs 10 key security checks on **Linux** or **Windows**, displays results in a colour-coded GUI, and generates a clean HTML report — all without needing any paid software or cloud services.

---

## 📸 Screenshot

> _Replace this with an actual screenshot of the GUI._

![CIS Audit Tool GUI](screenshots/gui_preview.png)

---

## 🛠 Tech Stack

| Layer       | Technology                     |
|-------------|--------------------------------|
| GUI         | Python 3.10+ / tkinter        |
| Linux Audit | Python + subprocess (Bash)     |
| Windows Audit | PowerShell 5.1+             |
| Reports     | Pure HTML/CSS (no JS frameworks) |

---

## 📦 Installation

### 1. Clone the repo

```bash
git clone https://github.com/VaradD21/cis-audit-tool.git
cd cis-audit-tool
```

### 2. Install Python dependencies

> **Note:** tkinter ships with Python on most systems. If it's missing on Linux, install it with:
> `sudo apt install python3-tk`

```bash
pip install -r requirements.txt
```

### 3. Run the tool

```bash
python main.py
```

> **Windows users:** To run the Windows audit, launch your terminal **as Administrator** — several checks require elevated privileges.

---

## ✅ CIS Checks Covered

### Linux (10 checks)

| #  | Check                          | What it verifies                        |
|----|--------------------------------|-----------------------------------------|
| 1  | UFW Firewall Enabled           | `ufw status` shows active               |
| 2  | Root SSH Login Disabled        | `PermitRootLogin no` in sshd_config     |
| 3  | Password Minimum Length        | `minlen >= 14` in pwquality.conf        |
| 4  | Guest Account Disabled         | No guest user in `/etc/passwd`           |
| 5  | Auditd Service Running         | `systemctl is-active auditd`            |
| 6  | /tmp Separate Partition        | `/tmp` mounted as its own partition     |
| 7  | Telnet Uninstalled             | telnet package not found (dpkg/rpm)     |
| 8  | Cron Daemon Enabled            | cron/crond service is enabled           |
| 9  | Sudo Logging Enabled           | `Defaults logfile` set in sudoers       |
| 10 | Sticky Bit on /tmp             | `/tmp` permissions start with `1` (1777)|

### Windows (10 checks)

| #  | Check                          | What it verifies                        |
|----|--------------------------------|-----------------------------------------|
| 1  | Minimum Password Length        | Security policy `>= 14` characters      |
| 2  | Account Lockout Threshold      | Lockout after `<= 5` failed attempts    |
| 3  | Firewall All Profiles          | Domain, Private, Public all enabled     |
| 4  | Guest Account Disabled         | Built-in Guest account is disabled      |
| 5  | AutoRun Disabled               | `NoDriveTypeAutoRun = 255` in registry  |
| 6  | Screen Saver with Password     | Screen saver active + password required |
| 7  | Windows Defender Enabled       | Real-time protection is on              |
| 8  | Remote Desktop Disabled        | `fDenyTSConnections = 1` in registry    |
| 9  | Audit Logon Events             | Success & Failure auditing enabled      |
| 10 | BitLocker on C:                | BitLocker protection status is On       |

---

## 📄 Reports

After running an audit, click **Generate Report** to create a self-contained HTML report at `results/audit_report.html`. The report includes:

- Date/time of the audit
- Summary cards (Total / Passed / Failed)
- A CSS-only pie chart
- A colour-coded results table

The report opens automatically in your default browser.

---

## ➕ How to Add New Checks

Adding a check is simple — each check is just a function that returns a dictionary.

### 1. Open the audit file

- Linux checks → `audits/linux.py`
- Windows checks → `audits/windows_audit.ps1`

### 2. Write a new check function (Linux example)

```python
def check_ssh_protocol_v2() -> CheckResult:
    """Ensure only SSH protocol 2 is used."""
    code, output = _run_cmd(["grep", "-Ei", r"^\s*Protocol", "/etc/ssh/sshd_config"])

    if code == 0 and "2" in output:
        return {"check_name": "SSH Protocol v2", "status": "PASS", "details": output}

    return {"check_name": "SSH Protocol v2", "status": "FAIL", "details": "Protocol 2 not enforced"}
```

### 3. Register it in `run_all_checks()`

```python
checks = [
    # ... existing checks ...
    check_ssh_protocol_v2,   # ← add here
]
```

That's it — the GUI and report generator pick it up automatically.

---

## 📁 Project Structure

```
cis-audit-tool/
├── main.py                  # Tkinter GUI entry point
├── requirements.txt         # Python dependencies
├── README.md
├── audits/
│   ├── __init__.py
│   ├── linux.py             # Linux audit checks (Python)
│   ├── windows.py           # Windows audit wrapper (Python)
│   └── windows_audit.ps1   # Windows audit checks (PowerShell)
├── reports/
│   ├── __init__.py
│   └── generator.py         # HTML report generator
└── results/                 # Auto-saved JSON + HTML reports
```

---

## 📜 License

This project is open-source and available under the [MIT License](LICENSE).

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature/new-check`)
3. Add your check following the pattern above
4. Submit a pull request

All contributions are welcome — even if it's just fixing a typo!
