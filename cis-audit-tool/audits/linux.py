"""
audits/linux.py - Linux CIS Benchmark Audit Checks

Runs 10 security checks based on CIS benchmarks using subprocess.
Each check returns: {"check_name": str, "status": "PASS"|"FAIL", "details": str}
"""

import subprocess
import os
from typing import TypedDict


class CheckResult(TypedDict):
    check_name: str
    status: str
    details: str


def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    """Run a shell command and return (returncode, stdout)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip()
    except FileNotFoundError:
        return -1, "command not found"
    except subprocess.TimeoutExpired:
        return -2, "command timed out"


# ── Check 1: UFW firewall enabled ──────────────────────────────
def check_ufw_enabled() -> CheckResult:
    """CIS: Ensure ufw firewall is active."""
    code, output = _run_cmd(["ufw", "status"])
    if code == -1:
        return {"check_name": "UFW Firewall Enabled", "status": "FAIL", "details": "ufw is not installed"}

    if "Status: active" in output:
        return {"check_name": "UFW Firewall Enabled", "status": "PASS", "details": "ufw is active"}

    return {"check_name": "UFW Firewall Enabled", "status": "FAIL", "details": f"ufw status: {output}"}


# ── Check 2: Root SSH login disabled ───────────────────────────
def check_root_ssh_disabled() -> CheckResult:
    """CIS: Ensure SSH root login is disabled (PermitRootLogin no)."""
    sshd_config = "/etc/ssh/sshd_config"
    if not os.path.isfile(sshd_config):
        return {"check_name": "Root SSH Login Disabled", "status": "FAIL", "details": f"{sshd_config} not found"}

    code, output = _run_cmd(
        ["grep", "-Ei", r"^\s*PermitRootLogin", sshd_config]
    )

    if code != 0 or not output:
        return {"check_name": "Root SSH Login Disabled", "status": "FAIL", "details": "PermitRootLogin not explicitly set"}

    # Last matching directive wins in sshd_config
    last_line = output.strip().splitlines()[-1].lower()
    if "no" in last_line and "without-password" not in last_line:
        return {"check_name": "Root SSH Login Disabled", "status": "PASS", "details": last_line.strip()}

    return {"check_name": "Root SSH Login Disabled", "status": "FAIL", "details": last_line.strip()}


# ── Check 3: Password minimum length ──────────────────────────
def check_password_min_length(required: int = 14) -> CheckResult:
    """CIS: Ensure password minimum length meets policy (default 14)."""
    conf = "/etc/security/pwquality.conf"
    if not os.path.isfile(conf):
        return {"check_name": "Password Minimum Length", "status": "FAIL", "details": f"{conf} not found"}

    code, output = _run_cmd(["grep", "-Ei", r"^\s*minlen", conf])

    if code != 0 or not output:
        return {"check_name": "Password Minimum Length", "status": "FAIL", "details": "minlen not set in pwquality.conf"}

    # Parse the last minlen value
    last_line = output.strip().splitlines()[-1]
    try:
        value = int(last_line.split("=")[1].strip())
    except (IndexError, ValueError):
        return {"check_name": "Password Minimum Length", "status": "FAIL", "details": f"Cannot parse: {last_line}"}

    if value >= required:
        return {"check_name": "Password Minimum Length", "status": "PASS", "details": f"minlen = {value} (>= {required})"}

    return {"check_name": "Password Minimum Length", "status": "FAIL", "details": f"minlen = {value} (required >= {required})"}


# ── Check 4: Guest account disabled ───────────────────────────
def check_guest_account_disabled() -> CheckResult:
    """CIS: Ensure guest account is disabled."""
    # Check lightdm config (common on Ubuntu desktops)
    lightdm_conf = "/etc/lightdm/lightdm.conf"
    if os.path.isfile(lightdm_conf):
        code, output = _run_cmd(
            ["grep", "-Ei", r"^\s*allow-guest\s*=\s*false", lightdm_conf]
        )
        if code == 0 and output:
            return {"check_name": "Guest Account Disabled", "status": "PASS", "details": "allow-guest=false in lightdm.conf"}

    # Check if a 'guest' user exists in /etc/passwd
    code, output = _run_cmd(["grep", "-c", "^guest:", "/etc/passwd"])
    if code == 0 and output.strip() != "0":
        return {"check_name": "Guest Account Disabled", "status": "FAIL", "details": "guest user found in /etc/passwd"}

    return {"check_name": "Guest Account Disabled", "status": "PASS", "details": "No guest account detected"}


# ── Check 5: Auditd service running ───────────────────────────
def check_auditd_running() -> CheckResult:
    """CIS: Ensure auditd service is active."""
    code, output = _run_cmd(["systemctl", "is-active", "auditd"])

    if output == "active":
        return {"check_name": "Auditd Service Running", "status": "PASS", "details": "auditd is active"}

    return {"check_name": "Auditd Service Running", "status": "FAIL", "details": f"auditd status: {output}"}


# ── Check 6: /tmp on separate partition ────────────────────────
def check_tmp_separate_partition() -> CheckResult:
    """CIS: Ensure /tmp is a separate partition."""
    code, output = _run_cmd(["findmnt", "-n", "/tmp"])

    if code == 0 and output:
        return {"check_name": "/tmp Separate Partition", "status": "PASS", "details": output.splitlines()[0]}

    # Fallback: check /etc/fstab
    code, output = _run_cmd(["grep", "-E", r"\s/tmp\s", "/etc/fstab"])
    if code == 0 and output:
        return {"check_name": "/tmp Separate Partition", "status": "PASS", "details": f"fstab entry: {output.splitlines()[0]}"}

    return {"check_name": "/tmp Separate Partition", "status": "FAIL", "details": "/tmp is not a separate mount"}


# ── Check 7: Telnet uninstalled ────────────────────────────────
def check_telnet_uninstalled() -> CheckResult:
    """CIS: Ensure telnet client/server is not installed."""
    # Check dpkg (Debian/Ubuntu)
    code, output = _run_cmd(["dpkg", "-s", "telnet"])
    if code == 0 and "Status: install ok installed" in output:
        return {"check_name": "Telnet Uninstalled", "status": "FAIL", "details": "telnet package is installed (dpkg)"}

    # Check rpm (RHEL/CentOS)
    code, output = _run_cmd(["rpm", "-q", "telnet"])
    if code == 0 and "not installed" not in output:
        return {"check_name": "Telnet Uninstalled", "status": "FAIL", "details": f"telnet installed (rpm): {output}"}

    return {"check_name": "Telnet Uninstalled", "status": "PASS", "details": "telnet is not installed"}


# ── Check 8: Cron daemon enabled ──────────────────────────────
def check_cron_enabled() -> CheckResult:
    """CIS: Ensure cron daemon is enabled and running."""
    code, output = _run_cmd(["systemctl", "is-enabled", "cron"])

    # Some distros use 'crond' instead of 'cron'
    if code != 0 or output != "enabled":
        code, output = _run_cmd(["systemctl", "is-enabled", "crond"])

    if output == "enabled":
        return {"check_name": "Cron Daemon Enabled", "status": "PASS", "details": "cron service is enabled"}

    return {"check_name": "Cron Daemon Enabled", "status": "FAIL", "details": f"cron status: {output}"}


# ── Check 9: Sudo logging enabled ─────────────────────────────
def check_sudo_logging() -> CheckResult:
    """CIS: Ensure sudo commands are logged (logfile directive in sudoers)."""
    # Check main sudoers and drop-in directory
    code, output = _run_cmd(
        ["grep", "-rEi", r"^\s*Defaults\s+logfile", "/etc/sudoers", "/etc/sudoers.d/"]
    )

    if code == 0 and output:
        return {"check_name": "Sudo Logging Enabled", "status": "PASS", "details": output.splitlines()[0]}

    return {"check_name": "Sudo Logging Enabled", "status": "FAIL", "details": "No 'Defaults logfile' found in sudoers"}


# ── Check 10: Sticky bit on /tmp ──────────────────────────────
def check_tmp_sticky_bit() -> CheckResult:
    """CIS: Ensure sticky bit is set on /tmp."""
    code, output = _run_cmd(["stat", "-c", "%a", "/tmp"])

    if code != 0:
        return {"check_name": "Sticky Bit on /tmp", "status": "FAIL", "details": f"Could not stat /tmp: {output}"}

    # Sticky bit adds 1000 to permissions (e.g. 1777)
    if output.startswith("1") and len(output) == 4:
        return {"check_name": "Sticky Bit on /tmp", "status": "PASS", "details": f"/tmp permissions: {output}"}

    return {"check_name": "Sticky Bit on /tmp", "status": "FAIL", "details": f"/tmp permissions: {output} (sticky bit not set)"}


# ── Runner ─────────────────────────────────────────────────────
def run_all_checks() -> list[CheckResult]:
    """Execute all 10 CIS benchmark checks and return results."""
    checks = [
        check_ufw_enabled,
        check_root_ssh_disabled,
        check_password_min_length,
        check_guest_account_disabled,
        check_auditd_running,
        check_tmp_separate_partition,
        check_telnet_uninstalled,
        check_cron_enabled,
        check_sudo_logging,
        check_tmp_sticky_bit,
    ]
    return [check() for check in checks]


if __name__ == "__main__":
    import json
    results = run_all_checks()
    print(json.dumps(results, indent=2))
