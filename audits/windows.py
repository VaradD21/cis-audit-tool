import json
import os
import subprocess
from typing import TypedDict

class CheckResult(TypedDict):
    check_name: str
    status: str
    details: str
    severity: str
    impact: str

def run_all_checks() -> list[CheckResult]:
    script_path = os.path.join(os.path.dirname(__file__), "windows_audit.ps1")

    if not os.path.isfile(script_path):
        return [{"check_name": "Script Missing", "status": "FAIL", "details": f"{script_path} not found", "severity": "High", "impact": "System Security"}]

    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", script_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return [{"check_name": "PowerShell Error", "status": "FAIL", "details": result.stderr.strip() or "Non-zero exit code", "severity": "High", "impact": "System Security"}]

        raw = json.loads(result.stdout)

        severity_map = {
            "Minimum Password Length": "High",
            "Account Lockout Threshold": "Medium",
            "Firewall All Profiles": "Critical",
            "Guest Account Disabled": "Critical",
            "AutoRun Disabled": "Medium",
            "Lock Screen on Wake": "Medium",
            "Windows Defender Enabled": "High",
            "Remote Desktop Disabled": "High",
            "Audit Logon Events": "Medium",
            "BitLocker on C:": "High",
            "UAC Enabled": "Critical",
            "SMBv1 Disabled": "Critical",
            "Windows Update Active": "High",
            "PowerShell Execution Policy": "Medium",
            "Administrator Account Renamed": "High",
        }

        return [
            {
                "check_name": item.get("check", "Unknown"),
                "status": item.get("status", "FAIL"),
                "details": item.get("details", ""),
                "severity": severity_map.get(item.get("check", ""), "Medium"),
                "impact": "System-Wide"
            }
            for item in raw
        ]

    except json.JSONDecodeError as exc:
        return [{"check_name": "JSON Parse Error", "status": "FAIL", "details": str(exc), "severity": "High", "impact": "System Security"}]
    except subprocess.TimeoutExpired:
        return [{"check_name": "Timeout", "status": "FAIL", "details": "PowerShell script exceeded 60s timeout", "severity": "High", "impact": "System Security"}]
    except FileNotFoundError:
        return [{"check_name": "PowerShell Not Found", "status": "FAIL", "details": "powershell.exe is not available on this system", "severity": "High", "impact": "System Security"}]

if __name__ == "__main__":
    print(json.dumps(run_all_checks(), indent=2))
