"""
audits/windows.py - Windows CIS Benchmark Audit Checks

Wraps the PowerShell audit script (windows_audit.ps1) and exposes
results through the same interface as linux.py.
"""

import json
import os
import subprocess
from typing import TypedDict


class CheckResult(TypedDict):
    check_name: str
    status: str
    details: str


def run_all_checks() -> list[CheckResult]:
    """
    Execute windows_audit.ps1 and return normalised results.

    The PS1 script outputs JSON with keys: check, status, details.
    We rename 'check' → 'check_name' for consistency with linux.py.
    """
    script_path = os.path.join(os.path.dirname(__file__), "windows_audit.ps1")

    if not os.path.isfile(script_path):
        return [{"check_name": "Script Missing", "status": "FAIL",
                 "details": f"{script_path} not found"}]

    try:
        result = subprocess.run(
            [
                "powershell", "-ExecutionPolicy", "Bypass",
                "-NoProfile", "-File", script_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return [{"check_name": "PowerShell Error", "status": "FAIL",
                     "details": result.stderr.strip() or "Non-zero exit code"}]

        raw: list[dict[str, str]] = json.loads(result.stdout)

        # Normalise key names to match linux.py
        return [
            {
                "check_name": item.get("check", "Unknown"),
                "status": item.get("status", "FAIL"),
                "details": item.get("details", ""),
            }
            for item in raw
        ]

    except json.JSONDecodeError as exc:
        return [{"check_name": "JSON Parse Error", "status": "FAIL",
                 "details": str(exc)}]
    except subprocess.TimeoutExpired:
        return [{"check_name": "Timeout", "status": "FAIL",
                 "details": "PowerShell script exceeded 60s timeout"}]
    except FileNotFoundError:
        return [{"check_name": "PowerShell Not Found", "status": "FAIL",
                 "details": "powershell.exe is not available on this system"}]


if __name__ == "__main__":
    results = run_all_checks()
    print(json.dumps(results, indent=2))
