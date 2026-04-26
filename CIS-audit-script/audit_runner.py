import subprocess
import json
import os

def run_windows_audit():
    """Run the PowerShell script and return the list of results."""
    ps_file = os.path.join(os.path.dirname(__file__), "win_checks.ps1")
    
    # Run powershell command
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_file]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    
    if proc.returncode == 0:
        return json.loads(proc.stdout)
    else:
        return [{"check": "Error", "status": "FAIL", "details": proc.stderr}]

def run_linux_audit():
    """Simple Linux checks using shell commands."""
    results = []
    
    # Check SSH Root Login
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            if "PermitRootLogin no" in f.read():
                results.append({"check": "SSH Root Login", "status": "PASS", "details": "Disabled"})
            else:
                results.append({"check": "SSH Root Login", "status": "FAIL", "details": "Enabled"})
    except:
        results.append({"check": "SSH Root Login", "status": "FAIL", "details": "Config not found"})
        
    return results
