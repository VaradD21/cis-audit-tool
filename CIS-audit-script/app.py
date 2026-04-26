import tkinter as tk
from tkinter import messagebox
import subprocess
import json
import os

# --- AUDIT LOGIC ---

def run_windows_audit():
    script = os.path.join(os.path.dirname(__file__), "win_audit.ps1")
    try:
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        return [{"check": "Error", "status": "FAIL", "details": str(e)}]

def run_linux_audit():
    # Very simple linux checks
    checks = []
    
    # Check 1: UFW
    res = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    if "active" in res.stdout:
        checks.append({"check": "UFW Firewall", "status": "PASS", "details": "Active"})
    else:
        checks.append({"check": "UFW Firewall", "status": "FAIL", "details": "Inactive"})
        
    # Check 2: SSH Root
    if os.path.exists("/etc/ssh/sshd_config"):
        with open("/etc/ssh/sshd_config", "r") as f:
            content = f.read()
            if "PermitRootLogin no" in content:
                checks.append({"check": "SSH Root", "status": "PASS", "details": "Disabled"})
            else:
                checks.append({"check": "SSH Root", "status": "FAIL", "details": "Enabled"})
    
    return checks

# --- GUI LOGIC ---

def start_audit(os_type):
    listbox.delete(0, tk.END)
    print(f"Running {os_type} audit...")
    
    if os_type == "Windows":
        data = run_windows_audit()
    else:
        data = run_linux_audit()
        
    for item in data:
        line = f"[{item['status']}] {item['check']}: {item['details']}"
        listbox.insert(tk.END, line)
        # Simple color coloring
        if item['status'] == "PASS":
            listbox.itemconfig(tk.END, {'fg': 'green'})
        else:
            listbox.itemconfig(tk.END, {'fg': 'red'})

# Setup Window
root = tk.Tk()
root.title("Simple Audit Tool")
root.geometry("500x400")

tk.Label(root, text="Audit Tool", font=("Arial", 16)).pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Run Windows", command=lambda: start_audit("Windows")).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Run Linux", command=lambda: start_audit("Linux")).pack(side=tk.LEFT, padx=5)

listbox = tk.Listbox(root, width=60, height=15)
listbox.pack(pady=10, padx=10)

root.mainloop()
