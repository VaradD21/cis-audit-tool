import tkinter as tk
from tkinter import ttk
import audit_runner

def execute_audit(system):
    # Clear old results
    for item in tree.get_children():
        tree.delete(item)
    
    label_status.config(text=f"Scanning {system}...", fg="blue")
    root.update()
    
    if system == "Windows":
        data = audit_runner.run_all_checks_win() # Wait, I named it differently in runner, let me fix it
        # Actually I'll just call the runner function directly
        data = audit_runner.run_windows_audit()
    else:
        data = audit_runner.run_linux_audit()
        
    for res in data:
        tag = "pass" if res['status'] == "PASS" else "fail"
        tree.insert("", "end", values=(res['check'], res['status'], res['details']), tags=(tag,))
    
    label_status.config(text=f"{system} Scan Complete!", fg="green")

# Window Setup
root = tk.Tk()
root.title("CIS Security Auditor")
root.geometry("800x500")

# Header
tk.Label(root, text="CIS Benchmark Audit Tool", font=("Arial", 20, "bold")).pack(pady=20)

# Buttons
frame_btns = tk.Frame(root)
frame_btns.pack(pady=10)

tk.Button(frame_btns, text="Scan Windows", width=20, height=2, bg="#e1e1e1", 
          command=lambda: execute_audit("Windows")).grid(row=0, column=0, padx=10)

tk.Button(frame_btns, text="Scan Linux", width=20, height=2, bg="#e1e1e1", 
          command=lambda: execute_audit("Linux")).grid(row=0, column=1, padx=10)

# Status
label_status = tk.Label(root, text="Ready to scan", font=("Arial", 10))
label_status.pack(pady=5)

# Table (Treeview)
columns = ("Check", "Status", "Details")
tree = ttk.Treeview(root, columns=columns, show="headings", height=10)
tree.heading("Check", text="Security Check")
tree.heading("Status", text="Status")
tree.heading("Details", text="Details")

tree.column("Check", width=200)
tree.column("Status", width=100, anchor="center")
tree.column("Details", width=450)

# Colors
tree.tag_configure("pass", foreground="green")
tree.tag_configure("fail", foreground="red")

tree.pack(pady=20, padx=20, fill="both", expand=True)

root.mainloop()
