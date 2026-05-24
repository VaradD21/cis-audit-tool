# audits/guides.py

WINDOWS_GUIDES = {
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

LINUX_GUIDES = {
    "Minimum Password Length": {
        "desc": "Enforces a minimum password length policy of 14 characters to prevent credential cracking.",
        "fix": "sudo sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf"
    },
    "Password Expiration": {
        "desc": "Requires users to change credentials every 90 days to shrink active exposure periods.",
        "fix": "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs"
    },
    "SSH Root Login Disabled": {
        "desc": "Disables SSH remote login as 'root' to enforce credential accountability and local logging.",
        "fix": "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\nsudo systemctl restart ssh"
    },
    "SSH Password Authentication": {
        "desc": "Disables vulnerable SSH password prompts to mandate highly secure key-based remote authentication.",
        "fix": "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config\nsudo systemctl restart ssh"
    },
    "Firewall All Profiles": {
        "desc": "Ensures the system runs an active local firewall wrapper to drop unauthorized network connections.",
        "fix": "sudo ufw enable || (sudo systemctl enable --now firewalld)"
    },
    "Windows Update Active": {
        "desc": "Configures automatic package updates to deploy system and security patches daily without manual latency.",
        "fix": "sudo apt install -y unattended-upgrades || (sudo dnf install -y dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer)"
    },
    "AutoRun Disabled": {
        "desc": "Address Space Layout Randomization (ASLR) randomizes process memory structures to block buffer overflow exploits.",
        "fix": "echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"
    },
    "Windows Defender Enabled": {
        "desc": "Enforces AppArmor or SELinux Mandatory Access Controls to secure host processes against filesystem privilege escalation.",
        "fix": "sudo systemctl enable --now apparmor || (sudo setenforce 1 && sudo sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config)"
    },
    "Guest Account Disabled": {
        "desc": "Confirms that only the legitimate 'root' user possesses UID 0 superuser status on the system.",
        "fix": "sudo passwd -l guest 2>/dev/null || true"
    },
    "Umask Configuration": {
        "desc": "Enforces default file permissions of 027 or tighter to block standard users from reading newly created group/other files.",
        "fix": "sudo sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs"
    },
    "Lock Screen on Wake": {
        "desc": "Configures core dumps restrictions system-wide to prevent sensitive application RAM credentials from caching on disks.",
        "fix": "echo '* hard core 0' | sudo tee -a /etc/security/limits.conf"
    },
    "Audit Logon Events": {
        "desc": "Integrates kernel system activity and authorization logging via auditd to generate security access trails.",
        "fix": "sudo apt install -y auditd || (sudo dnf install -y audit && sudo systemctl enable --now auditd)"
    },
    "BitLocker on C:": {
        "desc": "Sets the sticky bit permission (+t) on world-writable storage areas to prevent users from deleting others' files.",
        "fix": "sudo chmod +t /tmp /var/tmp"
    },
    "Remote Desktop Disabled": {
        "desc": "Blacklists the kernel driver module for usb-storage devices to prevent local physical usb keys data extraction.",
        "fix": "echo 'blacklist usb-storage' | sudo tee /etc/modprobe.d/usb-storage.conf && sudo modprobe -r usb-storage 2>/dev/null || true"
    },
    "Sudo Security": {
        "desc": "Enforces complete password verification for every sudo action, eliminating insecure NOPASSWD user settings.",
        "fix": "sudo sed -i 's/NOPASSWD://g' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true"
    },
    "UAC Enabled": {
        "desc": "Mandates that all privilege escalations run within a verified, interactive TTY screen.",
        "fix": "echo 'Defaults requiretty' | sudo tee -a /etc/sudoers"
    },
    "SMBv1 Disabled": {
        "desc": "Ensures the vulnerable legacy SMBv1 networking daemon is closed or blocked to avoid ransomware spreads.",
        "fix": "sudo systemctl disable --now smbd || true"
    },
    "Administrator Account Renamed": {
        "desc": "Eliminates generic administration names 'admin' and 'administrator' from passwd to disable standard brute force scans.",
        "fix": "sudo usermod -l renamed-admin admin 2>/dev/null || true"
    }
}

URLS = {
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
