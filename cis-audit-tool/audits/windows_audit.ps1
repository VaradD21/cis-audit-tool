<#
.SYNOPSIS
    CIS Benchmark Audit - Windows 11
.DESCRIPTION
    Runs 10 CIS benchmark checks and outputs results as JSON.
    Must be run as Administrator for full accuracy.
.OUTPUTS
    JSON array: [{"check": "...", "status": "PASS/FAIL", "details": "..."}]
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$results = [System.Collections.ArrayList]::new()

function Add-Result {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Details
    )
    [void]$results.Add(@{
        check   = $Check
        status  = $Status
        details = $Details
    })
}

# ── 1. Minimum Password Length (>= 14) ─────────────────────────
try {
    $secpol = & secedit /export /cfg "$env:TEMP\secpol_audit.cfg" 2>&1
    $cfg    = Get-Content "$env:TEMP\secpol_audit.cfg"
    $line   = $cfg | Where-Object { $_ -match "^\s*MinimumPasswordLength\s*=" }

    if ($line) {
        $value = [int]($line -split "=")[1].Trim()
        if ($value -ge 14) {
            Add-Result "Minimum Password Length" "PASS" "MinimumPasswordLength = $value (>= 14)"
        } else {
            Add-Result "Minimum Password Length" "FAIL" "MinimumPasswordLength = $value (required >= 14)"
        }
    } else {
        Add-Result "Minimum Password Length" "FAIL" "MinimumPasswordLength not found in security policy"
    }

    Remove-Item "$env:TEMP\secpol_audit.cfg" -Force -ErrorAction SilentlyContinue
} catch {
    Add-Result "Minimum Password Length" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 2. Account Lockout Threshold (<= 5) ────────────────────────
try {
    $netAccounts = & net accounts 2>&1
    $lockLine    = $netAccounts | Where-Object { $_ -match "Lockout threshold" }

    if ($lockLine) {
        $raw = ($lockLine -split ":\s*")[1].Trim()
        if ($raw -eq "Never") {
            Add-Result "Account Lockout Threshold" "FAIL" "Lockout threshold is set to Never (no lockout)"
        } else {
            $threshold = [int]$raw
            if ($threshold -le 5 -and $threshold -gt 0) {
                Add-Result "Account Lockout Threshold" "PASS" "Lockout threshold = $threshold (<= 5)"
            } else {
                Add-Result "Account Lockout Threshold" "FAIL" "Lockout threshold = $threshold (required 1-5)"
            }
        }
    } else {
        Add-Result "Account Lockout Threshold" "FAIL" "Could not read lockout threshold from net accounts"
    }
} catch {
    Add-Result "Account Lockout Threshold" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 3. Firewall Enabled on All Profiles ────────────────────────
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $disabled = $profiles | Where-Object { $_.Enabled -eq $false }

    if ($disabled) {
        $names = ($disabled | ForEach-Object { $_.Name }) -join ", "
        Add-Result "Firewall All Profiles" "FAIL" "Disabled on: $names"
    } else {
        Add-Result "Firewall All Profiles" "PASS" "Firewall enabled on Domain, Private, Public"
    }
} catch {
    Add-Result "Firewall All Profiles" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 4. Guest Account Disabled ──────────────────────────────────
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop

    if ($guest.Enabled -eq $false) {
        Add-Result "Guest Account Disabled" "PASS" "Guest account is disabled"
    } else {
        Add-Result "Guest Account Disabled" "FAIL" "Guest account is enabled"
    }
} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    Add-Result "Guest Account Disabled" "PASS" "Guest account does not exist"
} catch {
    Add-Result "Guest Account Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 5. AutoRun Disabled ────────────────────────────────────────
try {
    $regPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $autorun  = Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction Stop

    # 255 (0xFF) disables autorun on all drive types
    if ($autorun.NoDriveTypeAutoRun -eq 255) {
        Add-Result "AutoRun Disabled" "PASS" "NoDriveTypeAutoRun = 255 (all drives)"
    } else {
        Add-Result "AutoRun Disabled" "FAIL" "NoDriveTypeAutoRun = $($autorun.NoDriveTypeAutoRun) (expected 255)"
    }
} catch {
    Add-Result "AutoRun Disabled" "FAIL" "Registry key not set — AutoRun may be enabled"
}

# ── 6. Screen Saver with Password ──────────────────────────────
try {
    $ssActive = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" `
                    -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
    $ssSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" `
                    -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

    $isActive = $ssActive.ScreenSaveActive -eq "1"
    $isSecure = $ssSecure.ScreenSaverIsSecure -eq "1"

    if ($isActive -and $isSecure) {
        Add-Result "Screen Saver with Password" "PASS" "Screen saver enabled with password protection"
    } elseif (-not $isActive) {
        Add-Result "Screen Saver with Password" "FAIL" "Screen saver is not enabled"
    } else {
        Add-Result "Screen Saver with Password" "FAIL" "Screen saver enabled but password protection is off"
    }
} catch {
    Add-Result "Screen Saver with Password" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 7. Windows Defender Enabled ─────────────────────────────────
try {
    $defender = Get-MpPreference -ErrorAction Stop
    $status   = Get-MpComputerStatus -ErrorAction Stop

    if ($status.AntivirusEnabled -and -not $defender.DisableRealtimeMonitoring) {
        Add-Result "Windows Defender Enabled" "PASS" "Real-time protection is active"
    } else {
        $detail = @()
        if (-not $status.AntivirusEnabled)            { $detail += "Antivirus disabled" }
        if ($defender.DisableRealtimeMonitoring)       { $detail += "Real-time monitoring disabled" }
        Add-Result "Windows Defender Enabled" "FAIL" ($detail -join "; ")
    }
} catch {
    Add-Result "Windows Defender Enabled" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 8. Remote Desktop Disabled ─────────────────────────────────
try {
    $rdpReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
                  -Name "fDenyTSConnections" -ErrorAction Stop

    if ($rdpReg.fDenyTSConnections -eq 1) {
        Add-Result "Remote Desktop Disabled" "PASS" "fDenyTSConnections = 1 (RDP denied)"
    } else {
        Add-Result "Remote Desktop Disabled" "FAIL" "fDenyTSConnections = 0 (RDP allowed)"
    }
} catch {
    Add-Result "Remote Desktop Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 9. Audit Logon Events Enabled ──────────────────────────────
try {
    $auditpol = & auditpol /get /category:"Logon/Logoff" 2>&1
    $logon    = $auditpol | Where-Object { $_ -match "^\s*Logon\s" }

    if ($logon -and $logon -match "(Success and Failure|Success|Failure)") {
        $setting = $Matches[1]
        if ($setting -eq "Success and Failure") {
            Add-Result "Audit Logon Events" "PASS" "Logon auditing: $setting"
        } else {
            Add-Result "Audit Logon Events" "FAIL" "Logon auditing: $setting (should be Success and Failure)"
        }
    } else {
        Add-Result "Audit Logon Events" "FAIL" "Logon auditing is not configured or set to No Auditing"
    }
} catch {
    Add-Result "Audit Logon Events" "FAIL" "Error: $($_.Exception.Message)"
}

# ── 10. BitLocker Status on C: ─────────────────────────────────
try {
    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

    if ($bl.ProtectionStatus -eq "On") {
        Add-Result "BitLocker on C:" "PASS" "BitLocker protection is On (encryption: $($bl.EncryptionMethod))"
    } else {
        Add-Result "BitLocker on C:" "FAIL" "BitLocker protection status: $($bl.ProtectionStatus)"
    }
} catch {
    Add-Result "BitLocker on C:" "FAIL" "Error: $($_.Exception.Message)"
}

# ── Output as JSON ──────────────────────────────────────────────
$results | ConvertTo-Json -Depth 3
