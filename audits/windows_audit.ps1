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
    $obj = @{
        check   = $Check
        status  = $Status
        details = $Details
    }
    [void]$results.Add($obj)
}

# 1. Minimum Password Length (>= 14)
try {
    $secpolFile = "$env:TEMP\secpol_audit.cfg"
    secedit /export /cfg $secpolFile | Out-Null
    $cfg = Get-Content $secpolFile
    $line = $cfg | Where-Object { $_ -match "MinimumPasswordLength\s*=" }
    if ($line) {
        $value = [int]($line -split "=")[1].Trim()
        if ($value -ge 14) {
            Add-Result "Minimum Password Length" "PASS" "MinimumPasswordLength = $value (>= 14)"
        } else {
            Add-Result "Minimum Password Length" "FAIL" "MinimumPasswordLength = $value (required >= 14)"
        }
    } else {
        Add-Result "Minimum Password Length" "FAIL" "Setting not found"
    }
    if (Test-Path $secpolFile) { Remove-Item $secpolFile -Force }
} catch {
    Add-Result "Minimum Password Length" "FAIL" "Error: $($_.Exception.Message)"
}

# 2. Account Lockout Threshold (<= 5)
try {
    $netAccounts = net accounts
    $lockLine = $netAccounts | Where-Object { $_ -match "Lockout threshold" }
    if ($lockLine) {
        $raw = ($lockLine -split ":\s*")[1].Trim()
        if ($raw -eq "Never") {
            Add-Result "Account Lockout Threshold" "FAIL" "Lockout threshold is Never"
        } else {
            $threshold = [int]$raw
            if ($threshold -le 5 -and $threshold -gt 0) {
                Add-Result "Account Lockout Threshold" "PASS" "Threshold = $threshold (<= 5)"
            } else {
                Add-Result "Account Lockout Threshold" "FAIL" "Threshold = $threshold"
            }
        }
    }
} catch {
    Add-Result "Account Lockout Threshold" "FAIL" "Error: $($_.Exception.Message)"
}

# 3. Firewall Enabled on All Profiles
try {
    $profiles = Get-NetFirewallProfile
    $disabled = $profiles | Where-Object { $_.Enabled -eq $false }
    if ($disabled) {
        $names = ($disabled | ForEach-Object { $_.Name }) -join ", "
        Add-Result "Firewall All Profiles" "FAIL" "Disabled on: $names"
    } else {
        Add-Result "Firewall All Profiles" "PASS" "Enabled on all profiles"
    }
} catch {
    Add-Result "Firewall All Profiles" "FAIL" "Error: $($_.Exception.Message)"
}

# 4. Guest Account Disabled
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -eq $guest) {
        Add-Result "Guest Account Disabled" "PASS" "Guest account does not exist"
    } elseif ($guest.Enabled -eq $false) {
        Add-Result "Guest Account Disabled" "PASS" "Guest account is disabled"
    } else {
        Add-Result "Guest Account Disabled" "FAIL" "Guest account is enabled"
    }
} catch {
    Add-Result "Guest Account Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

# 5. AutoRun Disabled
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $valName = "NoDriveTypeAutoRun"
    if (Test-Path $regPath) {
        $val = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue
        if ($null -ne $val -and $val.$valName -eq 255) {
            Add-Result "AutoRun Disabled" "PASS" "NoDriveTypeAutoRun = 255"
        } else {
            Add-Result "AutoRun Disabled" "FAIL" "Not set to 255"
        }
    } else {
        Add-Result "AutoRun Disabled" "FAIL" "Registry path not found"
    }
} catch {
    Add-Result "AutoRun Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

# 6. Screen Saver with Password
try {
    $path = "HKCU:\Control Panel\Desktop"
    $ssActive = (Get-ItemProperty -Path $path -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
    $ssSecure = (Get-ItemProperty -Path $path -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    if ($ssActive -eq "1" -and $ssSecure -eq "1") {
        Add-Result "Screen Saver with Password" "PASS" "Enabled with password"
    } else {
        Add-Result "Screen Saver with Password" "FAIL" "Not enabled or no password"
    }
} catch {
    Add-Result "Screen Saver with Password" "FAIL" "Error: $($_.Exception.Message)"
}

# 7. Windows Defender Enabled
try {
    $status = Get-MpComputerStatus
    if ($status.AntivirusEnabled -eq $true) {
        Add-Result "Windows Defender Enabled" "PASS" "Antivirus is active"
    } else {
        Add-Result "Windows Defender Enabled" "FAIL" "Antivirus is disabled"
    }
} catch {
    Add-Result "Windows Defender Enabled" "FAIL" "Error: $($_.Exception.Message)"
}

# 8. Remote Desktop Disabled
try {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdp = (Get-ItemProperty -Path $path -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdp -eq 1) {
        Add-Result "Remote Desktop Disabled" "PASS" "RDP is disabled"
    } else {
        Add-Result "Remote Desktop Disabled" "FAIL" "RDP is enabled"
    }
} catch {
    Add-Result "Remote Desktop Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

# 9. Audit Logon Events Enabled
try {
    $audit = auditpol /get /category:"Logon/Logoff"
    $logon = $audit | Where-Object { $_ -match "Logon\s" }
    if ($logon -match "Success and Failure") {
        Add-Result "Audit Logon Events" "PASS" "Auditing success and failure"
    } else {
        Add-Result "Audit Logon Events" "FAIL" "Not auditing properly"
    }
} catch {
    Add-Result "Audit Logon Events" "FAIL" "Error: $($_.Exception.Message)"
}

# 10. BitLocker Status on C:
try {
    $bl = Get-BitLockerVolume -MountPoint "C:"
    if ($bl.ProtectionStatus -eq "On") {
        Add-Result "BitLocker on C:" "PASS" "BitLocker is On"
    } else {
        Add-Result "BitLocker on C:" "FAIL" "BitLocker is $($bl.ProtectionStatus)"
    }
} catch {
    Add-Result "BitLocker on C:" "FAIL" "Error: $($_.Exception.Message)"
}

# Output as JSON
$results | ConvertTo-Json -Depth 3
