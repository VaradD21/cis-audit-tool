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

try {
    $pinPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
    $pinEnabled = $false
    
    if (Test-Path $pinPath) {
        $props = Get-ItemProperty -Path $pinPath -ErrorAction SilentlyContinue
        if ($props) {
            $pinEnabled = $true
        }
    }
    
    if ($pinEnabled) {
        Add-Result "Minimum Password Length" "PASS" "Windows Hello PIN is configured"
    } else {
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
            Add-Result "Minimum Password Length" "FAIL" "Setting not found and PIN not configured"
        }
        if (Test-Path $secpolFile) { Remove-Item $secpolFile -Force }
    }
} catch {
    Add-Result "Minimum Password Length" "FAIL" "Error: $($_.Exception.Message)"
}

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

try {
    $powerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $noLock = $null
    
    if (Test-Path $powerPath) {
        $props = Get-ItemProperty -Path $powerPath -ErrorAction SilentlyContinue
        if ($props -and ($props | Get-Member -Name "NoLockScreen" -ErrorAction SilentlyContinue)) {
            $noLock = $props.NoLockScreen
        }
    }
    
    $desktopPath = "HKCU:\Control Panel\Desktop"
    $screenSave = $null
    if (Test-Path $desktopPath) {
        $props = Get-ItemProperty -Path $desktopPath -ErrorAction SilentlyContinue
        if ($props -and ($props | Get-Member -Name "ScreenSaveActive" -ErrorAction SilentlyContinue)) {
            $screenSave = $props.ScreenSaveActive
        }
    }
    
    if ($noLock -ne 1 -or $screenSave -eq "1") {
        Add-Result "Lock Screen on Wake" "PASS" "Lock screen enabled on wake-up"
    } else {
        Add-Result "Lock Screen on Wake" "FAIL" "Lock screen not enabled"
    }
} catch {
    Add-Result "Lock Screen on Wake" "FAIL" "Error: $($_.Exception.Message)"
}

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

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $val = (Get-ItemProperty -Path $regPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    if ($val -eq 1) {
        Add-Result "UAC Enabled" "PASS" "User Account Control is enabled"
    } else {
        Add-Result "UAC Enabled" "FAIL" "User Account Control is disabled"
    }
} catch {
    Add-Result "UAC Enabled" "FAIL" "Error: $($_.Exception.Message)"
}

try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $val = (Get-ItemProperty -Path $regPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
    if ($null -eq $val -or $val -eq 0) {
        Add-Result "SMBv1 Disabled" "PASS" "SMBv1 is safely disabled"
    } else {
        Add-Result "SMBv1 Disabled" "FAIL" "SMBv1 is enabled (Vulnerable)"
    }
} catch {
    Add-Result "SMBv1 Disabled" "FAIL" "Error: $($_.Exception.Message)"
}

try {
    $svc = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.StartType -ne "Disabled") {
        Add-Result "Windows Update Active" "PASS" "Windows Update service is not disabled"
    } else {
        Add-Result "Windows Update Active" "FAIL" "Windows Update service is disabled"
    }
} catch {
    Add-Result "Windows Update Active" "FAIL" "Error: $($_.Exception.Message)"
}

try {
    $policy = Get-ExecutionPolicy
    if ($policy -in @("Restricted", "RemoteSigned", "AllSigned")) {
        Add-Result "PowerShell Execution Policy" "PASS" "Execution Policy is safely configured ($policy)"
    } else {
        Add-Result "PowerShell Execution Policy" "FAIL" "Execution Policy is $policy"
    }
} catch {
    Add-Result "PowerShell Execution Policy" "FAIL" "Error: $($_.Exception.Message)"
}

try {
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like "*-500" }
    if ($null -eq $admin) {
        Add-Result "Administrator Account Renamed" "FAIL" "Could not enumerate users"
    } elseif ($admin.Name -eq "Administrator") {
        Add-Result "Administrator Account Renamed" "FAIL" "Built-in Administrator uses default name"
    } else {
        Add-Result "Administrator Account Renamed" "PASS" "Built-in Administrator is renamed"
    }
} catch {
    Add-Result "Administrator Account Renamed" "FAIL" "Error: $($_.Exception.Message)"
}

$results | ConvertTo-Json -Depth 3
