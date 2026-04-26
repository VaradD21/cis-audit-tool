# ==========================================================
# WINDOWS SECURITY CHECKS (CIS BENCHMARK)
# ==========================================================

$results = @()

function Log-Result($Name, $Status, $Info) {
    $results += [PSCustomObject]@{
        check   = $Name
        status  = $Status
        details = $Info
    }
}

# 1. Password Policy
$minLen = (net accounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
if ([int]$minLen -ge 14) { Log-Result "Password Length" "PASS" "Length is $minLen" }
else { Log-Result "Password Length" "FAIL" "Length is $minLen (Min 14)" }

# 2. Firewall Status
$profiles = Get-NetFirewallProfile
$disabled = $profiles | Where-Object { $_.Enabled -eq $false }
if ($null -eq $disabled) { Log-Result "Firewall" "PASS" "Enabled on all profiles" }
else { Log-Result "Firewall" "FAIL" "Disabled on $($disabled.Name)" }

# 3. Guest Account
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($null -eq $guest) { Log-Result "Guest Account" "PASS" "Does not exist" }
elseif ($guest.Enabled -eq $false) { Log-Result "Guest Account" "PASS" "Disabled" }
else { Log-Result "Guest Account" "FAIL" "Enabled" }

# 4. Windows Defender
$def = Get-MpComputerStatus
if ($def.AntivirusEnabled -eq $true) { Log-Result "Windows Defender" "PASS" "Active" }
else { Log-Result "Windows Defender" "FAIL" "Inactive" }

# 5. Remote Desktop (RDP)
$rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
if ($rdp -eq 1) { Log-Result "Remote Desktop" "PASS" "Disabled" }
else { Log-Result "Remote Desktop" "FAIL" "Enabled" }

# 6. Auto-Run
$ar = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
if ($ar -eq 255) { Log-Result "Auto-Run" "PASS" "Disabled (Value 255)" }
else { Log-Result "Auto-Run" "FAIL" "Enabled or Value is $ar" }

# Output results for Python to read
$results | ConvertTo-Json
