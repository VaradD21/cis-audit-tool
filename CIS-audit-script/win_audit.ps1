# Simple Windows Security Checks
$results = @()

function Add-Check ($name, $status, $details) {
    $global:results += [PSCustomObject]@{
        check   = $name
        status  = $status
        details = $details
    }
}

# 1. Password Length
$val = (net accounts | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
if ([int]$val -ge 14) { Add-Check "Password Length" "PASS" "Length is $val" } 
else { Add-Check "Password Length" "FAIL" "Length is $val (need 14)" }

# 2. Firewall
$fw = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}
if ($null -eq $fw) { Add-Check "Firewall" "PASS" "Enabled" } 
else { Add-Check "Firewall" "FAIL" "Disabled on some profiles" }

# 3. Guest Account
$guest = Get-LocalUser -Name "Guest"
if ($guest.Enabled -eq $false) { Add-Check "Guest Account" "PASS" "Disabled" } 
else { Add-Check "Guest Account" "FAIL" "Enabled" }

# 4. Windows Defender
$def = Get-MpComputerStatus
if ($def.AntivirusEnabled -eq $true) { Add-Check "Defender" "PASS" "Active" } 
else { Add-Check "Defender" "FAIL" "Inactive" }

# 5. Remote Desktop
$rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
if ($rdp -eq 1) { Add-Check "Remote Desktop" "PASS" "Disabled" } 
else { Add-Check "Remote Desktop" "FAIL" "Enabled" }

# Output as JSON
$results | ConvertTo-Json
