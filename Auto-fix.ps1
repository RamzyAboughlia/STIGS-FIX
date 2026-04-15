# Run in an elevated PowerShell window (Run as Administrator)
# Implements:
# - Account lockout duration (>=15 or 0)
# - Account lockout threshold (<=3 and NOT 0)
# - Rename built-in Guest account (name != "Guest")
# - If camera exists: Prevent enabling lock screen camera (Enabled)
# - Enable Audit Credential Validation (Failure)
#   + Also enforces "Force audit subcategory settings..." so subcategory auditing applies

# ----------------------------
# Settings (edit as needed)
# ----------------------------

# Lockout duration: 15+ minutes OR 0 (admin unlock required)
$LockoutDurationMinutes = 15     # or 0

# Lockout threshold: 1-3 (0 is NOT allowed)
$LockoutThreshold = 3

# Guest account new name (must NOT be "Guest", and must not already exist)
$NewGuestName = "Guest_Disabled_01"

# ----------------------------
# Helpers / prechecks
# ----------------------------

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) { throw "This script must be run as Administrator." }
}

function Write-Section($title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

Assert-Admin

# Validate lockout values
if ($LockoutDurationMinutes -lt 0) { throw "Lockout duration cannot be negative." }
if (($LockoutDurationMinutes -ne 0) -and ($LockoutDurationMinutes -lt 15)) {
    throw "STIG: Lockout duration must be 15 minutes or greater, or 0."
}
if ($LockoutThreshold -eq 0) { throw "STIG: Lockout threshold cannot be 0 (0 means 'no lockout')." }
if ($LockoutThreshold -gt 3) { throw "STIG: Lockout threshold must be 3 or less." }
if ($LockoutThreshold -lt 1) { throw "Lockout threshold must be at least 1." }

# Validate guest rename
if ([string]::IsNullOrWhiteSpace($NewGuestName)) { throw "New guest account name cannot be empty." }
if ($NewGuestName -ieq "Guest") { throw "STIG: Guest account must be renamed to something other than 'Guest'." }

# ----------------------------
# 1) Account lockout policy
# ----------------------------
Write-Section "Account Lockout Policy"

& net.exe accounts /lockoutduration:$LockoutDurationMinutes | Out-Null
& net.exe accounts /lockoutthreshold:$LockoutThreshold       | Out-Null

Write-Host "Applied lockout duration = $LockoutDurationMinutes minutes; threshold = $LockoutThreshold attempts."

# ----------------------------
# 2) Rename built-in Guest account
# ----------------------------
Write-Section "Rename Built-in Guest Account"

try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
} catch {
    $guest = $null
}

if (-not $guest) {
    Write-Host "Guest account not found (may already be renamed or removed). Skipping."
} else {
    # Ensure target name doesn't already exist
    $exists = $false
    try { Get-LocalUser -Name $NewGuestName -ErrorAction Stop | Out-Null; $exists = $true } catch { $exists = $false }

    if ($exists) {
        throw "Cannot rename Guest to '$NewGuestName' because a local user with that name already exists."
    }

    Rename-LocalUser -Name "Guest" -NewName $NewGuestName
    Write-Host "Renamed 'Guest' to '$NewGuestName'."
}

# ----------------------------
# 3) Lock screen camera policy (only if camera present)
#    Policy: Prevent enabling lock screen camera = Enabled
#    Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera = 1
# ----------------------------
Write-Section "Lock Screen Camera (Only If Camera Present)"

function Test-CameraPresent {
    # Try to detect camera devices robustly across different class names
    $classesToTry = @("Camera", "Image", "ImagingDevice")
    foreach ($cls in $classesToTry) {
        try {
            $dev = Get-PnpDevice -Class $cls -ErrorAction Stop | Where-Object {
                $_.Status -eq "OK" -or $_.Status -eq "Unknown"
            }
            if ($dev) { return $true }
        } catch {
            # ignore and try next class
        }
    }

    # Fallback: WMI query (less reliable, but helps on systems without Get-PnpDevice class mapping)
    try {
        $wmi = Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {
            ($_.PNPClass -match 'Image|Camera') -or ($_.Name -match 'camera|webcam')
        }
        if ($wmi) { return $true }
    } catch { }

    return $false
}

$cameraPresent = Test-CameraPresent
if (-not $cameraPresent) {
    Write-Host "No camera detected -> NA. Skipping lock screen camera policy."
} else {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "NoLockScreenCamera" -Type DWord -Value 1
    Write-Host "Camera detected -> Set NoLockScreenCamera=1 (Prevent enabling lock screen camera = Enabled)."
}

# ----------------------------
# 4) Audit Credential Validation (Failure)
#    Also enforce: "Force audit policy subcategory settings..." = Enabled
# ----------------------------
Write-Section "Advanced Auditing - Credential Validation (Failure)"

# Enforce subcategory override so auditpol subcategories apply:
# Security Option: "Audit: Force audit policy subcategory settings to override audit policy category settings"
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy = 1
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
New-Item -Path $lsaPath -Force | Out-Null
Set-ItemProperty -Path $lsaPath -Name "SCENoApplyLegacyAuditPolicy" -Type DWord -Value 1
Write-Host "Set SCENoApplyLegacyAuditPolicy=1 (force subcategory auditing)."

# Enable Credential Validation failure auditing
& auditpol.exe /set /subcategory:"Credential Validation" /failure:enable | Out-Null
Write-Host "Enabled Audit Credential Validation: Failure."

# ----------------------------
# Verify summary
# ----------------------------
Write-Section "Verification Summary"

Write-Host "`n[net accounts output]"
& net.exe accounts

Write-Host "`n[Guest account check]"
try {
    Get-LocalUser -Name $NewGuestName -ErrorAction Stop | Select-Object Name, Enabled, LastLogon
} catch {
    Write-Host "Could not find renamed guest account '$NewGuestName' (it may already have a different name)."
}

Write-Host "`n[Lock screen camera policy registry (if applicable)]"
if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization") {
    Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -ErrorAction SilentlyContinue |
        Select-Object NoLockScreenCamera
} else {
    Write-Host "Personalization policy key not present."
}

Write-Host "`n[AuditPol - Credential Validation]"
& auditpol.exe /get /subcategory:"Credential Validation"
