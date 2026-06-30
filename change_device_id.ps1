# This script designed by 'FOTE'.
param(
    [ValidateSet('Fingerprint','LegacyReset','RepairProfiles')]
    [string]$Mode = 'Fingerprint',

    [ValidateSet('Strict','Balanced')]
    [string]$PrivacyProfile = 'Balanced',

    [string]$StatePath = "${env:LOCALAPPDATA}\LicenseIdentity\fingerprint_state.json",

    [switch]$UpdateProfileListPaths
)

# Load assembly required for ProtectedData (not auto-loaded in Windows PowerShell 5.1)
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

if ($Mode -eq 'LegacyReset' -or $Mode -eq 'RepairProfiles') {
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Please run this script as Administrator!" -ForegroundColor Red
        Exit
    }
}

function Get-Sha256Hex {
    param(
        # NOTE: Do NOT name this $Input — that is a reserved PowerShell automatic
        # variable (pipeline enumerator). Naming it $Input causes PS 5.1 to
        # resolve it to an empty enumerator, making GetBytes() receive "" and
        # every hash becoming SHA256("") = e3b0c44...
        [Parameter(Mandatory=$true)][string]$InputText
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
        $hash = $sha.ComputeHash($bytes)
        return ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha.Dispose()
    }
}

function Protect-Bytes {
    param(
        [Parameter(Mandatory=$true)][byte[]]$Data
    )
    return [System.Security.Cryptography.ProtectedData]::Protect(
        $Data,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Unprotect-Bytes {
    param(
        [Parameter(Mandatory=$true)][byte[]]$Data
    )
    return [System.Security.Cryptography.ProtectedData]::Unprotect(
        $Data,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Read-State {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    if (-not (Test-Path $Path)) {
        return $null
    }
    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($obj -and $obj.protected) {
            $cipherBytes = [System.Convert]::FromBase64String([string]$obj.protected)
            $plainBytes = Unprotect-Bytes -Data $cipherBytes
            $plain = [System.Text.Encoding]::UTF8.GetString($plainBytes)
            return $plain | ConvertFrom-Json -ErrorAction Stop
        }
        return $obj
    } catch {
        return $null
    }
}

function Write-State {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$State
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $plain = $State | ConvertTo-Json -Depth 20
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
    $cipherBytes = Protect-Bytes -Data $plainBytes
    $wrapper = @{ protected = [System.Convert]::ToBase64String($cipherBytes) }
    $wrapper | ConvertTo-Json -Depth 5 | Out-File -FilePath $Path -Encoding UTF8
}

function Get-RandomHex {
    param(
        [int]$Length = 32
    )
    $bytesLen = [math]::Ceiling($Length / 2)
    $bytes = New-Object byte[] $bytesLen
    # Use GetBytes() for compatibility with Windows PowerShell 5.1 (.NET Framework)
    # ::Fill() is .NET Core / .NET 5+ only
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    return $hex.Substring(0, $Length)
}

function Get-StableSignals {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Strict','Balanced')][string]$Profile
    )

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
    $tz = (Get-TimeZone -ErrorAction SilentlyContinue)

    $signals = @{}

    if ($os) {
        $signals['os.caption'] = [string]$os.Caption
        $signals['os.build'] = [string]$os.BuildNumber
        $signals['os.arch'] = [string]$os.OSArchitecture
    }

    if ($cs) {
        $signals['hw.model'] = [string]$cs.Model
        $signals['hw.manufacturer'] = [string]$cs.Manufacturer
        $signals['hw.domain_role'] = [string]$cs.DomainRole
        $ramGb = 0
        if ($cs.TotalPhysicalMemory) {
            $ramGb = [math]::Round(([double]$cs.TotalPhysicalMemory / 1GB), 0)
        }
        $signals['hw.ram_gb_rounded'] = [string]$ramGb
    }

    if ($cpu) {
        $signals['cpu.name'] = [string]$cpu.Name
        $signals['cpu.cores'] = [string]$cpu.NumberOfCores
        $signals['cpu.logical'] = [string]$cpu.NumberOfLogicalProcessors
    }

    if ($bios) {
        $signals['bios.vendor'] = [string]$bios.Manufacturer
        $signals['bios.version'] = [string]$bios.SMBIOSBIOSVersion
    }

    if ($tz) {
        $signals['tz.id'] = [string]$tz.Id
    }

    $signals['culture'] = [string]([System.Globalization.CultureInfo]::CurrentCulture.Name)

    if ($Profile -eq 'Balanced') {
        $signals['ui.language'] = [string]([System.Globalization.CultureInfo]::CurrentUICulture.Name)
    }

    return $signals
}

function Get-SignalWeights {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Strict','Balanced')][string]$Profile
    )
    $w = @{
        'os.caption' = 0.05
        'os.build' = 0.10
        'os.arch' = 0.05
        'hw.model' = 0.12
        'hw.manufacturer' = 0.08
        'hw.domain_role' = 0.05
        'hw.ram_gb_rounded' = 0.10
        'cpu.name' = 0.12
        'cpu.cores' = 0.08
        'cpu.logical' = 0.08
        'bios.vendor' = 0.07
        'bios.version' = 0.05
        'tz.id' = 0.03
        'culture' = 0.02
        'ui.language' = 0.00
    }
    if ($Profile -eq 'Balanced') {
        $w['ui.language'] = 0.02
    }
    return $w
}

function Hash-Signals {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Signals,
        [Parameter(Mandatory=$true)][string]$Salt
    )
    $hashed = @{}
    foreach ($k in $Signals.Keys) {
        $v = [string]$Signals[$k]
        $hashed[$k] = Get-Sha256Hex -InputText ("$Salt|$k|$v")
    }
    return $hashed
}

function Score-Match {
    param(
        [Parameter(Mandatory=$true)][hashtable]$A,
        [Parameter(Mandatory=$true)][hashtable]$B,
        [Parameter(Mandatory=$true)][hashtable]$Weights
    )
    $keys = @($Weights.Keys)
    $total = 0.0
    $hit = 0.0
    foreach ($k in $keys) {
        $w = [double]$Weights[$k]
        if ($w -le 0) { continue }
        $total += $w
        if ($A.ContainsKey($k) -and $B.ContainsKey($k) -and ([string]$A[$k] -eq [string]$B[$k])) {
            $hit += $w
        }
    }
    if ($total -le 0) { return 0.0 }
    return [math]::Round(($hit / $total), 4)
}

# ConvertFrom-Json returns PSCustomObject for nested objects, not [hashtable].
# This helper normalises either type into a plain [hashtable] so Score-Match
# and Hash-Signals always receive the correct type.
function ConvertTo-SignalHashtable {
    param([Parameter(Mandatory=$true)]$Obj)
    if ($null -eq $Obj)               { return @{} }
    if ($Obj -is [hashtable])          { return $Obj }
    $ht = @{}
    $Obj.PSObject.Properties | ForEach-Object { $ht[$_.Name] = [string]$_.Value }
    return $ht
}

function Get-ConsensusSnapshot {
    param(
        [Parameter(Mandatory=$true)][array]$Snapshots,
        [Parameter(Mandatory=$true)][hashtable]$Weights
    )
    if (-not $Snapshots -or $Snapshots.Count -eq 0) {
        return $null
    }
    $signals = @{}
    $keys = @($Weights.Keys)
    foreach ($k in $keys) {
        $counts = @{}
        foreach ($s in $Snapshots) {
            if ($s -and $s.signals -and $s.signals.$k) {
                $val = [string]$s.signals.$k
                if (-not $counts.ContainsKey($val)) { $counts[$val] = 0 }
                $counts[$val] += 1
            }
        }
        if ($counts.Count -gt 0) {
            $top = $counts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1
            $signals[$k] = [string]$top.Key
        }
    }
    return $signals
}

if ($Mode -eq 'Fingerprint') {
    $state = Read-State -Path $StatePath
    if (-not $state) {
        $state = [ordered]@{
            version = 1
            createdAt = (Get-Date).ToString('o')
            salt = (Get-RandomHex -Length 64)
            snapshots = @()
        }
    }

    $weights = Get-SignalWeights -Profile $PrivacyProfile
    $signals = Get-StableSignals -Profile $PrivacyProfile
    $hashedSignals = Hash-Signals -Signals $signals -Salt ([string]$state.salt)

    $now = (Get-Date).ToString('o')
    $newSnapshot = [ordered]@{
        ts = $now
        signals = $hashedSignals
    }

    $existing = @()
    if ($state.snapshots) { $existing = @($state.snapshots) }

    $maxHistory = 12
    # Wrap in @() so $recent is always an [array], never $null, even when $existing is empty
    $recent = @($existing | Select-Object -Last $maxHistory)

    $lastSignals = $null
    if ($recent.Count -gt 0) {
        # Convert from PSCustomObject (ConvertFrom-Json output) to hashtable
        $lastSignals = ConvertTo-SignalHashtable $recent[-1].signals
    }

    $consensusSignals = Get-ConsensusSnapshot -Snapshots $recent -Weights $weights

    $scoreLast = $null
    if ($lastSignals) {
        $scoreLast = Score-Match -A $hashedSignals -B $lastSignals -Weights $weights
    }

    $scoreConsensus = $null
    if ($consensusSignals) {
        $scoreConsensus = Score-Match -A $hashedSignals -B $consensusSignals -Weights $weights
    }

    $threshold = 0.70
    if ($PrivacyProfile -eq 'Strict') { $threshold = 0.85 }

    $effectiveScore = $scoreConsensus
    if ($effectiveScore -eq $null) { $effectiveScore = $scoreLast }
    if ($effectiveScore -eq $null) { $effectiveScore = 1.0 }

    $sameIdentity = ($effectiveScore -ge $threshold)

    $snapshotsUpdated = @($recent + $newSnapshot)
    if ($snapshotsUpdated.Count -gt $maxHistory) {
        $snapshotsUpdated = $snapshotsUpdated | Select-Object -Last $maxHistory
    }

    $state.snapshots = $snapshotsUpdated
    Write-State -Path $StatePath -State $state

    $fingerprintIdMaterial = ($hashedSignals.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
    $fingerprintId = Get-Sha256Hex -InputText ("v1|$($state.salt)|$fingerprintIdMaterial")

    $out = [ordered]@{
        mode = 'Fingerprint'
        profile = $PrivacyProfile
        statePath = $StatePath
        ts = $now
        fingerprintId = $fingerprintId
        score = $effectiveScore
        threshold = $threshold
        sameIdentity = $sameIdentity
        scoreLast = $scoreLast
        scoreConsensus = $scoreConsensus
        historyCount = $snapshotsUpdated.Count
    }

    $out | ConvertTo-Json -Depth 10
    Exit
}

function Repair-ProfileList {
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    if (-not (Test-Path $profileListPath)) {
        Write-Host "ProfileList path not found: $profileListPath" -ForegroundColor Red
        return $false
    }

    $timestampLocal = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDirLocal = "$env:TEMP\ProfileListBackup_$timestampLocal"
    New-Item -ItemType Directory -Path $backupDirLocal -Force | Out-Null
    try {
        reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" "$backupDirLocal\ProfileList.reg" /y | Out-Null
        Write-Host "Backup created at: $backupDirLocal" -ForegroundColor Cyan
    } catch {
        Write-Host "Warning: Could not export ProfileList backup`: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $bakKeys = Get-ChildItem -Path $profileListPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*.bak' }
    foreach ($bakKey in $bakKeys) {
        $bakName = $bakKey.PSChildName
        $baseName = $bakName.Substring(0, $bakName.Length - 4)
        $baseKeyPath = Join-Path $profileListPath $baseName

        if (Test-Path $baseKeyPath) {
            try {
                Remove-Item -Path $baseKeyPath -Recurse -Force
                Write-Host "Removed temp profile key: $baseKeyPath" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove temp profile key $baseKeyPath`: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        }

        try {
            Rename-Item -Path $bakKey.PSPath -NewName $baseName -Force
            Write-Host "Renamed $bakName to $baseName" -ForegroundColor Green
        } catch {
            Write-Host "Failed to rename $bakName`: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        $fixedKeyPath = Join-Path $profileListPath $baseName
        try {
            if (-not (Test-Path $fixedKeyPath)) { continue }
            New-ItemProperty -Path $fixedKeyPath -Name 'State' -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $fixedKeyPath -Name 'RefCount' -PropertyType DWord -Value 0 -Force | Out-Null
            Write-Host "Set State/RefCount to 0 for: $fixedKeyPath" -ForegroundColor Green
        } catch {
            Write-Host "Failed to set State/RefCount for $fixedKeyPath`: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return $true
}

if ($Mode -eq 'RepairProfiles') {
    $ok = Repair-ProfileList
    if ($ok) {
        Write-Host "Profile repair complete. Please restart your computer." -ForegroundColor Yellow
        Exit
    }
    Write-Host "Profile repair failed. Please restore from backup if needed." -ForegroundColor Red
    Exit
}

# Create backup directory and timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "$env:TEMP\DeviceIDBackup_$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
Write-Host "Creating backup in: $backupDir" -ForegroundColor Cyan

# Initialize rollback system
$changeLog = @()
$rollbackNeeded = $false
$rollbackSucceeded = $true

# Rollback function to restore original values if something fails
function Restore-OriginalValues {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Changes
    )
    
    Write-Host "`nPerforming rollback of changes..." -ForegroundColor Yellow
    $rollbackSuccess = $true
    
    # Process changes in reverse order
    [array]::Reverse($Changes)
    
    foreach ($change in $Changes) {
        try {
            if ($change.ChangeType -eq "RegistryValue") {
                if ($change.OriginalExists) {
                    Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.OriginalValue -Force
                    Write-Host "Restored: $($change.Path)\$($change.Name) to $($change.OriginalValue)" -ForegroundColor Green
                } else {
                    Remove-ItemProperty -Path $change.Path -Name $change.Name -Force
                    Write-Host "Removed: $($change.Path)\$($change.Name)" -ForegroundColor Green
                }
            } elseif ($change.ChangeType -eq "ComputerName") {
                Rename-Computer -NewName $change.OriginalValue -Force
                Write-Host "Restored computer name to: $($change.OriginalValue)" -ForegroundColor Green
            }
        } catch {
            Write-Host "Failed to rollback $($change.Path)\$($change.Name)`: $($_.Exception.Message)" -ForegroundColor Red
            $rollbackSuccess = $false
        }
    }
    
    return $rollbackSuccess
}

# Backup current system information to file
$currentInfo = @{
    ComputerName = $env:COMPUTERNAME
    MachineId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient" -Name "MachineId" -ErrorAction SilentlyContinue).MachineId
    MachineGUID = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction SilentlyContinue).MachineGuid
    ProductId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductId" -ErrorAction SilentlyContinue).ProductId
    ProductName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName" -ErrorAction SilentlyContinue).ProductName
    RegisteredOwner = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "RegisteredOwner" -ErrorAction SilentlyContinue).RegisteredOwner
    RegisteredOrganization = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "RegisteredOrganization" -ErrorAction SilentlyContinue).RegisteredOrganization
}
$currentInfo | ConvertTo-Json | Out-File "$backupDir\system_info_backup.json"

# Export registry keys
try {
    reg export "HKLM\SOFTWARE\Microsoft\SQMClient" "$backupDir\SQMClient.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" "$backupDir\DeviceMetadata.reg" /y | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation" "$backupDir\SystemInformation.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "$backupDir\WindowsNTCurrentVersion.reg" /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Cryptography" "$backupDir\Cryptography.reg" /y | Out-Null
    # Backup user hives as well
    reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo" "$backupDir\SessionInfo.reg" /y | Out-Null
    reg export "HKCU\Software\Microsoft\IdentityCRL" "$backupDir\IdentityCRL.reg" /y | Out-Null
    reg export "HKCU\Software\Microsoft\Personalization" "$backupDir\Personalization.reg" /y | Out-Null
    Write-Host "Registry backups created successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not create complete registry backups`: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Generate new IDs
$newDeviceID = [System.Guid]::NewGuid().ToString().ToUpper()
$newMachineGUID = [System.Guid]::NewGuid().ToString()
$newProductID = "00331-" + (Get-Random -Minimum 10000 -Maximum 99999) + "-" + (Get-Random -Minimum 10000 -Maximum 99999) + "-" + (Get-Random -Minimum 10000 -Maximum 99999)
$newComputerName = "RESET-PC-" + (Get-Random -Minimum 1000 -Maximum 9999)

# Validate computer name (15 characters max for NetBIOS compatibility)
if ($newComputerName.Length -gt 15) {
    $newComputerName = $newComputerName.Substring(0, 15)
    Write-Host "Computer name truncated to 15 characters: $newComputerName" -ForegroundColor Yellow
}

Write-Host "`nCurrent System Information:" -ForegroundColor Cyan
Write-Host "Device Name: $env:COMPUTERNAME"
Write-Host "Device ID: $($currentInfo.MachineId)"
Write-Host "Machine GUID: $($currentInfo.MachineGUID)"
Write-Host "Product ID: $($currentInfo.ProductId)"

Write-Host "`nNew IDs will be:" -ForegroundColor Yellow
Write-Host "New Device ID: $newDeviceID"
Write-Host "New Machine GUID: $newMachineGUID"
Write-Host "New Product ID: $newProductID"
Write-Host "New Computer Name: $newComputerName"

# Registry paths to modify (with type information)
$registryPaths = @(
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\SQMClient"
        Name = "MachineId"
        Value = $newDeviceID
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"
        Name = "MachineId"
        Value = $newDeviceID
        Type = "String"
    },
    @{
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation"
        Name = "ComputerHardwareId"
        Value = $newDeviceID
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        Name = "MachineGuid"
        Value = $newMachineGUID
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Name = "ProductId"
        Value = $newProductID
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Name = "ProductName"
        Value = "Windows 10 Pro"
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Name = "RegisteredOwner"
        Value = "RESET"
        Type = "String"
    },
    @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        Name = "RegisteredOrganization"
        Value = "RESET"
        Type = "String"
    }
)

# Get a list of all user SIDs
$userProfiles = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | 
    Where-Object { $_.PSChildName -match "S-1-5-21" }

# Add user-specific registry entries to modify for each user profile
foreach ($profile in $userProfiles) {
    $sid = $profile.PSChildName
    $userHivePath = "$($profile.GetValue('ProfileImagePath'))\NTUSER.DAT"
    
    # Only process if the user hive exists
    if (Test-Path $userHivePath) {
        # Load the user's registry hive if it's not already loaded
        $hiveMounted = $false
        if (-not (Test-Path "Registry::HKEY_USERS\$sid")) {
            try {
                reg load "HKU\$sid" "$userHivePath" | Out-Null
                $hiveMounted = $true
                Write-Host "Loaded user hive for SID: $sid" -ForegroundColor Green
            } catch {
                Write-Host "Failed to load hive for SID $sid`: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }
        }
        
        # Add user-specific registry paths for this user
        $registryPaths += @(
            @{
                Path = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo"
                Name = "PermanentSessionId"
                Value = (Get-Random -Minimum 1 -Maximum 999)
                Type = "DWord"
                TempHive = $hiveMounted
                SID = $sid
            },
            @{
                Path = "Registry::HKEY_USERS\$sid\Software\Microsoft\IdentityCRL"
                Name = "DeviceId"
                Value = $newDeviceID
                Type = "String"
                TempHive = $hiveMounted
                SID = $sid
            },
            @{
                Path = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                Name = "MachineGuid"
                Value = $newMachineGUID
                Type = "String"
                TempHive = $hiveMounted
                SID = $sid
            }
        )
    }
}

# For current user, also update HKCU directly
$registryPaths += @(
    @{
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo"
        Name = "PermanentSessionId"
        Value = (Get-Random -Minimum 1 -Maximum 999)
        Type = "DWord"
    },
    @{
        Path = "HKCU:\Software\Microsoft\IdentityCRL"
        Name = "DeviceId"
        Value = $newDeviceID
        Type = "String"
    },
    @{
        Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        Name = "MachineGuid"
        Value = $newMachineGUID
        Type = "String"
    }
)

# Update registry values
$successCount = 0
$totalChanges = $registryPaths.Count

foreach ($reg in $registryPaths) {
    try {
        # Skip if path doesn't exist and doesn't have SID information (non-user registry)
        if (-not (Test-Path $reg.Path) -and -not $reg.ContainsKey('SID')) {
            Write-Host "Path not found: $($reg.Path)" -ForegroundColor Yellow
            try {
                # Try to create the path
                New-Item -Path $reg.Path -Force | Out-Null
                
                # Create a change log entry for rollback
                $changeLog += @{
                    ChangeType = "RegistryValue"
                    Path = $reg.Path
                    Name = $reg.Name
                    OriginalExists = $false
                    OriginalValue = $null
                }
                
                # Create new property with correct type
                switch ($reg.Type) {
                    "String" { 
                        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType String -Force | Out-Null 
                    }
                    "DWord" { 
                        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType DWord -Force | Out-Null 
                    }
                    "QWord" { 
                        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType QWord -Force | Out-Null 
                    }
                    "Binary" { 
                        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType Binary -Force | Out-Null 
                    }
                    Default { 
                        New-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType String -Force | Out-Null 
                    }
                }
                
                Write-Host "Created new registry entry: $($reg.Path)\$($reg.Name)" -ForegroundColor Green
                $successCount++
            } catch {
                Write-Host "Could not create registry path`: $($_.Exception.Message)" -ForegroundColor Red
                $rollbackNeeded = $true
                break
            }
        } else {
            # Path exists, try to get the original value for backup/rollback
            $originalExists = $false
            $originalValue = $null
            
            try {
                $regItem = Get-ItemProperty -Path $reg.Path -Name $reg.Name -ErrorAction SilentlyContinue
                if ($regItem -ne $null) {
                    $originalExists = $true
                    $originalValue = $regItem.$($reg.Name)
                    
                    # Backup current value
                    "$($reg.Path)|$($reg.Name)|$originalValue" | Out-File -FilePath "$backupDir\registry_values.txt" -Append
                    
                    # Add to change log for potential rollback
                    $changeLog += @{
                        ChangeType = "RegistryValue"
                        Path = $reg.Path
                        Name = $reg.Name
                        OriginalExists = $true
                        OriginalValue = $originalValue
                    }
                }
            } catch {
                # Property doesn't exist yet, will be created
                $originalExists = $false
                $changeLog += @{
                    ChangeType = "RegistryValue"
                    Path = $reg.Path
                    Name = $reg.Name
                    OriginalExists = $false
                    OriginalValue = $null
                }
            }
            
            # Set new value with proper type
            try {
                switch ($reg.Type) {
                    "String" { 
                        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type String -Force 
                    }
                    "DWord" { 
                        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord -Force 
                    }
                    "QWord" { 
                        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type QWord -Force 
                    }
                    "Binary" { 
                        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type Binary -Force 
                    }
                    Default { 
                        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Force 
                    }
                }
                
                # Verify change
                $newValue = (Get-ItemProperty -Path $reg.Path -Name $reg.Name -ErrorAction SilentlyContinue).$($reg.Name)
                if ($newValue -eq $reg.Value) {
                    Write-Host "Updated $($reg.Path)\$($reg.Name)" -ForegroundColor Green
                    $successCount++
                } else {
                    Write-Host "Failed to verify change for $($reg.Path)\$($reg.Name)" -ForegroundColor Red
                    $rollbackNeeded = $true
                    break
                }
            } catch {
                Write-Host "Failed to update $($reg.Path)\$($reg.Name)`: $($_.Exception.Message)" -ForegroundColor Red
                $rollbackNeeded = $true
                break
            }
        }
    } catch {
        Write-Host "Error processing $($reg.Path)\$($reg.Name)`: $($_.Exception.Message)" -ForegroundColor Red
        $rollbackNeeded = $true
        break
    }
}

# Change computer name if no rollback is needed
if (-not $rollbackNeeded) {
    try {
        # Add to change log for potential rollback
        $changeLog += @{
            ChangeType = "ComputerName"
            OriginalValue = $env:COMPUTERNAME
        }
        
        Rename-Computer -NewName $newComputerName -Force
        Write-Host "Computer name will be changed to: $newComputerName" -ForegroundColor Green
        $successCount++
    } catch {
        Write-Host "Failed to change computer name`: $($_.Exception.Message)" -ForegroundColor Red
        $rollbackNeeded = $true
    }

    if ($UpdateProfileListPaths) {
        # Update profile paths more safely
        try {
            $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            if (Test-Path $profileListPath) {
                $subKeys = Get-ChildItem -Path $profileListPath
                foreach ($key in $subKeys) {
                    try {
                        $profilePath = Get-ItemProperty -Path $key.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue
                        if ($profilePath -and $profilePath.ProfileImagePath) {
                            # Backup original path
                            "$($key.PSPath)|ProfileImagePath|$($profilePath.ProfileImagePath)" | Out-File -FilePath "$backupDir\profile_paths.txt" -Append
                            
                            # Add to change log for potential rollback
                            $changeLog += @{
                                ChangeType = "RegistryValue"
                                Path = $key.PSPath
                                Name = "ProfileImagePath"
                                OriginalExists = $true
                                OriginalValue = $profilePath.ProfileImagePath
                            }
                            
                            # Only replace if old computer name is in the path
                            if ($profilePath.ProfileImagePath -like "*$env:COMPUTERNAME*") {
                                $newPath = $profilePath.ProfileImagePath.Replace($env:COMPUTERNAME, $newComputerName)
                                Set-ItemProperty -Path $key.PSPath -Name "ProfileImagePath" -Value $newPath
                                Write-Host "Updated profile path: $newPath" -ForegroundColor Green
                            }
                        }
                    } catch {
                        Write-Host "Failed to update profile path`: $($_.Exception.Message)" -ForegroundColor Red
                        $rollbackNeeded = $true
                        break
                    }
                }
            }
        } catch {
            Write-Host "Failed to update profile paths`: $($_.Exception.Message)" -ForegroundColor Red
            $rollbackNeeded = $true
        }
    }
}

# Check if rollback is needed
if ($rollbackNeeded) {
    Write-Host "`nSome operations failed. Rolling back changes..." -ForegroundColor Red
    $rollbackSucceeded = Restore-OriginalValues -Changes $changeLog
    
    if ($rollbackSucceeded) {
        Write-Host "Rollback completed successfully." -ForegroundColor Green
    } else {
        Write-Host "WARNING: Some rollback operations failed!" -ForegroundColor Red
        Write-Host "System may be in an inconsistent state." -ForegroundColor Red
        Write-Host "Manual restoration from backup may be required: $backupDir" -ForegroundColor Red
    }
    
    # Unload any temporarily mounted hives
    foreach ($reg in $registryPaths) {
        if ($reg.ContainsKey('TempHive') -and $reg.TempHive -eq $true) {
            try {
                reg unload "HKU\$($reg.SID)" | Out-Null
                Write-Host "Unloaded user hive for SID`: $($reg.SID)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to unload hive for SID $($reg.SID)`: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "`nOperation aborted. No changes were made." -ForegroundColor Red
    Exit
}

# Unload any temporarily mounted hives
foreach ($reg in $registryPaths) {
    if ($reg.ContainsKey('TempHive') -and $reg.TempHive -eq $true) {
        try {
            reg unload "HKU\$($reg.SID)" | Out-Null
            Write-Host "Unloaded user hive for SID`: $($reg.SID)" -ForegroundColor Green
        } catch {
            Write-Host "Failed to unload hive for SID $($reg.SID)`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Completion status
Write-Host "`n=================================================" -ForegroundColor Cyan
$percentComplete = [math]::Round(($successCount / ($totalChanges + 1)) * 100)
Write-Host "CHANGES COMPLETE: $percentComplete% Success Rate" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "`nBackup created at: $backupDir" -ForegroundColor Cyan
Write-Host "`nIMPORTANT: System must restart for all changes to take effect." -ForegroundColor Yellow
Write-Host "After restart, your system will have:" -ForegroundColor Yellow
Write-Host "- New Device ID: $newDeviceID" -ForegroundColor Yellow
Write-Host "- New Machine GUID: $newMachineGUID" -ForegroundColor Yellow
Write-Host "- New Product ID: $newProductID" -ForegroundColor Yellow
Write-Host "- New Computer Name: $newComputerName" -ForegroundColor Yellow

# Create restore script
$restoreScriptPath = "$backupDir\restore_original_values.ps1"
@"
# Run as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Exit
}

# Import registry backups
Write-Host "Restoring registry backups..." -ForegroundColor Cyan
reg import "$backupDir\SQMClient.reg"
reg import "$backupDir\DeviceMetadata.reg"
reg import "$backupDir\SystemInformation.reg"
reg import "$backupDir\WindowsNTCurrentVersion.reg"
reg import "$backupDir\Cryptography.reg"
reg import "$backupDir\SessionInfo.reg"
reg import "$backupDir\IdentityCRL.reg"
reg import "$backupDir\Personalization.reg"

# Restore computer name
Rename-Computer -NewName "$($currentInfo.ComputerName)" -Force
Write-Host "Computer name will be restored to: $($currentInfo.ComputerName)" -ForegroundColor Green

Write-Host "System restoration complete. Please restart your computer." -ForegroundColor Green
"@ | Out-File -FilePath $restoreScriptPath -Encoding ASCII

Write-Host "`nA restore script has been created at: $restoreScriptPath" -ForegroundColor Cyan
Write-Host "You can run this script to restore your original settings if needed." -ForegroundColor Cyan

# Cleanup
Remove-Variable -Name currentInfo, newDeviceID, newMachineGUID, newProductID, newComputerName, registryPaths, successCount, totalChanges, changeLog, rollbackNeeded, rollbackSucceeded -ErrorAction SilentlyContinue

# Prompt for restart
$restart = Read-Host "`nWould you like to restart now? (y/n)"
if ($restart -eq 'y' -or $restart -eq 'Y') {
    Write-Host "Restarting system in 10 seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Remember to restart your system manually for changes to take effect." -ForegroundColor Yellow 
} 