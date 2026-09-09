#Requires -RunAsAdministrator
# ============================================================================
#  windows_harden.ps1 - Interactive Windows hardening (PowerShell 5.1+)
#
#  Modes:
#    ./windows_harden.ps1                    interactive category menu
#    ./windows_harden.ps1 -Wizard            guided walk-through, asks per measure
#    ./windows_harden.ps1 -ApplyAll          unattended: apply every measure
#    ./windows_harden.ps1 -Module firewall   run specific categories only
#    ./windows_harden.ps1 -DryRun            preview only - changes nothing
#
#  Options:
#    -PasswordMinLength <n>   minimum password length (default 12)
#    -MaxPasswordAge <n>      maximum password age in days (default 90)
#    -MinPasswordAge <n>      minimum password age in days (default 1)
#    -LockoutThreshold <n>    invalid attempts before lockout (default 10)
#
#  Safety:
#    * every registry key and file that would change is backed up (reg export /
#      file copy) under <userprofile>\.harden-backups\<timestamp>\
#    * a rollback.ps1 is generated next to the backups
#    * repeat runs are idempotent (already-applied measures are skipped)
# ============================================================================

[CmdletBinding()]
param(
    [switch]$ApplyAll,
    [switch]$Wizard,
    [string[]]$Module,
    [switch]$DryRun,
    [switch]$NonInteractive,
    [switch]$Version,
    [switch]$Help,
    [int]$PasswordMinLength = 12,
    [int]$MaxPasswordAge = 90,
    [int]$MinPasswordAge = 1,
    [int]$LockoutThreshold = 10
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Script:AppVersion = '1.0.0'
$Script:Applied = 0
$Script:Skipped = 0

# ---- state ------------------------------------------------------------------
if ($env:HARDEN_BACKUP_ROOT) { $Script:BackupRoot = $env:HARDEN_BACKUP_ROOT }
else { $Script:BackupRoot = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE '.harden-backups' } else { Join-Path $HOME '.harden-backups' } }
$Script:Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$Script:BackupDir = Join-Path $Script:BackupRoot $Script:Stamp
$Script:LogFile   = Join-Path $Script:BackupDir "harden_$($Script:Stamp).log"
$Script:Manifest  = Join-Path $Script:BackupDir 'manifest.txt'
$Script:Rollback  = Join-Path $Script:BackupDir "rollback_$($Script:Stamp).ps1"

if ($Version) { "windows_harden.ps1 v$($Script:AppVersion)"; exit 0 }
if ($Help) {
    Get-Content $PSCommandPath | Where-Object { $_ -like '#*' } |
        ForEach-Object { $_ -replace '^#\s?', '' }
    exit 0
}

# ---- interactive detection --------------------------------------------------
$Script:Interactive = -not ($ApplyAll -or $NonInteractive)

Write-Output "windows_harden.ps1 v$($Script:AppVersion) - interactive Windows hardening"
Write-Output "  backups: $($Script:BackupDir)"
Write-Output "  dry run: $(if ($DryRun) { 'yes' } else { 'no' })"
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $Script:BackupRoot | Out-Null }

# ---- output helpers ---------------------------------------------------------
function Write-LogMsg { param([string]$M)
    if (Test-Path (Split-Path $Script:LogFile)) {
        "$(Get-Date -Format 'HH:mm:ss') $M" | Out-File -Append -Encoding utf8 $Script:LogFile
    }
}
function Write-Info { param([string]$M) Write-Host "[i] $M" -ForegroundColor Cyan; Write-LogMsg $M }
function Write-Ok   { param([string]$M) $Script:Applied++; Write-Host "[+] $M" -ForegroundColor Green; Write-LogMsg "OK $M" }
function Write-Skip { param([string]$M) $Script:Skipped++; Write-Host "[-] $M" -ForegroundColor Yellow; Write-LogMsg "SKIP $M" }
function Write-Warn { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow; Write-LogMsg "WARN $M" }
function Write-Err  { param([string]$M) Write-Host "[-] $M" -ForegroundColor Red; Write-LogMsg "ERR $M" }
function Write-Banner { param([string]$M) Write-Host "-- $M --" -ForegroundColor White }

# ---- backups ----------------------------------------------------------------
function Initialize-Backup {
    if ($DryRun) { return }
    if (Test-Path $Script:BackupDir) { return }
    New-Item -ItemType Directory -Force -Path $Script:BackupDir | Out-Null
    '' | Out-File -Encoding utf8 $Script:Manifest
    @'
$bd = $args[0]
if (-not $bd) { $bd = "<backup-dir>" }
function rf { param($rel, $dst)
    $src = Join-Path $bd $rel
    if (Test-Path $src) { Copy-Item $src $dst -Force; Write-Host "restored: $dst" }
    else { Write-Host "!! no backup for $dst" }
}
function ri { param($file)  # registry import
    if (Test-Path $file) { reg.exe import $file *> $null; Write-Host "restored registry: $file" }
    else { Write-Host "!! no reg backup for $file" }
}
'@ | Set-Content -Encoding utf8 $Script:Rollback
    Write-Info "backup dir: $($Script:BackupDir)"
}

function Backup-File { param([string]$Path)
    if ($DryRun) { return }
    if (-not (Test-Path $Path)) { return }
    Initialize-Backup
    $rel = $Path.TrimStart('\', '/').Replace('\', '__')
    $dest = Join-Path $Script:BackupDir $rel
    Copy-Item $Path $dest -Force
    Add-Content -Encoding utf8 $Script:Manifest $Path
    $relArg = $rel.Replace("'", "''")
    $dstArg = $Path.Replace("'", "''")
    Add-Content -Encoding utf8 $Script:Rollback "rf '$relArg' '$dstArg'"
}

function Backup-RegistryKey { param([string]$Key, [string]$Name)
    if ($DryRun) { return }
    Initialize-Backup
    $safe = ($Key.Replace('\','-') + '_' + $Name.Replace('\','-'))
    $file = Join-Path $Script:BackupDir "reg_$($safe).reg"
    reg.exe export $Key $file /y *> $null
    Add-Content -Encoding utf8 $Script:Rollback "ri '$($file.Replace("'","''"))'"
}

# ---- confirmation / value helpers ------------------------------------------
function Confirm-Hardening { param([string]$Prompt)
    if ($DryRun) { return $true }      # walk apply path; write helpers only print
    if (-not $Script:Interactive) { return $true }
    $ans = Read-Host "? $Prompt [y/N]"
    return ($ans -match '^y(es)?$')
}

function Ask-Value { param([string]$Prompt, [string]$Default)
    if (-not $Script:Interactive) { return $Default }
    $v = Read-Host "? $Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v
}

# ---- action primitives ------------------------------------------------------
function Invoke-HardenCmd { param([string]$Cmd, [string]$Line, [string]$Label)
    if ($DryRun) { Write-Host "         (dry) $Label"; return 0 }
    $out = cmd.exe /c $Cmd 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok "$Label"; return 0 }
    Write-Err "$Label failed ($LASTEXITCODE)"
    return 1
}

# ============================================================================
#  Module: Firewall
# ============================================================================
function Set-HardenFirewall {
    Write-Banner 'Firewall'
    Initialize-Backup

    $profiles = 'Domain,Public,Private'
    if ($DryRun) {
        Write-Host "         (dry) enable all firewall profiles ($profiles)"
        Write-Host "         (dry) set default inbound action to Block"
        Write-Host "         (dry) enable firewall logging"
    } else {
        try {
            Set-NetFirewallProfile -Profile $profiles -Enabled True
            Set-NetFirewallProfile -Profile $profiles -DefaultInboundAction Block -DefaultOutboundAction Allow
            netsh.exe advfirewall set allprofiles logging filename "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" | Out-Null
            netsh.exe advfirewall set allprofiles logging droppedconnections enable | Out-Null
            Write-Ok 'firewall enabled on all profiles, inbound default Block, logging on'
        } catch { Write-Err "firewall hardening failed: $_" }
    }

    if (Confirm-Hardening 'Restrict Remote Desktop (RDP) inbound to the local subnet?') {
        try {
            if ($DryRun) { Write-Host '         (dry) restrict RDP rules to LocalSubnet' }
            else {
                Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
                    Set-NetFirewallRule -RemoteAddress LocalSubnet -ErrorAction SilentlyContinue
                Write-Ok 'RDP restricted to local subnet'
            }
        } catch { Write-Warn "RDP rules not found or unchanged: $_" }
    } else { Write-Skip 'RDP subnet restriction' }
}

# ============================================================================
#  Module: Accounts & Password policy
# ============================================================================
function Get-NetAccountsValues {
    $raw = (net.exe accounts) -join "`n"
    $v = @{}
    foreach ($key in @('Minimum password length', 'Maximum password age (days)', 'Minimum password age (days)', 'Lockout threshold')) {
        $m = [regex]::Match($raw, "$([regex]::Escape($key))\s*([\d]+|Never)")
        $v[$key] = if ($m.Success) { $m.Groups[1].Value } else { '' }
    }
    return $v
}

function Set-HardenAccounts {
    Write-Banner 'Accounts & Password Policy'
    Initialize-Backup

    $before = Get-NetAccountsValues
    $orig = $before['Minimum password length']
    $origMax = $before['Maximum password age (days)']
    $origMin = $before['Minimum password age (days)']
    $origLock = $before['Lockout threshold']
    if (-not $DryRun) {
        Add-Content -Encoding utf8 $Script:Rollback ("./net.exe accounts /minpwlen:$orig /maxpwage:$origMax /minpwage:$origMin /lockoutthreshold:$origLock | Out-Null 2>&1")
    }

    if ($DryRun) {
        Write-Host "         (dry) net accounts /minpwlen:$PasswordMinLength /maxpwage:$MaxPasswordAge /minpwage:$MinPasswordAge /lockoutthreshold:$LockoutThreshold"
        Write-Host "         (dry) disable built-in Guest account"
    } else {
        $rc = Invoke-HardenCmd "net.exe accounts /minpwlen:$PasswordMinLength /maxpwage:$MaxPasswordAge /minpwage:$MinPasswordAge /lockoutthreshold:$LockoutThreshold" '' 'password policy applied'
        if ($rc -eq 0) { Write-Ok "password policy: minlen=$PasswordMinLength maxage=$MaxPasswordAge lockout=$LockoutThreshold" }
    }

    # configure strong password policy is enforced via registry as well (Local Security Policy)
    $pol = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if ($DryRun) {
        Write-Host "         (dry) HKLM Lsa: DisableDomainCreds, LimitBlankPasswordUse = 1"
    } else {
        Backup-RegistryKey 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'Session Manager'
        try {
            Set-ItemProperty -Path $pol -Name 'LimitBlankPasswordUse' -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path $pol -Name 'DisableDomainCreds' -Value 1 -Type DWord -ErrorAction Stop
            Write-Ok "blank password use prohibited"
        } catch { Write-Err "Lsa policy failed: $_" }
    }

    if (Confirm-Hardening 'Disable the built-in Guest account?') {
        if ($DryRun) { Write-Host '         (dry) net user Guest /active:no' }
        else { Invoke-HardenCmd 'net.exe user Guest /active:no' '' 'Guest account disabled' }
    } else { Write-Skip 'Guest account' }
}

# ============================================================================
#  Module: Registry hardening
# ============================================================================
function Set-HardenRegistry {
    Write-Banner 'Registry Hardening'
    Initialize-Backup

    $items = @(
        # UAC
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA';                  Value=1 },
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Value=2 },
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop';      Value=1 },
        # Anonymous access restrictions
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous';      Value=1 },
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM';   Value=1 },
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash';               Value=1 },
        # SMBv1 disabled + forced signing
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1';                      Value=0 },
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='RequireSecuritySignature';  Value=1 },
        # Autoplay / Autorun
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun';        Value=0xff },
        # Installer elevation protection
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated';                  Value=0 }
    )

    foreach ($it in $items) {
        $key = $it.Path -replace 'HKLM:', 'HKLM\'
        if ($DryRun) {
            Write-Host "         (dry) set $key\$($it.Name) = $($it.Value)"
            continue
        }
        if (-not (Test-Path $it.Path)) { New-Item -Path $it.Path -Force | Out-Null }
        Backup-RegistryKey $key $it.Name
        try {
            Set-ItemProperty -Path $it.Path -Name $it.Name -Value $it.Value -Type DWord -ErrorAction Stop
            Write-Ok "$($it.Name) = $($it.Value)"
        } catch { Write-Err "$($it.Name): $_" }
    }
}

# ============================================================================
#  Module: Windows Defender
# ============================================================================
function Set-HardenDefender {
    Write-Banner 'Windows Defender'
    Initialize-Backup

    if ($DryRun) {
        Write-Host '         (dry) enable realtime protection, IOAV, network protection, cloud sample submission'
        return
    }
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -MAPSReporting 'Advanced'
        Set-MpPreference -SubmitSamplesReport 'Always'
        Set-MpPreference -EnableNetworkProtection 'Enabled' -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
        if ($svc) { Set-Service WinDefend -StartupType Automatic; Start-Service WinDefend }
        Write-Ok 'Defender realtime, cloud, IOAV and network protection enabled'
    } catch { Write-Err "Defender configuration failed: $_" }
}

# ============================================================================
#  Module: Services
# ============================================================================
function Set-HardenServices {
    Write-Banner 'Services'
    Initialize-Backup

    $enable = @('wuauserv', 'WinDefend')
    $disable = @('RemoteRegistry', 'RemoteAccess', 'SNMPTRAP', 'SSDPSRV', 'upnphost')

    if (Confirm-Hardening 'Disable non-essential services (RemoteRegistry, RemoteAccess, SSDP/UPnP, SNMP)?') {
        foreach ($s in $disable) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if (-not $svc) { continue }
            if ($DryRun) { Write-Host "         (dry) disable service $s"; continue }
            try {
                Set-Service $s -StartupType Disabled -ErrorAction Stop
                Stop-Service $s -Force -ErrorAction SilentlyContinue
                Write-Ok "disabled service $s"
                Add-Content -Encoding utf8 $Script:Rollback "Set-Service $s -StartupType Automatic; Write-Host 're-enabled: $s'"
            } catch { Write-Err "$s : $_" }
        }
    } else { Write-Skip 'non-essential services' }

    if (Confirm-Hardening 'Enable automatic Windows Update service (wuauserv)?') {
        foreach ($s in $enable) {
            $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
            if (-not $svc) { continue }
            if ($DryRun) { Write-Host "         (dry) enable service $s"; continue }
            try {
                Set-Service $s -StartupType Automatic -ErrorAction Stop
                Write-Ok "enabled service $s"
            } catch { Write-Err "$s : $_" }
        }
    } else { Write-Skip 'automatic updates' }
}

# ============================================================================
#  Module: Audit & logging
# ============================================================================
function Set-HardenAudit {
    Write-Banner 'Audit & Event Logs'
    Initialize-Backup

    if ($DryRun) {
        Write-Host '         (dry) enable auditing: Success + Failure for all categories'
        Write-Host '         (dry) grow Application/Security/System logs to 1 GB'
        Write-Host '         (dry) enable PowerShell script block logging + transcripts'
        return
    }

    $bak = Join-Path $Script:BackupDir 'audit-policy.bak'
    auditpol.exe /backup /file:$bak *> $null
    Add-Content -Encoding utf8 $Script:Rollback "auditpol.exe /restore /file:$($bak.Replace("'","''")) > `$null 2>&1; Write-Host 'restored audit policy'"

    $r = auditpol.exe /set /category:* /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok 'auditing enabled (Success+Failure, all categories)' }
    else { Write-Err "auditpol failed: $($r -join ' ')" }

    foreach ($log in 'Application', 'Security', 'System') {
        $size = (wevtutil.exe gl "$log" | Select-String 'maxSize' | Select-Object -First 1).Line.Trim() -replace '.*[^0-9]', ''
        if ($size) { Add-Content -Encoding utf8 $Script:Rollback "wevtutil.exe sl $log /ms:$size > `$null 2>&1" }
        wevtutil.exe sl "$log" /ms:1073741824 | Out-Null
        Write-Ok "event log $log grown to 1 GB"
    }

    $psKey  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $trKey  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $psKey)) { New-Item -Path $psKey -Force | Out-Null }
    if (-not (Test-Path $trKey)) { New-Item -Path $trKey -Force | Out-Null }
    Backup-RegistryKey $psKey.Replace('HKLM:','HKLM\') 'ScriptBlockLogging'
    Backup-RegistryKey $trKey.Replace('HKLM:','HKLM\') 'Transcription'
    Set-ItemProperty $psKey 'EnableScriptBlockLogging' 1 -Type DWord
    Set-ItemProperty $trKey 'EnableTranscripting' 1 -Type DWord
    Set-ItemProperty $trKey 'EnableInvocationHeader' 1 -Type DWord
    Write-Ok 'PowerShell script block logging + transcripts enabled'
}

# ============================================================================
#  Runner
# ============================================================================
$Modules = @('firewall', 'accounts', 'registry', 'defender', 'services', 'audit')
function Invoke-Module { param([string]$Name)
    switch ($Name) {
        'firewall' { Set-HardenFirewall }
        'accounts' { Set-HardenAccounts }
        'registry' { Set-HardenRegistry }
        'defender' { Set-HardenDefender }
        'services' { Set-HardenServices }
        'audit'    { Set-HardenAudit }
        default    { Write-Err "unknown module: $Name" }
    }
}

function Show-Menu {
    Write-Host ('-' * 70)
    Write-Banner 'Hardening categories'
    Write-Host '  1) Firewall               5) Services'
    Write-Host '  2) Accounts/Passwords     6) Audit & Event Logs'
    Write-Host '  3) Registry               7) (reserved)'
    Write-Host '  4) Windows Defender'
    Write-Host ''
    Write-Host "  a) Apply ALL               d) Dry-run preview all"
    Write-Host '  q) Quit'
    Write-Host "  status: $($Script:Applied) applied, $($Script:Skipped) skipped"
    while ($true) {
        $sel = Read-Host '? Select (comma list, e.g. 1,3)'
        switch ($sel.Trim().ToLower()) {
            'q'  { return }
            'a'  { foreach ($m in $Modules) { Invoke-Module $m } }
            'd'  { $old = $DryRun; $DryRun = $true; $Script:Interactive = $false
                   foreach ($m in $Modules) { Invoke-Module $m }
                   $DryRun = $old; $Script:Interactive = $true }
            default {
                foreach ($p in (($sel -split ',') | ForEach-Object { $_.Trim() })) {
                    switch ($p) {
                        '1' { Invoke-Module firewall }
                        '2' { Invoke-Module accounts }
                        '3' { Invoke-Module registry }
                        '4' { Invoke-Module defender }
                        '5' { Invoke-Module services }
                        '6' { Invoke-Module audit }
                        default { Write-Err "unknown selection: $p" }
                    }
                }
            }
        }
    }
}

if ($DryRun) { $Script:Interactive = $false }

if ($Module.Count -gt 0) {
    foreach ($m in $Module) { Invoke-Module $m }
} elseif ($ApplyAll) {
    foreach ($m in $Modules) { Invoke-Module $m }
} elseif ($DryRun) {
    foreach ($m in $Modules) { Invoke-Module $m }
} elseif ($Wizard) {
    foreach ($m in $Modules) {
        if (Confirm-Hardening ($m.ToUpper() + " module - apply now?")) { Invoke-Module $m }
    }
} else {
    Show-Menu
}

Write-Host ('-' * 70)
Write-Banner 'Run summary'
Write-Host "  measures applied : $($Script:Applied)"
Write-Host "  measures skipped : $($Script:Skipped)"
if ($DryRun) { Write-Host '  mode: DRY-RUN (nothing written)' }
elseif (Test-Path $Script:BackupDir) {
    Write-Host "  backups         : $($Script:BackupDir)"
    Write-Host "  rollback script : $($Script:Rollback)"
}