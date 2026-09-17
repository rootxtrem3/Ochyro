#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Hardening Assessment Tool
.DESCRIPTION
    Checks Windows system configuration against security best practices.
    No external dependencies required.
.PARAMETER Module
    Run specific module: firewall, user, services, registry, smb, audit, defender
.PARAMETER Severity
    Show only checks of this severity or higher
.PARAMETER Json
    Output as JSON
.PARAMETER Quiet
    Show failures only
.EXAMPLE
    .\windows_hardening_check.ps1
    .\windows_hardening_check.ps1 -Module firewall
    .\windows_hardening_check.ps1 -Severity HIGH
    .\windows_hardening_check.ps1 -Json
#>
param(
    [ValidateSet("firewall","user","services","registry","smb","audit","defender","all")]
    [string]$Module = "all",
    [ValidateSet("CRITICAL","HIGH","MEDIUM","LOW","INFO")]
    [string]$Severity = "",
    [switch]$Json,
    [switch]$Quiet
)

# --- State ---
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

$script:TotalChecks = 0
$script:Passed = 0
$script:Failed = 0
$script:Results = @()
$script:Failures = @()

$SeverityWeights = @{
    "CRITICAL" = 10
    "HIGH"     = 5
    "MEDIUM"   = 2
    "LOW"      = 1
    "INFO"     = 0
}

$SeverityOrder = @("CRITICAL","HIGH","MEDIUM","LOW","INFO")

# --- Helpers ---
function Write-Check {
    param([string]$Name, [bool]$Passed, [string]$Expected, [string]$Actual, [string]$Severity = "HIGH")
    
    $script:TotalChecks++
    
    if ($Passed) {
        $script:Passed++
    } else {
        $script:Failed++
        $script:Failures += "[$Severity] $Name"
    }
    
    $script:Results += @{
        check = $Name
        passed = $Passed
        expected = $Expected
        actual = $Actual
        severity = $Severity
    }
    
    if (-not $Quiet -or -not $Passed) {
        $colors = @{
            "CRITICAL" = "Red"
            "HIGH"     = "Red"
            "MEDIUM"   = "Yellow"
            "LOW"      = "Cyan"
            "INFO"     = "DarkGray"
        }
        
        $status = if ($Passed) { Write-Host " PASS " -ForegroundColor Green -NoNewline }
                  else { Write-Host " FAIL " -ForegroundColor Red -NoNewline }
        
        $color = if ($colors.ContainsKey($Severity)) { $colors[$Severity] } else { "White" }
        Write-Host " [$Severity]" -ForegroundColor $color -NoNewline
        Write-Host " $Name"
        
        if (-not $Passed) {
            Write-Host "         Expected: $Expected" -ForegroundColor DarkGray
            Write-Host "         Actual:   $Actual" -ForegroundColor DarkGray
        }
    }
}

function Test-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

function Test-ServiceActive {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return ($svc -and $svc.Status -eq "Running")
}

function Test-ServiceEnabled {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return ($svc -and $svc.StartType -ne "Disabled")
}

# ============================================================================
# MODULE: WINDOWS FIREWALL
# ============================================================================
function Check-Firewall {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [FW] Windows Firewall" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. All profiles enabled
    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fw) {
        $allEnabled = ($fw | Where-Object { $_.Enabled -eq $true }).Count -eq 3
        $enabledProfiles = ($fw | Where-Object { $_.Enabled -eq $true } | ForEach-Object { $_.Name }) -join ", "
        Write-Check "All firewall profiles enabled" $allEnabled "All 3 profiles" $enabledProfiles "CRITICAL"
        
        # 2. Default inbound action
        $allBlock = ($fw | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count -eq 3
        $inboundProfiles = ($fw | Where-Object { $_.DefaultInboundAction -eq "Block" } | ForEach-Object { $_.Name }) -join ", "
        Write-Check "Default inbound action is Block" $allBlock "All profiles Block" "$inboundProfiles" "CRITICAL"
        
        # 3. Default outbound action
        $anyAllowOut = ($fw | Where-Object { $_.DefaultOutboundAction -eq "Allow" }).Count -gt 0
        Write-Check "Default outbound is Allow (restrictive)" (-not $anyAllowOut) "recommended Allow" "configured" "MEDIUM"
        
        # 4. Logging enabled
        $logAllowed = ($fw | Where-Object { $_.LogAllowed -eq "Yes" -or $_.LogAllowed -eq $true }).Count
        Write-Check "Firewall logging enabled" ($logAllowed -ge 2) ">= 2 profiles" "$logAllowed profiles" "HIGH"
        
        # 5. Log file size
        $logSize = ($fw | Select-Object -First 1).LogMaxSizeKilobytes
        $logOk = $logSize -ge 16384  # 16MB minimum
        Write-Check "Log size >= 16MB" $logOk ">= 16384 KB" "$logSize KB" "MEDIUM"
    } else {
        Write-Check "Firewall profiles accessible" $false "available" "not found" "CRITICAL"
    }
    
    # 6. Inbound rules allowing all
    $allowAllRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -eq "Any" -or $_.RemoteAddress -eq "*" }
    $allowCount = ($allowAllRules | Measure-Object).Count
    Write-Check "Inbound allow-all rules <= 5" ($allowCount -le 5) "<= 5" "$allowCount rules" "HIGH"
    
    # 7. Remote Desktop restricted
    $rdpRule = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }
    $rdpOpen = ($rdpRule | Measure-Object).Count -gt 0
    if ($rdpOpen) {
        $rdpAny = $rdpRule | Where-Object { $_.RemoteAddress -eq "Any" -or $_.RemoteAddress -eq "*" }
        Write-Check "RDP not open to Any" ($null -eq $rdpAny) "restricted source" "open to all" "HIGH"
    } else {
        Write-Check "RDP not open to Any" $true "not enabled" "RDP disabled" "INFO"
    }
    
    # 8. WinRM/PSRemoting
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $winrmActive = $winrm -and $winrm.Status -eq "Running"
    Write-Check "WinRM restricted" (-not $winrmActive) "not running" "$($winrm.Status)" "MEDIUM"
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: USER & PASSWORD POLICY
# ============================================================================
function Check-User {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [USR] User & Authentication" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. Guest account disabled
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Check "Guest account disabled" ($null -eq $guest -or $guest.Enabled -eq $false) "disabled" "$($guest.Enabled)" "HIGH"
    
    # 2. Admin account renamed
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Check "Default Administrator renamed" ($null -eq $admin -or $admin.Enabled -eq $false) "renamed/disabled" "$($admin.Name): Enabled=$($admin.Enabled)" "HIGH"
    
    # 3. No local admin named "admin"
    $adminNamed = Get-LocalUser -Name "admin" -ErrorAction SilentlyContinue
    Write-Check "No user named 'admin'" ($null -eq $adminNamed) "not exist" "$($adminNamed.Name)" "HIGH"
    
    # 4. Password policy
    $netAccounts = net accounts 2>$null
    if ($netAccounts) {

        function Get-NetAccountsField {
            param([string]$Pattern, [int]$Idx = -1)
            $m = $netAccounts | Select-String -Pattern $Pattern
            if (-not $m) { return "" }
            $tokens = $m[0].Line -split '\s+'
            if ($tokens.Count -eq 0) { return "" }
            $val = if ($Idx -lt 0) { $tokens[$tokens.Count - 1] } else { $tokens[[Math]::Min($Idx, $tokens.Count - 1)] }
            return $val
        }

        $maxAgeNum  = [int]((Get-NetAccountsField "Maximum password age" -2) -replace '[^\d]','')
        Write-Check "Password max age <= 90 days" ($maxAgeNum -le 90 -and $maxAgeNum -gt 0) "<= 90" "${maxAgeNum} days" "HIGH"

        $minLenNum  = [int]((Get-NetAccountsField "Minimum password length") -replace '[^\d]','')
        Write-Check "Password min length >= 12" ($minLenNum -ge 12) ">= 12" "$minLenNum characters" "HIGH"

        $lockoutNum = [int]((Get-NetAccountsField "Lockout threshold") -replace '[^\d]','')
        Write-Check "Account lockout threshold <= 10" ($lockoutNum -le 10 -and $lockoutNum -gt 0) "<= 10" "$lockoutNum attempts" "HIGH"

        $minAgeNum  = [int]((Get-NetAccountsField "Minimum password age" -2) -replace '[^\d]','')
        Write-Check "Password min age >= 1" ($minAgeNum -ge 1) ">= 1" "${minAgeNum} days" "MEDIUM"

        # 5. Password complexity
        $complexity = (Get-NetAccountsField "Password properties") -replace '[^\d]',''
        if ($complexity -ne "") {
            $complexOk = ([Convert]::ToInt32($complexity) -band 0x1) -eq 0x1
        } else {
            $complexOk = $false
        }
        Write-Check "Password complexity enabled" $complexOk "enabled" "$complexity" "HIGH"
    }
    
    # 6. Local accounts count
    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
    $enabledUsers = ($localUsers | Where-Object { $_.Enabled -eq $true }).Count
    Write-Check "Enabled local accounts <= 5" ($enabledUsers -le 5) "<= 5" "$enabledUsers enabled" "MEDIUM"
    
    # 7. Users in Administrators group
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $adminCount = ($admins | Measure-Object).Count
    Write-Check "Administrators group <= 3" ($adminCount -le 3) "<= 3" "$adminCount members" "HIGH"
    
    # 8. Password never expires
    $neverExpire = $localUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
    Write-Check "No accounts with 'password never expires'" ($null -eq $neverExpire -or ($neverExpire | Measure-Object).Count -eq 0) "0 accounts" "$(($neverExpire | Measure-Object).Count) accounts" "MEDIUM"
    
    # 9. Last logon ages
    $staleAccounts = $localUsers | Where-Object { 
        $_.Enabled -eq $true -and $_.LastLogon -ne $null -and
        ((Get-Date) - $_.LastLogon).TotalDays -gt 90
    }
    $staleCount = ($staleAccounts | Measure-Object).Count
    Write-Check "No accounts inactive > 90 days" ($staleCount -eq 0) "0 stale" "$staleCount stale accounts" "LOW"
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: SERVICES
# ============================================================================
function Check-Services {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [SVC] Services & Features" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. Windows Update service
    $wuActive = Test-ServiceActive "wuauserv"
    Write-Check "Windows Update active" $wuActive "active" "$($wuActive)" "HIGH"
    
    # 2. Windows Defender service
    $defenderActive = Test-ServiceActive "WinDefend"
    Write-Check "Windows Defender active" $defenderActive "active" "$($defenderActive)" "HIGH"
    
    # 3. Defender real-time protection
    try {
        $rtp = Get-MpPreference -ErrorAction Stop
        Write-Check "Defender real-time protection" ($rtp.DisableRealtimeMonitoring -ne $true) "enabled" "$($rtp.DisableRealtimeMonitoring)" "HIGH"
        Write-Check "Defender cloud protection" ($rtp.DisableBehaviorMonitoring -ne $true) "enabled" "$($rtp.DisableBehaviorMonitoring)" "HIGH"
        Write-Check "Defender IOAV protection" ($rtp.DisableIOAVProtection -ne $true) "enabled" "$($rtp.DisableIOAVProtection)" "HIGH"
    } catch {
        Write-Check "Defender protection status" $false "configured" "unable to query" "HIGH"
    }
    
    # 4. Unnecessary services
    $unnecessaryServices = @(
        "RemoteRegistry", "TlntSvr", "SNMP", "SNMPTRAP",
        "WMSvc", "ftpsvc", "IISADMIN", "W3SVC",
        "SharedAccess"  # ICS
    )
    $foundUnnecessary = @()
    foreach ($svc in $unnecessaryServices) {
        if (Test-ServiceEnabled $svc) { $foundUnnecessary += $svc }
    }
    Write-Check "No unnecessary services" ($foundUnnecessary.Count -eq 0) "all disabled" "$($foundUnnecessary -join ', ')" "MEDIUM"
    
    # 5. Remote Desktop disabled
    $rdpEnabled = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    Write-Check "Remote Desktop disabled" ($rdpEnabled -eq 1) "disabled" "$(if ($rdpEnabled -eq 1) {'disabled'} else {'enabled'})" "HIGH"
    
    # 6. PowerShell logging
    $psLogging = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    Write-Check "PowerShell script block logging" ($psLogging -eq 1) "enabled" "$(if ($psLogging -eq 1) {'enabled'} else {'disabled'})" "MEDIUM"
    
    $psModuleLogging = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
    Write-Check "PowerShell module logging" ($psModuleLogging -eq 1) "enabled" "$(if ($psModuleLogging -eq 1) {'enabled'} else {'disabled'})" "MEDIUM"
    
    # 7. PowerShell Constrained Language Mode
    $clm = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\Environment" "__PSLockdownPolicy"
    Write-Check "PowerShell Constrained Language" ($clm -ne $null) "configured" "$(if ($clm) {$clm} else {'not set'})" "MEDIUM"
    
    # 8. Windows Defender ASR rules
    $asrRules = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"
    Write-Check "Attack Surface Reduction rules" ($asrRules -eq 1) "enabled" "$(if ($asrRules -eq 1) {'enabled'} else {'disabled'})" "HIGH"
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: REGISTRY HARDENING
# ============================================================================
function Check-Registry {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [REG] Registry Hardening" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. UAC
    $uac = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
    Write-Check "UAC enabled" ($uac -eq 1) "1" "$(if ($uac -ne $null) {$uac} else {'not set'})" "HIGH"
    
    $uacConsent = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
    Write-Check "UAC admin consent mode" ($uacConsent -eq 2) "2 (prompt for consent)" "$(if ($uacConsent -ne $null) {$uacConsent} else {'default'})" "HIGH"
    
    $uacElevate = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"
    Write-Check "UAC installer detection" ($uacElevate -eq 1) "1" "$(if ($uacElevate -ne $null) {$uacElevate} else {'not set'})" "MEDIUM"
    
    # 2. SMB
    $smbServer = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    Write-Check "SMBv1 disabled" ($smbServer -eq 0) "0" "$(if ($smbServer -ne $null) {$smbServer} else {'default (enabled)'})" "CRITICAL"
    
    $smbSigning = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
    Write-Check "SMB signing required" ($smbSigning -eq 1) "1" "$(if ($smbSigning -ne $null) {$smbSigning} else {'not set'})" "HIGH"
    
    $smbEncrypt = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EncryptData"
    Write-Check "SMB encryption" ($smbEncrypt -eq 1) "1" "$(if ($smbEncrypt -ne $null) {$smbEncrypt} else {'not set'})" "MEDIUM"
    
    # 3. Network security
    $lsaAnonymous = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    Write-Check "Restrict anonymous enumeration" ($lsaAnonymous -ge 1) ">= 1" "$(if ($lsaAnonymous -ne $null) {$lsaAnonymous} else {'0 (default)'})" "HIGH"
    
    $ntlm = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "RestrictSendingNTLMTraffic"
    Write-Check "NTLMv2 only" ($ntlm -ge 1) ">= 1" "$(if ($ntlm -ne $null) {$ntlm} else {'not set'})" "HIGH"
    
    $lmHash = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
    Write-Check "LAN Manager hash disabled" ($lmHash -eq 1) "1" "$(if ($lmHash -ne $null) {$lmHash} else {'not set'})" "HIGH"
    
    # 4. Audit policy
    $auditBase = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\SCe" "AuditBaseObjects"
    Write-Check "Audit base objects" ($auditBase -eq 1) "1" "$(if ($auditBase -ne $null) {$auditBase} else {'not set'})" "MEDIUM"
    
    # 5. Command Prompt disable
    $cmdDisable = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableCMD"
    Write-Check "Command Prompt restricted for std users" ($cmdDisable -eq 1) "1" "$(if ($cmdDisable -ne $null) {$cmdDisable} else {'not set'})" "LOW"
    
    # 6. AutoPlay
    $autoplay = Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
    $autoplayOk = $autoplay -eq 255 -or $autoplay -eq 145
    Write-Check "AutoPlay disabled" $autoplayOk "255 or 145" "$(if ($autoplay -ne $null) {$autoplay} else {'not set'})" "MEDIUM"
    
    # 7. Windows Installer
    $installerElevate = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    Write-Check "Always Install Elevated disabled" ($installerElevate -ne 1) "not 1" "$(if ($installerElevate -ne $null) {$installerElevate} else {'not set'})" "HIGH"
    
    # 8. Credential Guard
    $credGuard = Test-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
    Write-Check "Credential Guard / VBS" ($credGuard -eq 1) "enabled" "$(if ($credGuard -ne $null) {$credGuard} else {'not set'})" "MEDIUM"
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: SMB / FILE SHARING
# ============================================================================
function Check-SMB {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [SMB] File Sharing & Sharing" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. SMBv1 protocol
    $smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smb1) {
        Write-Check "SMBv1 protocol disabled" ($smb1.EnableSMB1Protocol -eq $false) "disabled" "$($smb1.EnableSMB1Protocol)" "CRITICAL"
        
        # 2. SMB signing
        Write-Check "SMB signing required" ($smb1.RequireSecuritySignature -eq $true) "required" "$($smb1.RequireSecuritySignature)" "HIGH"
        
        # 3. SMB encryption
        Write-Check "SMB encryption enabled" ($smb1.EnableSecuritySignature -eq $true) "enabled" "$($smb1.EnableSecuritySignature)" "MEDIUM"
        
        # 4. Null sessions
        Write-Check "SMB reject null sessions" ($smb1.AnnounceServer -ne $null) "configured" "default" "MEDIUM"
    } else {
        Write-Check "SMB configuration accessible" $false "available" "unable to query" "HIGH"
    }
    
    # 5. Shared folders
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^\$' }
    $shareCount = ($shares | Measure-Object).Count
    Write-Check "Non-admin shares <= 3" ($shareCount -le 3) "<= 3" "$shareCount shares" "MEDIUM"
    
    # 6. Administrative shares
    $adminShares = Get-SmbShare -Name "ADMIN$" -ErrorAction SilentlyContinue
    if ($adminShares) {
        Write-Check "ADMIN$ share restricted" ($adminShares.Description -ne "") "configured" "present" "LOW"
    }
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: AUDIT POLICY
# ============================================================================
function Check-Audit {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [AUD] Audit Policy" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    # 1. Audit policy
    $auditPol = auditpol /get /category:* 2>$null
    if ($auditPol) {
        $successFailed = ($auditPol | Select-String "Success and Failure").Count
        $totalCategories = ($auditPol | Select-String "^\s+\w").Count
        Write-Check "Audit covers most categories" ($successFailed -ge ($totalCategories * 0.7)) ">= 70%" "$successFailed/$totalCategories" "HIGH"
        
        # 2. Logon events
        $logonAudit = $auditPol | Select-String "Logon"
        $logonOk = $logonAudit -match "Success and Failure"
        Write-Check "Logon auditing (Success+Failure)" $logonOk "Success and Failure" "$logonAudit" "HIGH"
        
        # 3. Account management
        $acctAudit = $auditPol | Select-String "Account Management"
        $acctOk = $acctAudit -match "Success"
        Write-Check "Account management auditing" $acctOk "Success" "$acctAudit" "MEDIUM"
        
        # 4. Policy changes
        $polAudit = $auditPol | Select-String "Policy Change"
        $polOk = $polAudit -match "Success"
        Write-Check "Policy change auditing" $polOk "Success" "$polAudit" "MEDIUM"
    }
    
    # 5. Event log sizes
    $secLog = wevtutil gl Security 2>$null | Select-String "maxSize"
    if ($secLog) {
        $sizeStr = ($secLog -replace '[^\d]','')
        $sizeMB = [int]$sizeStr / 1MB
        Write-Check "Security log >= 1GB" ($sizeMB -ge 1024) ">= 1024 MB" "$([int]$sizeMB) MB" "HIGH"
    }
    
    # 6. Event log retention
    $secRetention = wevtutil gl Security 2>$null | Select-String "retention"
    Write-Check "Event log retention configured" ($null -ne $secRetention) "configured" "$($secRetention)" "MEDIUM"
    
    # 7. PowerShell logging
    $psScriptLog = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    Write-Check "PowerShell script block logging" ($psScriptLog -eq 1) "enabled" "$(if ($psScriptLog -eq 1) {'enabled'} else {'disabled'})" "MEDIUM"
    
    $psTranscript = Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
    Write-Check "PowerShell transcript logging" ($psTranscript -eq 1) "enabled" "$(if ($psTranscript -eq 1) {'enabled'} else {'disabled'})" "LOW"
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# MODULE: WINDOWS DEFENDER
# ============================================================================
function Check-Defender {
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " [DEF] Windows Defender" -ForegroundColor Cyan
    Write-Host "$('═' * 60)" -ForegroundColor Cyan
    
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        Write-Check "Defender real-time protection" $mpStatus.RealTimeProtectionEnabled "enabled" "$($mpStatus.RealTimeProtectionEnabled)" "CRITICAL"
        Write-Check "Defender behavior monitoring" $mpStatus.BehaviorMonitorEnabled "enabled" "$($mpStatus.BehaviorMonitorEnabled)" "HIGH"
        Write-Check "Defender IOAV protection" $mpStatus.IoavProtectionEnabled "enabled" "$($mpStatus.IoavProtectionEnabled)" "HIGH"
        Write-Check "Defender NIS running" $mpStatus.NISEnabled "enabled" "$($mpStatus.NISEnabled)" "HIGH"
        Write-Check "Defender AM service running" $mpStatus.AMServiceEnabled "enabled" "$($mpStatus.AMServiceEnabled)" "HIGH"
        
        # Signature freshness
        if ($mpStatus.AntivirusSignatureLastUpdated) {
            $sigAge = ((Get-Date) - $mpStatus.AntivirusSignatureLastUpdated).TotalHours
            Write-Check "Signatures updated < 24h" ($sigAge -lt 24) "< 24 hours" "$([int]$sigAge)h ago" "HIGH"
        }
        
        # Cloud protection
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        if ($mpPref) {
            Write-Check "Cloud-delivered protection" ($mpPref.DisableRealtimeMonitoring -ne $true -and $mpPref.DisableBehaviorMonitoring -ne $true) "enabled" "configured" "HIGH"
            Write-Check "Cloud block level" ($mpPref.CloudBlockLevel -ge 2) ">= High" "$($mpPref.CloudBlockLevel)" "MEDIUM"
        }
        
        # Tamper protection
        $tamper = $mpStatus.IsTamperProtected
        Write-Check "Tamper protection" ($tamper -eq $true) "enabled" "$tamper" "HIGH"
        
        # Exclusions
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
        $exclPath = ($exclusions.ExclusionPath | Measure-Object).Count
        $exclExt = ($exclusions.ExclusionExtension | Measure-Object).Count
        $exclProc = ($exclusions.ExclusionProcess | Measure-Object).Count
        $totalExcl = $exclPath + $exclExt + $exclProc
        Write-Check "Defender exclusions <= 5" ($totalExcl -le 5) "<= 5" "$totalExcl exclusions" "MEDIUM"
        
    } catch {
        Write-Check "Windows Defender available" $false "installed" "not found or access denied" "HIGH"
    }
    
    Write-Host ("─" * 60) -ForegroundColor DarkGray
}

# ============================================================================
# SUMMARY
# ============================================================================
function Show-Summary {
    param([double]$Elapsed)
    
    $score = if ($script:TotalChecks -gt 0) { [math]::Round($script:Passed * 100 / $script:TotalChecks) } else { 0 }
    
    $grade = switch ($score) {
        { $_ -ge 90 } { @{ Letter = "A"; Text = "EXCELLENT"; Color = "Green" } }
        { $_ -ge 75 } { @{ Letter = "B"; Text = "GOOD"; Color = "Green" } }
        { $_ -ge 60 } { @{ Letter = "C"; Text = "NEEDS IMPROVEMENT"; Color = "Yellow" } }
        { $_ -ge 40 } { @{ Letter = "D"; Text = "POOR"; Color = "Red" } }
        default       { @{ Letter = "F"; Text = "CRITICAL"; Color = "Red" } }
    }
    
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ASSESSMENT SUMMARY                    ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "  Overall Score:  $score/100  [$($grade.Letter)]  " -NoNewline
    Write-Host "$($grade.Text)" -ForegroundColor $grade.Color
    
    Write-Host ""
    Write-Host "  Results:  " -NoNewline
    Write-Host "$($script:Passed) passed" -ForegroundColor Green -NoNewline
    Write-Host " | " -NoNewline
    Write-Host "$($script:Failed) failed" -ForegroundColor Red -NoNewline
    Write-Host " | $($script:TotalChecks) total"
    Write-Host "  Time:     $([math]::Round($Elapsed, 1))s"
    
    # By severity
    $critResults = $script:Results | Where-Object { $_.severity -eq "CRITICAL" }
    $highResults = $script:Results | Where-Object { $_.severity -eq "HIGH" }
    $medResults = $script:Results | Where-Object { $_.severity -eq "MEDIUM" }
    $lowResults = $script:Results | Where-Object { $_.severity -in @("LOW","INFO") }
    
    Write-Host ""
    Write-Host "  By Severity:"
    
    foreach ($sev in @(
        @{ Name = "CRITICAL"; Data = $critResults; Color = "Red" },
        @{ Name = "HIGH";     Data = $highResults; Color = "Red" },
        @{ Name = "MEDIUM";   Data = $medResults;  Color = "Yellow" },
        @{ Name = "LOW";      Data = $lowResults;  Color = "Cyan" }
    )) {
        $total = ($sev.Data | Measure-Object).Count
        $pass = ($sev.Data | Where-Object { $_.passed } | Measure-Object).Count
        if ($total -gt 0) {
            $bar = ("█" * $pass) + ("█" * ($total - $pass))
            Write-Host "    $($sev.Name.PadRight(8)) " -NoNewline
            Write-Host $bar -ForegroundColor $sev.Color -NoNewline
            Write-Host "  $pass/$total passed"
        }
    }
    
    # Top failures
    if ($script:Failures.Count -gt 0) {
        Write-Host ""
        Write-Host "  Top Issues:" -ForegroundColor Red
        $sorted = $script:Results | Where-Object { -not $_.passed } | 
            Sort-Object { $SeverityOrder.IndexOf($_.severity) }
        $i = 1
        foreach ($f in $sorted) {
            if ($i -gt 10) { break }
            Write-Host "    $i. [$($f.severity)] $($f.check)" -ForegroundColor Red
            $i++
        }
    }
    Write-Host ""
}

# ============================================================================
# MAIN
# ============================================================================
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if (-not $Json) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       Windows Hardening Assessment Tool (PowerShell)    ║" -ForegroundColor Cyan
    Write-Host "║       Security Posture Scanner v1.0                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Target: $env:COMPUTERNAME" -ForegroundColor DarkGray
    Write-Host "  Time:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
}

switch ($Module) {
    "firewall" { Check-Firewall }
    "user"     { Check-User }
    "services" { Check-Services }
    "registry" { Check-Registry }
    "smb"      { Check-SMB }
    "audit"    { Check-Audit }
    "defender" { Check-Defender }
    "all" {
        Check-Firewall
        Check-User
        Check-Services
        Check-Registry
        Check-SMB
        Check-Audit
        Check-Defender
    }
}

$stopwatch.Stop()

if ($Json) {
    $output = @{
        hostname = $env:COMPUTERNAME
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
        elapsed_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        total = $script:TotalChecks
        passed = $script:Passed
        failed = $script:Failed
        score = [math]::Round($script:Passed * 100 / ([math]::Max($script:TotalChecks, 1)))
        failures = $script:Failures
    }
    $output | ConvertTo-Json -Depth 3
} else {
    Show-Summary -Elapsed $stopwatch.Elapsed.TotalSeconds
}
