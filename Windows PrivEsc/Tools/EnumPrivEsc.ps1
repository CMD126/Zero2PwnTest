# Windows Privilege Escalation Enumeration Script
# Author: Security Assessment Tool
# Description: Comprehensive enumeration for Windows privilege escalation vectors

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

function Write-Critical {
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Red -BackgroundColor Black
}

function Write-Info {
    param([string]$Text)
    Write-Host "[i] $Text" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Text)
    Write-Host "`n[$Text]" -ForegroundColor Yellow
    Write-Host ("-" * 40) -ForegroundColor DarkYellow
}

# Main enumeration function
function Start-PrivEscEnum {
    Write-ColorOutput "Windows PrivEsc Enum v1.0" "Green"
    Write-ColorOutput "Computer: $env:COMPUTERNAME | User: $env:USERNAME" "Green"
    Write-ColorOutput "Time: $(Get-Date -Format 'HH:mm:ss')" "Green"

    # 1. User Privileges Check
    Write-Section "USER PRIVILEGES"
    try {
        Write-Info "Checking user privileges..."
        $privileges = whoami /priv | Out-String
        
        # Check for critical privileges first
        $criticalPrivs = @(
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege", 
            "SeDebugPrivilege",
            "SeTakeOwnershipPrivilege"
        )

        $foundCritical = $false
        foreach ($priv in $criticalPrivs) {
            if ($privileges -match $priv) {
                if ($privileges -match "$priv\s+Enabled") {
                    Write-Critical "DANGEROUS: $priv is ENABLED!"
                    $foundCritical = $true
                } else {
                    Write-Critical "POTENTIAL: $priv (check if can be enabled)"
                    $foundCritical = $true
                }
            }
        }
        
        if (-not $foundCritical) {
            Write-Host "No critical privileges found." -ForegroundColor Green
        }
        
        # Show compact privilege list
        Write-Host "`nCurrent Privileges:" -ForegroundColor Gray
        $privileges -split "`n" | Where-Object {$_ -match "Privilege"} | ForEach-Object {
            if ($_ -match "Enabled") {
                Write-Host "  $_" -ForegroundColor White
            } else {
                Write-Host "  $_" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 2. Group Membership Check
    Write-Section "GROUP MEMBERSHIP"
    try {
        Write-Info "Checking group memberships..."
        $groups = whoami /groups | Out-String

        # Check for critical groups
        $criticalGroups = @(
            "Backup Operators",
            "Event Log Readers", 
            "DnsAdmins",
            "Hyper-V Administrators",
            "Print Operators",
            "Server Operators"
        )

        $foundCriticalGroup = $false
        foreach ($group in $criticalGroups) {
            if ($groups -match $group) {
                Write-Critical "DANGEROUS GROUP: $group"
                $foundCriticalGroup = $true
            }
        }
        
        if (-not $foundCriticalGroup) {
            Write-Host "No dangerous group memberships found." -ForegroundColor Green
        }
        
        # Show compact group list (only non-default groups)
        Write-Host "`nCurrent Groups:" -ForegroundColor Gray
        $groups -split "`n" | Where-Object {
            $_ -match "Group Name" -or 
            ($_ -notmatch "Everyone|BUILTIN|NT AUTHORITY|Well-known group" -and $_ -match "\S")
        } | ForEach-Object {
            Write-Host "  $_" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 3. UAC Configuration Check
    Write-Section "UAC CONFIGURATION"
    try {
        Write-Info "Checking UAC settings..."
        
        $enableLUA = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v EnableLUA 2>$null
        $consentPrompt = reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" /v ConsentPromptBehaviorAdmin 2>$null
        
        if ($enableLUA -match "0x0") {
            Write-Critical "UAC is DISABLED (EnableLUA = 0)!"
        } elseif ($enableLUA -match "0x1") {
            Write-Host "EnableLUA: Enabled" -ForegroundColor Green
        } else {
            Write-Host "EnableLUA: Could not determine" -ForegroundColor Yellow
        }
        
        if ($consentPrompt -match "0x0") {
            Write-Critical "UAC Admin consent prompt is DISABLED!"
        } elseif ($consentPrompt -match "0x[1-5]") {
            Write-Host "ConsentPromptBehaviorAdmin: Configured" -ForegroundColor Green
        } else {
            Write-Host "ConsentPromptBehaviorAdmin: Could not determine" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 4. Installed Software Check
    Write-Section "INSTALLED SOFTWARE"
    try {
        Write-Info "Checking installed software (may take time)..."
        
        try {
            $software = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Select-Object Name, Version
            if ($software) {
                Write-Host "Found $($software.Count) installed programs:" -ForegroundColor Gray
                $software | Sort-Object Name | ForEach-Object {
                    Write-Host "  $($_.Name) - v$($_.Version)" -ForegroundColor DarkGray
                }
            } else {
                Write-Host "Using alternative method..."
                $regSoftware = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
                    Select-Object DisplayName, DisplayVersion | 
                    Where-Object {$_.DisplayName -ne $null} | 
                    Sort-Object DisplayName
                
                Write-Host "Found $($regSoftware.Count) programs:" -ForegroundColor Gray
                $regSoftware | ForEach-Object {
                    Write-Host "  $($_.DisplayName) - $($_.DisplayVersion)" -ForegroundColor DarkGray
                }
            }
        }
        catch {
            Write-Host "Failed to enumerate software: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 5. Sticky Notes Check
    Write-Section "STICKY NOTES"
    try {
        Write-Info "Checking for Sticky Notes..."
        
        $stickyNotesPath = "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
        $legacyStickyPath = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt"
        
        $found = $false
        if (Test-Path $stickyNotesPath) {
            $size = [math]::Round((Get-Item $stickyNotesPath).Length / 1KB, 2)
            Write-Critical "STICKY NOTES DB FOUND: plum.sqlite ($size KB)"
            $found = $true
        }
        
        if (Test-Path $legacyStickyPath) {
            $size = [math]::Round((Get-Item $legacyStickyPath).Length / 1KB, 2)
            Write-Critical "LEGACY STICKY NOTES: StickyNotes.snt ($size KB)"
            $found = $true
        }
        
        if (-not $found) {
            Write-Host "No sticky notes found." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 6. Cached Credentials Check
    Write-Section "CACHED CREDENTIALS"
    try {
        Write-Info "Checking cached credentials..."
        
        # Check Credential Manager
        $credman = cmdkey /list 2>$null
        if ($credman -match "Target:") {
            Write-Critical "STORED CREDENTIALS IN CREDENTIAL MANAGER!"
            $credman -split "`n" | Where-Object {$_ -match "Target:"} | ForEach-Object {
                Write-Host "  $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Credential Manager: No stored credentials" -ForegroundColor Green
        }
        
        # Check PuTTY Sessions
        $putty = reg query "HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions" 2>$null
        if ($putty -notmatch "ERROR") {
            Write-Critical "PUTTY SESSIONS FOUND!"
            $putty -split "`n" | Where-Object {$_ -match "Sessions\\"} | ForEach-Object {
                Write-Host "  $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "PuTTY: No sessions found" -ForegroundColor Green
        }
        
        # Check Winlogon
        $winlogon = reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>$null
        if ($winlogon -notmatch "ERROR") {
            Write-Critical "WINLOGON DEFAULT PASSWORD FOUND!"
        } else {
            Write-Host "Winlogon: No default password" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 7. Always Install Elevated Check
    Write-Section "ALWAYS INSTALL ELEVATED"
    try {
        Write-Info "Checking AlwaysInstallElevated policy..."
        
        $userPolicy = reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
        $machinePolicy = reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>$null
        
        $userEnabled = $userPolicy -match "0x1"
        $machineEnabled = $machinePolicy -match "0x1"
        
        if ($userEnabled -and $machineEnabled) {
            Write-Critical "ALWAYS INSTALL ELEVATED IS ENABLED!"
            Write-Host "MSI packages will run as SYSTEM!" -ForegroundColor Red
        } elseif ($userEnabled -or $machineEnabled) {
            Write-Host "Partially configured (need both HKCU and HKLM)" -ForegroundColor Yellow
        } else {
            Write-Host "AlwaysInstallElevated: Not enabled" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 8. User and Computer Description Check
    Write-Section "DESCRIPTIONS"
    try {
        Write-Info "Checking user/computer descriptions..."
        
        $users = Get-LocalUser | Where-Object {$_.Description -ne ""} | Select-Object Name, Description, Enabled
        if ($users) {
            Write-Host "User descriptions:" -ForegroundColor Gray
            $users | ForEach-Object {
                $desc = $_.Description
                if ($desc -match "password|pwd|pass|key|secret|credential") {
                    Write-Critical "SUSPICIOUS USER DESC: $($_.Name) - $desc"
                } else {
                    Write-Host "  $($_.Name): $desc" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "No user descriptions found" -ForegroundColor Green
        }
        
        $computerDesc = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Description
        if ($computerDesc.Description) {
            if ($computerDesc.Description -match "password|pwd|pass|key|secret") {
                Write-Critical "SUSPICIOUS COMPUTER DESC: $($computerDesc.Description)"
            } else {
                Write-Host "Computer: $($computerDesc.Description)" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "No computer description" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 9. Scheduled Tasks Check
    Write-Section "SCHEDULED TASKS"
    try {
        Write-Info "Checking scheduled tasks..."
        
        # Get non-Microsoft tasks
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | 
            Where-Object {$_.Author -notlike "*Microsoft*" -and $_.TaskName -notlike "\Microsoft\*"} | 
            Select-Object TaskName, Author, State, TaskPath
        
        if ($tasks) {
            Write-Host "Non-Microsoft tasks found:" -ForegroundColor Gray
            $tasks | ForEach-Object {
                Write-Host "  Task: $($_.TaskName) | State: $($_.State)" -ForegroundColor DarkGray
                
                # Check task details
                try {
                    $taskInfo = Get-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                    if ($taskInfo -and $taskInfo.Actions) {
                        foreach ($action in $taskInfo.Actions) {
                            if ($action.Execute) {
                                Write-Host "    Executes: $($action.Execute)" -ForegroundColor DarkGray
                                
                                # Check for writable paths
                                $execPath = Split-Path $action.Execute -Parent
                                if ($execPath -and (Test-Path $execPath)) {
                                    try {
                                        $acl = Get-Acl $execPath -ErrorAction SilentlyContinue
                                        if ($acl) {
                                            $writePermissions = $acl.Access | Where-Object {
                                                ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                                                ($_.IdentityReference -match "$env:USERNAME|Everyone|Users|Authenticated Users")
                                            }
                                            if ($writePermissions) {
                                                Write-Critical "WRITABLE TASK PATH: $execPath"
                                            }
                                        }
                                    }
                                    catch {
                                        # Ignore ACL errors
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    # Ignore task detail errors
                }
            }
        } else {
            Write-Host "No non-Microsoft scheduled tasks found." -ForegroundColor Green
        }
        
        # Quick check for SYSTEM tasks
        try {
            $systemTasks = schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv | 
                Where-Object {$_."Run As User" -eq "SYSTEM" -and $_."Author" -notlike "*Microsoft*"}
            if ($systemTasks) {
                Write-Host "`nSYSTEM tasks (non-Microsoft):" -ForegroundColor Yellow
                $systemTasks | Select-Object -First 5 | ForEach-Object {
                    Write-Host "  $($_.'TaskName') - $($_.'Task To Run')" -ForegroundColor Yellow
                }
                if ($systemTasks.Count -gt 5) {
                    Write-Host "  ... and $($systemTasks.Count - 5) more" -ForegroundColor Yellow
                }
            }
        }
        catch {
            # Ignore schtasks errors
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Summary
    Write-Section "SUMMARY"
    Write-ColorOutput "Enumeration complete!" "Green"
    Write-ColorOutput "Items marked [!] in RED require immediate attention" "Yellow"
    Write-ColorOutput "Review all findings for potential privilege escalation" "Cyan"
}

# Run the enumeration
Start-PrivEscEnum
