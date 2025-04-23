# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Error handling setup
$ErrorActionPreference = "Stop"

# Color definitions
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

# Configuration file paths
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# Logging function
function Write-Log {
    param (
        [string]$level,
        [string]$message
    )
    
    $color = $NC
    switch ($level) {
        "INFO" { $color = $GREEN }
        "WARN" { $color = $YELLOW }
        "ERROR" { $color = $RED }
        "DEBUG" { $color = $BLUE }
        default { $color = $NC }
    }
    
    Write-Host "$color[$level]$NC $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $message"
}

# Check administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Log "ERROR" "Administrator privileges required"
    Write-Host "Please right-click the script and select 'Run as administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Menu
function Show-Menu {
    Clear-Host
    Write-Host "$BLUE╔══════════════════════════════════════════════════════════════╗$NC"
    Write-Host "$BLUE║$NC             $GREEN↺ CURSOR ID RENEW TOOL ↺$NC                     $BLUE       ║$NC"
    Write-Host "$BLUE╚══════════════════════════════════════════════════════════════╝$NC"
    Write-Host ""
    Write-Host "$YELLOW▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀$NC"
    Write-Host "$GREEN✓ DESCRIPTION:$NC"
    Write-Host "  This tool updates Cursor's unique identifiers,"
    Write-Host "  which can help solve licensing issues and renew"
    Write-Host "  your device's identification in the system."
    Write-Host ""
    Write-Host "$GREEN✓ ACTIONS TO BE PERFORMED:$NC"
    Write-Host ""
    Write-Host "  ${BLUE}1.$NC Detect Cursor installation and active processes"
    Write-Host "     ${YELLOW}→$NC Check if Cursor is running"
    Write-Host "     ${YELLOW}→$NC Offer to safely close the application"
    Write-Host ""
    Write-Host "  ${BLUE}2.$NC Create automatic backups"
    Write-Host "     ${YELLOW}→$NC Back up current configuration files"
    Write-Host "     ${YELLOW}→$NC Save original machine ID"
    Write-Host "     ${YELLOW}→$NC Store everything with timestamps for recovery"
    Write-Host ""
    Write-Host "  ${BLUE}3.$NC Generate new identifiers"
    Write-Host "     ${YELLOW}→$NC Machine ID: Unique system identifier"
    Write-Host "     ${YELLOW}→$NC Device ID: Hardware recognition"
    Write-Host "     ${YELLOW}→$NC Telemetry ID: Statistical data renewal"
    Write-Host ""
    Write-Host "$GREEN✓ BENEFITS:$NC"
    Write-Host "  • Solves authorization problems"
    Write-Host "  • Resets editor state"
    Write-Host "  • Maintains privacy of your installation"
    Write-Host "  • Automatic and safe process"
    Write-Host ""
    Write-Host "$RED▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄$NC"
    Write-Host "$RED⚠ IMPORTANT NOTE:$NC"
    Write-Host "  This process is safe, but will modify Cursor's configuration."
    Write-Host "  All backups are saved automatically."
    Write-Host "$RED▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄$NC"
    Write-Host ""
    
    while ($true) {
        Write-Host "$GREEN Do you want to continue with the process?$NC"
        $response = Read-Host "[y/N]"
        switch -regex ($response.ToLower()) {
            '^(y|yes)$' {
                Write-Host "$GREEN▶ Starting the process...$NC"
                Start-Sleep -Seconds 1
                return $true
            }
            '^(n|no|)$' {
                Write-Host "$YELLOW▶ Operation cancelled by user$NC"
                Write-Log "INFO" "Operation cancelled by user"
                exit 0
            }
            default {
                Write-Host "$RED✗ Please answer 'y' (yes) or 'n' (no)$NC"
            }
        }
    }
}

# Get and display Cursor version
function Get-CursorVersion {
    try {
        # Main detection path
        $packagePath = "$env:LOCALAPPDATA\Programs\cursor\resources\app\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Log "INFO" "Current Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        # Alternative path detection
        $altPath = "$env:LOCALAPPDATA\cursor\resources\app\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Log "INFO" "Current Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Log "WARN" "Unable to detect Cursor version"
        Write-Log "INFO" "Please ensure Cursor is properly installed"
        return $null
    }
    catch {
        Write-Log "ERROR" "Failed to get Cursor version: $_"
        return $null
    }
}

function Get-ProcessDetails {
    param($processName)
    Write-Log "DEBUG" "Getting $processName process details:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" | 
        Select-Object ProcessId, ExecutablePath, CommandLine | 
        Format-List
}

# Define maximum retries and wait time
$MAX_RETRIES = 5
$WAIT_TIME = 1

# Handle process closing
function Close-CursorProcess {
    param($processName)
    
    $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Log "WARN" "Found $processName running"
        Get-ProcessDetails $processName
        
        $response = Read-Host "Do you want to close Cursor safely before continuing? [y/N]"
        if ($response -match '^[yY]') {
            Write-Log "INFO" "Attempting to close $processName..."
            Stop-Process -Name $processName -Force
            
            $retryCount = 0
            while ($retryCount -lt $MAX_RETRIES) {
                $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
                if (-not $process) { break }
                
                $retryCount++
                if ($retryCount -ge $MAX_RETRIES) {
                    Write-Log "ERROR" "Failed to close $processName after $MAX_RETRIES attempts"
                    Get-ProcessDetails $processName
                    Write-Log "ERROR" "Please close the process manually and try again"
                    Read-Host "Press Enter to exit"
                    exit 1
                }
                Write-Log "WARN" "Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
                Start-Sleep -Seconds $WAIT_TIME
            }
            Write-Log "INFO" "Successfully closed $processName"
        } else {
            Write-Log "WARN" "Continuing without closing Cursor. Some changes may not apply correctly."
        }
    } else {
        Write-Log "INFO" "No $processName processes found running"
    }
}

# Backup files function
function Backup-CursorFiles {
    Write-Log "INFO" "Creating backup directory if needed..."
    if (-not (Test-Path $BACKUP_DIR)) {
        New-Item -ItemType Directory -Path $BACKUP_DIR | Out-Null
        Write-Log "INFO" "Backup directory created: $BACKUP_DIR"
    }

    # Backup existing configuration
    if (Test-Path $STORAGE_FILE) {
        Write-Log "INFO" "Backing up configuration file..."
        $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $backupPath = "$BACKUP_DIR\$backupName"
        Copy-Item $STORAGE_FILE $backupPath
        Write-Log "INFO" "Configuration backed up to: $backupPath"
    } else {
        Write-Log "WARN" "Storage file not found at $STORAGE_FILE"
    }

    # Backup registry MachineGuid
    try {
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (Test-Path $registryPath) {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
                $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
                
                if ($backupResult.ExitCode -eq 0) {
                    Write-Log "INFO" "Registry MachineGuid backed up to: $backupFile"
                } else {
                    Write-Log "WARN" "Registry backup failed, continuing anyway..."
                }
            }
        }
    } catch {
        Write-Log "WARN" "Could not backup registry: $_"
    }
}

# Generate new ID
function New-RandomIds {
    Write-Log "INFO" "Generating new unique identifiers..."

    function Get-RandomHex {
        param ([int]$length)
        
        $bytes = New-Object byte[] ($length)
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($bytes)
        $hexString = [System.BitConverter]::ToString($bytes) -replace '-',''
        $rng.Dispose()
        return $hexString
    }

    # Improved ID generation function
    function New-StandardMachineId {
        $template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
        $result = $template -replace '[xy]', {
            param($match)
            $r = [Random]::new().Next(16)
            $v = if ($match.Value -eq "x") { $r } else { ($r -band 0x3) -bor 0x8 }
            return $v.ToString("x")
        }
        return $result
    }

    # Use new function when generating ID
    $MAC_MACHINE_ID = New-StandardMachineId
    $UUID = [System.Guid]::NewGuid().ToString()
    # Convert auth0|user_ to hex bytes
    $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
    $prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
    # Generate 32 bytes (64 hex characters) as random part of machineId
    $randomPart = Get-RandomHex -length 32
    $MACHINE_ID = "$prefixHex$randomPart"
    $SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

    Write-Log "DEBUG" "Generated machine ID: $MACHINE_ID"
    Write-Log "DEBUG" "Generated MAC machine ID: $MAC_MACHINE_ID"
    Write-Log "DEBUG" "Generated device ID: $UUID"
    Write-Log "DEBUG" "Generated SQM ID: $SQM_ID"

    # Return the IDs as a hashtable
    return @{
        MachineId = $MACHINE_ID
        MacMachineId = $MAC_MACHINE_ID
        DeviceId = $UUID
        SqmId = $SQM_ID
    }
}

function Update-MachineGuid {
    try {
        # Check if registry path exists, create if not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Log "WARN" "Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Log "INFO" "Registry path created successfully"
        }

        # Get current MachineGuid, use empty string as default if not exists
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Log "INFO" "Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" 
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Log "WARN" "MachineGuid value does not exist, will create new value"
            }
        } catch {
            Write-Log "WARN" "Failed to get MachineGuid: $($_.Exception.Message)"
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop
        
        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Log "INFO" "Registry updated successfully:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Log "ERROR" "Registry operation failed: $($_.Exception.Message)"
        
        # Try to restore backup if available
        if (($backupFile -ne $null) -and (Test-Path $backupFile)) {
            Write-Log "WARN" "Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru
            
            if ($restoreResult.ExitCode -eq 0) {
                Write-Log "INFO" "Original registry value restored"
            } else {
                Write-Log "ERROR" "Restore failed, please manually import backup file: $backupFile"
            }
        } else {
            Write-Log "WARN" "No backup file found or backup creation failed, cannot restore automatically"
        }
        return $false
    }
}

# Update cursor configuration
function Update-CursorConfig {
    param (
        [hashtable]$ids
    )

    Write-Log "INFO" "Updating Cursor configuration..."

    try {
        # Check if configuration file exists
        if (-not (Test-Path $STORAGE_FILE)) {
            Write-Log "ERROR" "Configuration file not found: $STORAGE_FILE"
            Write-Log "INFO" "Please install and run Cursor once before using this script"
            Read-Host "Press Enter to exit"
            exit 1
        }

        # Read existing configuration file
        try {
            $originalContent = Get-Content $STORAGE_FILE -Raw -Encoding UTF8
            
            # Convert JSON string to PowerShell object
            $config = $originalContent | ConvertFrom-Json 

            # Backup current values
            $oldValues = @{
                'machineId' = $config.'telemetry.machineId'
                'macMachineId' = $config.'telemetry.macMachineId'
                'devDeviceId' = $config.'telemetry.devDeviceId'
                'sqmId' = $config.'telemetry.sqmId'
            }

            # Update specific values
            $config.'telemetry.machineId' = $ids.MachineId
            $config.'telemetry.macMachineId' = $ids.MacMachineId
            $config.'telemetry.devDeviceId' = $ids.DeviceId
            $config.'telemetry.sqmId' = $ids.SqmId

            # Convert updated object back to JSON and save
            $updatedJson = $config | ConvertTo-Json -Depth 10
            
            # Use UTF8 without BOM encoding
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            
            # Use LF line endings consistently
            $updatedJson = $updatedJson.Replace("`r`n", "`n")
            
            [System.IO.File]::WriteAllText(
                [System.IO.Path]::GetFullPath($STORAGE_FILE), 
                $updatedJson, 
                $utf8NoBom
            )
            
            Write-Log "INFO" "Successfully updated configuration file"
            return $true
        } catch {
            # If error occurs, try to restore original content
            if ($originalContent) {
                [System.IO.File]::WriteAllText(
                    [System.IO.Path]::GetFullPath($STORAGE_FILE), 
                    $originalContent, 
                    [System.Text.Encoding]::UTF8
                )
            }
            throw "JSON processing failed: $_"
        }
    } catch {
        Write-Log "ERROR" "Main operation failed: $_"
        Write-Log "WARN" "Using alternative method..."
        
        try {
            # Alternative method: using Add-Content
            $tempFile = [System.IO.Path]::GetTempFileName()
            $config | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
            Copy-Item -Path $tempFile -Destination $STORAGE_FILE -Force
            Remove-Item -Path $tempFile
            Write-Log "INFO" "Successfully wrote configuration using alternative method"
            return $true
        } catch {
            Write-Log "ERROR" "All attempts failed"
            Write-Log "ERROR" "Error details: $_"
            Write-Log "ERROR" "Target file: $STORAGE_FILE"
            Write-Log "ERROR" "Please ensure you have sufficient permissions to access this file"
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

function Show-FileStructure {
    # Display file tree structure
    Write-Host ""
    Write-Log "INFO" "File structure:"
    Write-Host "$BLUE$env:APPDATA\Cursor\User$NC"
    Write-Host "├── globalStorage"
    Write-Host "│   ├── storage.json (modified)"
    Write-Host "│   └── backups"

    # List backup files
    $backupFiles = Get-ChildItem "$BACKUP_DIR\*" -ErrorAction SilentlyContinue
    if ($backupFiles) {
        foreach ($file in $backupFiles) {
            Write-Host "│       └── $($file.Name)"
        }
    } else {
        Write-Host "│       └── (empty)"
    }
}

function Ask-DisableAutoUpdate {
    Write-Host ""
    Write-Log "INFO" "Auto-update configuration"
    $choice = Read-Host "Do you want to disable Cursor auto-update? [y/N]"

    if ($choice -match '^[yY]') {
        Write-Log "INFO" "Processing auto-update..."
        $updaterPath = "$env:LOCALAPPDATA\cursor-updater"

        # Define manual setup guide
        function Show-ManualGuide {
            Write-Host ""
            Write-Log "WARN" "Automatic setup failed, please try manual operation:"
            Write-Host "$YELLOWManual disable update steps:$NC"
            Write-Host "1. Open PowerShell as administrator"
            Write-Host "2. Copy and paste the following commands:"
            Write-Host "$BLUECommand 1 - Delete existing directory (if exists):$NC"
            Write-Host "Remove-Item -Path `"$updaterPath`" -Force -Recurse -ErrorAction SilentlyContinue"
            Write-Host ""
            Write-Host "$BLUECommand 2 - Create blocking file:$NC"
            Write-Host "New-Item -Path `"$updaterPath`" -ItemType File -Force | Out-Null"
            Write-Host ""
            Write-Host "$BLUECommand 3 - Set read-only attribute:$NC"
            Write-Host "Set-ItemProperty -Path `"$updaterPath`" -Name IsReadOnly -Value `$true"
            Write-Host ""
            Write-Host "$BLUECommand 4 - Set permissions (optional):$NC"
            Write-Host "icacls `"$updaterPath`" /inheritance:r /grant:r `"`$($env:USERNAME):(R)`""
            Write-Host ""
            Write-Host "$YELLOWVerification method:$NC"
            Write-Host "1. Run command: Get-ItemProperty `"$updaterPath`""
            Write-Host "2. Confirm IsReadOnly attribute is True"
            Write-Host "3. Run command: icacls `"$updaterPath`""
            Write-Host "4. Confirm only read permissions"
            Write-Host ""
            Write-Log "INFO" "Please restart Cursor after completion"
        }

        try {
            # Check if cursor-updater exists
            if (Test-Path $updaterPath) {
                # If it's a file, blocking is already created
                if ((Get-Item $updaterPath) -is [System.IO.FileInfo]) {
                    Write-Log "INFO" "Update blocking file already exists, no need to block again"
                    return
                }
                # If it's a directory, try to delete
                else {
                    try {
                        Remove-Item -Path $updaterPath -Force -Recurse -ErrorAction Stop
                        Write-Log "INFO" "Successfully deleted cursor-updater directory"
                    }
                    catch {
                        Write-Log "ERROR" "Failed to delete cursor-updater directory"
                        Show-ManualGuide
                        return
                    }
                }
            }

            # Create blocking file
            try {
                New-Item -Path $updaterPath -ItemType File -Force -ErrorAction Stop | Out-Null
                Write-Log "INFO" "Successfully created blocking file"
            }
            catch {
                Write-Log "ERROR" "Failed to create blocking file"
                Show-ManualGuide
                return
            }

            # Set file permissions
            try {
                # Set read-only attribute
                Set-ItemProperty -Path $updaterPath -Name IsReadOnly -Value $true -ErrorAction Stop
                
                # Use icacls to set permissions
                $result = Start-Process "icacls.exe" -ArgumentList "`"$updaterPath`" /inheritance:r /grant:r `"$($env:USERNAME):(R)`"" -Wait -NoNewWindow -PassThru
                if ($result.ExitCode -ne 0) {
                    throw "icacls command failed"
                }
                
                Write-Log "INFO" "Successfully set file permissions"
            }
            catch {
                Write-Log "ERROR" "Failed to set file permissions"
                Show-ManualGuide
                return
            }

            # Verify settings
            try {
                $fileInfo = Get-ItemProperty $updaterPath
                if (-not $fileInfo.IsReadOnly) {
                    Write-Log "ERROR" "Verification failed: file permissions may not be set correctly"
                    Show-ManualGuide
                    return
                }
            }
            catch {
                Write-Log "ERROR" "Failed to verify settings"
                Show-ManualGuide
                return
            }

            Write-Log "INFO" "Successfully disabled auto-update"
        }
        catch {
            Write-Log "ERROR" "Unknown error occurred: $_"
            Show-ManualGuide
        }
    }
    else {
        Write-Log "INFO" "Keeping default auto-update settings"
    }
}

# Main function
function Start-CursorRenewal {
    # Get Cursor version
    $cursorVersion = Get-CursorVersion
    
    # Show menu and get confirmation
    $proceed = Show-Menu
    
    # Check and close Cursor processes
    Write-Log "INFO" "Checking Cursor processes..."
    Close-CursorProcess "Cursor"
    Close-CursorProcess "cursor"
    
    # Create backups
    Backup-CursorFiles
    
    # Generate new IDs
    $newIds = New-RandomIds
    
    # Update Cursor configuration
    $configUpdated = Update-CursorConfig -ids $newIds
    
    # Update Windows registry
    $registryUpdated = Update-MachineGuid
    
    # Show file structure
    Show-FileStructure
    
    # Ask about disabling auto-update
    Ask-DisableAutoUpdate
    
    # Show completion message
    Write-Host ""
    Write-Host "$GREEN================================$NC"
    Write-Host "$GREEN  ✓ PROCESS COMPLETED SUCCESSFULLY  $NC"
    Write-Host "$GREEN================================$NC"
    Write-Host ""
    Write-Host "$YELLOW Actions performed:$NC"
    Write-Host "• Checked Cursor status and processes"
    Write-Host "• Created configuration backups"
    Write-Host "• Generated new unique identifiers"
    Write-Host "• Updated system registry"
    if ($registryUpdated) {
        Write-Host "• Successfully updated Windows registry identifiers"
    }
    if ($configUpdated) {
        Write-Host "• Successfully updated Cursor configuration"
    }
    Write-Host ""
    Write-Log "INFO" "Please restart Cursor to apply the new configuration"
    Write-Host ""
    Write-Host "$GREEN▶ Thank you for using Cursor ID Renew Tool$NC"
    
    Write-Host ""
    Read-Host "Press Enter to exit"
}

# Start the script execution
Start-CursorRenewal 
