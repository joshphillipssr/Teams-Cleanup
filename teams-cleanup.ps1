# Script execution flags declaration

param (
    [Alias("i")]
    [switch]$Interactive,   # Use -Interactive or -i switch to run in interactive mode
    [switch]$PreventExit    # Use -PreventExit switch to prevent script from exiting
)

# Script variables to manually set

$script:LogFilePath = "C:\Logs\TeamsCleanup.log"
$script:LogSharePath = "\\SERVER\Share"
$script:LogShareUsername = "DOMAIN\Username"
$script:LogSharePassword = "Password"

# Script variables auto-set during execution

$script:FinalStatus = "INFO"
$script:InteractiveMode = $false
$script:ConfirmAll = $false
$script:SkipAll = $false
$script:PreventExit = $false
$script:RunContext = $null # User or System
$script:LoggedInUserInfo = $null
$script:WebView2EvergreenExeVersion = $null
$script:WebView2EvergreenRegVersion = $null
$script:WebView2EvergreenStatus = $null
$script:WebView2MSIProductCodes = $null
$script:TeamsClassicWideStatus = $null
$script:TeamsPersonalProvisionedStatus = $null
$script:TeamsUserProfileFilesStatus = $null
$script:TeamsUserProfileStatus = $null
$script:TeamsProvisionedPackageStatus = $null
$script:TeamsUserRegisteredPackageStatus = $null

# Function to write log messages to the console and a log file

function Write-Log {
    param (
        [string]$LogLevel = "INFO",
        [string]$Text
    )

    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    $logMessage = "$timestamp [$LogLevel] - $Text"

    # Update script Final Status global variable based on highest severity logged
    switch ($LogLevel.ToUpper()) {
        "ERROR" {
            $script:FinalStatus = "ERROR"
            Write-Error $logMessage
        }
        "WARNING" {
            if ($script:FinalStatus -ne "ERROR") {
                $script:FinalStatus = "WARNING"
            }
            Write-Warning $logMessage
        }
        "INFO" {
            # No need to update if FinalStatus is already WARNING or ERROR
            if (-not $script:FinalStatus -or $script:FinalStatus -eq "INFO") {
                $script:FinalStatus = "INFO"
            }
            Write-Information $logMessage -InformationAction Continue
        }
        default {
            Write-Information $logMessage -InformationAction Continue
        }
    }

    # Write all log levels to the log file
    try {
        Add-Content -Path $script:LogFilePath -Value $logMessage
    } catch {
        Write-Error "ERROR: Failed to write to log file. Exception: $_"
    }
}

# Function to verify or create the log directory

function Invoke-LogsDirectory {
    try {
        # Extract the directory path from the script log file path
        $logDirectory = Split-Path -Path $script:LogFilePath -Parent

        # Check if the directory exists; create it if it doesn't
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
            Write-Log -LogLevel INFO "Log directory created: $logDirectory"
        } else {
            Write-Log -LogLevel INFO "Verified log directory exists: $logDirectory"
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to verify or create log directory. Exception: $_"
    }
}

# Set Interactive mode script variable based on script parameters

if ($Interactive) {
    $script:InteractiveMode = $true
    Write-Log -LogLevel INFO "Interactive mode enabled via command-line parameter."
} else {
    $script:InteractiveMode = $false
    Write-Log -LogLevel INFO "Running in non-interactive mode."
}

# Set PreventExit script variable based on script parameters

$script:PreventExit = $PreventExit.IsPresent

# Function to test script elevation

function Test-ScriptElevation {
    # Checking if the script has elevated privileges...
    Write-Log -LogLevel INFO "Checking if the script has elevated privileges..."
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log -LogLevel ERROR "This script requires elevation. Please run as administrator."
        Exit-Script 1
    }
    Write-Log -LogLevel INFO "Script is running with elevated privileges."
}

# Function to determine the execution context (User or System)

function Get-ExecutionContext {
    try {
        # Get the current user identity
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUserName = $currentUser.Name

        # Check if the current user is the SYSTEM account
        if ($currentUserName -eq "NT AUTHORITY\SYSTEM") {
            Write-Log -LogLevel INFO "Script is running in the System Context."
            $script:RunContext = "System"
        } else {
            Write-Log -LogLevel INFO "Script is running in the User Context."
            $script:RunContext = "User"
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to determine execution context. Exception: $_"
        $script:RunContext = $null
    }
}

# Function to make a system change when in interactive mode

function Invoke-SystemChange {
    param (
        [Parameter(Mandatory)]
        [scriptblock]$Action,
        [string]$Message = "Do you want to proceed with this change?"
    )

    Write-Log -LogLevel INFO "Preparing to make a system change..."

    if (-not (Confirm-Action -Message $Message)) {
        Write-Log -LogLevel INFO "Skipping the system change as per user input."
        return
    }

    try {
        & $Action
        Write-Log -LogLevel INFO "System change completed successfully."
    } catch {
        Write-Log -LogLevel INFO "An error occurred during the system change. Exception: $_"
    }
}

# Used by Invoke-SystemChange to confirm user action

function Confirm-Action {
    param (
        [string]$Message = "Do you want to proceed?"
    )

    if ($script:InteractiveMode) {
        if (-not $script:ConfirmAll -and -not $script:SkipAll) {
            $confirmation = Read-Host "$Message [Y]es/[N]o/[A]ll/[S]kip All"
            switch ($confirmation.ToUpper()) {
                'Y' { return $true }
                'YES' { return $true }
                'N' { return $false }
                'NO' { return $false }
                'A' {
                    $script:ConfirmAll = $true
                    return $true
                }
                'S' {
                    $script:SkipAll = $true
                    return $false
                }
                default { return $false }
            }
        } elseif ($script:ConfirmAll) {
            return $true
        } elseif ($script:SkipAll) {
            return $false
        }
    } else {
        # Non-interactive mode behavior
        return $false  # or $true based on desired default
    }
}

# Script termination function

function Exit-Script {
    param (
        [int]$ExitCode
    )

    # Attempt to copy the log file to the network share before exiting
    try {
        Copy-LogToNetworkShare
        Write-Log -LogLevel INFO "Log file successfully copied to network share before exiting."
    } catch {
        Write-Log -LogLevel ERROR "Failed to copy log file to network share before exiting. Exception: $_"
    }

    # Exit the script if the PreventExit flag is not set
    if (-not $script:PreventExit) {
        exit $ExitCode
    } else {
        Write-Log -LogLevel ERROR "Exit code: $ExitCode"
        return $ExitCode
    }
}

# Function to capture system details

function Get-SystemDetails {
    Write-Log -LogLevel INFO "Capturing system details."

    try {
        # Retrieve machine name
        $machineName = $env:COMPUTERNAME
        Write-Log -LogLevel INFO "Machine Name: $machineName"

        # Retrieve operating system details
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $osName = $os.Caption
        Write-Log -LogLevel INFO "Operating System: $osName"

        # Retrieve IP address
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet' -ErrorAction SilentlyContinue).IPAddress
        if (-not $ipAddress) {
            $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Wi-Fi' -ErrorAction SilentlyContinue).IPAddress
        }
        Write-Log -LogLevel INFO "IP Address: $ipAddress"
    } catch {
        Write-Log -LogLevel ERROR "Failed to capture system details. Exception: $_"
    }
}

# Function to retrieve information about the currently logged-in user

function Get-LoggedInUserInfo {
    try {
        Write-Log -LogLevel INFO "Retrieving information about the current logged-in user."

        # Use quser to retrieve information about the current logged-in user
        $quserOutput = quser

        if ($quserOutput -and $quserOutput -ne "") {
            # Split the output by line and parse each line, skipping the header line
            $userDetailsList = $quserOutput -split "`n" | Select-Object -Skip 1

            foreach ($userDetails in $userDetailsList) {
                # Remove leading > if present and trim leading spaces
                $userDetails = $userDetails -replace '^[>\s]+', ''
                # Replace multiple spaces with a single space for easier splitting
                $userDetails = $userDetails -replace '\s{2,}', ' '

                $detailsArray = $userDetails -split ' '

                if ($detailsArray.Count -ge 4) {
                    # Extract the username and session ID from the quser output
                    $userOnly = $detailsArray[0].Trim()
                    $sessionId = [int]$detailsArray[2].Trim()
                    Write-Log -LogLevel INFO "Logged-in user detected: ${userOnly} with Session ID: ${sessionId}. Retrieving SID for this user."

                    # Get the user's SID using CIM
                    $userSID = (Get-CimInstance -Class Win32_UserAccount -Filter "Name='$userOnly'").SID
                    if (-not $userSID) {
                        Write-Log -LogLevel WARNING "Could not retrieve the SID for the user: ${userOnly}."
                        return $null
                    }
                    Write-Log -LogLevel INFO "Retrieved SID for user ${userOnly}: SID = ${userSID}"

                    # Store the information globally
                    $script:LoggedInUserInfo = [PSCustomObject]@{
                        UserName  = $userOnly   # Assign the username
                        UserSID   = $userSID    # Assign the SID
                        SessionId = $sessionId  # Assign the session ID
                    }

                    # Return the custom object
                    return $script:LoggedInUserInfo
                }
            }

            # If no valid user was found
            Write-Log -LogLevel WARNING "No logged-in user detected."
            return $null
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to retrieve logged-in user information. Exception: $_"
        return $null
    }
}

# Function to send a notification to the logged-in user if changes are required

function Send-UserNotification {
    param (
        [string]$message,
        [bool]$WaitBeforeStart = $false  # Optional parameter to control waiting behavior
    )
    $truncatedMessage = if ($message.Length -gt 50) { 
        $message.Substring(0, 50) + "..." 
    } else { 
        $message 
    }
    Write-Log -LogLevel INFO "Sending user notification: $truncatedMessage"

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $script:LoggedInUserInfo
        if (-not $userInfo) {
            Write-Log -LogLevel WARNING "Current logged in user information could not be retrieved. There may be no logged in user."
        }

        $sessionId = $userInfo.SessionId
        $userOnly = $userInfo.UserName

        Write-Log -LogLevel INFO "Sending notification to user ${userOnly} in session ${sessionId}."

        # Send the notification using msg.exe
        Start-Process -FilePath "msg.exe" -ArgumentList "$sessionId /TIME:300 `"$message`"" -NoNewWindow

        # Pause the script to wait for user interaction or timeout if the parameter is true
        if ($WaitBeforeStart) {
            Write-Log -LogLevel INFO "Pausing script for 5 minutes to allow user to discontinue using Teams."
            Start-Sleep -Seconds 300  # Wait for 5 minutes before continuing
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to display user notification. Exception: $_"
        Exit-Script 1  # Exit the script if there is an error notifying the user
    }
}

# Function to stop all running Microsoft Edge processes

function Stop-EdgeProcesses {
    Write-Log -LogLevel INFO "Checking for running Microsoft Edge processes..."
    try {
        $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
        if ($edgeProcesses) {
            foreach ($process in $edgeProcesses) {
                Write-Log -LogLevel INFO "Preparing to terminate Edge process ID $($process.Id)"

                # Define the action to stop the process
                $action = {
                    Stop-Process -Id $using:process.Id -Force -ErrorAction SilentlyContinue
                }

                # Use Invoke-SystemChange to prompt the user
                Invoke-SystemChange -Action $action -Message "Do you want to terminate Edge process ID $($process.Id)?"

                # Check if the process still exists
                if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
                    Write-Log -LogLevel WARNING "Edge process ID $($process.Id) is still running."
                } else {
                    Write-Log -LogLevel INFO "Edge process ID $($process.Id) terminated successfully."
                }
            }
        } else {
            Write-Log -LogLevel INFO "No running Edge processes found."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to terminate Edge processes. Exception: $_"
    }
}

# Check for WebView2 Evergreen version of WebView2 Runtime Executable

function Get-WebView2EvergreenVersion {
    $baseRuntimePath = 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application'
    Write-Log -LogLevel INFO "Searching System Context Path for WebView2 Evergreen..."

    $versionedDirs = Get-ChildItem -Path $baseRuntimePath -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending

    if ($versionedDirs -and $versionedDirs.Count -gt 0) {
        $latestVersionDir = $versionedDirs | Select-Object -First 1
        $runtimePath = Join-Path $latestVersionDir.FullName "msedgewebview2.exe"

        if (Test-Path -Path $runtimePath) {
            $exeVersionInfo = (Get-Item -Path $runtimePath).VersionInfo
            Write-Log -LogLevel INFO "Found WebView2 Evergreen executable: Version $($exeVersionInfo.ProductVersion)"
            $script:WebView2EvergreenExeVersion = $exeVersionInfo.ProductVersion
        } else {
            Write-Log -LogLevel INFO "WebView2 Evergreen executable not found in $latestVersionDir."
            $script:WebView2EvergreenExeVersion = $null
        }
    } else {
        Write-Log -LogLevel INFO "No valid versioned subdirectory found under $baseRuntimePath."
        $script:WebView2EvergreenExeVersion = $null
    }
}

# Check for WebView2 Evergreen version of WebView2 Runtime in the registry

function Get-WebView2EvergreenRegistryKey {
    Write-Log -LogLevel INFO "Searching registry for WebView2 Evergreen..."

    $baseRegistryPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients'

    try {
        # Get all subkeys under the base path
        $subKeys = Get-ChildItem -Path $baseRegistryPath -ErrorAction SilentlyContinue

        if ($subKeys) {
            foreach ($subKey in $subKeys) {
                # Check if the "name" value matches "Microsoft Edge WebView2 Runtime"
                $nameValue = Get-ItemProperty -Path $subKey.PSPath -Name 'name' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty name -ErrorAction SilentlyContinue
                if ($nameValue -eq "Microsoft Edge WebView2 Runtime") {
                    # Retrieve the version from the registry
                    $version = Get-ItemProperty -Path $subKey.PSPath -Name 'pv' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty pv -ErrorAction SilentlyContinue
                    Write-Log -LogLevel INFO "WebView2 Evergreen version in registry: $version"
                    $script:WebView2EvergreenRegVersion = $version
                    return
                }
            }
        }

        Write-Log -LogLevel WARNING "No registry key found for WebView2 Evergreen under $baseRegistryPath."
        $script:WebView2EvergreenRegVersion = $null
    } catch {
        Write-Log -LogLevel ERROR "An error occurred while searching for the WebView2 Evergreen registry key. Exception: $_"
        $script:WebView2EvergreenRegVersion = $null
    }
}

# Check if the WebView2 Evergreen exe and registry versions match

function Test-WebView2EvergreenVersionMatch {
    if ($script:WebView2EvergreenExeVersion -eq $script:WebView2EvergreenRegVersion) {
        Write-Log -LogLevel INFO "WebView2 Evergreen exe and registry exist and versions match. Installation is valid."
        return $true
    } else {
        Write-Log -LogLevel WARNING "WebVew2 Evergreen version mismatch: Executable ($script:WebView2EvergreenExeVersion), Registry ($script:WebView2EvergreenRegVersion)."
        return $false
    }
}

# Function to install WebView2 Evergreen

function Install-WebView2Evergreen {
    try {
        $installerUrl = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
        $installerPath = Join-Path $env:TEMP "MicrosoftEdgeWebView2RuntimeInstaller.exe"

        if (Test-Path $installerPath) {
            Remove-Item -Path $installerPath -Force
        }
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

        Start-Process -FilePath $installerPath -ArgumentList "/silent /install /system-level" -Wait -NoNewWindow

        Write-Log -LogLevel INFO "WebView2 Runtime reinstalled successfully."
        return $true
    } catch {
        Write-Log -LogLevel ERROR "WebView2 Runtime reinstallation failed. Exception: $_"
        return $false
    }
}

function Get-WebView2Evergreen {
    Write-Log -LogLevel INFO "Checking for WebView2 Evergreen installation..."

    # Get the WebView2 Evergreen versions
    Get-WebView2EvergreenVersion
    Get-WebView2EvergreenRegistryKey

    # Test if the versions match
    $isValid = Test-WebView2EvergreenVersionMatch

    # Update the status based on the version match
    if ($isValid) {
        $script:WebView2EvergreenStatus = $true
        Write-Log -LogLevel INFO "WebView2 Evergreen installation is valid."
    } else {
        $script:WebView2EvergreenStatus = $false
        Write-Log -LogLevel WARNING "WebView2 Evergreen installation is not valid."
    }
}

# Function to gather MSI-based WebView2 installations

function Get-WebView2MSI {
    # Log the start of the check for older MSI-based WebView2 installations
    Write-Log -LogLevel INFO "Checking for older MSI-based installations of WebView2 Runtime..."

    # Initialize an array to store product codes of found installations
    $msiProductCodes = @()

    # Method 1: Using Get-Package
    try {
        $packages = Get-Package -ProviderName Programs -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*WebView2*" }
        if ($packages) {
            foreach ($package in $packages) {
                if ($package.Version) {
                    Write-Log -LogLevel INFO "Found MSI-based WebView2 Runtime installation via Get-Package: $($package.Name), Version: $($package.Version)"
                    $msiProductCodes += $package.IdentifyingNumber
                }
            }
        }
    } catch {
        Write-Log -LogLevel WARNING "Get-Package did not find any MSI-based WebView2 installations."
    }

    # Method 2: Using WMI/CIM
    try {
        $wmiPackages = Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%WebView2%'" -ErrorAction SilentlyContinue
        if ($wmiPackages) {
            foreach ($wmiPackage in $wmiPackages) {
                Write-Log -LogLevel INFO "Found MSI-based WebView2 Runtime installation via WMI: $($wmiPackage.Name), Version: $($wmiPackage.Version)"
                $msiProductCodes += $wmiPackage.IdentifyingNumber
            }
        }
    } catch {
        Write-Log -LogLevel INFO "WMI did not find any MSI-based WebView2 installations."
    }

    # Store the found product codes in the script variable
    if ($msiProductCodes.Count -gt 0) {
        $script:WebView2MSIProductCodes = $msiProductCodes
        Write-Log -LogLevel INFO "Found the following MSI-based WebView2 Runtime installations: $($msiProductCodes -join ', ')"
    } else {
        $script:WebView2MSIProductCodes = $false
        Write-Log -LogLevel INFO "No MSI-based WebView2 Runtime installations found."
    }
}

# Function to remove MSI-based WebView2 installations

function Remove-WebView2MSI {
    param (
        [string[]]$ProductCodes
    )

    # Ensure Edge processes are terminated before uninstallation
    Terminate-EdgeProcesses

    foreach ($productCode in $ProductCodes) {
        Write-Log -LogLevel INFO "Uninstalling MSI-based WebView2 Runtime with Product Code $productCode"
        $msiExecArgs = "/x $productCode /qn /l*v `"C:\Logs\WebView2Uninstall_$($productCode).log`""
        $uninstallProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiExecArgs -Wait -PassThru

        if ($uninstallProcess.ExitCode -eq 0) {
            Write-Log -LogLevel INFO "Successfully uninstalled MSI-based WebView2 Runtime with Product Code $productCode"
        } else {
            Write-Log -LogLevel ERROR "Failed to uninstall MSI-based WebView2 Runtime with Product Code $productCode. Exit Code: $($uninstallProcess.ExitCode). Check the log at C:\Logs\WebView2Uninstall_$($productCode).log"
        }
    }
}

# Function to detect the Machine-Wide version 1 of Teams

function Get-TeamsClassicWide {
    Write-Log -LogLevel INFO "Checking for Teams Machine-Wide Installer in the registry..."

    # These are the GUIDs for x86 and x64 Teams Machine-Wide Installer
    $msiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
    $msiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"

    # Check if the Teams Machine-Wide Installer is installed (both 32-bit and 64-bit)
    try {
        $uninstallReg64 = Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }
        $uninstallReg32 = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }

        if ($uninstallReg64) {
            Write-Log -LogLevel INFO "Teams Classic Machine-Wide Installer x64 found."
            $script:TeamsClassicWideStatus = $msiPkg64Guid
        } elseif ($uninstallReg32) {
            Write-Log -LogLevel INFO "Teams Machine-Wide Installer x86 found."
            $script:TeamsClassicWideStatus = $msiPkg32Guid
        } else {
            Write-Log -LogLevel INFO "No Machine-Wide Teams version found."
            $script:TeamsClassicWideStatus = $false
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to check for Teams Machine-Wide Installer. Exception: $_"
        $script:TeamsClassicWideStatus = $false
    }
}

# Function to remove the Machine-Wide version 1 of Teams

function Remove-TeamsClassicWide {
    try {
        # Uninstall machine-wide versions of Teams
        Write-Log -LogLevel INFO "Attempting to uninstall the Machine-Wide version of Teams."

        if ($script:TeamsClassicWideStatus -ne $false) {
            $msiExecUninstallArgs = "/X $script:TeamsClassicWideStatus /quiet"
            $action = {
                $p = Start-Process "msiexec.exe" -ArgumentList $using:msiExecUninstallArgs -Wait -PassThru -WindowStyle Hidden
                if ($p.ExitCode -eq 0) {
                    Write-Log -LogLevel INFO "Teams Classic Machine-Wide uninstalled successfully."
                } elseif ($p.ExitCode -eq 1605) {
                    Write-Log -LogLevel WARNING "Teams Classic Machine-Wide uninstall failed because the product is not installed (exit code 1605)."
                    Write-Log -LogLevel INFO "Cleaning up residual registry entries for Teams Machine-Wide Installer."

                    # Remove the residual registry entries if uninstallation failed with error 1605
                    if ($script:TeamsClassicWideStatus -eq "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}") {
                        Remove-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg64.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log -LogLevel INFO "Removed Teams Classic Machine-Wide x64 registry entry."
                    } elseif ($script:TeamsClassicWideStatus -eq "{39AF0813-FA7B-4860-ADBE-93B9B214B914}") {
                        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg32.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log -LogLevel INFO "Removed Teams Classic Machine-Wide x86 registry entry."
                    }
                } else {
                    Write-Log -LogLevel ERROR "Teams Classic Machine-Wide uninstall failed with exit code $($p.ExitCode)."
                }
            }

            if ($script:InteractiveMode) {
                Invoke-SystemChange -Action $action -Message "Do you want to uninstall the Machine-Wide version of Teams?"
            } else {
                & $action
            }
        } else {
            Write-Log -LogLevel INFO "No Machine-Wide Teams version found. Skipping uninstallation."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to uninstall Teams Machine-Wide. Exception: $_"
    }
}

# Function to detect the Microsoft Teams Personal provisioned package

function Get-TeamsPersonalProvisionedPackage {
    Write-Log -LogLevel INFO "Checking for Microsoft Teams Personal provisioned package..."

    try {
        # Find the provisioned package for Microsoft Teams
        $package = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MicrosoftTeams*" }

        if ($package) {
            Write-Log -LogLevel INFO "Microsoft Teams Personal provisioned package found: $($package.DisplayName), Version: $($package.Version)"
            $script:TeamsPersonalProvisionedStatus = $package.PackageName
        } else {
            Write-Log -LogLevel INFO "No Microsoft Teams Personal provisioned package found."
            $script:TeamsPersonalProvisionedStatus = $false
        }
    } catch {
        # Catch any errors during the process
        Write-Log -LogLevel ERROR "An exception occurred while checking for Microsoft Teams Personal provisioned package. Exception: $_"
        $script:TeamsPersonalProvisionedStatus = $false
    }
}

# Function to remove the Microsoft Teams Personal provisioned package

function Remove-TeamsPersonalProvisionedPackage {
    Write-Log -LogLevel INFO "Starting removal of Microsoft Teams Personal provisioned package..."

    try {
        if ($script:TeamsPersonalProvisionedStatus -ne $false) {
            $action = {
                # Attempt to remove the provisioned package
                Write-Log -LogLevel INFO "Attempting to remove Microsoft Teams Personal provisioned package..."
                $result = Remove-AppxProvisionedPackage -Online -PackageName $using:script:TeamsPersonalProvisionedStatus

                if ($result) {
                    Write-Log -LogLevel INFO "Microsoft Teams Personal provisioned package removed successfully."
                } else {
                    Write-Log -LogLevel ERROR "Failed to remove Microsoft Teams Personal provisioned package."
                }
            }

            if ($script:InteractiveMode) {
                Invoke-SystemChange -Action $action -Message "Do you want to remove the Microsoft Teams Personal provisioned package?"
            } else {
                & $action
            }
        } else {
            Write-Log -LogLevel INFO "No Microsoft Teams Personal provisioned package found."
        }
    } catch {
        # Catch any errors during the process
        Write-Log -LogLevel ERROR "An exception occurred while attempting to remove Microsoft Teams Personal provisioned package. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed removal process for Microsoft Teams Personal provisioned package."
}

# Function to kill any running Microsoft Teams processes

function Invoke-KillTeamsProcesses {
    Write-Log -LogLevel INFO "Starting to search for and terminate any running Microsoft Teams processes."

    try {
        # Search for any running processes with names matching *teams*
        $teamsProcesses = Get-Process -Name "*teams*" -ErrorAction SilentlyContinue

        if ($teamsProcesses) {
            foreach ($process in $teamsProcesses) {
                Write-Log -LogLevel INFO "Found running Teams process: $($process.ProcessName) (ID: $($process.Id)). Attempting to terminate."
                
                # Attempt to stop the process
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Write-Log -LogLevel INFO "Successfully terminated process: $($process.ProcessName) (ID: $($process.Id))."
            }
        } else {
            Write-Log -LogLevel INFO "No running Teams processes found."
        }
    } catch {
        Write-Log -LogLevel WARNING "Failed to terminate Teams process. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed search and termination of Teams processes."
}

# Function to detect Teams installations in the user context

function Get-TeamsForUser {
    Write-Log -LogLevel INFO "Checking Teams installations in the user context."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $script:LoggedInUserInfo
        if (-not $userInfo) {
            Write-Log -LogLevel WARNING "User information could not be retrieved. Skipping Teams detection for the user."
            $script:TeamsUserProfileStatus = $false
            return
        }

        $userOnly = $userInfo.UserName
        $userSID = $userInfo.UserSID

        Write-Log -LogLevel INFO "Logged-in user detected: ${userOnly}. Checking Teams installation for this user."

        # Check and list all found Teams (Appx packages)
        $teams = Get-AppxPackage -User $userSID | Where-Object { $_.Name -like "*Teams*" }
        if ($teams) {
            Write-Log -LogLevel INFO "Found the following Teams packages for user ${userOnly}:"
            foreach ($package in $teams) {
                Write-Log -LogLevel INFO " - $($package.Name), Version: $($package.Version)"
            }
            $script:TeamsUserProfileStatus = $teams
        } else {
            Write-Log -LogLevel INFO "No Teams packages found for user."
            $script:TeamsUserProfileStatus = $false
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to detect Teams installations for the user. Exception: $_"
        $script:TeamsUserProfileStatus = $false
    }
}

# Function to remove Teams installations in the user context

function Remove-TeamsForUser {
    Write-Log -LogLevel INFO "Starting cleanup of Teams installations in the user context."

    try {
        if ($script:TeamsUserProfileStatus -ne $false) {
            # Retrieve the information of the currently logged-in user
            $userInfo = $script:LoggedInUserInfo
            if (-not $userInfo) {
                Write-Log -LogLevel WARNING "User information could not be retrieved. Skipping Teams cleanup for the user."
                return
            }

            $userOnly = $userInfo.UserName
            $userSID = $userInfo.UserSID

            # Proceed to remove each detected Teams package
            Write-Log -LogLevel INFO "Removing all detected Teams packages..."
            foreach ($package in $script:TeamsUserProfileStatus) {
                Remove-AppxPackage -Package $package.PackageFullName -User $userSID
                Write-Log -LogLevel INFO "Removed Teams package: $($package.Name)"
            }

            # Check and remove Teams v1 from AppData
            $teamsV1Path = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Teams")
            if (Test-Path -Path $teamsV1Path) {
                Write-Log -LogLevel INFO "Teams v1 detected at $teamsV1Path. Removing..."
                Remove-Item -Path $teamsV1Path -Recurse -Force
                Write-Log -LogLevel INFO "Teams v1 removed."
            } else {
                Write-Log -LogLevel INFO "Teams v1 is not found for user in AppData."
            }
        } else {
            Write-Log -LogLevel INFO "No Teams packages found for user."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to clean up Teams installations for the user. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed cleanup of Teams installations in the user context."
}

# Add the new detection function

function Get-TeamsUserProfileFiles {
    Write-Log -LogLevel INFO "Checking for leftover Teams files in the user profile."

    try {
        # Retrieve information about the logged-in user
        $userInfo = $script:LoggedInUserInfo
        if (-not $userInfo) {
            $script:TeamsUserProfileFilesStatus = $false
            return
        }

        $userOnly = $userInfo.UserName

        # Define the path to the Teams folder in the user's profile
        $teamsUserProfilePath = "C:\Users\$userOnly\AppData\Local\Microsoft\Teams"

        # Check if the path exists
        if (Test-Path -Path $teamsUserProfilePath) {
            Write-Log -LogLevel INFO "Teams folder detected at $teamsUserProfilePath."
            $script:TeamsUserProfileFilesStatus = $true
        } else {
            Write-Log -LogLevel INFO "Teams folder not found for user ${userOnly}."
            $script:TeamsUserProfileFilesStatus = $false
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to check Teams files in the user profile. Exception: $_"
        $script:TeamsUserProfileFilesStatus = $false
    }
}

# Modify Remove-TeamsUserProfileFiles to only remove files

function Remove-TeamsUserProfileFiles {
    Write-Log -LogLevel INFO "Starting removal of leftover Teams files from the user profile."

    try {
        if ($script:TeamsUserProfileFilesStatus -eq $true) {
            # Retrieve information about the logged-in user
            $userInfo = $script:LoggedInUserInfo
            if (-not $userInfo) {
                return
            }

            $userOnly = $userInfo.UserName
            $teamsUserProfilePath = "C:\Users\$userOnly\AppData\Local\Microsoft\Teams"

            # Define the action to remove the Teams folder
            $action = {
                Write-Log -LogLevel INFO "Removing Teams folder at $using:teamsUserProfilePath..."
                Remove-Item -Path $using:teamsUserProfilePath -Recurse -Force
                Write-Log -LogLevel INFO "Teams folder removed successfully."
            }

            # Use Invoke-SystemChange if in interactive mode
            if ($script:InteractiveMode) {
                Invoke-SystemChange -Action $action -Message "Do you want to remove leftover Teams files from the user profile?"
            } else {
                & $action
            }
        } else {
            Write-Log -LogLevel INFO "No Teams files to remove from the user profile."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to remove Teams files from the user profile. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed removal of leftover Teams files from the user profile."
}

# Function to get the current registry entry for the Teams protocol handler

function Get-TeamsProtocolHandler {
    Write-Log -LogLevel INFO "Checking the registry entry for the Microsoft Teams protocol handler."

    # Determine which registry base path to use based on execution context
    if ($script:RunContext -eq "User") {
        # Running in user context, we can directly access HKCU
        $registryPath = "HKCU:\Software\Classes\msteams\shell\open\command"
    } elseif ($script:RunContext -eq "System") {
        # Running in System context, we need to use the user SID
        if (-not $script:LoggedInUserInfo) {
            Write-Log -LogLevel WARNING "No logged-in user information found while running in System context. Cannot retrieve Teams protocol handler entry from registry."
            $script:TeamsRegistryEntry = $null
            return
        }
        
        $userSID = $script:LoggedInUserInfo.UserSID
        $registryPath = "HKU:\$userSID\Software\Classes\msteams\shell\open\command"
    } else {
        Write-Log -LogLevel WARNING "Unknown execution context: $($script:RunContext). Cannot determine which registry hive to use."
        $script:TeamsRegistryEntry = $null
        return
    }

    try {
        if (Test-Path -Path $registryPath) {
            $currentValue = (Get-ItemProperty -Path $registryPath -Name '(Default)').'(Default)'
            Write-Log -LogLevel INFO "Current registry value for Teams protocol handler: $currentValue"
            $script:TeamsRegistryEntry = $currentValue
        } else {
            Write-Log -LogLevel WARNING "Registry path $registryPath does not exist. Cannot retrieve Teams protocol handler entry."
            $script:TeamsRegistryEntry = $null
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to retrieve the Teams protocol handler registry entry. Exception: $_"
        $script:TeamsRegistryEntry = $null
    }
}

# Function to update the registry for Microsoft Teams protocol handler

function Update-TeamsProtocolHandler {
    Write-Log -LogLevel INFO "Starting update of Microsoft Teams protocol handler registry entry."

    $registryPath = "HKCU:\Software\Classes\msteams\shell\open\command"
    $expectedValue = '"msteams.exe" "%1"'

    try {
        if ($script:TeamsRegistryEntry -ne $expectedValue) {
            Write-Log -LogLevel INFO "Current registry value for Teams protocol handler does not match the expected value. Updating..."
            Set-ItemProperty -Path $registryPath -Name '(Default)' -Value $expectedValue
            Write-Log -LogLevel INFO "Registry value for Teams protocol handler updated successfully."
        } else {
            Write-Log -LogLevel INFO "Registry value for Teams protocol handler is already set correctly. No update needed."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to update the Teams protocol handler registry entry. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed update of Microsoft Teams protocol handler registry entry."
}

function Get-TeamsInstall {
    param (
        [string]$AppxPackageName = "MSTeams"
    )
    Write-Log -LogLevel INFO "Checking if Microsoft Teams 2.0 ($AppxPackageName) is already provisioned."
    $teamsProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $AppxPackageName }
    if ($teamsProvisionedPackage) {
        Write-Log -LogLevel INFO "Microsoft Teams 2.0 is already provisioned. Version: $($teamsProvisionedPackage.Version)"
        $script:TeamsProvisionedPackageStatus = $teamsProvisionedPackage
    } else {
        Write-Log -LogLevel INFO "Microsoft Teams 2.0 is not provisioned."
        $script:TeamsProvisionedPackageStatus = $false
    }
}

function Invoke-InstallTeams {
    try {
        Write-Log -LogLevel INFO "Installing the latest version of Microsoft Teams (Teams 2.0) from the MSIX package."
        Get-TeamsInstall
        if ($script:TeamsProvisionedPackageStatus -ne $false) {
            Write-Log -LogLevel INFO "Teams 2.0 is already provisioned. Skipping installation."
            return
        }

        if ($script:InteractiveMode) {
            $action = {
                Write-Log -LogLevel INFO "Microsoft Teams 2.0 is not provisioned. Downloading and installing from the MSIX package..."

                # Define the download URL and local path for the MSIX package
                $msixPackageUrl = "https://go.microsoft.com/fwlink/?linkid=2196106"
                $msixPackagePath = Join-Path $env:TEMP "MSTeams-x64.msix"

                # Download the MSIX package
                Write-Log -LogLevel INFO "Downloading MSIX package from $msixPackageUrl..."
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($msixPackageUrl, $msixPackagePath)
                $webClient.Dispose()
                Write-Log -LogLevel INFO "Download completed: $msixPackagePath."

                # Install Teams 2.0 using Add-AppProvisionedPackage
                Write-Log -LogLevel INFO "Installing Microsoft Teams 2.0 from the MSIX package..."
                Add-AppxProvisionedPackage -Online -PackagePath $msixPackagePath -SkipLicense
                Write-Log -LogLevel INFO "Microsoft Teams 2.0 installation initiated from the MSIX package."

                # Wait for a few seconds to allow the system to register the installation
                Start-Sleep -Seconds 5

                # Verify the installation using Get-AppProvisionedPackage
                $teamsProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MSTeams" }

                if ($teamsProvisionedPackage) {
                    Write-Log -LogLevel INFO "Microsoft Teams 2.0 provisioned successfully. Version: $($teamsProvisionedPackage.Version)"
                    return $true
                } else {
                    Write-Log -LogLevel ERROR "Failed to verify the provisioning of Microsoft Teams 2.0."
                    return $false
                }
            }
            Invoke-SystemChange -Action $action -Message "Do you want to install Microsoft Teams 2.0?"
        } else {
            Write-Log -LogLevel INFO "Microsoft Teams 2.0 is not provisioned. Downloading and installing from the MSIX package..."

            # Define the download URL and local path for the MSIX package
            $msixPackageUrl = "https://go.microsoft.com/fwlink/?linkid=2196106"
            $msixPackagePath = Join-Path $env:TEMP "MSTeams-x64.msix"

            # Download the MSIX package
            Write-Log -LogLevel INFO "Downloading MSIX package from $msixPackageUrl..."
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($msixPackageUrl, $msixPackagePath)
            $webClient.Dispose()
            Write-Log -LogLevel INFO "Download completed: $msixPackagePath."

            # Install Teams 2.0 using Add-AppProvisionedPackage
            Write-Log -LogLevel INFO "Installing Microsoft Teams 2.0 from the MSIX package..."
            Add-AppxProvisionedPackage -Online -PackagePath $msixPackagePath -SkipLicense
            Write-Log -LogLevel INFO "Microsoft Teams 2.0 installation initiated from the MSIX package."

            # Wait for a few seconds to allow the system to register the installation
            Start-Sleep -Seconds 5

            # Verify the installation using Get-AppProvisionedPackage
            $teamsProvisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "MSTeams" }

            if ($teamsProvisionedPackage) {
                Write-Log -LogLevel INFO "Microsoft Teams 2.0 provisioned successfully. Version: $($teamsProvisionedPackage.Version)"
                return $true
            } else {
                Write-Log -LogLevel ERROR "Failed to verify the provisioning of Microsoft Teams 2.0."
                return $false
            }
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to install Microsoft Teams. Exception: $_"
        return $false
    }
}

# Register the Teams package for the current user

function Register-TeamsPackageForUser {
    Write-Log -LogLevel INFO "Starting registration of Microsoft Teams package for the current logged-in user."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $script:LoggedInUserInfo
        if (-not $userInfo) {
            Write-Log -LogLevel WARNING "User information could not be retrieved. Skipping Teams registration for the user."
            return
        }

        $userOnly = $userInfo.UserName

        # Get the path to the provisioned Microsoft Teams package
        $teamsPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MSTeams*" }
        if (-not $teamsPackage) {
            Write-Log -LogLevel ERROR "Could not locate the Microsoft Teams provisioned package. Skipping registration."
            return
        }

        $packagePath = $teamsPackage.InstallLocation

        # Run Add-AppxPackage in the context of the logged-in user to register the app
        Add-AppxPackage -Path $packagePath -Register -DisableDevelopmentMode

        # Verify if Teams was successfully registered for the user
        $teamsInstalled = Get-AppxPackage -User $userOnly | Where-Object { $_.Name -like "*MSTeams*" }
        if ($teamsInstalled) {
            Write-Log -LogLevel INFO "Successfully registered Microsoft Teams package for the current logged-in user: $($userInfo.UserName). Version: $($teamsInstalled.Version)"
        } else {
            Write-Log -LogLevel ERROR "Microsoft Teams package registration verification failed for the user."
        }
    } catch {
        Write-Log -LogLevel ERROR "Failed to register Microsoft Teams package for the user. Exception: $_"
    }

    Write-Log -LogLevel INFO "Completed registration of Microsoft Teams package."
}

# Function to copy the log file to a network share

function Copy-LogToNetworkShare {
    try {
        # Ensure the log file exists
        if (-not (Test-Path -Path $script:LogFilePath)) {
            Write-Log -LogLevel WARNING "Log file not found at path: $script:LogFilePath. Skipping copy to network share."
            return
        }

        # Define the destination file name and path
        $hostname = $env:COMPUTERNAME
        $destinationFileName = "${hostname}_${script:FinalStatus}.log"
        $destinationPath = Join-Path -Path $script:LogSharePath -ChildPath $destinationFileName

        Write-Log -LogLevel INFO "Attempting to copy log file to network share: $destinationPath"

        # Create PSCredential object for authentication
        $securePassword = $script:LogSharePassword | ConvertTo-SecureString -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($script:LogShareUsername, $securePassword)

        # Map the network share using the provided credentials
        New-PSDrive -Name Z -PSProvider FileSystem -Root $script:LogSharePath -Credential $credential -ErrorAction Stop

        # Copy the log file to the network share
        Copy-Item -Path $script:LogFilePath -Destination "Z:\$destinationFileName" -Force -ErrorAction Stop

        Write-Log -LogLevel INFO "Log file successfully copied to network share."

        # Remove the mapped drive
        Remove-PSDrive -Name Z -ErrorAction Stop
    } catch {
        Write-Log -LogLevel ERROR "Failed to copy log file to network share. Exception: $_"
    }
}

# Function to initialize the script

function Invoke-InitializeScript {
    Invoke-LogsDirectory
    Test-ScriptElevation
    Get-ExecutionContext
    Get-SystemDetails
}

# Function to get the status of all components and update script variables

function Get-StatusAll {
    Get-LoggedInUserInfo
    Get-WebView2MSI
    Get-WebView2Evergreen
    Get-TeamsClassicWide
    Get-TeamsPersonalProvisionedPackage
    Get-TeamsForUser
    Get-TeamsInstall
    Get-TeamsProtocolHandler
}

function Invoke-ScriptStatusAndPrompt {
    Write-Log -LogLevel INFO "Checking the status of script variables to determine if changes need to be made."

    # Determine if any changes are needed
    $changesNeeded = $false

    if ($script:WebView2EvergreenStatus -eq $false) {
        Write-Log -LogLevel INFO "WebView2 Evergreen installation is not valid."
        $changesNeeded = $true
    }
    if ($script:TeamsClassicWideStatus -ne $false) {
        Write-Log -LogLevel INFO "Teams Machine-Wide Installer is present."
        $changesNeeded = $true
    }
    if ($script:TeamsPersonalProvisionedStatus -ne $false) {
        Write-Log -LogLevel INFO "Teams Personal provisioned package is present."
        $changesNeeded = $true
    }
    if ($script:TeamsUserProfileStatus -ne $false) {
        Write-Log -LogLevel INFO "Teams installations found in user profile."
        $changesNeeded = $true
    }
    if ($script:TeamsUserProfileFilesStatus -eq $true) {
        Write-Log -LogLevel INFO "Leftover Teams files found in user profile."
        $changesNeeded = $true
    }
    if ($script:TeamsRegistryEntry -ne '"msteams.exe" "%1"') {
        Write-Log -LogLevel INFO "Teams protocol handler registry entry is not set correctly."
        $changesNeeded = $true
    }

    if ($changesNeeded) {
        if ($script:InteractiveMode) {
            $proceed = Confirm-Action -Message "Changes are needed to clean up Teams. Do you want to proceed?"
            if ($proceed) {
                Invoke-SystemChange
            } else {
                Write-Log -LogLevel INFO "User chose not to proceed with changes. Exiting script."
                Exit-Script 0
            }
        } else {
            Write-Log -LogLevel INFO "Non-interactive mode: Proceeding with changes."
            Invoke-SystemChange
        }
    } else {
        Write-Log -LogLevel INFO "No changes needed. Exiting script."
        Exit-Script 0
    }
}

Invoke-InitializeScript
Get-StatusAll
Invoke-ScriptStatusAndPrompt
