$global:FinalStatus = "INFO"

function Log {
    param (
        [string]$Text,
        [string]$LogLevel = "INFO"
    )
    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    $logMessage = "$timestamp `[$LogLevel`] - $($Text)"
    
    # Update global script status based on log level
    if ($LogLevel -eq "ERROR") {
        $global:FinalStatus = "ERROR"
    } elseif ($LogLevel -eq "WARNING" -and $global:FinalStatus -ne "ERROR") {
        $global:FinalStatus = "WARNING"
    } elseif ($LogLevel -eq "INFO" -and -not $global:FinalStatus) {
        $global:FinalStatus = "INFO"
    }
    
    # Write to shell for INFO, WARNING, and ERROR levels
    if ($LogLevel -eq "INFO" -or $LogLevel -eq "WARNING" -or $LogLevel -eq "ERROR") {
        switch ($LogLevel) {
            "INFO"    { Write-Information -MessageData $logMessage -InformationAction Continue }
            "WARNING" { Write-Warning $logMessage }
            "ERROR"   { Write-Error $logMessage }
        }
    }
    
    # Write all log levels to the log file
    $logFilePath = "C:\Logs\TeamsCleanup.log"
    try {
        if (-not (Test-Path -Path "C:\Logs")) {
            New-Item -Path "C:\Logs" -ItemType Directory -Force
        }
        
        Add-Content -Path $logFilePath -Value $logMessage
    } catch {
        Write-Error "ERROR: Failed to write to log file. Exception: $_"
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
        Log -LogLevel INFO "Log file successfully copied to network share before exiting."
    } catch {
        Log -LogLevel ERROR "Failed to copy log file to network share before exiting. Exception: $_"
    }

    # Exit the script if the PreventExit flag is not set
    if (-not $global:PreventExit) {
        exit $ExitCode
    } else {
        Log -LogLevel ERROR "Exit code: $ExitCode"
        return $ExitCode
    }
}

# Function to check for elevated privileges
function Check-Elevation {
    Log -LogLevel INFO "Checking if the script has elevated privileges..."
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Log -LogLevel ERROR "This script requires elevation. Please run as administrator."
        Exit-Script 1
    }
    Log -LogLevel WARNING "Script is running with elevated privileges."
}

# Function to retrieve information about the currently logged-in user
function Get-LoggedInUserInfo {
    try {
        Log -LogLevel INFO "Retrieving information about the current logged-in user."

        # Use quser to retrieve information about the current logged-in user
        $quserOutput = quser | Select-String "^>" | ForEach-Object { $_ -replace '^>', '' }

        if ($quserOutput -and $quserOutput -ne "") {
            $userDetails = $quserOutput -split '\s{2,}'
            if ($userDetails.Count -ge 4) {
                # Extract the username and session ID from the quser output
                $userOnly = $userDetails[0].Trim()
                $sessionId = [int]$userDetails[2].Trim()
                Log -LogLevel INFO "Logged-in user detected: ${userOnly} with Session ID: ${sessionId}. Retrieving SID for this user."

                # Get the user's SID using CIM
                $userSID = (Get-CimInstance -Class Win32_UserAccount | Where-Object { $_.Name -eq $userOnly }).SID
                if (-not $userSID) {
                    Log -LogLevel WARNING "Could not retrieve the SID for the user: ${userOnly}."
                    return $null
                }
                Log -LogLevel INFO "Retrieved SID for user ${userOnly}: SID = ${userSID}"

                # Store the information globally
                $global:LoggedInUserInfo = [PSCustomObject]@{
                    UserName  = $userOnly
                    UserSID   = $userSID
                    SessionId = $sessionId
                }

                return $global:LoggedInUserInfo
            } else {
                Log -LogLevel ERROR "Failed to parse the quser output to retrieve user information."
                return $null
            }
        } else {
            Log -LogLevel WARNING "No logged-in user detected."
            return $null
        }
    } catch {
        Log -LogLevel ERROR "Failed to retrieve logged-in user information. Exception: $_"
        return $null
    }
}

# Function to send a notification to the logged-in user
function User-Notification {
    param (
        [string]$message,
        [bool]$WaitBeforeStart = $false  # Optional parameter to control waiting behavior
    )
    Log -LogLevel INFO "Sending user notification: $message"

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            Log -LogLevel WARNING "Current logged in user information could not be retrieved. There may be no logged in user."
        }

        $sessionId = $userInfo.SessionId
        $userOnly = $userInfo.UserName

        Log -LogLevel INFO "Sending notification to user ${userOnly} in session ${sessionId}."

        # Send the notification using msg.exe
        Start-Process -FilePath "msg.exe" -ArgumentList "$sessionId /TIME:300 `"$message`"" -NoNewWindow

        # Pause the script to wait for user interaction or timeout if the parameter is true
        if ($WaitBeforeStart) {
            Log -LogLevel INFO "Pausing script for 5 minutes to allow user to discontinue using Teams."
            Start-Sleep -Seconds 300  # Wait for 5 minutes before continuing
        }
    } catch {
        Log -LogLevel ERROR "Failed to display user notification. Exception: $_"
        Exit-Script 1  # Exit the script if there is an error notifying the user
    }
}

# Function to check and install Microsoft Edge WebView2 if it's not already installed
function Check-WebView2Installation {
    Log -LogLevel INFO "Checking for Microsoft Edge WebView2 installation..."

    try {
        # Use Get-Package to detect WebView2 installation
        $webView2Package = Get-Package | Where-Object { $_.Name -like "*WebView2*" }

        # If WebView2 is found, log and return true
        if ($webView2Package) {
            Log -LogLevel INFO "Microsoft Edge WebView2 is already installed (Version: $($webView2Package.Version))."
            return $true
        } else {
            Log -LogLevel INFO "Microsoft Edge WebView2 is not installed. Downloading and installing now."

            # Download and install WebView2
            $webView2InstallerUrl = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
            $webView2InstallerPath = Join-Path $env:TEMP "MicrosoftEdgeWebView2Setup.exe"
            Invoke-WebRequest -Uri $webView2InstallerUrl -OutFile $webView2InstallerPath -UseBasicParsing

            # Install WebView2 silently
            Start-Process -FilePath $webView2InstallerPath -ArgumentList "/silent /install" -Wait

            # Recheck using Get-Package after the installation
            $webView2Package = Get-Package | Where-Object { $_.Name -like "*WebView2*" }

            if ($webView2Package) {
                Log -LogLevel INFO "Microsoft Edge WebView2 installed successfully (Version: $($webView2Package.Version))."
                return $true
            } else {
                Log -LogLevel ERROR "Microsoft Edge WebView2 installation failed."
                return $false
            }
        }
    } catch {
        Log -LogLevel ERROR "Failed to check or install Microsoft Edge WebView2. Exception: $_"
        return $false
    }
}

# Function to remove the Machine-Wide version 1 of Teams
function RemoveTeamsClassicWide {
    try {
        # Uninstall machine-wide versions of Teams
        Log -LogLevel INFO "Attempting to uninstall the Machine-Wide version of Teams."

        # These are the GUIDs for x86 and x64 Teams Machine-Wide Installer
        $msiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
        $msiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"

        # Check if the Teams Machine-Wide Installer is installed (both 32-bit and 64-bit)
        Log -LogLevel INFO "Checking for Teams Machine-Wide Installer in the registry..."
        $uninstallReg64 = Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }
        $uninstallReg32 = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }

        if ($uninstallReg64) {
            $msiExecUninstallArgs = "/X $msiPkg64Guid /quiet"
            Log -LogLevel INFO "Teams Classic Machine-Wide Installer x64 found. Proceeding with uninstall."
        } elseif ($uninstallReg32) {
            $msiExecUninstallArgs = "/X $msiPkg32Guid /quiet"
            Log -LogLevel INFO "Teams Machine-Wide Installer x86 found. Proceeding with uninstall."
        } else {
            Log -LogLevel INFO "No Machine-Wide Teams version found. Skipping uninstallation."
            return
        }

        # Run the uninstallation if a valid GUID is found
        $p = Start-Process "msiexec.exe" -ArgumentList $msiExecUninstallArgs -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) {
            Log -LogLevel INFO "Teams Classic Machine-Wide uninstalled successfully."
        } elseif ($p.ExitCode -eq 1605) {
            Log -LogLevel WARNING "Teams Classic Machine-Wide uninstall failed because the product is not installed (exit code 1605)."
            Log -LogLevel INFO "Cleaning up residual registry entries for Teams Machine-Wide Installer."

            # Remove the residual registry entries if uninstallation failed with error 1605
            if ($uninstallReg64) {
                Remove-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg64.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                Log -LogLevel INFO "Removed Teams Classic Machine-Wide x64 registry entry."
            }

            if ($uninstallReg32) {
                Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg32.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                Log -LogLevel INFO "Removed Teams Classic Machine-Wide x86 registry entry."
            }
        } else {
            Log -LogLevel ERROR "Teams Classic Machine-Wide uninstall failed with exit code $($p.ExitCode)."
        }
    } catch {
        Log -LogLevel ERROR "Failed to uninstall Teams Machine-Wide. Exception: $_"
    }
}

# Function to remove the Microsoft Teams Personal provisioned package
function RemoveTeamsPersonalProvisionedPackage {
    Log -LogLevel INFO "Starting removal of Microsoft Teams Personal provisioned package..."

    try {
        # Find the provisioned package for Microsoft Teams
        $package = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MicrosoftTeams*" }

        if ($package) {
            Log -LogLevel INFO "Microsoft Teams Personal provisioned package found: $($package.DisplayName), Version: $($package.Version)"

            # Attempt to remove the provisioned package
            Log -LogLevel INFO "Attempting to remove Microsoft Teams Personal provisioned package..."
            $result = Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName

            if ($result) {
                Log -LogLevel INFO "Microsoft Teams Personal provisioned package removed successfully."
            } else {
                Log -LogLevel ERROR "Failed to remove Microsoft Teams Personal provisioned package."
            }
        } else {
            Log -LogLevel INFO "No Microsoft Teams Personal provisioned package found."
        }
    } catch {
        # Catch any errors during the process
        Log -LogLevel ERROR "An exception occurred while attempting to remove Microsoft Teams Personal provisioned package. Exception: $_"
    }

    Log -LogLevel INFO "Completed removal process for Microsoft Teams Personal provisioned package."
}

# Function to kill any running Microsoft Teams processes
function KillTeamsProcesses {
    Log -LogLevel INFO "Starting to search for and terminate any running Microsoft Teams processes."

    try {
        # Search for any running processes with names matching *teams*
        $teamsProcesses = Get-Process -Name "*teams*" -ErrorAction SilentlyContinue

        if ($teamsProcesses) {
            foreach ($process in $teamsProcesses) {
                Log -LogLevel INFO "Found running Teams process: $($process.ProcessName) (ID: $($process.Id)). Attempting to terminate."
                
                # Attempt to stop the process
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Log -LogLevel INFO "Successfully terminated process: $($process.ProcessName) (ID: $($process.Id))."
            }
        } else {
            Log -LogLevel INFO "No running Teams processes found."
        }
    } catch {
        Log -LogLevel WARNING "Failed to terminate Teams process. Exception: $_"
    }

    Log -LogLevel INFO "Completed search and termination of Teams processes."
}

# Function to remove Teams installations in the user context
function RemoveTeamsForUser {
    Log -LogLevel INFO "Starting cleanup of Teams installations in the user context."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            Log -LogLevel WARNING "User information could not be retrieved. Skipping Teams cleanup for the user."
            return
        }

        $userOnly = $userInfo.UserName
        $userSID = $userInfo.UserSID

        Log -LogLevel INFO "Logged-in user detected: ${userOnly}. Checking Teams installation for this user."

        # Check and list all found Teams (Appx packages) before removing them
        $teams = Get-AppxPackage -User $userSID | Where-Object { $_.Name -like "*Teams*" }
        if ($teams) {
            Log -LogLevel INFO "Found the following Teams packages for user ${userOnly}:"
            foreach ($package in $teams) {
                Log -LogLevel INFO " - $($package.Name), Version: $($package.Version)"
            }

            # Proceed to remove each detected Teams package
            Log -LogLevel INFO "Removing all detected Teams packages..."
            foreach ($package in $teams) {
                Remove-AppxPackage -Package $package.PackageFullName -User $userSID
                Log -LogLevel INFO "Removed Teams package: $($package.Name)"
            }
        } else {
            Log -LogLevel INFO "No Teams packages found for user."
        }

        # Check and remove Teams v1 from AppData
        $teamsV1Path = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Teams")
        if (Test-Path -Path $teamsV1Path) {
            Log -LogLevel INFO "Teams v1 detected at $teamsV1Path. Removing..."
            Remove-Item -Path $teamsV1Path -Recurse -Force
            Log -LogLevel INFO "Teams v1 removed."
        } else {
            Log -LogLevel INFO "Teams v1 is not found for user in AppData."
        }
    } catch {
        Log -LogLevel ERROR "Failed to clean up Teams installations for the user. Exception: $_"
    }

    Log -LogLevel INFO "Completed cleanup of Teams installations in the user context."
}

# Function to manually remove leftover Teams files from the user profile
function Remove-TeamsUserProfileFiles {
    Log -LogLevel INFO "Starting manual removal of leftover Teams files from the user profile."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            return
        }

        $userOnly = $userInfo.UserName

        Log -LogLevel INFO "Logged-in user detected: ${userOnly}. Removing leftover Teams files."

        # Define the path to the Teams folder in the user's profile
        $teamsUserProfilePath = "C:\Users\$userOnly\AppData\Local\Microsoft\Teams"

        # Check if the path exists and remove it if it does
        if (Test-Path -Path $teamsUserProfilePath) {
            Log -LogLevel INFO "Teams folder detected at $teamsUserProfilePath. Removing..."
            Remove-Item -Path $teamsUserProfilePath -Recurse -Force
            Log -LogLevel INFO "Teams folder removed successfully."
        } else {
            Log -LogLevel INFO "Teams folder not found for user ${userOnly}. No action needed."
        }
    } catch {
        Log -LogLevel ERROR "Failed to remove Teams files from the user profile. Exception: $_"
    }

    Log -LogLevel INFO "Completed manual removal of leftover Teams files from the user profile."
}

# Function to update the registry for Microsoft Teams protocol handler
function Update-TeamsRegistryEntry {
    Log -LogLevel INFO "Starting update of Microsoft Teams registry entry."

    

        # Define the registry path for the Teams protocol handler
        $registryPath = "HKCU:\Software\Classes\msteams\shell\open\command"
        
        # Check if the registry key exists
        if (Test-Path -Path $registryPath) {
            # Get the current value of the (Default) key
            $currentValue = (Get-ItemProperty -Path $registryPath -Name '(Default)').'(Default)'
            
            # Define the expected value
            $expectedValue = '"msteams.exe" "%1"'

            # Update the value if it does not match the expected value
            if ($currentValue -ne $expectedValue) {
                Log -LogLevel INFO "Current registry value for Teams does not match the expected value. Updating..."
                Set-ItemProperty -Path $registryPath -Name '(Default)' -Value $expectedValue
                Log -LogLevel INFO "Registry value for Teams updated successfully."
            } else {
                Log -LogLevel INFO "Registry value for Teams is already set correctly. No update needed."
            }
        } else {
            Log -LogLevel WARNING "Registry path $registryPath does not exist. Cannot update Teams registry entry."
        }
     Log -LogLevel INFO "Completed update of Microsoft Teams registry entry."
} 

# Install Latest version of Teams
function InstallTeams {
    try {
        Log -LogLevel INFO "Installing the latest version of Microsoft Teams (Teams 2.0) from the MSIX package."

        # Define the correct Teams Appx package name for Microsoft Teams 2.0
        $teamsAppxPackageName = "MSTeams"

        # Check if Teams 2.0 is already provisioned
        $teamsProvisionedPackage = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $teamsAppxPackageName }
        if ($teamsProvisionedPackage) {
            Log -LogLevel INFO "Microsoft Teams 2.0 is already provisioned on the system. Version: $($teamsProvisionedPackage.Version)"
            return $true
        }

        # If not provisioned, attempt to download and install the MSIX package
        Log -LogLevel INFO "Microsoft Teams 2.0 is not provisioned. Downloading and installing from the MSIX package..."

        # Define the download URL and local path for the MSIX package
        $msixPackageUrl = "https://go.microsoft.com/fwlink/?linkid=2196106"
        $msixPackagePath = Join-Path $env:TEMP "MSTeams-x64.msix"

        # Download the MSIX package
        Log -LogLevel INFO "Downloading MSIX package from $msixPackageUrl..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($msixPackageUrl, $msixPackagePath)
        $webClient.Dispose()
        Log -LogLevel INFO "Download completed: $msixPackagePath."

        # Install Teams 2.0 using Add-AppProvisionedPackage
        Log -LogLevel INFO "Installing Microsoft Teams 2.0 from the MSIX package..."
        Add-AppProvisionedPackage -Online -PackagePath $msixPackagePath -SkipLicense
        Log -LogLevel INFO "Microsoft Teams 2.0 installation initiated from the MSIX package."

        # Wait for a few seconds to allow the system to register the installation
        Start-Sleep -Seconds 5

        # Verify the installation using Get-AppProvisionedPackage
        $teamsProvisionedPackage = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $teamsAppxPackageName }

        if ($teamsProvisionedPackage) {
            Log -LogLevel INFO "Microsoft Teams 2.0 provisioned successfully. Version: $($teamsProvisionedPackage.Version)"
            return $true
        } else {
            Log -LogLevel ERROR "Failed to verify the provisioning of Microsoft Teams 2.0."
            return $false
        }

    } catch {
        Log -LogLevel ERROR "Failed to install Microsoft Teams. Exception: $_"
        return $false
    }
}

# Register the Teams package for the current user
function Register-TeamsPackageForUser {
    Log -LogLevel INFO "Starting registration of Microsoft Teams package for the current logged-in user."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            Log -LogLevel WARNING "User information could not be retrieved. Skipping Teams registration for the user."
            return
        }

        $userOnly = $userInfo.UserName

        # Get the path to the provisioned Microsoft Teams package
        $teamsPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MSTeams*" }
        if (-not $teamsPackage) {
            Log -LogLevel ERROR "Could not locate the Microsoft Teams provisioned package. Skipping registration."
            return
        }

        $packagePath = $teamsPackage.InstallLocation

        # Run Add-AppxPackage in the context of the logged-in user to register the app
        Add-AppxPackage -Path $packagePath -Register -DisableDevelopmentMode

        # Verify if Teams was successfully registered for the user
        $teamsInstalled = Get-AppxPackage -User $userOnly | Where-Object { $_.Name -like "*MSTeams*" }
        if ($teamsInstalled) {
            Log -LogLevel INFO "Successfully registered Microsoft Teams package for the current logged-in user: $($userInfo.UserName). Version: $($teamsInstalled.Version)"
        } else {
            Log -LogLevel ERROR "Microsoft Teams package registration verification failed for the user."
        }
    } catch {
        Log -LogLevel ERROR "Failed to register Microsoft Teams package for the user. Exception: $_"
    }

    Log -LogLevel INFO "Completed registration of Microsoft Teams package."
}

# Function to copy the log file to a network share
function Copy-LogToNetworkShare {
    try {
        # Define network share location and filename format
        $networkSharePath = "\\ch-ad2\Public\Teams Push Logs"
        $hostname = $env:COMPUTERNAME
        $logFilePath = "C:\Logs\TeamsCleanup.log"

        # Use the global FinalStatus variable to name the file
        $destinationFileName = "${hostname}_${global:FinalStatus}.log"
        $destinationPath = Join-Path -Path $networkSharePath -ChildPath $destinationFileName

        # Check if the log file exists before attempting to copy
        if (Test-Path -Path $logFilePath) {
            Log -LogLevel INFO "Attempting to copy log file to network share: $destinationPath"
            
            # Attempt to copy the log file to the network share
            Copy-Item -Path $logFilePath -Destination $destinationPath -Force -ErrorAction Stop

            Log -LogLevel INFO "Log file successfully copied to network share."
        } else {
            Log -LogLevel WARNING "Log file not found at path: $logFilePath. Skipping copy to network share."
        }
    } catch {
        Log -LogLevel ERROR "Failed to copy log file to network share. Exception: $_"
    }
}

function Teams-Cleanup {
    Log -LogLevel INFO "Starting Microsoft Teams installation/uninstallation process."

    # Check for elevated privileges
    Check-Elevation

    # Retrieve the information of the currently logged-in user and store it for use in other functions
    Get-LoggedInUserInfo

    # Notify the user that Teams cleanup will begin
    User-Notification -Title "Teams Cleanup" -Message "IT is performing a cleanup of Microsoft Teams on this system. The process will begin in 5 minutes and will likely affect Microsoft Teams functionality for a few minutes while it runs. You will receive another message when the process is complete." -WaitBeforeStart $false

    # Check and install Microsoft Edge WebView2 if required
    Check-WebView2Installation

    # Kill any running Teams processes
    KillTeamsProcesses

    # Uninstall existing machine-wide Teams installation
    RemoveTeamsClassicWide

    # Uninstall Teams Personal Provisioned Package
    RemoveTeamsPersonalProvisionedPackage

    # Clean up Teams installations for the current user
    RemoveTeamsForUser

    # Manually remove leftover Teams files from the user profile
    Remove-TeamsUserProfileFiles

    # Install Teams after the cleanup
    InstallTeams
    
    # Register the Teams package for the current user
    Register-TeamsPackageForUser

    # Update the registry for the Microsoft Teams protocol handler
    Update-TeamsRegistryEntry

    # Notify the user that Teams cleanup has completed
    User-Notification -Title "Teams Cleanup Complete" -Message "Microsoft Teams cleanup has completed and is now ready to use. If prompted select your <firstname.lastname@goodyearaz.gov> email account. `n`n Contact the Helpdesk at (623) 822-7850 if you have problems." -WaitBeforeStart $false

    Copy-LogToNetworkShare

}

# Run the script to uninstall previous versions and install the latest Teams
Teams-Cleanup
