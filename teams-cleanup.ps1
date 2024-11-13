function Log {
    param (
        [string]$Text,
        [string]$LogLevel = "INFO"
    )
    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    $logMessage = "$timestamp `[$LogLevel`] - $($Text)"
    
    # Write to shell
    if ($LogLevel -eq "INFO" -or $LogLevel -eq "ERROR") {
        Write-Information -MessageData $logMessage -InformationAction Continue
    }
    
    # Write to log file
    $logFilePath = "C:\Logs\TeamsCleanup.log"
    try {
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
    if (-not $global:PreventExit) {
        Write-Host "Exit code: $ExitCode. Script completed."
        return $ExitCode
    } else {
        Write-Host "Exit code: $ExitCode"
        return $ExitCode
    }
}

# Function to check for elevated privileges
function Check-Elevation {
    Log "Checking if the script has elevated privileges..."
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Log "ERROR: This script requires elevation. Please run as administrator."
        Exit-Script 1
    }
    Log "Script is running with elevated privileges."
}

# Function to send a notification to the logged-in user
function User-Notification {
    param (
        [string]$message,
        [bool]$WaitBeforeStart = $false  # Optional parameter to control waiting behavior
    )
    Log "Sending user notification: $message"

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            Log "ERROR: User information could not be retrieved. Skipping user notification."
            return
        }

        $sessionId = $userInfo.SessionId
        $userOnly = $userInfo.UserName

        Log "Sending notification to user ${userOnly} in session ${sessionId}."

        # Send the notification using msg.exe
        Start-Process -FilePath "msg.exe" -ArgumentList "$sessionId /TIME:300 `"$message`"" -NoNewWindow

        # Pause the script to wait for user interaction or timeout if the parameter is true
        if ($WaitForAcknowledgement) {
            Start-Sleep -Seconds 300  # Wait for 5 minutes before continuing
        }
    } catch {
        Log "ERROR: Failed to display user notification. Exception: $_"
    }
}

# Function to check and install Microsoft Edge WebView2 if it's not already installed
function Check-WebView2Installation {
    Log "Checking for Microsoft Edge WebView2 installation..."

    try {
        # Use Get-Package to detect WebView2 installation
        $webView2Package = Get-Package | Where-Object { $_.Name -like "*WebView2*" }

        # If WebView2 is found, log and return true
        if ($webView2Package) {
            Log "Microsoft Edge WebView2 is already installed (Version: $($webView2Package.Version))."
            return $true
        } else {
            Log "Microsoft Edge WebView2 is not installed. Downloading and installing now."

            # Download and install WebView2
            $webView2InstallerUrl = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
            $webView2InstallerPath = Join-Path $env:TEMP "MicrosoftEdgeWebView2Setup.exe"
            Invoke-WebRequest -Uri $webView2InstallerUrl -OutFile $webView2InstallerPath -UseBasicParsing

            # Install WebView2 silently
            Start-Process -FilePath $webView2InstallerPath -ArgumentList "/silent /install" -Wait

            # Recheck using Get-Package after the installation
            $webView2Package = Get-Package | Where-Object { $_.Name -like "*WebView2*" }

            if ($webView2Package) {
                Log "Microsoft Edge WebView2 installed successfully (Version: $($webView2Package.Version))."
                return $true
            } else {
                Log "ERROR: Microsoft Edge WebView2 installation failed."
                return $false
            }
        }
    } catch {
        Log "ERROR: Failed to check or install Microsoft Edge WebView2. Exception: $_"
        return $false
    }
}

function RemoveTeamsClassicWide {
    try {
        # Uninstall machine-wide versions of Teams
        Log "Attempting to uninstall the Machine-Wide version of Teams."

        # These are the GUIDs for x86 and x64 Teams Machine-Wide Installer
        $msiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
        $msiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"

        # Check if the Teams Machine-Wide Installer is installed (both 32-bit and 64-bit)
        Log "Checking for Teams Machine-Wide Installer in the registry..."
        $uninstallReg64 = Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }
        $uninstallReg32 = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }

        if ($uninstallReg64) {
            $msiExecUninstallArgs = "/X $msiPkg64Guid /quiet"
            Log "Teams Classic Machine-Wide Installer x64 found. Proceeding with uninstall."
        } elseif ($uninstallReg32) {
            $msiExecUninstallArgs = "/X $msiPkg32Guid /quiet"
            Log "Teams Machine-Wide Installer x86 found. Proceeding with uninstall."
        } else {
            Log "No Machine-Wide Teams version found. Skipping uninstallation."
            return
        }

        # Run the uninstallation if a valid GUID is found
        $p = Start-Process "msiexec.exe" -ArgumentList $msiExecUninstallArgs -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) {
            Log "Teams Classic Machine-Wide uninstalled successfully."
        } elseif ($p.ExitCode -eq 1605) {
            Log "NOTICE: Teams Classic Machine-Wide uninstall failed because the product is not installed (exit code 1605)."
            Log "Cleaning up residual registry entries for Teams Machine-Wide Installer."

            # Remove the residual registry entries if uninstallation failed with error 1605
            if ($uninstallReg64) {
                Remove-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg64.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                Log "Removed Teams Classic Machine-Wide x64 registry entry."
            }

            if ($uninstallReg32) {
                Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($uninstallReg32.PSChildName)" -Recurse -Force -ErrorAction SilentlyContinue
                Log "Removed Teams Classic Machine-Wide x86 registry entry."
            }
        } else {
            Log "ERROR: Teams Classic Machine-Wide uninstall failed with exit code $($p.ExitCode)."
        }
    } catch {
        Log "ERROR: Failed to uninstall Teams Machine-Wide. Exception: $_"
    }
}

function RemoveTeamsPersonalProvisionedPackage {
    Log "Starting removal of Microsoft Teams Personal provisioned package..."

    try {
        # Find the provisioned package for Microsoft Teams
        $package = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MicrosoftTeams*" }

        if ($package) {
            Log "Microsoft Teams Personal provisioned package found: $($package.DisplayName), Version: $($package.Version)"

            # Attempt to remove the provisioned package
            Log "Attempting to remove Microsoft Teams Personal provisioned package..."
            $result = Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName

            if ($result) {
                Log "Microsoft Teams Personal provisioned package removed successfully."
            } else {
                Log "ERROR: Failed to remove Microsoft Teams Personal provisioned package."
            }
        } else {
            Log "No Microsoft Teams Personal provisioned package found."
        }
    } catch {
        # Catch any errors during the process
        Log "ERROR: An exception occurred while attempting to remove Microsoft Teams Personal provisioned package. Exception: $_"
    }

    Log "Completed removal process for Microsoft Teams Personal provisioned package."
}

# Function to retrieve information about the currently logged-in user
function Get-LoggedInUserInfo {
    try {
        # Run quser to get logged-in user information
        $quserOutput = quser | Select-Object -Skip 1 | Out-String
        $userDetails = $quserOutput -split '\s{2,}'
        
        if ($userDetails.Count -ge 4) {
            # Extract the username and session ID from the quser output
            $userOnly = $userDetails[0].Trim()
            if ($userOnly.StartsWith(">")) {
                $userOnly = $userOnly.TrimStart(">")
                $userOnly = $userOnly.Trim()
            }
            $sessionId = [int]$userDetails[2].Trim()
            Log "Logged-in user detected: ${userOnly} with Session ID: ${sessionId}. Retrieving SID for this user."

            # Get the user's SID using Get-CimInstance
            $userSID = (Get-CimInstance -Class Win32_UserAccount | Where-Object { $_.Name -eq $userOnly }).SID
            if (-not $userSID) {
                Log "ERROR: Could not retrieve the SID for the user: ${userOnly}."
                return $null
            }

            Log "Retrieved SID for user ${userOnly}: SID = ${userSID}"

            # Store the information globally
            $global:LoggedInUserInfo = [PSCustomObject]@{
                UserName  = $userOnly
                UserSID   = $userSID
                SessionId = $sessionId
            }

            return $global:LoggedInUserInfo
        } else {
            Log "ERROR: Could not parse quser output correctly. No user session information available."
            return $null
        }
    } catch {
        Log "ERROR: Failed to retrieve logged-in user information. Exception: $_"
        return $null
    }
}

function KillTeamsProcesses {
    Log "Starting to search for and terminate any running Microsoft Teams processes."

    try {
        # Search for any running processes with names matching *teams*
        $teamsProcesses = Get-Process -Name "*teams*" -ErrorAction SilentlyContinue

        if ($teamsProcesses) {
            foreach ($process in $teamsProcesses) {
                Log "Found running Teams process: $($process.ProcessName) (ID: $($process.Id)). Attempting to terminate."
                
                # Attempt to stop the process
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                Log "Successfully terminated process: $($process.ProcessName) (ID: $($process.Id))."
            }
        } else {
            Log "No running Teams processes found."
        }
    } catch {
        Log "ERROR: Failed to terminate Teams process. Exception: $_"
    }

    Log "Completed search and termination of Teams processes."
}

function RemoveTeamsForUser {
    Log "Starting cleanup of Teams installations in the user context."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
        Log "ERROR: User information could not be retrieved. Skipping Teams cleanup for the user."
        return
    }

        $userOnly = $userInfo.UserName
        $userSID = $userInfo.UserSID

        Log "Logged-in user detected: ${userOnly}. Checking Teams installation for this user."

        # Check and list all found Teams (Appx packages) before removing them
        $teams = Get-AppxPackage -User $userSID | Where-Object { $_.Name -like "*Teams*" }
        if ($teams) {
            Log "Found the following Teams packages for user ${userOnly}:"
            foreach ($package in $teams) {
                Log " - $($package.Name), Version: $($package.Version)"
            }

            # Proceed to remove each detected Teams package
            Log "Removing all detected Teams packages..."
            foreach ($package in $teams) {
                Remove-AppxPackage -Package $package.PackageFullName -User $userSID
                Log "Removed Teams package: $($package.Name)"
            }
        } else {
            Log "No Teams packages found for user."
        }

        # Check and remove Teams v1 from AppData
        $teamsV1Path = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Microsoft", "Teams")
        if (Test-Path -Path $teamsV1Path) {
            Log "Teams v1 detected at $teamsV1Path. Removing..."
            Remove-Item -Path $teamsV1Path -Recurse -Force
            Log "Teams v1 removed."
        } else {
            Log "Teams v1 is not found for user."
        }
    } catch {
        Log "ERROR: Failed to clean up Teams installations for the user. Exception: $_"
    }

    Log "Completed cleanup of Teams installations in the user context."
}

# Function to manually remove leftover Teams files from the user profile
function Remove-TeamsUserProfileFiles {
    Log "Starting manual removal of leftover Teams files from the user profile."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            return
        }

        $userOnly = $userInfo.UserName

        Log "Logged-in user detected: ${userOnly}. Removing leftover Teams files."

        # Define the path to the Teams folder in the user's profile
        $teamsUserProfilePath = "C:\Users\$userOnly\AppData\Local\Microsoft\Teams"

        # Check if the path exists and remove it if it does
        if (Test-Path -Path $teamsUserProfilePath) {
            Log "Teams folder detected at $teamsUserProfilePath. Removing..."
            Remove-Item -Path $teamsUserProfilePath -Recurse -Force
            Log "Teams folder removed successfully."
        } else {
            Log "Teams folder not found for user ${userOnly}. No action needed."
        }
    } catch {
        Log "ERROR: Failed to remove Teams files from the user profile. Exception: $_"
    }

    Log "Completed manual removal of leftover Teams files from the user profile."
}

# Function to update the registry for Microsoft Teams protocol handler
function Update-TeamsRegistryEntry {
    Log "Starting update of Microsoft Teams registry entry."

    

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
                Log "Current registry value for Teams does not match the expected value. Updating..."
                Set-ItemProperty -Path $registryPath -Name '(Default)' -Value $expectedValue
                Log "Registry value for Teams updated successfully."
            } else {
                Log "Registry value for Teams is already set correctly. No update needed."
            }
        } else {
            Log "ERROR: Registry path $registryPath does not exist. Cannot update Teams registry entry."
        }
     Log "Completed update of Microsoft Teams registry entry."
    } 

# Install Latest version of Teams
function InstallTeams {
    try {
        Log "Installing the latest version of Microsoft Teams (Teams 2.0) from the MSIX package."

        # Define the correct Teams Appx package name for Microsoft Teams 2.0
        $teamsAppxPackageName = "MSTeams"

        # Check if Teams 2.0 is already provisioned
        $teamsProvisionedPackage = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $teamsAppxPackageName }
        if ($teamsProvisionedPackage) {
            Log "Microsoft Teams 2.0 is already provisioned on the system. Version: $($teamsProvisionedPackage.Version)"
            return $true
        }

        # If not provisioned, attempt to download and install the MSIX package
        Log "Microsoft Teams 2.0 is not provisioned. Downloading and installing from the MSIX package..."

        # Define the download URL and local path for the MSIX package
        $msixPackageUrl = "https://go.microsoft.com/fwlink/?linkid=2196106"
        $msixPackagePath = Join-Path $env:TEMP "MSTeams-x64.msix"

        # Download the MSIX package
        Log "Downloading MSIX package from $msixPackageUrl..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($msixPackageUrl, $msixPackagePath)
        $webClient.Dispose()
        Log "Download completed: $msixPackagePath."

        # Install Teams 2.0 using Add-AppProvisionedPackage
        Log "Installing Microsoft Teams 2.0 from the MSIX package..."
        Add-AppProvisionedPackage -Online -PackagePath $msixPackagePath -SkipLicense
        Log "Microsoft Teams 2.0 installation initiated from the MSIX package."

        # Wait for a few seconds to allow the system to register the installation
        Start-Sleep -Seconds 5

        # Verify the installation using Get-AppProvisionedPackage
        $teamsProvisionedPackage = Get-AppProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $teamsAppxPackageName }

        if ($teamsProvisionedPackage) {
            Log "Microsoft Teams 2.0 provisioned successfully. Version: $($teamsProvisionedPackage.Version)"
            return $true
        } else {
            Log "ERROR: Failed to verify the provisioning of Microsoft Teams 2.0."
            return $false
        }

    } catch {
        Log "ERROR: Failed to install Microsoft Teams. Exception: $_"
        return $false
    }
}

function Register-TeamsPackageForUser {
    Log "Starting registration of Microsoft Teams package for the current logged-in user."

    try {
        # Retrieve the information of the currently logged-in user
        $userInfo = $global:LoggedInUserInfo
        if (-not $userInfo) {
            Log "ERROR: User information could not be retrieved. Skipping Teams registration for the user."
            return
        }

        $userOnly = $userInfo.UserName

        # Get the path to the provisioned Microsoft Teams package
        $teamsPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MSTeams*" }
        if (-not $teamsPackage) {
            Log "ERROR: Could not locate the Microsoft Teams provisioned package. Skipping registration."
            return
        }

        $packagePath = $teamsPackage.InstallLocation

        # Run Add-AppxPackage in the context of the logged-in user to register the app
        Add-AppxPackage -Path $packagePath -Register -DisableDevelopmentMode

        # Verify if Teams was successfully registered for the user
        $teamsInstalled = Get-AppxPackage -User $userOnly | Where-Object { $_.Name -like "*MSTeams*" }
        if ($teamsInstalled) {
            Log "Successfully registered Microsoft Teams package for the current logged-in user: $($userInfo.UserName). Version: $($teamsInstalled.Version)"
        } else {
            Log "ERROR: Microsoft Teams package registration verification failed for the user."
        }
    } catch {
        Log "ERROR: Failed to register Microsoft Teams package for the user. Exception: $_"
    }

    Log "Completed registration of Microsoft Teams package."
}

function Teams-Cleanup {
    Log "Starting Microsoft Teams installation/uninstallation process."

    # Check for elevated privileges
    Check-Elevation

    # Retrieve the information of the currently logged-in user and store it for use in other functions
    $loggedInUserInfo = Get-LoggedInUserInfo
    if (-not $loggedInUserInfo) {
        Log "ERROR: Could not retrieve the logged-in user information. Continuing with Teams cleanup."
    }

    # Notify the user that Teams cleanup will begin
    Log "Notifying current user of impending Teams cleanup."
    User-Notification -Title "Teams Cleanup" -Message "IT is performing a cleanup of Microsoft Teams on this system. The process will begin in 5 minutes and will likely affect Microsoft Teams functionality for a few minutes while it runs. You will receive another message when the process is complete." -WaitBeforeStart $false

    # Check and install Microsoft Edge WebView2 if required
    if (-not (Check-WebView2Installation)) {
        Log "ERROR: Microsoft Edge WebView2 installation failed. Cannot proceed with Teams installation."
        Exit-Script 1
    }

    # Kill any running Teams processes
    KillTeamsProcesses

    # Uninstall existing machine-wide Teams installation
    Log "Calling function to uninstall the Teams v1 Machine-Wide version..."
    RemoveTeamsClassicWide

    # Uninstall Teams Personal Provisioned Package
    Log "Calling function to remove Teams Personal provisioned package"
    RemoveTeamsPersonalProvisionedPackage

    # Clean up Teams installations for the current user
    Log "Checking for and removing any Teams versions installed for the currently logged-in user."
    RemoveTeamsForUser

    # Manually remove leftover Teams files from the user profile
    Log "Removing leftover Teams files from the user profile."
    Remove-TeamsUserProfileFiles

    # Install Teams after the cleanup
    Log "Proceeding with Teams installation."
    if (InstallTeams) {
        Log "Microsoft Teams successfully installed."
        Exit-Script 0
    } else {
        Log "ERROR: Microsoft Teams installation failed."
        Exit-Script 1
    }
    
    # Register the Teams package for the current user
    Register-TeamsPackageForUser

    # Update the registry for the Microsoft Teams protocol handler
    Log "Updating registry for Microsoft Teams protocol handler."
    Update-TeamsRegistryEntry

    # Notify the user that Teams cleanup has completed
    Log "Notifying user Teams cleanup has completed."
    User-Notification -Title "Teams Cleanup Complete" -Message "Microsoft Teams cleanup has completed successfully. You may now use Microsoft Teams. When you first launch teams, please be sure to select your <firstname.lastname@goodyearaz.gov> email account if it asks for one.\n\nIf you encounter any problems with Teams, please contact the Helpdesk at (623) 822-7850." -WaitBeforeStart $false
}

# Run the script to uninstall previous versions and install the latest Teams
Teams-Cleanup
