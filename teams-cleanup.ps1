function Log {
    param (
        [string]$Text
    )
    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    Write-Information -MessageData "$timestamp `- $($Text)" -InformationAction Continue
}

# Script termination function
function Exit-Script {
    param (
        [int]$ExitCode
    )
    if (-not $global:PreventExit) {
        exit $ExitCode
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

function RemoveTeamsForUser {
    Log "Starting cleanup of Teams installations in the user context."

    try {
        # Use Get-CimInstance to retrieve information about the current logged-in user
        $loggedInUserInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        
        if ($loggedInUserInfo -and $loggedInUserInfo -ne "") {
            # Extract the username (without the domain)
            $userOnly = $loggedInUserInfo -replace '.*\\', ''
            Log "Logged-in user detected: ${userOnly}. Checking Teams installation for this user."

            # Get the user's SID using the new WMI (CIM) method
            $userSID = (Get-CimInstance -Class Win32_UserAccount | Where-Object { $_.Name -eq $userOnly }).SID
            if (-not $userSID) {
                Log "ERROR: Could not retrieve the SID for the user: ${userOnly}."
                return $false
            }
            Log "Retrieved SID for user ${userOnly}: ${userSID}"

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
        } else {
            Log "No user is currently logged in."
        }
    } catch {
        Log "ERROR: Failed to clean up Teams installations for the user. Exception: $_"
    }

    Log "Completed cleanup of Teams installations in the user context."
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
            Log "Microsoft Teams 2.0 is already provisioned on the system."
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
        Start-Sleep -Seconds 15

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

function Teams-Cleanup {
    Log "Starting Microsoft Teams installation/uninstallation process."

    # Check for elevated privileges
    Check-Elevation

    # Check and install Microsoft Edge WebView2 if required
    if (-not (Check-WebView2Installation)) {
        Log "ERROR: Microsoft Edge WebView2 installation failed. Cannot proceed with Teams installation."
        Exit-Script 1
    }

    # Uninstall existing machine-wide Teams installation
    Log "Calling function to uninstall the Teams v1 Machine-Wide version..."
    RemoveTeamsClassicWide

    # Remove Teams Personal Provisioned Package
    Log "Calling function to remove Teams Personal Provisioned Package"
    RemoveTeamsPersonalProvisionedPackage

    # Clean up Teams installations for the current user
    Log "Checking for and removing any Teams versions installed for the currently logged-in user."
    RemoveTeamsForUser

    # Install Teams after the cleanup
    Log "Proceeding with Teams installation."
    if (InstallTeams) {
        Log "Microsoft Teams successfully installed."
        Exit-Script 0
    } else {
        Log "ERROR: Microsoft Teams installation failed."
        Exit-Script 1
    }
}

# Run the script to uninstall previous versions and install the latest Teams
Teams-Cleanup