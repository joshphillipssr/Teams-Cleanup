function Teams-Cleanup {
    Log "Starting Microsoft Teams installation/uninstallation process."

    # Check for elevated privileges
    Log "Checking if the script has elevated privileges..."
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Log "ERROR: This script requires elevation. Please run as administrator."
        exit 1
    }
    Log "Script is running with elevated privileges."

    # Check and install Microsoft Edge WebView2 if required
    if (-not (InstallWebView2)) {
        Log "ERROR: Microsoft Edge WebView2 installation failed. Cannot proceed with Teams installation."
        exit 1
    }

    # Define default paths for the bootstrapper
    Log "Attempting to download the Microsoft Teams bootstrapper..."
    $BootstrapperPath = DownloadFile "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" "bootstrapper.exe"
    if ($null -eq $BootstrapperPath) {
        Log "ERROR: Failed to download the bootstrapper."
        exit 1
    }
    Log "Bootstrapper downloaded successfully: $BootstrapperPath."

    # Always attempt to uninstall any existing Machine-Wide version of Teams, regardless of Appx version
    Log "Attempting to uninstall any previous Machine-Wide versions of Microsoft Teams..."
    RemoveTeamsClassicWide

    # Now check if the latest Appx version of Teams is installed
    Log "Checking if the latest version of Microsoft Teams is already installed."
    if (-not (IsLatestTeamsInstalled)) {
        Log "No latest version of Teams detected. Proceeding with installation."
        $install = InstallTeams -BootstrapperPath $BootstrapperPath
        if ($install -eq $true) {
            Log "Microsoft Teams successfully installed."
            exit 0
        } else {
            Log "ERROR: Microsoft Teams installation failed."
            exit 1
        }
    } else {
        Log "Latest version of Microsoft Teams is already installed. Skipping installation."
        exit 0
    }
}

function InstallTeams {
    param (
        [Parameter(Mandatory=$true)]
        [string]$BootstrapperPath
    )
    try {
        Log "Installing the latest version of Microsoft Teams (Teams 2.0) from Microsoft Store."

        # Define the Teams Appx package family name for Microsoft Teams 2.0
        $teamsAppxPackageName = "MicrosoftTeams_8wekyb3d8bbwe"

        # Check if Teams 2.0 is already installed
        $teamsAppxPackage = Get-AppxPackage -Name $teamsAppxPackageName
        if ($teamsAppxPackage) {
            Log "Microsoft Teams 2.0 is already installed. Version: $($teamsAppxPackage.Version)"
            return $true
        }

        # If not installed, attempt to install from the Microsoft Store
        Log "Microsoft Teams 2.0 is not installed. Installing from the Microsoft Store..."

        # Install Teams 2.0 using Add-AppxPackage (silent)
        $teamsUri = "https://www.microsoft.com/store/productId/9WZDNCRFJB13"
        Start-Process -FilePath "ms-windows-store://pdp?productid=9WZDNCRFJB13" -Wait
        Log "Microsoft Teams 2.0 installation initiated from the Microsoft Store."

        # Verify installation after initiating
        $teamsAppxPackage = Get-AppxPackage -Name $teamsAppxPackageName
        if ($teamsAppxPackage) {
            Log "Microsoft Teams 2.0 installed successfully. Version: $($teamsAppxPackage.Version)"
            return $true
        } else {
            Log "ERROR: Failed to install Microsoft Teams 2.0."
            return $false
        }
    } catch {
        Log "ERROR: Failed to install Microsoft Teams. Exception: $_"
        return $false
    }
}

function IsLatestTeamsInstalled {
    try {
        Log "Checking for the currently logged-in user..."

        # Get the currently logged-in user
        $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
        if ($loggedInUser -and $loggedInUser -ne "") {
            # Extract the username (without the domain)
            $userOnly = $loggedInUser -replace '.*\\', ''
            Log "Logged-in user detected: ${userOnly}. Checking Teams installation for this user."

            # Get the user's SID using WindowsIdentity instead of WMI
            $userSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

            if (-not $userSID) {
                Log "ERROR: Could not retrieve the SID for the user: ${userOnly}."
                return $false
            }

            Log "Retrieved SID for user ${userOnly}: ${userSID}"

            # Check for Teams Appx package for the logged-in user by SID
            $teamsPackage = Get-AppxPackage -User $userSID | Where-Object { $_.Name -eq "MSTeams" }
            if ($teamsPackage) {
                Log "Teams version $($teamsPackage.Version) is installed for user ${userOnly} (SID: ${userSID})."
                return $true
            } else {
                Log "Microsoft Teams is not installed for user ${userOnly} (SID: ${userSID})."
                return $false
            }
        } else {
            Log "No user is currently logged in."
            return $false
        }
    } catch {
        Log "ERROR: Could not check Microsoft Teams version. Exception: $_"
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

function DownloadFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$url,
        [Parameter(Mandatory=$true)]
        [string]$fileName,
        [string]$path = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
    )
    $webClient = New-Object -TypeName System.Net.WebClient
    $file = $null
    if (-not(Test-Path -Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    try {
        Log "Starting download of $fileName from $url."
        $outputPath = Join-Path -Path $path -ChildPath $fileName
        $webClient.DownloadFile($url, $outputPath)
        Log "Download of $fileName completed: $outputPath."
        $file = $outputPath
    } catch {
        Log "ERROR: Failed to download $fileName from $url. Exception: $_"
    }
    $webClient.Dispose()
    return $file
}

# Function to check and install Microsoft Edge WebView2 if it's not already installed
function InstallWebView2 {
    try {
        Log "Checking for Microsoft Edge WebView2 installation..."

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
        Log "ERROR: Failed to install Microsoft Edge WebView2. Exception: $_"
        return $false
    }
}

function Log {
    param (
        [string]$Text
    )
    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    Write-Information -MessageData "$timestamp `- $($Text)" -InformationAction Continue
}

# Run the script to uninstall previous versions and install the latest Teams
Teams-Cleanup
