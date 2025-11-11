<#!
.SYNOPSIS
    Installs all prerequisites required to build the Windows host service and shared tooling.
.DESCRIPTION
    Uses winget to provision free Microsoft Build Tools, the Windows SDK, CMake, and Ninja.
    When winget is unavailable the script falls back to downloading the Visual Studio Build Tools
    bootstrapper directly from Microsoft and installs it silently.
#>
[CmdletBinding()]
param()

function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Install script must be run from an elevated PowerShell session." -ErrorAction Stop
    }
}

function Ensure-Winget {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        return $true
    }
    Write-Warning "winget not detected. Attempting to install App Installer from Microsoft Store.";
    $appInstallerUri = 'https://aka.ms/getwinget';
    $tempPath = Join-Path $env:TEMP "AppInstaller.msixbundle";
    Invoke-WebRequest -Uri $appInstallerUri -OutFile $tempPath;
    Add-AppxPackage -Path $tempPath;
    Remove-Item $tempPath -ErrorAction SilentlyContinue;
    return (Get-Command winget -ErrorAction SilentlyContinue) -ne $null;
}

function Install-WithWinget {
    param(
        [Parameter(Mandatory)] [string] $Id,
        [string] $Override
    )
    $arguments = @('--id', $Id, '-e', '--source', 'winget', '--accept-package-agreements', '--accept-source-agreements');
    if ($Override) {
        $arguments += '--override';
        $arguments += $Override;
    }
    Write-Host "[install] winget install $Id"
    winget install @arguments
}

function Install-BuildToolsFallback {
    $bootstrapper = 'https://aka.ms/vs/17/release/vs_BuildTools.exe';
    $target = Join-Path $env:TEMP 'vs_BuildTools.exe';
    Invoke-WebRequest -Uri $bootstrapper -OutFile $target;
    & $target --quiet --wait --norestart --nocache --installPath "C:\BuildTools" --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended;
    Remove-Item $target -Force;
}

function Ensure-BuildTools {
    if (Get-Command 'cl.exe' -ErrorAction SilentlyContinue) {
        Write-Host "[install] Visual C++ Build Tools already present.";
        return;
    }

    if (Ensure-Winget) {
        try {
            Install-WithWinget -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart"
            return;
        } catch {
            Write-Warning "winget installation of Build Tools failed. Falling back to bootstrapper. $_";
        }
    }

    Install-BuildToolsFallback;
}

function Ensure-Package {
    param(
        [Parameter(Mandatory)] [string] $Command,
        [Parameter(Mandatory)] [string] $PackageId
    )
    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        Write-Host "[install] $Command already available.";
        return;
    }

    if (-not (Ensure-Winget)) {
        throw "winget is required to install $PackageId automatically. Install it manually and rerun the script.";
    }
    Install-WithWinget -Id $PackageId;
}

Assert-Administrator;

Ensure-BuildTools;
Ensure-Package -Command cmake -PackageId 'Kitware.CMake';
Ensure-Package -Command ninja -PackageId 'Ninja-build.Ninja';
Ensure-Package -Command git -PackageId 'Git.Git';

Write-Host '[install] Build prerequisites installed successfully.';
