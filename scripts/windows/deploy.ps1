<#!
.SYNOPSIS
    Installs the Windows host service, supporting directories, and shared report tool.
.DESCRIPTION
    Copies compiled binaries into Program Files, prepares ProgramData for logs, registers
    the Windows service, and configures it to start automatically under LocalService.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$buildDir = Join-Path $repoRoot 'build\windows'
$serviceBinary = Join-Path $buildDir "${Configuration}\WslShutdownMonitor.exe"
$reportBinary = Join-Path $buildDir "${Configuration}\master_report.exe"
$installRoot = 'C:\Program Files\WslMonitor'
$programDataRoot = 'C:\ProgramData\WslMonitor'

function Assert-Administrator {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Deployment requires elevated privileges.'
    }
}

function Ensure-Build {
    if (-not (Test-Path $serviceBinary)) {
        Write-Host '[deploy] Compiled binaries not found. Triggering build...'
        & (Join-Path $PSScriptRoot 'build.ps1') -Configuration $Configuration
    }
}

function Install-Binaries {
    Write-Host "[deploy] Installing binaries into $installRoot"
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
    Copy-Item $serviceBinary -Destination (Join-Path $installRoot 'WslShutdownMonitor.exe') -Force
    if (Test-Path $reportBinary) {
        Copy-Item $reportBinary -Destination (Join-Path $installRoot 'master_report.exe') -Force
    }
}

function Prepare-DataPaths {
    Write-Host "[deploy] Preparing data directory $programDataRoot"
    New-Item -ItemType Directory -Path $programDataRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $programDataRoot 'chain-state') -Force | Out-Null
}

function Register-Service {
    $serviceName = 'WslShutdownMonitor'
    $binaryPath = '"' + (Join-Path $installRoot 'WslShutdownMonitor.exe') + '"'

    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host '[deploy] Service already exists. Recycling...'
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }

    Write-Host '[deploy] Creating Windows service'
    New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'WSL Shutdown Monitor' -Description 'Collects forensic telemetry for WSL shutdown investigations.' -StartupType Automatic
    sc.exe config $serviceName obj= 'NT AUTHORITY\LocalService' password= '' | Out-Null
    sc.exe failure $serviceName reset= 120 actions= restart/5000 | Out-Null
}

function Start-ServiceSafe {
    Write-Host '[deploy] Starting service'
    Start-Service -Name 'WslShutdownMonitor'
}

Assert-Administrator
Ensure-Build
Install-Binaries
Prepare-DataPaths
Register-Service
Start-ServiceSafe

Write-Host '[deploy] Deployment completed successfully.'
