<#!
.SYNOPSIS
    Configures and builds the Windows host service and shared tooling using CMake.
.DESCRIPTION
    Creates an out-of-source build directory and invokes MSBuild through CMake.
    The script validates dependencies and restarts configuration when the generator changes.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')]
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$buildDir = Join-Path $repoRoot 'build\windows'

function Get-VsInstallPath {
    $programFilesPaths = @(
        [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),
        [Environment]::GetEnvironmentVariable('ProgramFiles')
    ) | Where-Object { $_ }

    $vswhereCandidates = $programFilesPaths | ForEach-Object {
        Join-Path $_ 'Microsoft Visual Studio\Installer\vswhere.exe'
    } | Where-Object { Test-Path $_ }

    if (-not $vswhereCandidates) {
        throw 'Unable to locate vswhere.exe. Re-run install_dependencies.ps1 or install Visual Studio Build Tools manually.'
    }

    foreach ($candidate in $vswhereCandidates) {
        $installPath = & $candidate -products Microsoft.VisualStudio.Product.BuildTools -latest -requires Microsoft.Component.MSBuild -property installationPath 2>$null
        if ($LASTEXITCODE -eq 0 -and $installPath) {
            return $installPath.Trim()
        }
    }

    throw 'Visual Studio Build Tools installation not detected. Ensure Build Tools 2022 are installed.'
}

function Invoke-Configure {
    Write-Host "[build] Configuring CMake project..."
    $vsInstallPath = Get-VsInstallPath
    $args = @(
        '-S', $repoRoot,
        '-B', $buildDir,
        '-G', 'Visual Studio 17 2022',
        '-A', 'x64',
        '-T', 'host=x64',
        "-DCMAKE_GENERATOR_INSTANCE=$vsInstallPath"
    )
    & cmake @args
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed with exit code $LASTEXITCODE."
    }
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw 'cmake not found. Run scripts/windows/install_dependencies.ps1 first.'
}

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

if (-not (Test-Path (Join-Path $buildDir 'CMakeCache.txt'))) {
    Invoke-Configure
}

Write-Host "[build] Building configuration $Configuration"
& cmake --build $buildDir --config $Configuration
if ($LASTEXITCODE -ne 0) {
    throw "CMake build failed with exit code $LASTEXITCODE."
}

Write-Host '[build] Build completed successfully.'
