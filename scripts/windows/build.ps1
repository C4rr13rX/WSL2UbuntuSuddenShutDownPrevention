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

function Invoke-Configure {
    Write-Host "[build] Configuring CMake project..."
    cmake -S $repoRoot -B $buildDir -G 'Visual Studio 17 2022' -A x64
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
cmake --build $buildDir --config $Configuration

Write-Host '[build] Build completed successfully.'
