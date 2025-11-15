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
$script:vsInstallPath = $null

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

function Ensure-VsInstallPath {
    if (-not $script:vsInstallPath) {
        $script:vsInstallPath = Get-VsInstallPath
    }
    return $script:vsInstallPath
}

function Invoke-WithVsEnvironment {
    param(
        [Parameter(Mandatory)] [string] $CommandLine
    )

    $vsInstallPath = Ensure-VsInstallPath
    $vsDevCmd = Join-Path $vsInstallPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path $vsDevCmd)) {
        throw "VsDevCmd.bat not found at $vsDevCmd. Re-run install_dependencies.ps1 to repair the Build Tools installation."
    }

    $comspec = if ($env:COMSPEC) { $env:COMSPEC } else { 'cmd.exe' }
    & $comspec /c "`"$vsDevCmd`" -no_logo -arch=x64 && $CommandLine"
    return $LASTEXITCODE
}

function Invoke-Configure {
    Write-Host "[build] Configuring CMake project..."
    $vsInstallPath = Ensure-VsInstallPath
    $configureCommand = "cmake -S `"$repoRoot`" -B `"$buildDir`" -G `"Visual Studio 17 2022`" -A x64 -T host=x64 -DCMAKE_GENERATOR_INSTANCE=`"$vsInstallPath`""
    $exitCode = Invoke-WithVsEnvironment -CommandLine $configureCommand
    if ($exitCode -ne 0) {
        throw "CMake configuration failed with exit code $exitCode."
    }
}

function Test-GeneratorMatch {
    $cachePath = Join-Path $buildDir 'CMakeCache.txt'
    if (-not (Test-Path $cachePath)) {
        return $false
    }

    try {
        $cacheContent = Get-Content $cachePath -ErrorAction Stop
    } catch {
        Write-Warning "Unable to read $cachePath. Regenerating project. $_"
        return $false
    }

    $match = $cacheContent | Select-String -SimpleMatch 'CMAKE_GENERATOR:INTERNAL=Visual Studio 17 2022'
    return $null -ne $match
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw 'cmake not found. Run scripts/windows/install_dependencies.ps1 first.'
}

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

if (-not (Test-GeneratorMatch)) {
    if (Test-Path $buildDir) {
        Write-Host '[build] Regenerating project with Visual Studio 17 2022 generator...'
        Remove-Item $buildDir -Recurse -Force
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    } else {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
    Invoke-Configure
}

Write-Host "[build] Building configuration $Configuration"
$buildCommand = "cmake --build `"$buildDir`" --config $Configuration"
$buildExitCode = Invoke-WithVsEnvironment -CommandLine $buildCommand
if ($buildExitCode -ne 0) {
    throw "CMake build failed with exit code $buildExitCode."
}

Write-Host '[build] Build completed successfully.'
