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
$script:vsInstance = $null

function Get-VsInstance {
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
        $json = & $candidate -products Microsoft.VisualStudio.Product.BuildTools -latest -requires Microsoft.Component.MSBuild -format json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) {
            continue
        }

        try {
            $instances = $json | ConvertFrom-Json
        } catch {
            Write-Warning "Unable to parse vswhere output. $_"
            continue
        }

        if (-not $instances) {
            continue
        }

        foreach ($instance in $instances) {
            if (-not $instance.installationPath) { continue }
            $path = $instance.installationPath.Trim()
            $version = if ($instance.installationVersion) { $instance.installationVersion.Trim() } else { $null }
            if ($path) {
                return [PSCustomObject]@{
                    InstallationPath    = $path
                    InstallationVersion = $version
                }
            }
        }
    }

    throw 'Visual Studio Build Tools installation not detected. Ensure Build Tools 2022 are installed.'
}

function Ensure-VsInstance {
    if (-not $script:vsInstance) {
        $script:vsInstance = Get-VsInstance
    }
    return $script:vsInstance
}

function Invoke-WithVsEnvironment {
    param(
        [Parameter(Mandatory)] [string] $CommandLine
    )

    $vsInstance = Ensure-VsInstance
    $vsInstallPath = $vsInstance.InstallationPath
    $vsDevCmd = Join-Path $vsInstallPath 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path $vsDevCmd)) {
        throw "VsDevCmd.bat not found at $vsDevCmd. Re-run install_dependencies.ps1 to repair the Build Tools installation."
    }

    $comspec = if ($env:COMSPEC) { $env:COMSPEC } else { 'cmd.exe' }
    $batchInvocation = "call `"$vsDevCmd`" -no_logo -arch=x64 && $CommandLine"
    & $comspec /c "$batchInvocation"
    return $LASTEXITCODE
}

function Invoke-Configure {
    Write-Host "[build] Configuring CMake project..."
    $vsInstance = Ensure-VsInstance
    $vsInstallPath = $vsInstance.InstallationPath
    $configureArgs = @(
        'cmake',
        '-S', "`"$repoRoot`"",
        '-B', "`"$buildDir`"",
        '-G', "`"Visual Studio 17 2022`"",
        '-A', 'x64',
        '-T', 'host=x64',
        "-DCMAKE_GENERATOR_INSTANCE=`"$vsInstallPath`""
    )

    if ($vsInstance.InstallationVersion) {
        $configureArgs += "-DCMAKE_GENERATOR_INSTANCE_VERSION=`"$vsInstance.InstallationVersion`""
    }

    $configureCommand = $configureArgs -join ' '
    $exitCode = Invoke-WithVsEnvironment -CommandLine $configureCommand
    if ($exitCode -ne 0) {
        throw "CMake configuration failed with exit code $exitCode."
    }
}

function Get-NormalizedPath {
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    } catch {
        return $Path
    }
}

function Get-CMakeCacheMap {
    param(
        [Parameter(Mandatory)] [string] $CachePath
    )

    $result = @{}
    $content = Get-Content $CachePath -ErrorAction Stop
    foreach ($line in $content) {
        if ($line.StartsWith('#')) { continue }
        $equalsIndex = $line.IndexOf('=')
        if ($equalsIndex -lt 0) { continue }
        $keyPart = $line.Substring(0, $equalsIndex)
        $value = $line.Substring($equalsIndex + 1)
        $colonIndex = $keyPart.IndexOf(':')
        if ($colonIndex -lt 0) { continue }
        $key = $keyPart.Substring(0, $colonIndex)
        $result[$key] = $value
    }
    return $result
}

function Test-BuildCacheMatch {
    param(
        [Parameter(Mandatory)] [string] $ExpectedGenerator,
        [Parameter()] [string] $ExpectedToolset,
        [Parameter()] [string] $ExpectedInstance,
        [Parameter()] [string] $ExpectedInstanceVersion
    )

    $cachePath = Join-Path $buildDir 'CMakeCache.txt'
    if (-not (Test-Path $cachePath)) {
        return $false
    }

    try {
        $cacheMap = Get-CMakeCacheMap -CachePath $cachePath
    } catch {
        Write-Warning "Unable to parse $cachePath. Regenerating project. $_"
        return $false
    }

    if (-not $cacheMap.ContainsKey('CMAKE_GENERATOR')) {
        return $false
    }

    if ($cacheMap['CMAKE_GENERATOR'] -ne $ExpectedGenerator) {
        return $false
    }

    if ($ExpectedToolset) {
        if (-not $cacheMap.ContainsKey('CMAKE_GENERATOR_TOOLSET')) {
            return $false
        }

        $toolset = $cacheMap['CMAKE_GENERATOR_TOOLSET']
        if (-not $toolset.Equals($ExpectedToolset, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }

    if ($ExpectedInstance) {
        if (-not $cacheMap.ContainsKey('CMAKE_GENERATOR_INSTANCE')) {
            return $false
        }

        $actualInstance = Get-NormalizedPath -Path $cacheMap['CMAKE_GENERATOR_INSTANCE']
        $desiredInstance = Get-NormalizedPath -Path $ExpectedInstance

        if (-not $actualInstance.Equals($desiredInstance, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }

    if ($ExpectedInstanceVersion) {
        if (-not $cacheMap.ContainsKey('CMAKE_GENERATOR_INSTANCE_VERSION')) {
            return $false
        }

        $actualVersion = $cacheMap['CMAKE_GENERATOR_INSTANCE_VERSION']
        if (-not $actualVersion.Equals($ExpectedInstanceVersion, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }

    return $true
}

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw 'cmake not found. Run scripts/windows/install_dependencies.ps1 first.'
}

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

$vsInstance = Ensure-VsInstance
$vsInstallPath = $vsInstance.InstallationPath
$expectedGenerator = 'Visual Studio 17 2022'
$expectedToolset = 'host=x64'
$expectedInstance = $vsInstallPath
$expectedInstanceVersion = $vsInstance.InstallationVersion

if (-not (Test-BuildCacheMatch -ExpectedGenerator $expectedGenerator -ExpectedToolset $expectedToolset -ExpectedInstance $expectedInstance -ExpectedInstanceVersion $expectedInstanceVersion)) {
    if (Test-Path $buildDir) {
        Write-Host '[build] Detected generator/toolset mismatch. Regenerating project...'
        Remove-Item $buildDir -Recurse -Force
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
}

Invoke-Configure

Write-Host "[build] Building configuration $Configuration"
$buildCommand = "cmake --build `"$buildDir`" --config $Configuration"
$buildExitCode = Invoke-WithVsEnvironment -CommandLine $buildCommand
if ($buildExitCode -ne 0) {
    throw "CMake build failed with exit code $buildExitCode."
}

Write-Host '[build] Build completed successfully.'
