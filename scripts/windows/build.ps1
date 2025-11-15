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
$script:activeGenerator = $null

$primaryGeneratorSpec = [PSCustomObject]@{
    Name             = 'Visual Studio 17 2022'
    Toolset          = 'host=x64'
    MultiConfig      = $true
    RequiresInstance = $true
    Description      = 'Visual Studio 2022 (MSBuild)'
}

$fallbackGeneratorSpec = [PSCustomObject]@{
    Name             = 'Ninja'
    Toolset          = $null
    MultiConfig      = $false
    RequiresInstance = $false
    Description      = 'Ninja (MSVC toolchain)'
}

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

function Join-CommandLine {
    param(
        [Parameter(Mandatory)] [string[]] $Args
    )

    $escapedArgs = foreach ($arg in $Args) {
        if ($null -eq $arg -or $arg.Length -eq 0) {
            '""'
            continue
        }

        $needsQuotes = $arg -match '[\s"]'
        $escaped = $arg -replace '(\\*)"', '$1$1"'

        if ($needsQuotes) {
            $escaped = $escaped -replace '(\\+)$', '$1$1'
            "\"{0}\"" -f $escaped
        } else {
            $escaped
        }
    }

    return ($escapedArgs -join ' ')
}

function Invoke-Configure {
    param(
        [Parameter(Mandatory)] [pscustomobject] $GeneratorSpec,
        [Parameter()] [pscustomobject] $VsInstance
    )

    Write-Host "[build] Configuring CMake project with $($GeneratorSpec.Description)..."

    $configureArgs = @(
        'cmake',
        '-S', $repoRoot,
        '-B', $buildDir,
        '-G', $GeneratorSpec.Name
    )

    if ($GeneratorSpec.Name -eq 'Visual Studio 17 2022') {
        $configureArgs += @('-A', 'x64')
    }

    if ($GeneratorSpec.Toolset) {
        $configureArgs += @('-T', $GeneratorSpec.Toolset)
    }

    if ($GeneratorSpec.RequiresInstance -and $VsInstance) {
        $vsInstallPath = $VsInstance.InstallationPath
        $configureArgs += "-DCMAKE_GENERATOR_INSTANCE=$vsInstallPath"

        if ($VsInstance.InstallationVersion) {
            $configureArgs += "-DCMAKE_GENERATOR_INSTANCE_VERSION=$($VsInstance.InstallationVersion)"
        }
    }

    if (-not $GeneratorSpec.MultiConfig) {
        $configureArgs += "-DCMAKE_BUILD_TYPE=$Configuration"
    }

    $configureCommand = Join-CommandLine -Args $configureArgs
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

function Prepare-BuildDirectory {
    param(
        [Parameter(Mandatory)] [pscustomobject] $GeneratorSpec,
        [Parameter()] [pscustomobject] $VsInstance
    )

    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
        return
    }

    $expectedGenerator = $GeneratorSpec.Name
    $expectedToolset = $GeneratorSpec.Toolset
    $expectedInstance = if ($GeneratorSpec.RequiresInstance -and $VsInstance) { $VsInstance.InstallationPath } else { $null }
    $expectedInstanceVersion = if ($GeneratorSpec.RequiresInstance -and $VsInstance) { $VsInstance.InstallationVersion } else { $null }

    if (-not (Test-BuildCacheMatch -ExpectedGenerator $expectedGenerator -ExpectedToolset $expectedToolset -ExpectedInstance $expectedInstance -ExpectedInstanceVersion $expectedInstanceVersion)) {
        Write-Host "[build] Detected generator mismatch for $($GeneratorSpec.Name). Regenerating project..."
        Remove-Item $buildDir -Recurse -Force
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
}

function Configure-Build {
    param(
        [Parameter(Mandatory)] [pscustomobject] $GeneratorSpec,
        [switch] $AllowFallback
    )

    $vsInstance = $null
    if ($GeneratorSpec.RequiresInstance) {
        $vsInstance = Ensure-VsInstance
    }

    Prepare-BuildDirectory -GeneratorSpec $GeneratorSpec -VsInstance $vsInstance

    try {
        Invoke-Configure -GeneratorSpec $GeneratorSpec -VsInstance $vsInstance
        $script:activeGenerator = $GeneratorSpec
    } catch {
        if ($AllowFallback) {
            Write-Warning "Primary generator failed: $($_.Exception.Message). Attempting Ninja fallback."
            Prepare-BuildDirectory -GeneratorSpec $fallbackGeneratorSpec -VsInstance $vsInstance
            Invoke-Configure -GeneratorSpec $fallbackGeneratorSpec -VsInstance $vsInstance
            $script:activeGenerator = $fallbackGeneratorSpec
        } else {
            throw
        }
    }
}

Configure-Build -GeneratorSpec $primaryGeneratorSpec -AllowFallback

if (-not $script:activeGenerator) {
    throw 'Unable to configure any generator. Check Visual Studio Build Tools installation.'
}

Write-Host "[build] Building configuration $Configuration"

if ($script:activeGenerator.MultiConfig) {
    $buildArgs = @('cmake', '--build', $buildDir, '--config', $Configuration)
} else {
    $buildArgs = @('cmake', '--build', $buildDir)
}

$buildCommand = Join-CommandLine -Args $buildArgs
$buildExitCode = Invoke-WithVsEnvironment -CommandLine $buildCommand
if ($buildExitCode -ne 0) {
    throw "CMake build failed with exit code $buildExitCode."
}

Write-Host "[build] Build completed successfully using $($script:activeGenerator.Name)."
