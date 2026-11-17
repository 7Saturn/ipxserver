<#
.SYNOPSIS
    Builds the release binaries of ipxserver for all supported platforms.

.DESCRIPTION
    The Windows counterpart of build.sh, for Windows PowerShell 5 and
    PowerShell 7. Result: dist\<RID>\ipxserver[.exe], one self-contained
    executable per platform. .NET can build for all platforms from any
    platform, so the Linux binaries can be built under Windows, too.

    Note for Linux binaries built under Windows: Windows file systems do not
    know the "executable" flag. After copying such a binary to a Linux machine,
    run "chmod +x ipxserver" there once. (The archives of the official releases
    are built under Linux by the GitHub workflow and do not have this problem.)

.PARAMETER Version
    Version number to compile into the binaries (default: the one from
    Directory.Build.props).

.PARAMETER Rids
    The platforms (.NET runtime identifiers) to build for.

.PARAMETER SkipTests
    Do not run the tests first.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Version 2.1.0 -Rids win-x64,linux-x64

    If PowerShell refuses to run the script ("running scripts is disabled"):
    powershell -ExecutionPolicy Bypass -File .\build.ps1
#>
param(
    [string]   $Version = "",
    [string[]] $Rids = @("win-x64", "linux-x64", "linux-arm64", "linux-arm"),
    [switch]   $SkipTests
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Ends the script if the last external program reported an error.
function Assert-Success([string] $what) {
    if ($LASTEXITCODE -ne 0) {
        Write-Error "$what failed (exit code $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

# Only pass a version on to dotnet if one was given.
$versionArgs = @()
if ($Version -ne "") {
    $versionArgs = @("-p:Version=$Version")
}

if (-not $SkipTests) {
    Write-Host "### Running tests"
    dotnet run --project tests/ipxserver.Tests -c Release
    Assert-Success "Tests"
}

if (Test-Path dist) {
    Remove-Item -Recurse -Force dist
}
foreach ($rid in $Rids) {
    Write-Host "### Publishing for $rid"
    dotnet publish src/ipxserver -c Release -r $rid -o "dist/$rid" @versionArgs
    Assert-Success "Publishing for $rid"
}

Write-Host "### Done. Results are in $(Join-Path $PSScriptRoot 'dist')"
