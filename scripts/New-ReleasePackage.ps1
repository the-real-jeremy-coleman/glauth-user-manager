[CmdletBinding()]
param(
    [Parameter()]
    [string]$Version = '',

    [Parameter()]
    [string]$OutputRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Path $PSScriptRoot -Parent
$versionFile = Join-Path -Path $projectRoot -ChildPath 'VERSION'

if (-not $Version) {
    $Version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
}

if (-not $Version) {
    throw 'Version is required.'
}

if (-not $OutputRoot) {
    $OutputRoot = Join-Path -Path $projectRoot -ChildPath 'dist'
}

$packageName = 'glauth-user-manager-v{0}' -f $Version
$packageRoot = Join-Path -Path $OutputRoot -ChildPath $packageName
$zipPath = Join-Path -Path $OutputRoot -ChildPath ('{0}.zip' -f $packageName)

if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}

if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null

foreach ($path in @('Launch-GlauthUserManager.ps1', 'Run-GlauthUserManager.cmd', 'README.md', 'VERSION')) {
    Copy-Item -LiteralPath (Join-Path -Path $projectRoot -ChildPath $path) -Destination $packageRoot -Force
}

foreach ($path in @('src', 'lib', 'docs')) {
    Copy-Item -LiteralPath (Join-Path -Path $projectRoot -ChildPath $path) -Destination $packageRoot -Recurse -Force
}

Compress-Archive -Path $packageRoot -DestinationPath $zipPath -Force

[pscustomobject]@{
    Version     = $Version
    PackageRoot = $packageRoot
    ZipPath     = $zipPath
}
