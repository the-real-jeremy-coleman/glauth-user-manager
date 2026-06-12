[CmdletBinding()]
param()

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'GLAuth User Manager requires PowerShell 7 or newer. Launch it with pwsh.'
}

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'src\GlauthUserManager.psm1'
Import-Module -Name $modulePath -Force

Show-GlauthUserManagerWindow
