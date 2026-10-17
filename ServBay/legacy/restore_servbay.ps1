<#
  restore_servbay.ps1
  Rolls ServBay.dll back from the .bak created by patch_servbay.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Path
)
$ErrorActionPreference = 'Stop'
$full = (Resolve-Path $Path).Path
if (-not (Test-Path "$full.bak")){ throw "No backup at $full.bak" }
Copy-Item -LiteralPath "$full.bak" -Destination $full -Force
Write-Host "Restored $full from $full.bak"
