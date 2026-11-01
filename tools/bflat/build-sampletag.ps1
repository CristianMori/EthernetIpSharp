# Build samples/SampleTag as a single native .exe with bflat.
#
# Usage:
#   # On PATH:
#   .\tools\bflat\build-sampletag.ps1
#
#   # Explicit bflat path:
#   .\tools\bflat\build-sampletag.ps1 -BflatPath C:\tools\bflat\bflat.exe
#
#   # Pick output location:
#   .\tools\bflat\build-sampletag.ps1 -OutPath C:\temp\sample-tag.exe
#
# bflat releases: https://github.com/bflattened/bflat/releases
# The 2.2 MB native binary this script produces has no .NET runtime dependency.

[CmdletBinding()]
param(
    [string]$BflatPath = "bflat",
    [string]$OutPath   = "sample-tag.exe",
    [ValidateSet('x64','arm64','x86')] [string]$Arch = 'x64',
    [switch]$OptSize
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$toolsDir = $PSScriptRoot

$projects = @(
    'samples\SampleTag',
    'src\EthernetIPSharp.Logix',
    'src\EthernetIPSharp.Cip',
    'src\EthernetIPSharp.Connections',
    'src\EthernetIPSharp.Protocol'
) | ForEach-Object { Join-Path $repoRoot $_ }

$sources = @(Join-Path $toolsDir '_implicit_usings.cs')
foreach ($p in $projects) {
    $sources += Get-ChildItem -Path $p -Recurse -Filter '*.cs' |
                Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' } |
                Select-Object -ExpandProperty FullName
}

Write-Host "Compiling $($sources.Count) files -> $OutPath"

$optFlag = if ($OptSize) { '-Os' } else { '-Ot' }

& $BflatPath build `
    -o $OutPath `
    --target Exe `
    --arch $Arch `
    $optFlag `
    @sources

if ($LASTEXITCODE -ne 0) { throw "bflat failed with exit $LASTEXITCODE" }

$fi = Get-Item $OutPath
Write-Host ("Done. {0}  ({1:N0} bytes)" -f $fi.FullName, $fi.Length)
