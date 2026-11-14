# Universal Clipboard installer for Windows (PowerShell).
# Downloads the small `uclip` command-line app from {{ORIGIN}} into %LOCALAPPDATA%\uclip.
# Read it first if you like: irm {{ORIGIN}}/install.ps1
$ErrorActionPreference = 'Stop'
$Origin = '{{ORIGIN}}'
$Dest = Join-Path $env:LOCALAPPDATA 'uclip'

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw 'Node.js 20 or newer is required: https://nodejs.org' }
if ([int]((node -p 'process.versions.node.split(".")[0]')) -lt 20) { throw "Node.js 20 or newer is required (found $(node -v))" }

foreach ($d in 'cli', 'shared', 'bin') { New-Item -ItemType Directory -Force -Path (Join-Path $Dest $d) | Out-Null }
foreach ($f in 'cli/uclip.js', 'cli/clipboard.js', 'shared/client.js', 'shared/crypto.js', 'shared/auth.js') {
  $target = Join-Path $Dest ($f -replace '/', '\')
  Invoke-WebRequest -UseBasicParsing -Uri "$Origin/dl/$f" -OutFile "$target.tmp"
  Move-Item -Force "$target.tmp" $target
}
[IO.File]::WriteAllText((Join-Path $Dest 'package.json'), '{"type":"module"}')

$launcher = "@echo off`r`nif ""%UCLIP_SERVER%""=="""" set ""UCLIP_SERVER=$Origin""`r`nnode ""$Dest\cli\uclip.js"" %*`r`n"
[IO.File]::WriteAllText((Join-Path $Dest 'bin\uclip.cmd'), $launcher)

$bin = Join-Path $Dest 'bin'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $bin) {
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $bin), 'User')
  Write-Host "Added $bin to your PATH. Open a new terminal to use it."
}
Write-Host "Installed uclip to $bin"
Write-Host ''
Write-Host 'Next:  uclip login     (approve the code in your browser)'
Write-Host '       uclip daemon    (keeps your clipboard in sync)'
