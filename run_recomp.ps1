param(
    [string]$MainToml = "F:\XBox\Recomp\MW05\mw05_recomp.toml",
    [string]$PpcContext = "D:\Repos\Games\XenonRecomp\XenonUtils\ppc_context.h",
    [string]$BuildDir = "D:\Repos\Games\XenonRecomp\build"
)
$ErrorActionPreference = "Stop"
Write-Host "Locating XenonRecomp.exe under $BuildDir ..."
$exe = Get-ChildItem -Path $BuildDir -Recurse -Filter XenonRecomp.exe | Select-Object -First 1
if (-not $exe) { throw "XenonRecomp.exe not found under $BuildDir. Build the solution in Rider (Release|x64) first." }
Write-Host "Using:" $exe.FullName
# Validate inputs
if (-not (Test-Path -LiteralPath $MainToml)) { throw "Main TOML not found: $MainToml" }
if (-not (Test-Path -LiteralPath $PpcContext)) { throw "ppc_context.h not found: $PpcContext" }
# Run
& $exe.FullName -- "%MainToml%" "%PpcContext%"
