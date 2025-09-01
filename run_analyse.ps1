param(
    [string]$XexPath = "F:\XBox\ISO\CDMWEuropeGer - English ver\NfsMWEuropeGerMilestone.xex",
    [string]$OutToml = "F:\XBox\Recomp\MW05\mw05_switch_tables.toml",
    [string]$BuildDir = "D:\Repos\Games\XenonRecomp\build"
)
$ErrorActionPreference = "Stop"
Write-Host "Locating XenonAnalyse.exe under $BuildDir ..."
$exe = Get-ChildItem -Path $BuildDir -Recurse -Filter XenonAnalyse.exe | Select-Object -First 1
if (-not $exe) { throw "XenonAnalyse.exe not found under $BuildDir. Build the solution in Rider (Release|x64) first." }
Write-Host "Using:" $exe.FullName
# Ensure output dir exists
$null = New-Item -ItemType Directory -Force -Path (Split-Path -Path $OutToml)
# Run
& $exe.FullName -- "%XexPath%" "%OutToml%"
