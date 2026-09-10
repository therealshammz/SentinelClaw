# Build a standalone SentinelClaw Windows binary with PyInstaller (P6-29).
#
# Usage (from PowerShell, repo root):
#   .\scripts\build_binary.ps1
#
# Produces:
#   dist\sentinelclaw.exe
#
# Optional runtime extras (pcap, evtx, yara) are only bundled when they
# are importable in this environment; install them first to include
# them, e.g.: python -m pip install -e ".[build,pcap,evtx,yara]"
#
# Note: unsigned by default; see packaging/README.md for the
# release-time codesigning process.
param()

$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

python -m pip install -e ".[build]"
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed"
}

python -m PyInstaller --noconfirm --clean packaging\sentinelclaw.spec
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed"
}

Write-Host ""
Write-Host "Built: dist\sentinelclaw.exe"
Write-Host "Smoke test: .\dist\sentinelclaw.exe --help"
