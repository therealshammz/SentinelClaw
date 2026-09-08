@echo off
setlocal

cd /d "%~dp0"

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m sentinelclaw.main %*
) else (
    python -m sentinelclaw.main %*
)

endlocal
