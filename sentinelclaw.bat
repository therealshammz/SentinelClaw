@echo off
setlocal

cd /d "%~dp0"

rem Prefer the documented `venv` directory; fall back to `.venv` for
rem setups created before the convention was fixed (P6-29).
set "SC_PYTHON="

if exist "%~dp0venv\Scripts\python.exe" (
    set "SC_PYTHON=%~dp0venv\Scripts\python.exe"
) else if exist "%~dp0.venv\Scripts\python.exe" (
    set "SC_PYTHON=%~dp0.venv\Scripts\python.exe"
)

if not defined SC_PYTHON (
    echo [SentinelClaw] No virtual environment found.
    echo Create one and install SentinelClaw first, for example:
    echo.
    echo   python -m venv venv
    echo   venv\Scripts\python -m pip install -e .
    echo.
    exit /b 1
)

"%SC_PYTHON%" -m sentinelclaw.main %*

endlocal
