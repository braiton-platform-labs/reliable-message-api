@echo off
setlocal enabledelayedexpansion

REM Launcher for hack\install-python.ps1 that works even when PowerShell script execution is disabled
REM (it does not change ExecutionPolicy on the machine; it only bypasses for this process).

set "SCRIPT_DIR=%~dp0"
set "PS_EXE=powershell"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=pwsh"
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install-python.ps1" %*

