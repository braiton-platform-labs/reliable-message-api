@echo off
setlocal enabledelayedexpansion

REM One-command uninstall for the dev environment on Windows.
REM Usage:
REM   .\hack\uninstall-all.cmd
REM   .\hack\uninstall-all.cmd -NoPurge
REM   .\hack\uninstall-all.cmd -NoAutoReboot   (deprecated; kept for compatibility)

set "SCRIPT_DIR=%~dp0"
set "PS_EXE=powershell"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=pwsh"
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%uninstall-all.ps1" %*
