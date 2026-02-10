@echo off
setlocal enabledelayedexpansion

REM One-command install for the full dev environment on Windows:
REM   WSL2 (Ubuntu 22.04) -> Docker Desktop -> Python -> hosts -> bootstrap (WSL) -> make dev
REM
REM Usage:
REM   .\hack\install-all.cmd
REM   .\hack\install-all.cmd -NoAutoReboot
REM   .\hack\install-all.cmd -SkipPython

set "SCRIPT_DIR=%~dp0"
set "PS_EXE=powershell"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=pwsh"
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install-all.ps1" %*
