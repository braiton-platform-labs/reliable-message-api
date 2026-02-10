@echo off
setlocal enabledelayedexpansion

REM Opens a WSL shell in the repo root (or runs a command there).
REM Example:
REM   hack\\wsl-here.cmd
REM   hack\\wsl-here.cmd -Command "make first-run"

set "SCRIPT_DIR=%~dp0"
set "PS_EXE=powershell"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=pwsh"
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%wsl-here.ps1" %*

