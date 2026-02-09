@echo off
setlocal enabledelayedexpansion

REM Launcher for hack\bootstrap.ps1 that works even when PowerShell script execution is disabled
REM (it does not change ExecutionPolicy on the machine; it only bypasses for this process).

set "SCRIPT_DIR=%~dp0"
set "PS_EXE=powershell"

REM Sensible Windows defaults: keep installs local to the repo (no admin needed).
if "%BOOTSTRAP_INSTALL_MODE%"=="" set "BOOTSTRAP_INSTALL_MODE=local"
if "%BOOTSTRAP_ENFORCE_GLOBAL_BIN%"=="" set "BOOTSTRAP_ENFORCE_GLOBAL_BIN=0"

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PS_EXE=pwsh"
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%bootstrap.ps1" %*
