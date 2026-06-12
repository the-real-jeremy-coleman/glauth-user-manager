@echo off
setlocal

where pwsh >nul 2>nul
if errorlevel 1 (
    echo PowerShell 7+ ^(pwsh^) is required to run GLAuth User Manager.
    pause
    exit /b 1
)

pwsh -NoLogo -ExecutionPolicy Bypass -File "%~dp0Launch-GlauthUserManager.ps1"
