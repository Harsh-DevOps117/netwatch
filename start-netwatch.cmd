@echo off
setlocal
rem UTF-8 console so the launcher's emoji status lines render.
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-netwatch.ps1" %*
exit /b %errorlevel%
