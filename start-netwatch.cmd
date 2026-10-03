@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-netwatch.ps1" %*
exit /b %errorlevel%
