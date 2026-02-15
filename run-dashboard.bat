@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\dashboard-start.ps1" -Port 8080 -SessionRole operator -DBPath :memory: -OpenBrowser
endlocal
