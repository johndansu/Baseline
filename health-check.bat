@echo off
REM Baseline Production Monitoring Script

set BASELINE_CONFIG_PATH=C:\baseline-production\config.yaml

echo Baseline Production Health Check
echo =============================

REM Check if Baseline is running
tasklist | find "baseline.exe" >nul
if %errorlevel% == 0 (
    echo [OK] Baseline process is running
) else (
    echo [WARNING] Baseline process is not running
    echo Starting Baseline...
    start /B C:\baseline-production\baseline.exe scan
)

REM Check configuration file
if exist "C:\baseline-production\config.yaml" (
    echo [OK] Configuration file exists
) else (
    echo [ERROR] Configuration file missing
)

REM Check log directory
if not exist "C:\baseline-production\logs" (
    mkdir C:\baseline-production\logs
    echo [INFO] Created logs directory
)

REM Test Baseline functionality
C:\baseline-production\baseline.exe --version >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] Baseline is functional
) else (
    echo [ERROR] Baseline is not functional
)

echo Health check completed at %date% %time%
echo =============================
