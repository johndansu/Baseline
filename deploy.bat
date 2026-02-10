@echo off
REM Baseline Production Deployment Script

echo Baseline Production Deployment
echo ============================

REM Create directories
if not exist "C:\baseline-production\logs" mkdir "C:\baseline-production\logs"
if not exist "C:\baseline-production\backups" mkdir "C:\baseline-production\backups"

REM Set environment variables
set BASELINE_CONFIG_PATH=C:\baseline-production\config.yaml
set BASELINE_LOG_LEVEL=info
set BASELINE_MODE=production

REM Add to system PATH (temporary for this session)
set PATH=%PATH%;C:\baseline-production

REM Verify deployment
echo Verifying Baseline deployment...
C:\baseline-production\baseline.exe --version
if %errorlevel% == 0 (
    echo [OK] Baseline binary is functional
) else (
    echo [ERROR] Baseline binary is not functional
    exit /b 1
)

REM Test configuration
echo Testing configuration...
C:\baseline-production\baseline.exe check --dry-run
if %errorlevel% == 0 (
    echo [OK] Configuration is valid
) else (
    echo [WARNING] Configuration may have issues
)

REM Create Windows Service (optional)
echo Creating Windows Service...
sc create Baseline binPath= "C:\baseline-production\baseline.exe" start= auto
sc description Baseline "Production Policy Enforcement Service"

REM Set up scheduled task for health checks
schtasks /create /tn "Baseline Health Check" /tr "C:\baseline-production\health-check.bat" /sc daily /st 00:00

echo.
echo DEPLOYMENT COMPLETED
echo ==================
echo Baseline is now deployed to production
echo.
echo Next steps:
echo 1. Run: C:\baseline-production\start-baseline.bat
echo 2. Monitor: C:\baseline-production\health-check.bat
echo 3. Configure: C:\baseline-production\config.yaml
echo.
pause
