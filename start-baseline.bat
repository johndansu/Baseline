@echo off
REM Baseline Production Service
REM Start Baseline in production mode

set BASELINE_CONFIG_PATH=C:\baseline-production\config.yaml
set BASELINE_LOG_LEVEL=info
set BASELINE_MODE=production

echo Starting Baseline Production Service...
echo Configuration: %BASELINE_CONFIG_PATH%
echo Mode: %BASELINE_MODE%

REM Start Baseline monitoring
C:\baseline-production\baseline.exe scan

pause
