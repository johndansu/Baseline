@echo off
REM Baseline Desktop Production Launcher

echo Baseline Desktop Production
echo ========================

set BASELINE_CONFIG_PATH=C:\Users\John Dansu\OneDrive\Desktop\baseline-prod\config.yaml
set BASELINE_LOG_LEVEL=info
set BASELINE_MODE=production

echo Configuration: %BASELINE_CONFIG_PATH%
echo Mode: %BASELINE_MODE%

REM Add to PATH for this session
set PATH=%PATH%;C:\Users\John Dansu\OneDrive\Desktop\baseline-prod

echo Starting Baseline Desktop Production...
echo.
echo Available commands:
echo   baseline check    - Run policy checks
echo   baseline scan     - Deep repository scan
echo   baseline enforce   - Enforce policies
echo   baseline version   - Show version
echo.
echo Current directory: %CD%
echo.

REM Start interactive mode
C:\Users\John Dansu\OneDrive\Desktop\baseline-prod\baseline.exe %*
