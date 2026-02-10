@echo off
REM Quick Baseline Access

echo Baseline Quick Access
echo ====================

REM Add to PATH for this session
set PATH=%PATH%;C:\Users\John Dansu\OneDrive\Desktop\baseline-prod

echo Baseline is now available from any directory
echo.
echo Commands available:
echo   baseline check
echo   baseline scan  
echo   baseline enforce
echo   baseline version
echo.
echo Test with: baseline version

REM Test the installation
C:\Users\John Dansu\OneDrive\Desktop\baseline-prod\baseline.exe version

echo.
echo Baseline is ready for production use!
echo.
