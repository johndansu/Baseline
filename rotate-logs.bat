@echo off
REM Baseline Log Rotation Script

set LOG_DIR=C:\baseline-production\logs
set BACKUP_DIR=C:\baseline-production\logs\backup
set MAX_DAYS=7

echo Baseline Log Rotation
echo ===================

REM Create backup directory if not exists
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"

REM Rotate logs older than 7 days
forfiles /p "%LOG_DIR%" /s /m *.log /d -%MAX_DAYS% /c "cmd /c echo Moving @file... & move @path @file\..\backup\ 2>nul"

REM Compress old backup logs
cd "%BACKUP_DIR%"
forfiles /m *.log /c "cmd /c echo Compressing @file... & compact @file /C"

REM Clean up compressed files
forfiles /m *.log /c "cmd /c echo Deleting @file... & del @file"

echo Log rotation completed
echo Current logs in: %LOG_DIR%
echo Backed up logs in: %BACKUP_DIR%
echo.
