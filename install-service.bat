@echo off
REM Create Baseline Windows Service

echo Creating Baseline Windows Service...
echo =====================================

REM Install service using sc (Service Controller)
sc create "Baseline Service" binPath= "C:\baseline-production\baseline.exe" start= auto DisplayName= "Baseline Policy Enforcement" type= own

REM Set service description
sc description "Baseline Service" "Production Policy Enforcement Engine that scans repositories for security and compliance violations"

REM Set service to restart on failure
sc failure "Baseline Service" reset= 86400 actions= restart/30000/restart/30000

REM Configure service dependencies
sc config "Baseline Service" depend= Tcpip/Dnscache

echo Windows Service created successfully
echo.
echo To start the service: net start "Baseline Service"
echo To stop the service: net stop "Baseline Service"
echo To check status: sc query "Baseline Service"
echo.
pause
