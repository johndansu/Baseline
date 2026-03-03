@echo off
echo Starting Baseline Development Server...
echo.
echo Navigate to: http://localhost:3000
echo.
echo Press Ctrl+C to stop the server
echo.

REM Change to frontend directory
cd /d "c:\Users\John Dansu\OneDrive\Desktop\Baseline\frontend"

REM Start Python HTTP server
python -m http.server 3000

pause
