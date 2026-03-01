Write-Host "Starting Baseline Development Server..." -ForegroundColor Green
Write-Host ""
Write-Host "Navigate to: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Change to frontend directory
Set-Location "c:\Users\John Dansu\OneDrive\Desktop\Baseline\frontend"

# Start Python HTTP server
try {
    python -m http.server 3000
} catch {
    Write-Host "Error starting server: $_" -ForegroundColor Red
    Write-Host "Make sure Python is installed and in PATH" -ForegroundColor Red
    Read-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoExit,KeyDown")
}
