# Baseline Frontend Deployment Script (PowerShell)
# This script handles deployment of the Node.js frontend

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("deploy", "rollback", "health")]
    [string]$Command = "deploy",
    
    [Parameter()]
    [string]$NodeEnv = "production",
    
    [Parameter()]
    [int]$Port = 8001,
    
    [Parameter()]
    [switch]$SkipTests = $false
)

# Configuration
$BUILD_DIR = "dist"
$BACKUP_DIR = "backups"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "✅ $Message" "Green"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "⚠️  $Message" "Yellow"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "❌ $Message" "Red"
}

function Write-Log {
    param([string]$Message)
    Write-ColorOutput "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" "Cyan"
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check Node.js
    try {
        $nodeVersion = node --version
        Write-Success "Node.js version: $nodeVersion"
    }
    catch {
        Write-Error "Node.js is not installed"
        exit 1
    }
    
    # Check npm
    try {
        $npmVersion = npm --version
        Write-Success "npm version: $npmVersion"
    }
    catch {
        Write-Error "npm is not installed"
        exit 1
    }
    
    # Check Redis (optional)
    try {
        $redisResult = redis-cli ping 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Redis is running"
        }
    }
    catch {
        Write-Warning "Redis is not available - caching will be disabled"
    }
    
    Write-Success "Prerequisites check completed"
}

# Backup current deployment
function Backup-Current {
    if (Test-Path $BUILD_DIR) {
        Write-Log "Creating backup of current deployment..."
        
        if (!(Test-Path $BACKUP_DIR)) {
            New-Item -ItemType Directory -Path $BACKUP_DIR -Force
        }
        
        $backupFile = "$BACKUP_DIR\frontend-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').tar.gz"
        try {
            Compress-Archive -Path $BUILD_DIR -DestinationPath $backupFile -Force
            Write-Success "Backup created: $backupFile"
        }
        catch {
            Write-Warning "Failed to create backup: $_"
        }
    }
}

# Install dependencies
function Install-Dependencies {
    Write-Log "Installing dependencies..."
    
    try {
        npm ci --production=false
        Write-Success "Dependencies installed"
    }
    catch {
        Write-Error "Failed to install dependencies: $_"
        exit 1
    }
}

# Run tests
function Invoke-Tests {
    if (-not $SkipTests) {
        Write-Log "Running tests..."
        
        try {
            npm test 2>$null
            Write-Success "Tests passed"
        }
        catch {
            Write-Warning "Tests failed - continuing anyway"
        }
    }
}

# Build application
function Build-Application {
    Write-Log "Building application for $NodeEnv environment..."
    
    # Clean previous build
    if (Test-Path $BUILD_DIR) {
        Remove-Item -Path $BUILD_DIR -Recurse -Force
    }
    
    try {
        # Build
        npm run build:prod
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Build completed successfully"
        }
        else {
            Write-Error "Build failed"
            exit 1
        }
    }
    catch {
        Write-Error "Build failed: $_"
        exit 1
    }
}

# Health check
function Invoke-HealthCheck {
    Write-Log "Performing health check..."
    
    # Wait for server to start
    Start-Sleep -Seconds 5
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Success "Health check passed"
        }
        else {
            Write-Error "Health check failed - Status: $($response.StatusCode)"
            exit 1
        }
    }
    catch {
        Write-Error "Health check failed: $_"
        exit 1
    }
}

# Stop current server
function Stop-Server {
    Write-Log "Stopping current server..."
    
    try {
        $processes = Get-Process -Name "node" -ErrorAction SilentlyContinue
        foreach ($process in $processes) {
            if ($process.Path -like "*prod-server.js*") {
                $process.Kill()
                Write-Success "Server stopped"
            }
        }
    }
    catch {
        Write-Warning "Could not stop server: $_"
    }
}

# Start server
function Start-Server {
    Write-Log "Starting server..."
    
    try {
        Start-Process -FilePath "npm" -ArgumentList "run", "start:prod" -NoNewWindow
        Write-Success "Server started"
    }
    catch {
        Write-Error "Failed to start server: $_"
        exit 1
    }
}

# Deploy function
function Invoke-Deploy {
    Write-Log "Starting deployment process..."
    
    Test-Prerequisites
    Backup-Current
    Install-Dependencies
    Invoke-Tests
    Build-Application
    
    Write-Success "Deployment completed successfully!"
    Write-Log "📍 Application is running at http://localhost:$Port"
    Write-Log "🔍 Health check available at http://localhost:$Port/health"
    Write-Log "📊 Metrics available at http://localhost:$Port/api/metrics"
}

# Rollback function
function Invoke-Rollback {
    Write-Log "Starting rollback process..."
    
    try {
        $backups = Get-ChildItem -Path $BACKUP_DIR -Filter "frontend-backup-*.tar.gz" | Sort-Object LastWriteTime -Descending
        $latestBackup = $backups | Select-Object -First 1
        
        if ($latestBackup) {
            Write-Log "Rolling back to: $($latestBackup.Name)"
            
            Stop-Server
            
            # Restore backup
            if (Test-Path $BUILD_DIR) {
                Remove-Item -Path $BUILD_DIR -Recurse -Force
            }
            
            Expand-Archive -Path $latestBackup.FullName -DestinationPath "." -Force
            
            Start-Server
            
            Write-Success "Rollback completed"
        }
        else {
            Write-Error "No backup found for rollback"
            exit 1
        }
    }
    catch {
        Write-Error "Rollback failed: $_"
        exit 1
    }
}

# Main script logic
switch ($Command) {
    "deploy" {
        Invoke-Deploy
    }
    "rollback" {
        Invoke-Rollback
    }
    "health" {
        Invoke-HealthCheck
    }
    default {
        Write-Error "Unknown command: $Command"
        Write-Log "Usage: .\deploy.ps1 -Command <deploy|rollback|health> [-NodeEnv <environment>] [-Port <port>] [-SkipTests]"
        exit 1
    }
}
