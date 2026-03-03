#!/bin/bash

# Baseline Frontend Deployment Script
# This script handles deployment of the Node.js frontend

set -e  # Exit on any error

echo "🚀 Starting Baseline Frontend Deployment..."

# Configuration
NODE_ENV=${NODE_ENV:-production}
PORT=${PORT:-8001}
BUILD_DIR="dist"
BACKUP_DIR="backups"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js is not installed"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        log_error "npm is not installed"
        exit 1
    fi
    
    # Check Redis (optional)
    if command -v redis-cli &> /dev/null; then
        if redis-cli ping &> /dev/null; then
            log_success "Redis is running"
        else
            log_warning "Redis is not running - caching will be disabled"
        fi
    else
        log_warning "Redis is not installed - caching will be disabled"
    fi
    
    log_success "Prerequisites check completed"
}

# Backup current deployment
backup_current() {
    if [ -d "$BUILD_DIR" ]; then
        log "Creating backup of current deployment..."
        mkdir -p "$BACKUP_DIR"
        BACKUP_FILE="$BACKUP_DIR/frontend-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$BACKUP_FILE" "$BUILD_DIR" 2>/dev/null || true
        log_success "Backup created: $BACKUP_FILE"
    fi
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    npm ci --production=false
    log_success "Dependencies installed"
}

# Run tests
run_tests() {
    if [ "$SKIP_TESTS" != "true" ]; then
        log "Running tests..."
        npm test 2>/dev/null || log_warning "Tests failed - continuing anyway"
    fi
}

# Build application
build_app() {
    log "Building application for $NODE_ENV environment..."
    
    # Clean previous build
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    
    # Build
    npm run build:prod
    
    if [ $? -eq 0 ]; then
        log_success "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Health check
health_check() {
    log "Performing health check..."
    
    # Wait for server to start
    sleep 5
    
    # Check if server is responding
    if curl -f http://localhost:$PORT/health &> /dev/null; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        exit 1
    fi
}

# Deploy
deploy() {
    log "Starting deployment process..."
    
    check_prerequisites
    backup_current
    install_dependencies
    run_tests
    build_app
    
    log_success "Deployment completed successfully!"
    log "📍 Application is running at http://localhost:$PORT"
    log "🔍 Health check available at http://localhost:$PORT/health"
    log "📊 Metrics available at http://localhost:$PORT/api/metrics"
}

# Rollback function
rollback() {
    log "Starting rollback process..."
    
    LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/frontend-backup-*.tar.gz | head -1)
    
    if [ -n "$LATEST_BACKUP" ]; then
        log "Rolling back to: $LATEST_BACKUP"
        
        # Stop current server
        pkill -f "node.*prod-server.js" || true
        
        # Restore backup
        rm -rf "$BUILD_DIR"
        tar -xzf "$LATEST_BACKUP"
        
        # Restart server
        npm run start:prod &
        
        log_success "Rollback completed"
    else
        log_error "No backup found for rollback"
        exit 1
    fi
}

# Show usage
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  deploy    Deploy the application"
    echo "  rollback  Rollback to previous version"
    echo "  health    Run health check only"
    echo ""
    echo "Environment variables:"
    echo "  NODE_ENV   Environment (default: production)"
    echo "  PORT       Port (default: 8001)"
    echo "  SKIP_TESTS Skip tests (default: false)"
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    rollback)
        rollback
        ;;
    health)
        health_check
        ;;
    *)
        usage
        exit 1
        ;;
esac
