#!/bin/bash

# Baseline Backup Script
# This script creates backups of critical Baseline data

set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="baseline_backup_${TIMESTAMP}"

echo "Creating backup: ${BACKUP_NAME}"

# Create backup directory
mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"

# Backup source code
cp -r . "${BACKUP_DIR}/${BACKUP_NAME}/"

# Remove unnecessary files from backup
cd "${BACKUP_DIR}/${BACKUP_NAME}"
rm -rf .git/
rm -rf backups/
rm -f *.exe
rm -f baseline_*.exe

# Create backup archive
cd "${BACKUP_DIR}"
tar -czf "${BACKUP_NAME}.tar.gz" "${BACKUP_NAME}/"
rm -rf "${BACKUP_NAME}/"

echo "Backup created: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"

# Clean up old backups (keep last 7)
ls -t *.tar.gz | tail -n +8 | xargs -r rm

echo "Backup completed successfully"
