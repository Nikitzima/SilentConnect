#!/bin/bash
set -euo pipefail

DATE=$(date +%Y-%m-%d_%H-%M-%S)
SERVER="aeza_pl"
LOG_PREFIX="[backup-$(date +%H:%M:%S)]"

echo "${LOG_PREFIX} Starting backup for ${SERVER} at ${DATE}..."

# --- 1. FULL OS IMAGE (~1.5 GB, 7-day retention) ---
FULL_NAME="full_os_${SERVER}_${DATE}.tar.gz"
FULL_PATH="/tmp/${FULL_NAME}"

echo "${LOG_PREFIX} Creating Full OS image..."
tar -czf ${FULL_PATH} \
  --exclude=/proc \
  --exclude=/sys \
  --exclude=/dev \
  --exclude=/run \
  --exclude=/tmp \
  --exclude=/lost+found \
  --exclude=/var/cache \
  --exclude=/var/log/journal \
  / 2>/dev/null || true

echo "${LOG_PREFIX} Uploading Full OS image to Google Drive..."
rclone copy ${FULL_PATH} gdrive:SilentConnect_Backups/${SERVER}/full_os/
rclone delete gdrive:SilentConnect_Backups/${SERVER}/full_os/ --min-age 7d --include "full_os_${SERVER}_*.tar.gz" 2>/dev/null || true
rm -f ${FULL_PATH}

# --- 2. LIGHTWEIGHT STACK ARCHIVE (~1.5 MB, 30-day retention) ---
STACK_NAME="${SERVER}_stack_${DATE}.tar.gz"
STACK_PATH="/tmp/${STACK_NAME}"

echo "${LOG_PREFIX} Creating lightweight Stack archive..."
# Create consistent sqlite backup of x-ui.db first
sqlite3 /etc/x-ui/x-ui.db ".backup '/etc/x-ui/x-ui.db.backup'" 2>/dev/null || true

tar -czf ${STACK_PATH} \
  /root/subjson* \
  /root/vpn-shop \
  /root/*.py \
  /root/*.json \
  /etc/x-ui \
  /etc/caddy \
  /etc/systemd/system/x-ui* \
  /etc/systemd/system/subjson* \
  /etc/systemd/system/caddy* \
  /root/backup_to_gdrive.sh 2>/dev/null || true

echo "${LOG_PREFIX} Uploading Stack archive to Google Drive..."
rclone copy ${STACK_PATH} gdrive:SilentConnect_Backups/${SERVER}/stack/
rclone delete gdrive:SilentConnect_Backups/${SERVER}/stack/ --min-age 30d --include "${SERVER}_stack_*.tar.gz" 2>/dev/null || true
rm -f ${STACK_PATH}

echo "${LOG_PREFIX} Backup for ${SERVER} finished successfully!"
