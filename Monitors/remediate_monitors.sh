#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
#
# Description: Mark pending (monitor serial, laptop serial) pairs as handled locally.
#              MDM runs this script automatically when audit_monitors.sh exits 1.
#              This script stops repeated audit alerts and does not call external APIs.
# Location: Monitors/remediate_monitors.sh
# Dependencies: macOS built-ins (grep, stat, date)
# Required Permissions: root (MDM execution context)
# Inputs: monitor_pending.txt written by audit_monitors.sh
# Outputs: Appends handled pairs to monitor_notified.txt and clears monitor_pending.txt
# Logs: Stdout only, captured by MDM. Local state lives in HISTORY_DIR.
# Rollback: Delete a pair from monitor_notified.txt to trigger the alert again.
# Expected Result: Exit 0 after marking all pending pairs as handled.
#                  Exit 1 if monitor_pending.txt does not exist or a write fails.
# Safety Notes: Modifies only monitor_notified.txt and monitor_pending.txt in HISTORY_DIR.

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
umask 077

if [[ $EUID -eq 0 ]]; then
    HISTORY_DIR="/Library/Application Support/MDM_Monitor_Tracker"
else
    HISTORY_DIR="${HISTORY_DIR:-/Library/Application Support/MDM_Monitor_Tracker}"
fi

NOTIFIED_FILE="$HISTORY_DIR/monitor_notified.txt"
PENDING_FILE="$HISTORY_DIR/monitor_pending.txt"
LOCK_DIR="$HISTORY_DIR/.lock"

echo "[INFO] Starting external monitor remediation..."

if [[ -L "$HISTORY_DIR" || ! -d "$HISTORY_DIR" ]]; then
    echo "[ERROR] Invalid state directory: $HISTORY_DIR"
    exit 1
fi

DIR_UID=$(/usr/bin/stat -f%u "$HISTORY_DIR" 2>/dev/null)
if [[ "$DIR_UID" != "$EUID" ]]; then
    echo "[ERROR] Invalid state directory owner: $HISTORY_DIR"
    exit 1
fi
/bin/chmod 700 "$HISTORY_DIR" || exit 1

for f in "$NOTIFIED_FILE" "$PENDING_FILE" "$LOCK_DIR"; do
    if [[ -L "$f" ]]; then
        echo "[ERROR] Refusing to use symlink path: $f"
        exit 1
    fi
done

acquire_lock() {
    local attempts=0 lock_mtime now
    while ! /bin/mkdir "$LOCK_DIR" 2>/dev/null; do
        if [[ -d "$LOCK_DIR" && ! -L "$LOCK_DIR" ]]; then
            lock_mtime=$(/usr/bin/stat -f%m "$LOCK_DIR" 2>/dev/null || true)
            if [[ "$lock_mtime" =~ ^[0-9]+$ ]]; then
                now=$(/bin/date '+%s')
                if (( now - lock_mtime > 600 )) && /bin/rmdir "$LOCK_DIR" 2>/dev/null; then
                    continue
                fi
            fi
        fi
        attempts=$((attempts + 1))
        if (( attempts >= 30 )); then
            echo "[ERROR] Could not acquire lock: $LOCK_DIR"
            return 1
        fi
        /bin/sleep 1
    done
    return 0
}

acquire_lock || exit 1
trap '/bin/rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [[ ! -f "$PENDING_FILE" ]]; then
    echo "[ERROR] $PENDING_FILE not found - audit script may not have run yet."
    exit 1
fi

/usr/bin/touch "$NOTIFIED_FILE" || exit 1

MARKED=0
while IFS= read -r NOTIFY_KEY; do
    [[ -z "$NOTIFY_KEY" ]] && continue
    /usr/bin/grep -qxF -- "$NOTIFY_KEY" "$NOTIFIED_FILE"
    grep_rc=$?
    if (( grep_rc > 1 )); then
        echo "[ERROR] Failed to read $NOTIFIED_FILE"
        exit 1
    elif (( grep_rc == 1 )); then
        printf '%s\n' "$NOTIFY_KEY" >> "$NOTIFIED_FILE" || exit 1
        MARKED=$((MARKED + 1))
        echo "[INFO] Marked $NOTIFY_KEY as handled."
    fi
done < "$PENDING_FILE"

: > "$PENDING_FILE" || exit 1

echo "[SUCCESS] Remediation complete. $MARKED pair(s) marked as handled."
exit 0
