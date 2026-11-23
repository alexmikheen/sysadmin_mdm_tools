#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
#
# Description: Audit external monitor connections on macOS over a 21-day rolling window.
#              Output MONITOR_INVENTORY lines for external asset reconciliation pipelines.
#              Exit 1 when a monitor reaches DAYS_THRESHOLD unique days on this laptop.
# Location: Monitors/audit_monitors.sh
# Dependencies: macOS built-ins (ioreg, awk, grep, date, stat, mktemp, tr)
# Required Permissions: root (MDM execution context)
# Inputs: none (optional HISTORY_DIR environment variable for non-root runs)
# Outputs: MONITOR_INVENTORY and MONITOR_EVENT single-line JSON records on stdout
# Logs: Stdout only, captured by MDM. Local state lives in HISTORY_DIR.
# Rollback: Unassign the MDM script item. Local state files stay inactive without it.
# Expected Result: Exit 0 when no monitor needs remediation.
#                  Exit 1 when a monitor crosses DAYS_THRESHOLD and triggers remediation.
# Safety Notes: Read-only against ioreg. Writes only to tracking files inside HISTORY_DIR.

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
umask 077

if [[ $EUID -eq 0 ]]; then
    HISTORY_DIR="/Library/Application Support/MDM_Monitor_Tracker"
else
    HISTORY_DIR="${HISTORY_DIR:-/Library/Application Support/MDM_Monitor_Tracker}"
fi

HISTORY_FILE="$HISTORY_DIR/monitor_history.txt"
NOTIFIED_FILE="$HISTORY_DIR/monitor_notified.txt"
PENDING_FILE="$HISTORY_DIR/monitor_pending.txt"
LOCK_DIR="$HISTORY_DIR/.lock"
DAYS_THRESHOLD=7
ROLLING_WINDOW_DAYS=21

echo "[INFO] Starting external monitor audit..."

if [[ -L "$HISTORY_DIR" ]]; then
    echo "[ERROR] Refusing to use symlink directory: $HISTORY_DIR"
    exit 1
fi

if [[ ! -d "$HISTORY_DIR" ]]; then
    /bin/mkdir -p "$HISTORY_DIR" || exit 1
fi
/bin/chmod 700 "$HISTORY_DIR" || exit 1

DIR_UID=$(/usr/bin/stat -f%u "$HISTORY_DIR" 2>/dev/null)
if [[ -L "$HISTORY_DIR" || ! -d "$HISTORY_DIR" || "$DIR_UID" != "$EUID" ]]; then
    echo "[ERROR] Invalid state directory ownership or type: $HISTORY_DIR"
    exit 1
fi

for f in "$HISTORY_FILE" "$NOTIFIED_FILE" "$PENDING_FILE" "$LOCK_DIR"; do
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

/usr/bin/touch "$HISTORY_FILE" "$NOTIFIED_FILE" || exit 1
: > "$PENDING_FILE" || exit 1

TODAY=$(/bin/date '+%Y-%m-%d')
CUTOFF_DATE=$(/bin/date -v-${ROLLING_WINDOW_DAYS}d '+%Y-%m-%d')

echo "[INFO] Rolling window cutoff date: $CUTOFF_DATE"

# Pad legacy 3-field lines to 5 fields so same-day deduplication works.
if [[ -s "$HISTORY_FILE" ]]; then
    tmp_hist=$(/usr/bin/mktemp "$HISTORY_DIR/.hist.XXXXXX") || exit 1
    if /usr/bin/awk -F'|' -v cutoff="$CUTOFF_DATE" '$3 >= cutoff { if (NF == 3) print $0 "||"; else print $0 }' "$HISTORY_FILE" > "$tmp_hist"; then
        /bin/mv -f "$tmp_hist" "$HISTORY_FILE" || { /bin/rm -f "$tmp_hist"; exit 1; }
    else
        /bin/rm -f "$tmp_hist"
        exit 1
    fi
fi

if [[ -s "$NOTIFIED_FILE" ]]; then
    tmp_notified=$(/usr/bin/mktemp "$HISTORY_DIR/.notified.XXXXXX") || exit 1
    if /usr/bin/tail -n 500 "$NOTIFIED_FILE" > "$tmp_notified"; then
        /bin/mv -f "$tmp_notified" "$NOTIFIED_FILE" || { /bin/rm -f "$tmp_notified"; exit 1; }
    else
        /bin/rm -f "$tmp_notified"
        exit 1
    fi
fi

sanitize_field() {
    printf '%s' "$1" | LC_ALL=C /usr/bin/tr -d '\000-\037\177|\\"'
}

emit_monitor_event() {
    J_SERIAL="$1" J_MODEL="$2" J_LAPTOP="$3" J_DAYS="$4" J_ACTION="$5" J_HANDLED="$6" J_DATE="$7" /usr/bin/awk '
    function jesc(s) {
        gsub(/\\/, "\\\\", s)
        gsub(/"/, "\\\"", s)
        gsub(/\r/, "", s)
        gsub(/\n/, " ", s)
        gsub(/\t/, " ", s)
        return s
    }
    function jint(v, def) {
        return (v ~ /^[0-9]+$/) ? v : def
    }
    function jbool(v) {
        return (v == "true") ? "true" : "false"
    }
    BEGIN {
        printf "MONITOR_EVENT: {\"monitor_serial\":\"%s\",\"monitor_model\":\"%s\",\"laptop_serial\":\"%s\",\"days_connected\":%s,\"action_needed\":%s,\"already_handled\":%s,\"date\":\"%s\"}\n", \
            jesc(ENVIRON["J_SERIAL"]), jesc(ENVIRON["J_MODEL"]), jesc(ENVIRON["J_LAPTOP"]), \
            jint(ENVIRON["J_DAYS"], "0"), jbool(ENVIRON["J_ACTION"]), jbool(ENVIRON["J_HANDLED"]), \
            jesc(ENVIRON["J_DATE"])
    }'
}

emit_monitor_inventory() {
    J_SERIAL="$1" J_MODEL="$2" J_LAPTOP="$3" J_YEAR="$4" J_WEEK="$5" J_DAYS="$6" J_DATE="$7" /usr/bin/awk '
    function jesc(s) {
        gsub(/\\/, "\\\\", s)
        gsub(/"/, "\\\"", s)
        gsub(/\r/, "", s)
        gsub(/\n/, " ", s)
        gsub(/\t/, " ", s)
        return s
    }
    function jint(v, def) {
        return (v ~ /^[0-9]+$/) ? v : def
    }
    BEGIN {
        printf "MONITOR_INVENTORY: {\"monitor_serial\":\"%s\",\"monitor_model\":\"%s\",\"laptop_serial\":\"%s\",\"mfg_year\":%s,\"mfg_week\":%s,\"days_connected\":%s,\"date\":\"%s\"}\n", \
            jesc(ENVIRON["J_SERIAL"]), jesc(ENVIRON["J_MODEL"]), jesc(ENVIRON["J_LAPTOP"]), \
            jint(ENVIRON["J_YEAR"], "null"), jint(ENVIRON["J_WEEK"], "null"), \
            jint(ENVIRON["J_DAYS"], "0"), jesc(ENVIRON["J_DATE"])
    }'
}

LAPTOP_SERIAL=$(/usr/sbin/ioreg -c IOPlatformExpertDevice -d 2 | /usr/bin/awk -F'"' '/IOPlatformSerialNumber/{print $4; exit}')
LAPTOP_SERIAL=$(sanitize_field "$LAPTOP_SERIAL")
if [[ -z "$LAPTOP_SERIAL" ]]; then
    # Use a sentinel value so NOTIFY_KEY never collapses to "SERIAL|".
    LAPTOP_SERIAL="UNKNOWN_LAPTOP"
    echo "[WARN] Could not read IOPlatformSerialNumber - reporting laptop_serial=UNKNOWN_LAPTOP."
fi

MONITORS_FOUND=false
ACTION_NEEDED=false

while IFS= read -r line; do
    if [[ "$line" == *"Built-in"* ]] || [[ "$line" == *"Color LCD"* ]]; then
        continue
    fi

    MODEL=$(printf '%s\n' "$line" | /usr/bin/grep -o '"ProductName"="[^"]*"' | /usr/bin/cut -d'"' -f4 | /usr/bin/head -n1)
    SERIAL=$(printf '%s\n' "$line" | /usr/bin/grep -o '"AlphanumericSerialNumber"="[^"]*"' | /usr/bin/cut -d'"' -f4 | /usr/bin/head -n1)
    MFG_YEAR=$(printf '%s\n' "$line" | /usr/bin/grep -o '"YearOfManufacture"=[0-9]*' | /usr/bin/cut -d'=' -f2 | /usr/bin/head -n1)
    MFG_WEEK=$(printf '%s\n' "$line" | /usr/bin/grep -o '"WeekOfManufacture"=[0-9]*' | /usr/bin/cut -d'=' -f2 | /usr/bin/head -n1)

    MODEL=$(sanitize_field "$MODEL")
    SERIAL=$(sanitize_field "$SERIAL")
    [[ "$MFG_YEAR" =~ ^[0-9]+$ ]] || MFG_YEAR=""
    [[ "$MFG_WEEK" =~ ^[0-9]+$ ]] || MFG_WEEK=""

    if [[ -n "$SERIAL" && -n "$MODEL" ]]; then
        MONITORS_FOUND=true

        if ! S="$SERIAL" M="$MODEL" D="$TODAY" /usr/bin/awk -F'|' '$1 == ENVIRON["S"] && $2 == ENVIRON["M"] && $3 == ENVIRON["D"] { found=1; exit } END { exit !found }' "$HISTORY_FILE"; then
            printf '%s|%s|%s|%s|%s\n' "$SERIAL" "$MODEL" "$TODAY" "$MFG_YEAR" "$MFG_WEEK" >> "$HISTORY_FILE" || exit 1
        fi

        DAYS_CONNECTED=$(S="$SERIAL" /usr/bin/awk -F'|' '$1 == ENVIRON["S"] && $3 != "" { dates[$3]=1 } END { n=0; for (d in dates) n++; print n }' "$HISTORY_FILE")

        NOTIFY_KEY="${SERIAL}|${LAPTOP_SERIAL}"

        ALREADY_HANDLED=false
        /usr/bin/grep -qxF -- "$NOTIFY_KEY" "$NOTIFIED_FILE"
        grep_rc=$?
        if (( grep_rc == 0 )); then
            ALREADY_HANDLED=true
        elif (( grep_rc > 1 )); then
            echo "[ERROR] Failed to read $NOTIFIED_FILE"
            exit 1
        fi

        NEEDS_ACTION=false
        if (( DAYS_CONNECTED >= DAYS_THRESHOLD )) && [[ "$ALREADY_HANDLED" == "false" ]]; then
            NEEDS_ACTION=true
            ACTION_NEEDED=true
            printf '%s\n' "$NOTIFY_KEY" >> "$PENDING_FILE" || exit 1
        fi

        echo "[INFO] Monitor $SERIAL connected for $DAYS_CONNECTED day(s) within the last $ROLLING_WINDOW_DAYS days (laptop $LAPTOP_SERIAL, action_needed=$NEEDS_ACTION, already_handled=$ALREADY_HANDLED)."
        emit_monitor_event "$SERIAL" "$MODEL" "$LAPTOP_SERIAL" "$DAYS_CONNECTED" "$NEEDS_ACTION" "$ALREADY_HANDLED" "$TODAY"
    fi
done < <(/usr/sbin/ioreg -lw0 | /usr/bin/grep "DisplayAttributes")

if [[ "$MONITORS_FOUND" == "false" ]]; then
    echo "[INFO] No external monitors with readable serial numbers detected today."
fi

# Replay every monitor recorded today so disconnected monitors stay visible in MDM logs.
while IFS='|' read -r H_SERIAL H_MODEL H_DATE H_YEAR H_WEEK; do
    H_DAYS=$(S="$H_SERIAL" /usr/bin/awk -F'|' '$1 == ENVIRON["S"] && $3 != "" { dates[$3]=1 } END { n=0; for (d in dates) n++; print n }' "$HISTORY_FILE")
    emit_monitor_inventory "$H_SERIAL" "$H_MODEL" "$LAPTOP_SERIAL" "$H_YEAR" "$H_WEEK" "$H_DAYS" "$H_DATE"
done < <(D="$TODAY" /usr/bin/awk -F'|' '$3 == ENVIRON["D"]' "$HISTORY_FILE")

if [[ "$ACTION_NEEDED" == "true" ]]; then
    echo "[ALERT] One or more monitors crossed the $DAYS_THRESHOLD-day threshold and need remediation."
    exit 1
fi

echo "[INFO] Monitor audit complete - nothing pending."
exit 0
