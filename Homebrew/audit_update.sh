#!/usr/bin/env zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
# Licensed under the MIT License. See LICENSE in the project root for details.
#
# Description: Global audit script to check if ANY unpinned Homebrew packages (formulae or casks) require updates, run from a root MDM execution context. Exit 1 = remediation required or a prefix could not be evaluated; exit 0 = compliant.

set -e
set -u
set -o pipefail

LOG_FILE="/var/log/brew-global-audit.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

log "=== Starting Global Brew Vulnerability Audit (Multi-Arch) ==="

console_user=$(/usr/bin/stat -f%Su /dev/console)
if [[ -z "$console_user" || "$console_user" == "root" || "$console_user" == "loginwindow" ]]; then
    log "Audit passed/skipped: No active GUI user to check brew context."
    exit 0
fi

user_uid=$(/usr/bin/id -u "$console_user")
user_home=$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory | /usr/bin/awk '{print $2}')
host_arch=$(/usr/bin/uname -m)

candidate_brews=(
  /opt/homebrew/bin/brew   # Apple Silicon
  /usr/local/bin/brew      # Intel
)

run_brew() {
    local brew_bin="$1"; shift
    local wrap="$1"; shift
    /bin/launchctl asuser "$user_uid" /usr/bin/sudo -u "$console_user" \
        /usr/bin/env HOME="$user_home" ${=wrap} "$brew_bin" "$@"
}

REQUIRES_REMEDIATION=0
FOUND_BREW=0
PROBE_FAILED=0

for brew_bin in "${candidate_brews[@]}"; do
    [[ -x "$brew_bin" ]] || continue
    FOUND_BREW=1

    wrap=""
    if [[ "$brew_bin" == /usr/local/* && "$host_arch" == "arm64" ]]; then
        if [[ -x /usr/bin/arch ]] && /usr/bin/arch -x86_64 /usr/bin/true 2>/dev/null; then
            wrap="/usr/bin/arch -x86_64"
        else
            continue
        fi
    fi

    BREW_PROBE=""
    BREW_PROBE=$(run_brew "$brew_bin" "$wrap" --repository 2>&1) || {
        log "Audit WARN: brew at $brew_bin cannot run in this context — skipping this prefix. Reason: $(echo "$BREW_PROBE" | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' ')"
        PROBE_FAILED=1
        continue
    }

    # 1. Check the last time 'brew update' was run natively for this prefix. Take the last ABSOLUTE-PATH line: a trailing env hint/warning on the merged stream would otherwise corrupt the repo path and defeat the FETCH_HEAD freshness check (false daily staleness).
    BREW_REPO=$(echo "$BREW_PROBE" | /usr/bin/grep '^/' | /usr/bin/tail -n 1 || true)
    BREW_CACHE=$(run_brew "$brew_bin" "$wrap" --cache 2>/dev/null) || {
        log "Audit WARN: brew --cache failed for $brew_bin — skipping this prefix."
        PROBE_FAILED=1
        continue
    }
    LAST_UPDATE=0

    if [[ -f "$BREW_REPO/.git/FETCH_HEAD" ]]; then
        MOD_TIME=$(/usr/bin/stat -f "%m" "$BREW_REPO/.git/FETCH_HEAD")
        [[ "$MOD_TIME" -gt "$LAST_UPDATE" ]] && LAST_UPDATE=$MOD_TIME
    fi
    if [[ -f "$BREW_CACHE/api/formula.jws.json" ]]; then
        MOD_TIME=$(/usr/bin/stat -f "%m" "$BREW_CACHE/api/formula.jws.json")
        [[ "$MOD_TIME" -gt "$LAST_UPDATE" ]] && LAST_UPDATE=$MOD_TIME
    fi

    CURRENT_TIME=$(date "+%s")
    DIFF_DAYS=$(( (CURRENT_TIME - LAST_UPDATE) / 86400 ))

    if [[ "$LAST_UPDATE" -eq 0 || "$DIFF_DAYS" -ge 2 ]]; then
        log "Audit Failed: Cache for $brew_bin is $DIFF_DAYS days old. Triggering remediation."
        REQUIRES_REMEDIATION=1
        continue
    fi

    # 2. Check local cache for outdated packages
    OUTDATED_PACKAGES=$(run_brew "$brew_bin" "$wrap" outdated --formula -q 2>/dev/null || true)

    if [[ -n "$OUTDATED_PACKAGES" ]]; then
        for PKG in ${(f)OUTDATED_PACKAGES}; do
            [[ -z "$PKG" ]] && continue
            # Use brew info --json to check pin status per-package. 'brew list --pinned' can return empty in some MDM execution contexts.
            PKG_INFO=$(run_brew "$brew_bin" "$wrap" info --json=v2 "$PKG" 2>/dev/null || true)
            if echo "$PKG_INFO" | grep -q '"pinned":true'; then
                log "Audit OK: Package '$PKG' in $brew_bin is outdated but pinned by user policy. Skipping."
                continue
            fi
            log "Audit Failed: Package '$PKG' in $brew_bin is outdated (and not pinned by user policy, so it is eligible for update)."
            REQUIRES_REMEDIATION=1
            break
        done
    fi

    # 3. Check for outdated casks (GUI apps)
    OUTDATED_CASKS=$(run_brew "$brew_bin" "$wrap" outdated --cask -q 2>/dev/null || true)
    if [[ -n "$OUTDATED_CASKS" ]]; then
        FIRST_CASK=$(echo "$OUTDATED_CASKS" | /usr/bin/head -n 1)
        log "Audit Failed: Cask '$FIRST_CASK' (and possibly others) in $brew_bin is outdated."
        REQUIRES_REMEDIATION=1
    fi
done

if [[ "$FOUND_BREW" -eq 0 ]]; then
    log "Homebrew not found. Device is compliant."
    exit 0
fi

if [[ "$REQUIRES_REMEDIATION" -eq 1 ]]; then
    exit 1
elif [[ "$PROBE_FAILED" -eq 1 ]]; then
    log "Audit result: NON-COMPLIANT — a Homebrew prefix could not be evaluated on this Mac (see the Audit WARN above)."
    exit 1
else
    log "Audit result: Device is compliant across all Homebrew installations."
    exit 0
fi
