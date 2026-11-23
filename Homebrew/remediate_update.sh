#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
# Licensed under the MIT License. See LICENSE in the project root for details.
#
# Description: Upgrade all unpinned Homebrew formulae and casks on macOS from a root MDM context.
# Dependencies: stat, awk, dscl, brew, pmset, caffeinate, osascript, profiles, softwareupdate, xcodebuild, codesign, MDM agent CLI (optional).
# Expected Result: Upgrades unpinned formulae and eligible casks. Reinstalls outdated CLT and accepts the Xcode license unattended. Migrates MDM Auto App casks out of Homebrew after Team ID verification. Exits 1 on formula errors, prefix permission blocks, or broken Auto App detection.
# Required Permissions: root (MDM execution context).
# Inputs: Optional BREW_HELP_URL environment variable for MDM alert help links.
# Outputs: Status messages to stdout.
# Logs Place: /var/log/brew-global-remediation.log.
# Rollback: Manual downgrade with 'brew install <package>@<version>'.
# Safety Notes: Stops below 20 percent battery and uses caffeinate to prevent sleep. Trusts third-party taps per item. Verifies Team IDs before migrating MDM casks. Enforces a 45-minute budget. Creates the CLT marker with O_EXCL and deletes user-owned paths as the console user.

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

set -e
set -u
set -o pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

export HOMEBREW_NO_INTERACTIVE=1
export HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_UPGRADE_QUIT_CASKS=1

LOG_FILE="/var/log/brew-global-remediation.log"
if [[ ! -w "$(/usr/bin/dirname "$LOG_FILE")" || ( -e "$LOG_FILE" && ! -w "$LOG_FILE" ) ]]; then
    LOG_FILE="/tmp/$(/usr/bin/basename "$LOG_FILE")"
fi
/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")"
exec > >(/usr/bin/tee -a "$LOG_FILE") 2>&1

log() { echo "[$(/bin/date '+%Y-%m-%d %H:%M:%S')] $1"; }

log "=== Starting Global Brew Vulnerability Remediation (Multi-Arch) ==="

# Stop starting heavy operations after 45 minutes because MDM agents terminate scripts at 60 minutes.
SCRIPT_START_EPOCH=$(/bin/date +%s)
TIME_BUDGET_SECONDS=2700
BREW_HELP_URL="${BREW_HELP_URL:-}"

valid_mdm_agent() {
    local bin="$1" parent real_bin real_parent parent_mode real_mode real_parent_mode
    [[ -e "$bin" ]] || return 1
    if [[ -L "$bin" ]]; then
        [[ "$(/usr/bin/stat -f%u "$bin" 2>/dev/null)" == "0" ]] || return 1
        parent="${bin:h}"
        [[ ! -L "$parent" ]] || return 1
        [[ "$(/usr/bin/stat -f%u "$parent" 2>/dev/null)" == "0" ]] || return 1
        parent_mode=$(/usr/bin/stat -f%Lp "$parent" 2>/dev/null) || return 1
        [[ "$parent_mode" =~ '^[0-7]+$' ]] || return 1
        (( (8#$parent_mode & 8#022) == 0 )) || return 1
    fi
    real_bin="${bin:A}"
    [[ -f "$real_bin" && ! -L "$real_bin" && -x "$real_bin" ]] || return 1
    real_parent="${real_bin:h}"
    [[ ! -L "$real_parent" ]] || return 1
    [[ "$(/usr/bin/stat -f%u "$real_bin" 2>/dev/null)" == "0" ]] || return 1
    [[ "$(/usr/bin/stat -f%u "$real_parent" 2>/dev/null)" == "0" ]] || return 1
    real_mode=$(/usr/bin/stat -f%Lp "$real_bin" 2>/dev/null) || return 1
    real_parent_mode=$(/usr/bin/stat -f%Lp "$real_parent" 2>/dev/null) || return 1
    [[ "$real_mode" =~ '^[0-7]+$' && "$real_parent_mode" =~ '^[0-7]+$' ]] || return 1
    (( (8#$real_mode & 8#022) == 0 )) || return 1
    (( (8#$real_parent_mode & 8#022) == 0 )) || return 1
    /usr/bin/codesign --verify --strict "$real_bin" >/dev/null 2>&1 || return 1
    print -r -- "$real_bin"
    return 0
}

MDM_AGENT_BIN=""
for candidate_agent in /usr/local/bin/mdm-agent /usr/local/bin/iru /usr/local/bin/kandji; do
    if resolved_agent=$(valid_mdm_agent "$candidate_agent"); then
        MDM_AGENT_BIN="$resolved_agent"
        break
    fi
done

BATT_INFO=$(/usr/bin/pmset -g batt)
if /usr/bin/grep -q "Battery Power" <<< "$BATT_INFO" || /usr/bin/grep -q "Discharging" <<< "$BATT_INFO"; then
    BATT_PCT=$(echo "$BATT_INFO" | /usr/bin/grep -oE '[0-9]+%' | /usr/bin/tr -d '%' | /usr/bin/head -n 1 || true)
    if [[ -n "$BATT_PCT" && "$BATT_PCT" -lt 20 ]]; then
        log "WARNING: Battery is below 20% ($BATT_PCT%). Aborting safe upgrade."
        exit 0
    fi
fi

console_user=$(/usr/bin/stat -f%Su /dev/console)
if [[ -z "$console_user" || "$console_user" == "root" || "$console_user" == "loginwindow" ]]; then
    log "ERROR: No active console user found. Aborting."
    exit 1
fi

user_uid=$(/usr/bin/id -u "$console_user")
user_home=$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory | /usr/bin/awk '{print $2}')
host_arch=$(/usr/bin/uname -m)

BREW_ENV_FILE="/etc/homebrew/brew.env"
/bin/mkdir -p /etc/homebrew
/usr/bin/touch "$BREW_ENV_FILE"
/usr/bin/sed -i '' '/^HOMEBREW_NO_REQUIRE_TAP_TRUST=/d' "$BREW_ENV_FILE" 2>/dev/null || true
for kv in HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_UPGRADE_QUIT_CASKS=1; do
    key="${kv%%=*}"
    /usr/bin/grep -q "^${key}=" "$BREW_ENV_FILE" || echo "$kv" >> "$BREW_ENV_FILE"
done
/bin/chmod 644 "$BREW_ENV_FILE"

candidate_brews=(
  /opt/homebrew/bin/brew
  /usr/local/bin/brew
)

run_brew_arm() {
    local brew_bin="$1"; shift
    /usr/bin/caffeinate -i \
        /bin/launchctl asuser "$user_uid" \
        /usr/bin/sudo -u "$console_user" \
        /usr/bin/env HOME="$user_home" \
            HOMEBREW_NO_INTERACTIVE=1 \
            HOMEBREW_NO_ENV_HINTS=1 \
            HOMEBREW_NO_UPGRADE_QUIT_CASKS=1 \
        "$brew_bin" "$@" </dev/null
}

run_brew_rosetta() {
    local brew_bin="$1"; shift
    /usr/bin/caffeinate -i \
        /bin/launchctl asuser "$user_uid" \
        /usr/bin/sudo -u "$console_user" \
        /usr/bin/env HOME="$user_home" \
            HOMEBREW_NO_INTERACTIVE=1 \
            HOMEBREW_NO_ENV_HINTS=1 \
            HOMEBREW_NO_UPGRADE_QUIT_CASKS=1 \
        /usr/bin/arch -x86_64 "$brew_bin" "$@" </dev/null
}

run_brew() {
    local brew_bin="$1"; shift
    local is_rosetta="$1"; shift
    if [[ "$is_rosetta" == "1" ]]; then
        run_brew_rosetta "$brew_bin" "$@"
    else
        run_brew_arm "$brew_bin" "$@"
    fi
}

time_budget_exceeded() {
    (( $(/bin/date +%s) - SCRIPT_START_EPOCH > TIME_BUDGET_SECONDS ))
}

PERM_BLOCKED=0
PERM_BLOCKED_ARM=0
PERM_BLOCKED_INTEL=0
PERM_BLOCKED_PATHS=()
PERM_LEFTOVER_PATHS=()
PERM_STALE_KEGS=()
PERM_COSMETIC_PATHS=()
PERM_ATTEMPT_BLOCKED=0
PERM_ATTEMPT_PATHS=()
PERM_ATTEMPT_COSMETIC=()
AUTOAPP_DETECT_BROKEN=""
FORMULA_ERROR=0

remove_user_path() {
    local target="$1"
    [[ -e "$target" || -L "$target" ]] || return 0
    /usr/bin/sudo -u "$console_user" /bin/rm -rf "$target" 2>/dev/null && return 0
    [[ -e "$target" || -L "$target" ]] || return 0
    PERM_LEFTOVER_PATHS+=("$target")
    log "    [WARN] '$target' is not removable as $console_user (root-owned leftovers) — NOT removing as root; reporting instead."
    return 1
}

receipt_tap() {
    local f="$1"
    [[ -f "$f" && ! -L "$f" && ! -p "$f" ]] || return 0
    /usr/bin/sudo -u "$console_user" /usr/bin/grep -oE '"tap"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" 2>/dev/null \
        | /usr/bin/head -n 1 | /usr/bin/sed -E 's/.*"([^"]+)"$/\1/' || true
}

cask_is_running() {
    local app_name="$1" search_term="$2" escaped
    if [[ -n "$app_name" ]]; then
        escaped=$(print -r -- "$app_name" | /usr/bin/sed 's/[][\\.^$*+?(){}|]/\\&/g')
        /usr/bin/pgrep -i -f -- "/${escaped}/Contents/MacOS/" >/dev/null 2>&1
    elif (( ${#search_term} >= 4 )); then
        escaped=$(print -r -- "$search_term" | /usr/bin/sed 's/[][\\.^$*+?(){}|]/\\&/g')
        /usr/bin/pgrep -i -f -- "/Applications/.*${escaped}.*\.app/" >/dev/null 2>&1
    else
        return 1
    fi
}

run_formula_upgrade() {
    local brew_bin="$1" is_rosetta="$2" line p perm_paths
    shift 2
    UPGRADE_EXIT=0
    UPGRADE_OUTPUT=$(run_brew "$brew_bin" "$is_rosetta" upgrade --formula "$@" 2>&1) || UPGRADE_EXIT=$?
    while IFS= read -r line; do
        log "    $line"
    done <<< "$UPGRADE_OUTPUT"

    PERM_ATTEMPT_BLOCKED=0
    PERM_ATTEMPT_PATHS=()
    PERM_ATTEMPT_COSMETIC=()

    perm_paths=$( { /usr/bin/grep -oE 'Permission denied @ [a-z_0-9]+ - [^[:space:]]+' <<< "$UPGRADE_OUTPUT" \
                      | /usr/bin/sed -E 's/^Permission denied @ [a-z_0-9]+ - //' || true
                    /usr/bin/grep -oE '/[^[:space:]]+ is not writable' <<< "$UPGRADE_OUTPUT" \
                      | /usr/bin/sed 's/ is not writable$//' || true; } | /usr/bin/sort -u || true)
    [[ -z "$perm_paths" ]] && return 0

    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        if [[ -z "${BREW_PREFIX:-}" || "$p" != "$BREW_PREFIX"/* ]]; then
            log "    [INFO] permission complaint outside the brew prefix — not treated as a broken install: $p"
            continue
        fi
        case "${p#$BREW_PREFIX/}" in
            share/man|share/man/*|share/info|share/info/*|share/doc|share/doc/*| \
            share/zsh|share/zsh/*|share/fish|share/fish/*| \
            share/bash-completion|share/bash-completion/*| \
            etc/bash_completion.d|etc/bash_completion.d/*)
                PERM_ATTEMPT_COSMETIC+=("$p")
                log "    [WARN] unwritable doc/completion tree (symlink target, not brew's own working state) — reported to IT only, run not failed: $p"
                continue
                ;;
        esac
        PERM_ATTEMPT_BLOCKED=1
        PERM_ATTEMPT_PATHS+=("$p")
    done <<< "$perm_paths"

    (( PERM_ATTEMPT_BLOCKED )) || return 0
    log "    [WARN] brew is blocked by filesystem permissions inside its own prefix — NOT repairing ownership:"
    for p in "${PERM_ATTEMPT_PATHS[@]}"; do
        log "    [WARN]   $p"
    done
}

# ===== BEGIN devtools block (verbatim in remediate_update.sh and install.sh) =====
# Define binary and marker paths as plain variables so tests can override them.
SOFTWAREUPDATE_BIN=/usr/sbin/softwareupdate
XCODEBUILD_BIN=/usr/bin/xcodebuild
CLT_MARKER=/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress

devtools_verdict() {
    local out="$1"
    if /usr/bin/grep -qE "You have not agreed to the Xcode license|xcodebuild -license" <<< "$out"; then
        echo license
    elif /usr/bin/grep -qE "Command Line Tools are too outdated|Command Line Tools \(CLT\) does not support macOS|No developer tools installed|Xcode alone is not sufficient on|'git' must be installed and in your PATH" <<< "$out"; then
        echo clt
    elif /usr/bin/grep -qE "Your Xcode \(.*\) .* is too outdated|Your Xcode does not support macOS" <<< "$out"; then
        echo xcode
    else
        echo none
    fi
}

devtools_culprit() {
    local line
    line=$(/usr/bin/grep -E '^==> Upgrading ' <<< "$1" | /usr/bin/grep -vE '^==> Upgrading [0-9]+ ' | /usr/bin/tail -n 1 || true)
    [[ -z "$line" ]] && return 0
    if [[ "$line" == *" dependency: "* ]]; then
        line="${line#*dependency: }"
    else
        line="${line#==> Upgrading }"
    fi
    print -r -- "${line%% *}"
}

xcode_outdated_detail() {
    local have need
    have=$(/usr/bin/grep -oE 'Your Xcode (\([^)]*\) at [^[:space:]]+ is too outdated|does not support macOS [0-9.]+)' <<< "$1" | /usr/bin/head -n 1 || true)
    need=$(/usr/bin/grep -oE 'Please update to Xcode [0-9.]+' <<< "$1" | /usr/bin/head -n 1 || true)
    print -r -- "${have:-Xcode is too outdated for Homebrew}${need:+ — $need}"
}

repair_clt() {
    local label rc=1
    /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
    if ! ( set -o noclobber; : > "$CLT_MARKER" ) 2>/dev/null || [[ -L "$CLT_MARKER" || ! -f "$CLT_MARKER" ]]; then
        log "    [WARN] Could not create '$CLT_MARKER' as a fresh regular file (something planted a path there) — refusing to run the CLT repair on this Mac."
        /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
        return 1
    fi
    label=$("$SOFTWAREUPDATE_BIN" -l 2>/dev/null | /usr/bin/grep -oE 'Label: Command Line Tools[^,]*' | /usr/bin/sed 's/^Label: //' | /usr/bin/sort -V | /usr/bin/tail -n 1 || true)
    if [[ -z "$label" ]]; then
        log "    [WARN] softwareupdate offered no Command Line Tools package — manual CLT reinstall needed on this Mac."
    else
        log "    [FIX] Installing '$label' (can take several minutes)..."
        if /usr/bin/caffeinate -i "$SOFTWAREUPDATE_BIN" -i "$label" >/dev/null 2>&1; then
            log "    [OK] Command Line Tools installed: $label"
            rc=0
        else
            log "    [WARN] softwareupdate failed to install '$label' — manual CLT reinstall needed on this Mac."
        fi
    fi
    /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
    return $rc
}

repair_xcode_license() {
    "$XCODEBUILD_BIN" -license accept >/dev/null 2>&1
}

# ===== END devtools block =====

DEVTOOLS_SKIPPED=()
DEVTOOLS_RETRY_NAMES=()

retry_without_source_builds() {
    local brew_bin="$1" is_rosetta="$2" round=0 culprit outdated pinned pkg skipped
    local -a names
    DEVTOOLS_SKIPPED=()
    DEVTOOLS_RETRY_NAMES=()
    while (( round < 3 )); do
        if time_budget_exceeded; then
            log "    [INFO] Time budget reached — skipping the bottled-only retry; the next daily run picks it up."
            break
        fi
        culprit=$(devtools_culprit "$UPGRADE_OUTPUT")
        [[ -z "$culprit" ]] && break
        DEVTOOLS_SKIPPED+=("$culprit")
        round=$(( round + 1 ))
        outdated=$(run_brew "$brew_bin" "$is_rosetta" outdated --formula -q 2>/dev/null || true)
        pinned=$(run_brew "$brew_bin" "$is_rosetta" list --pinned 2>/dev/null || true)
        names=()
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            /usr/bin/grep -qFx -- "$pkg" <<< "$pinned" && continue
            for skipped in "${DEVTOOLS_SKIPPED[@]}"; do
                [[ "${pkg##*/}" == "${skipped##*/}" ]] && continue 2
            done
            names+=("$pkg")
        done <<< "$outdated"
        if (( ${#names[@]} == 0 )); then
            log "    [INFO] Nothing left to upgrade once the from-source formula(e) are excluded: ${(j:, :)DEVTOOLS_SKIPPED}."
            break
        fi
        log "    [FIX] Retrying formula upgrade without '$culprit' (round $round, ${#names[@]} formula(e) left)..."
        DEVTOOLS_RETRY_NAMES=("${names[@]}")
        run_formula_upgrade "$brew_bin" "$is_rosetta" "${names[@]}"
        [[ "$(devtools_verdict "$UPGRADE_OUTPUT")" == none ]] && break
    done
    return 0
}

notify_user() {
    local title="$1"
    local msg="$2"
    local suppress_key="${3:-}"
    local -a extra_args
    extra_args=()
    [[ -n "$BREW_HELP_URL" ]] && extra_args+=(--help-url "$BREW_HELP_URL")
    [[ -n "$suppress_key" ]] && extra_args+=(--suppression-key "$suppress_key")
    if [[ -n "$MDM_AGENT_BIN" ]]; then
        "$MDM_AGENT_BIN" display-alert \
            --title "$title" \
            --message "$msg" \
            "${extra_args[@]}" \
            --no-wait 2>/dev/null || true
    else
        /bin/launchctl asuser "$user_uid" /usr/bin/sudo -u "$console_user" /usr/bin/osascript \
            -e 'on run argv' \
            -e 'display notification (item 1 of argv) with title (item 2 of argv)' \
            -e 'end run' \
            -- "$msg" "$title" 2>/dev/null || true
    fi
}

# Keep the literal com.kandji.profile.autoapp. vendor prefix because the MDM agent writes that identifier.
# Use print -r -- instead of echo so zsh preserves backslash escapes in profile output.
PROFILES_RAW=$(/usr/bin/profiles -C -o stdout 2>/dev/null || true)
MDM_AUTOAPP_RAW=$(print -r -- "$PROFILES_RAW" \
    | /usr/bin/awk -F'"' '
        /ProfileDisplayName =/  {name=$2; sub(/ Settings$/,"",name); in_auto=0; expect=0}
        /ProfileIdentifier = "com\.kandji\.profile\.autoapp\./ {in_auto=1; print "NAME\t" name}
        in_auto && /RuleType = TeamIdentifier/ {expect=1}
        in_auto && expect && match($0, /RuleValue = [A-Z0-9]+;/) {
            s=substr($0,RSTART,RLENGTH); sub(/RuleValue = /,"",s); sub(/;$/,"",s);
            if (length(s)==10) print "TEAM\t" name "\t" s; expect=0 }
        in_auto && match($0, /TeamIdentifier = [A-Z0-9]+;/) {
            s=substr($0,RSTART,RLENGTH); sub(/TeamIdentifier = /,"",s); sub(/;$/,"",s);
            if (length(s)==10) print "TEAM\t" name "\t" s }
        in_auto && /subject\.OU\] = / {
            t=$0; sub(/.*subject\.OU\] = /,"",t); sub(/^[^A-Z0-9]+/,"",t); sub(/[^A-Z0-9].*$/,"",t);
            if (length(t)==10) print "TEAM\t" name "\t" t }' \
    | /usr/bin/sort -u || true)
MDM_AUTOAPP_NAMES=$(print -r -- "$MDM_AUTOAPP_RAW" | /usr/bin/awk -F'\t' '$1=="NAME"{print $2}' || true)
MDM_AUTOAPP_TEAMS=$(print -r -- "$MDM_AUTOAPP_RAW" | /usr/bin/awk -F'\t' '$1=="TEAM"' || true)

AUTOAPP_PROFILE_COUNT=$(print -r -- "$PROFILES_RAW" \
    | /usr/bin/grep -c 'ProfileIdentifier = "com\.kandji\.profile\.autoapp\.' || true)
AUTOAPP_NAME_COUNT=$(print -r -- "$MDM_AUTOAPP_NAMES" | /usr/bin/grep -c . || true)
if [[ -z "$PROFILES_RAW" ]]; then
    AUTOAPP_DETECT_BROKEN="'profiles -C -o stdout' returned nothing (not root, or profiles unreadable)"
    log "[ERROR] $AUTOAPP_DETECT_BROKEN — Auto App detection is DOWN, every MDM-managed cask will be treated as brew-managed."
elif (( AUTOAPP_PROFILE_COUNT == 0 )); then
    log "[WARN] No MDM Auto App profiles on this Mac — no cask will be recognised as MDM-managed (the path heuristic in the cask loop still applies)."
elif (( AUTOAPP_NAME_COUNT == 0 )); then
    AUTOAPP_DETECT_BROKEN="$AUTOAPP_PROFILE_COUNT Auto App profile(s) on disk but the matcher extracted no display name"
    log "[ERROR] $AUTOAPP_DETECT_BROKEN — the identifier pattern is stale or the payload shape changed."
else
    log "MDM Auto Apps detected on this Mac ($AUTOAPP_NAME_COUNT of $AUTOAPP_PROFILE_COUNT profile(s)): $(print -r -- "$MDM_AUTOAPP_NAMES" | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//; s/,/, /g')"
    if (( AUTOAPP_NAME_COUNT < AUTOAPP_PROFILE_COUNT )); then
        log "[WARN] Auto App matcher extracted $AUTOAPP_NAME_COUNT name(s) from $AUTOAPP_PROFILE_COUNT profile(s) — duplicate display names, or the matcher is partially broken."
    fi
fi

normalize_name() { print -r -- "$1" | /usr/bin/tr '[:upper:]' '[:lower:]' | /usr/bin/tr -cd 'a-z0-9'; }

mdm_manages_cask() {
    local cask="$1"
    local norm_cask norm_name name
    MDM_MATCHED_PROFILE=""
    [[ -z "$MDM_AUTOAPP_NAMES" ]] && return 1
    norm_cask=$(normalize_name "$cask")
    [[ -z "$norm_cask" ]] && return 1
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        norm_name=$(normalize_name "$name")
        [[ -z "$norm_name" ]] && continue
        if [[ "$norm_name" == "$norm_cask" ]] || { (( ${#norm_cask} >= 4 )) && [[ "$norm_name" == *"$norm_cask"* ]]; }; then
            MDM_MATCHED_PROFILE="$name"
            return 0
        fi
    done <<< "$MDM_AUTOAPP_NAMES"
    return 1
}

GLOBAL_FAILED_PKGS=()
DEVTOOLS_BLOCKED_PKGS=()
MDM_CONFLICT_PKGS=()
MIGRATED_PKGS=()

for brew_bin in "${candidate_brews[@]}"; do
    [[ -x "$brew_bin" ]] || continue

    IS_ROSETTA=0
    if [[ "$brew_bin" == /usr/local/* && "$host_arch" == "arm64" ]]; then
        if [[ -x /usr/bin/arch ]] && /usr/bin/arch -x86_64 /usr/bin/true 2>/dev/null; then
            IS_ROSETTA=1
        else
            log "==> Skipping $brew_bin: Intel prefix on arm64 but Rosetta is unavailable."
            continue
        fi
    fi

    if time_budget_exceeded; then
        log "==> 45-min time budget reached — deferring $brew_bin and any remaining prefixes to the next daily run."
        break
    fi

    PREFIX_LABEL="$brew_bin$([[ "$IS_ROSETTA" -eq 1 ]] && echo ' (via Rosetta)' || true)"
    log "==> Processing Homebrew Prefix: $PREFIX_LABEL"

    BREW_PROBE=""
    BREW_PROBE=$(run_brew "$brew_bin" "$IS_ROSETTA" --prefix 2>&1) || {
        log "    [ERROR] brew at $brew_bin cannot run in this context — skipping this prefix. Reason: $(echo "$BREW_PROBE" | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' ')"
        FORMULA_ERROR=1
        continue
    }
    # Read the last line that starts with a slash to ignore environment hints.
    BREW_PREFIX=$(echo "$BREW_PROBE" | /usr/bin/grep '^/' | /usr/bin/tail -n 1 || true)
    if [[ "$BREW_PREFIX" != "/opt/homebrew" && "$BREW_PREFIX" != "/usr/local" ]]; then
        log "    [ERROR] Unexpected BREW_PREFIX '$BREW_PREFIX' for $brew_bin. Skipping for safety."
        FORMULA_ERROR=1
        continue
    fi

    LOCK_DIR="$BREW_PREFIX/var/homebrew/locks"
    if [[ -d "$LOCK_DIR" && ! -L "$LOCK_DIR" ]]; then
        if /usr/sbin/lsof +D "$LOCK_DIR" >/dev/null 2>&1 || /usr/bin/pgrep -u "$user_uid" -f -- "$BREW_PREFIX/((Homebrew/)?bin/brew|Library/Homebrew/brew\.rb)([[:space:]]|$)" >/dev/null 2>&1; then
            log "    Active brew process detected — skipping lock removal."
        else
            log "    Clearing stale lock files..."
            remove_user_path "$LOCK_DIR" || true
        fi
    fi

    log "    Updating formula definitions..."
    run_brew "$brew_bin" "$IS_ROSETTA" update 2>&1 | while IFS= read -r line; do
        log "    $line"
    done || true

    log "    Trusting installed third-party tap formulae/casks..."
    TRUST_JSON=""
    for tj in "$user_home/.homebrew/trust.json" "$user_home/.config/homebrew/trust.json"; do
        if [[ -f "$tj" && ! -L "$tj" && ! -p "$tj" ]]; then
            TRUST_JSON+="$(/usr/bin/sudo -u "$console_user" /bin/cat "$tj" 2>/dev/null || true)"
        fi
    done
    typeset -a trust_formulae trust_casks
    trust_formulae=(); trust_casks=(); trust_seen=""
    for receipt in "$BREW_PREFIX"/Cellar/*/*/INSTALL_RECEIPT.json(N.); do
        tap=$(receipt_tap "$receipt")
        [[ -z "$tap" || "$tap" == homebrew/* ]] && continue
        full="$tap/${receipt:h:h:t}"
        [[ "$trust_seen" == *"|$full|"* ]] && continue
        trust_seen+="|$full|"
        [[ "$TRUST_JSON" == *"\"$full\""* || "$TRUST_JSON" == *"\"$tap\""* ]] && continue
        trust_formulae+=("$full")
    done
    for creceipt in "$BREW_PREFIX"/Caskroom/*/.metadata/*/*/INSTALL_RECEIPT.json(N.) "$BREW_PREFIX"/Caskroom/*/.metadata/*/*/*/INSTALL_RECEIPT.json(N.); do
        ctap=$(receipt_tap "$creceipt")
        [[ -z "$ctap" || "$ctap" == homebrew/* ]] && continue
        ctoken=${${creceipt#$BREW_PREFIX/Caskroom/}%%/*}
        cfull="$ctap/$ctoken"
        [[ "$trust_seen" == *"|$cfull|"* ]] && continue
        trust_seen+="|$cfull|"
        [[ "$TRUST_JSON" == *"\"$cfull\""* || "$TRUST_JSON" == *"\"$ctap\""* ]] && continue
        trust_casks+=("$cfull")
    done
    if (( ${#trust_formulae} )); then
        run_brew "$brew_bin" "$IS_ROSETTA" trust --formula "${trust_formulae[@]}" >/dev/null 2>&1 \
            || log "    [INFO] Could not trust one or more formulae: ${trust_formulae[*]}"
    fi
    if (( ${#trust_casks} )); then
        run_brew "$brew_bin" "$IS_ROSETTA" trust --cask "${trust_casks[@]}" >/dev/null 2>&1 \
            || log "    [INFO] Could not trust one or more casks: ${trust_casks[*]}"
    fi

    log "    Upgrading ALL unpinned formulae (CLI packages)..."
    DEVTOOLS_RETRY_NAMES=()
    run_formula_upgrade "$brew_bin" "$IS_ROSETTA"

    DEVTOOLS_VERDICT=$(devtools_verdict "$UPGRADE_OUTPUT")
    case "$DEVTOOLS_VERDICT" in
        license)
            log "    [FIX] Xcode license not accepted blocks brew — accepting it as root..."
            if repair_xcode_license; then
                log "    [OK] Xcode license accepted — retrying formula upgrade once..."
                run_formula_upgrade "$brew_bin" "$IS_ROSETTA"
            else
                log "    [WARN] 'xcodebuild -license accept' failed — manual acceptance needed on this Mac."
            fi
            ;;
        clt)
            if time_budget_exceeded; then
                log "    [INFO] Time budget reached — deferring Command Line Tools reinstall to the next daily run."
            else
                log "    [FIX] Outdated or missing Command Line Tools block brew — reinstalling CLT via softwareupdate..."
                if repair_clt; then
                    log "    [OK] Retrying formula upgrade once..."
                    run_formula_upgrade "$brew_bin" "$IS_ROSETTA"
                fi
            fi
            ;;
        xcode)
            XCODE_DETAIL=$(xcode_outdated_detail "$UPGRADE_OUTPUT")
            XCODE_VER=$(/usr/bin/grep -oE 'Your Xcode \([^) ]+' <<< "$UPGRADE_OUTPUT" | /usr/bin/head -n 1 | /usr/bin/tr -cd '0-9.' || true)
            log "    [WARN] $XCODE_DETAIL — update Xcode from the App Store, or delete it so brew uses the Command Line Tools. Not repairable from MDM."
            notify_user "Xcode update required" "Homebrew cannot build packages: $XCODE_DETAIL. Update Xcode from the App Store, or delete it so Homebrew uses the Command Line Tools instead." "brew-xcode-outdated-${XCODE_VER:-unsupported}"
            ;;
    esac
    DEVTOOLS_VERDICT=$(devtools_verdict "$UPGRADE_OUTPUT")
    if [[ "$DEVTOOLS_VERDICT" != none ]]; then
        retry_without_source_builds "$brew_bin" "$IS_ROSETTA"
        FORMULA_ERROR=1
        DEVTOOLS_BLOCKED_PKGS+=("${DEVTOOLS_SKIPPED[@]}")
        log "    [ERROR] Developer tools block from-source builds on this Mac ($DEVTOOLS_VERDICT); not upgraded: ${${(j:, :)DEVTOOLS_SKIPPED}:-none identified}."
    fi

    if /usr/bin/grep -q "Failed to download resource" <<< "$UPGRADE_OUTPUT" \
       && /usr/bin/grep -qE "rb_sysopen -.*Caches/Homebrew/downloads" <<< "$UPGRADE_OUTPUT"; then
        DL_CACHE="$user_home/Library/Caches/Homebrew/downloads"
        if [[ "$DL_CACHE" == /Users/*/Library/Caches/Homebrew/downloads && -d "$DL_CACHE" ]]; then
            log "    [FIX] Inconsistent Homebrew download cache — clearing $DL_CACHE before retrying..."
            remove_user_path "$DL_CACHE" || true
        else
            log "    [FIX] Homebrew download cache entry missing ($DL_CACHE absent) — retrying the upgrade to rebuild it..."
        fi
        run_formula_upgrade "$brew_bin" "$IS_ROSETTA" "${DEVTOOLS_RETRY_NAMES[@]}"
    fi

    # Trust an uninstalled sibling formula only when this Mac already has an installed item from the same tap.
    SIBLING_ROUND=0
    while :; do
        SIBLING_ITEMS=$(/usr/bin/grep -oE 'Refusing to load formula [^[:space:]]+' <<< "$UPGRADE_OUTPUT" \
            | /usr/bin/sed 's/^Refusing to load formula //' | /usr/bin/sort -u || true)
        [[ -z "$SIBLING_ITEMS" ]] && break
        (( SIBLING_ROUND >= 3 )) && { log "    [WARN] sibling trust: still blocked after $SIBLING_ROUND rounds — giving up."; break; }
        SIBLING_ROUND=$(( SIBLING_ROUND + 1 ))
        SIBLING_TRUSTED=0
        while IFS= read -r sib; do
            [[ -z "$sib" ]] && continue
            sib_tap="${sib%/*}"
            if [[ "$sib_tap" != */* || "$trust_seen" != *"|$sib_tap/"* ]]; then
                log "    [WARN] '$sib' is blocking the upgrade, but nothing from tap '$sib_tap' is installed on this Mac — not trusting it."
                continue
            fi
            log "    [FIX] Trusting '$sib' — a sibling formula brew must load from '$sib_tap', a tap already in use here."
            if run_brew "$brew_bin" "$IS_ROSETTA" trust --formula "$sib" >/dev/null 2>&1; then
                SIBLING_TRUSTED=1
            else
                log "    [WARN] Could not trust '$sib'."
            fi
        done <<< "$SIBLING_ITEMS"
        [[ "$SIBLING_TRUSTED" -eq 0 ]] && break
        log "    [FIX] Retrying formula upgrade after trusting sibling formula(e) (round $SIBLING_ROUND)..."
        run_formula_upgrade "$brew_bin" "$IS_ROSETTA" "${DEVTOOLS_RETRY_NAMES[@]}"
    done

    if (( ${#PERM_ATTEMPT_COSMETIC[@]} )); then
        PERM_COSMETIC_PATHS+=("${PERM_ATTEMPT_COSMETIC[@]}")
    fi
    if (( PERM_ATTEMPT_BLOCKED )); then
        PERM_BLOCKED=1
        PERM_BLOCKED_PATHS+=("${PERM_ATTEMPT_PATHS[@]}")
        if [[ "$brew_bin" == /usr/local/* ]]; then
            PERM_BLOCKED_INTEL=1
        else
            PERM_BLOCKED_ARM=1
        fi
        FORMULA_ERROR=1
    fi

    if [[ "$UPGRADE_EXIT" -ne 0 ]]; then
        LINK_PKGS=$(echo "$UPGRADE_OUTPUT" \
            | /usr/bin/grep -oE 'brew link --overwrite [^ ]+' \
            | /usr/bin/grep -v -- '--dry-run' \
            | /usr/bin/awk '{print $NF}' \
            | /usr/bin/sort -u || true)

        if [[ -n "$LINK_PKGS" ]]; then
            log "    [WARN] Symlink conflicts detected. Attempting brew link --overwrite for affected packages..."
            RELINK_ERROR=0
            while IFS= read -r pkg; do
                [[ -z "$pkg" ]] && continue
                log "    [FIX] Relinking: $pkg"
                run_brew "$brew_bin" "$IS_ROSETTA" link --overwrite "$pkg" 2>&1 | while IFS= read -r line; do
                    log "    $line"
                done || {
                    log "    [ERROR] Could not relink '$pkg'. Manual intervention may be required."
                    RELINK_ERROR=1
                }
            done <<< "$LINK_PKGS"
            [[ "$RELINK_ERROR" -eq 1 ]] && FORMULA_ERROR=1
        else
            PINNED_BLOCKING=$(echo "$UPGRADE_OUTPUT" | /usr/bin/grep -c "brew unpin" || true)
            OTHER_ERRORS=$(echo "$UPGRADE_OUTPUT" | /usr/bin/grep "^Error:" | /usr/bin/grep -v "brew unpin" || true)

            if [[ "$PINNED_BLOCKING" -gt 0 && -z "$OTHER_ERRORS" ]]; then
                BLOCKED_PKGS=$(echo "$UPGRADE_OUTPUT" \
                    | /usr/bin/grep "brew unpin" \
                    | /usr/bin/grep -oE "['\`]brew unpin [^'\`]+['\`]" \
                    | /usr/bin/sed "s/.*brew unpin //; s/['\`]$//" \
                    | /usr/bin/sort -u | /usr/bin/tr '\n' ' ' || true)
                log "    [INFO] Upgrade blocked by intentional pin(s): ${BLOCKED_PKGS}— expected per user policy, skipping."
            elif [[ "$PINNED_BLOCKING" -gt 0 && -n "$OTHER_ERRORS" ]]; then
                log "    [ERROR] Formula upgrade failed for $brew_bin with errors beyond pinned dependencies:"
                while IFS= read -r line; do log "    $line"; done <<< "$OTHER_ERRORS"
                FORMULA_ERROR=1
                STILL_OUTDATED=$(run_brew "$brew_bin" "$IS_ROSETTA" outdated --formula -q 2>/dev/null || true)
                PINNED_PKGS=$(run_brew "$brew_bin" "$IS_ROSETTA" list --pinned 2>/dev/null || true)
                while IFS= read -r pkg; do
                    [[ -z "$pkg" ]] && continue
                    if ! /usr/bin/grep -qFx -- "$pkg" <<< "$PINNED_PKGS"; then
                        GLOBAL_FAILED_PKGS+=("$pkg")
                    fi
                done <<< "$STILL_OUTDATED"
            else
                log "    [ERROR] Formula upgrade failed for $brew_bin (exit code: $UPGRADE_EXIT)."
                FORMULA_ERROR=1
                STILL_OUTDATED=$(run_brew "$brew_bin" "$IS_ROSETTA" outdated --formula -q 2>/dev/null || true)
                PINNED_PKGS=$(run_brew "$brew_bin" "$IS_ROSETTA" list --pinned 2>/dev/null || true)
                while IFS= read -r pkg; do
                    [[ -z "$pkg" ]] && continue
                    if ! /usr/bin/grep -qFx -- "$pkg" <<< "$PINNED_PKGS"; then
                        GLOBAL_FAILED_PKGS+=("$pkg")
                    fi
                done <<< "$STILL_OUTDATED"
            fi
        fi
    fi

    log "    Checking for outdated casks (GUI apps)..."
    OUTDATED_CASKS=$(run_brew "$brew_bin" "$IS_ROSETTA" outdated --cask --verbose 2>/dev/null || true)

    if [[ -n "$OUTDATED_CASKS" ]]; then
        while IFS= read -r CASK_LINE; do
            [[ -z "$CASK_LINE" ]] && continue
            CASK=$(echo "$CASK_LINE" | /usr/bin/awk '{print $1}')
            [[ -z "$CASK" ]] && continue
            MISMATCH_FALLTHROUGH=0

            if time_budget_exceeded; then
                log "    [INFO] 45-min time budget reached — deferring '$CASK' and the remaining casks to the next daily run (the agent kills scripts at 60 min)."
                break
            fi
            NEW_VERSION=$(echo "$CASK_LINE" | /usr/bin/awk 'NF > 1 {print $NF}')
            SUPPRESS_KEY="brew-update-${CASK}${NEW_VERSION:+-$NEW_VERSION}"

            APP_NAME=""
            meta_files=(
                "$BREW_PREFIX/Caskroom/$CASK"/.metadata/*/*/Casks/*.rb(N.)
                "$BREW_PREFIX/Caskroom/$CASK"/.metadata/*/*/Casks/*.json(N.)
                "$BREW_PREFIX/Caskroom/$CASK"/.metadata/*/*/*/Casks/*.rb(N.)
                "$BREW_PREFIX/Caskroom/$CASK"/.metadata/*/*/*/Casks/*.json(N.)
            )
            for mf in "${meta_files[@]}"; do
                [[ -f "$mf" && ! -L "$mf" && ! -p "$mf" ]] || continue
                APP_NAME=$(/usr/bin/sudo -u "$console_user" /usr/bin/grep -hoE '"[^"]+\.app"' "$mf" 2>/dev/null \
                    | /usr/bin/head -n 1 | /usr/bin/tr -d '"' || true)
                [[ -n "$APP_NAME" ]] && break
            done
            APP_NAME="${APP_NAME##*/}"

            if mdm_manages_cask "$CASK"; then
                MIGRATE_OK=1
                PROFILE_TEAMS=$(print -r -- "$MDM_AUTOAPP_TEAMS" | /usr/bin/awk -F'\t' -v n="$MDM_MATCHED_PROFILE" '$1=="TEAM" && $2==n {print $3}' | /usr/bin/sort -u || true)
                APP_PATH=""
                for base in /Applications "$user_home/Applications"; do
                    [[ -n "$APP_NAME" && -e "$base/$APP_NAME" ]] && { APP_PATH="$base/$APP_NAME"; break; }
                done
                APP_TEAM=""
                if [[ -n "$APP_PATH" ]]; then
                    APP_TEAM=$(/usr/bin/codesign -dv "$APP_PATH" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2}' || true)
                    [[ "$APP_TEAM" == "not set" ]] && APP_TEAM=""
                fi
                if [[ -n "$PROFILE_TEAMS" ]]; then
                    if [[ -n "$APP_TEAM" ]] && /usr/bin/grep -qFx "$APP_TEAM" <<< "$PROFILE_TEAMS"; then
                        MIGRATE_NOTE="Auto App profile '$MDM_MATCHED_PROFILE' (verified: app team $APP_TEAM matches)"
                    else
                        log "    [SKIP-MDM-MISMATCH] '$CASK' name-matches Auto App profile '$MDM_MATCHED_PROFILE' but its app (${APP_PATH:-not found in /Applications or ~/Applications}) team '${APP_TEAM:-unknown}' does not match the profile team(s) $(echo "$PROFILE_TEAMS" | /usr/bin/tr '\n' ' ')— refusing to migrate a possibly-different same-name product. Keeping it under brew."
                        MIGRATE_OK=0
                        MISMATCH_FALLTHROUGH=1
                    fi
                else
                    norm_cask_chk=$(normalize_name "$CASK")
                    norm_profile_chk=$(normalize_name "$MDM_MATCHED_PROFILE")
                    if [[ "$norm_profile_chk" == "$norm_cask_chk" && -n "$APP_PATH" ]]; then
                        MIGRATE_NOTE="Auto App profile '$MDM_MATCHED_PROFILE' (exact name match, app present, no Team ID in profile)"
                    else
                        log "    [SKIP-MDM-UNVERIFIED] '$CASK' matched Auto App profile '$MDM_MATCHED_PROFILE' without a Team ID and without an exact name and app match — keeping it under brew."
                        MIGRATE_OK=0
                        MISMATCH_FALLTHROUGH=1
                    fi
                fi
                if [[ "$MIGRATE_OK" -eq 1 ]]; then
                    CASKROOM_DIR="$BREW_PREFIX/Caskroom/$CASK"
                    if [[ -d "$CASKROOM_DIR" ]]; then
                        log "    [MIGRATE-MDM] '$CASK' matched $MIGRATE_NOTE — removing brew's Caskroom record ($CASKROOM_DIR); the application itself is untouched."
                        if remove_user_path "$CASKROOM_DIR"; then
                            MIGRATED_PKGS+=("$CASK")
                        else
                            log "    [WARN] Could not remove $CASKROOM_DIR — manual cleanup needed."
                            MDM_CONFLICT_PKGS+=("$CASK")
                        fi
                    else
                        log "    [SKIP-MDM] '$CASK' matched $MIGRATE_NOTE but has no Caskroom record at $CASKROOM_DIR — nothing to forget."
                        MDM_CONFLICT_PKGS+=("$CASK")
                    fi
                    continue
                fi
            fi

            SEARCH_TERM=$(echo "$CASK" | /usr/bin/tr '-' ' ')
            if [[ "$MISMATCH_FALLTHROUGH" != 1 ]] && cask_is_running "$APP_NAME" "$SEARCH_TERM"; then
                log "    [SKIP] '$CASK' is currently running — notifying user to update via Self Service."
                notify_user "Update Available: $CASK" \
                    "A security update for '$CASK' is ready. Please install it via MDM Self Service when you are done using the app." \
                    "$SUPPRESS_KEY"
                continue
            fi

            log "    Upgrading cask: $CASK..."
            CASK_OUTPUT=""
            CASK_EXIT=0
            CASK_OUTPUT=$(run_brew "$brew_bin" "$IS_ROSETTA" upgrade --cask "$CASK" 2>&1) || CASK_EXIT=$?

            while IFS= read -r line; do
                log "    $line"
            done <<< "$CASK_OUTPUT"

            if [[ "$CASK_EXIT" -ne 0 ]] || /usr/bin/grep -q "cannot be upgraded as-is" <<< "$CASK_OUTPUT"; then
                CONFLICT_PATH=$(/usr/bin/grep -oE "already an App at '[^']+'" <<< "$CASK_OUTPUT" | /usr/bin/head -n 1 | /usr/bin/sed "s/^already an App at '//; s/'$//" || true)
                if [[ -n "$CONFLICT_PATH" && "$CONFLICT_PATH" != "$BREW_PREFIX"/Caskroom/* ]]; then
                    log "    [SKIP-EXTERNAL] '$CASK': conflicting copy at '$CONFLICT_PATH' was not staged by brew — likely MDM-managed, manually installed, or a rolled-back mid-install. Migrate it out of brew."
                    MDM_CONFLICT_PKGS+=("$CASK")
                    continue
                fi
                if [[ -z "$CONFLICT_PATH" ]] && /usr/bin/grep -qE "Reverting upgrade for Cask|Rolling back the failed upgrade" <<< "$CASK_OUTPUT"; then
                    log "    [WARN] '$CASK' upgrade failed mid-install and brew rolled it back — treating as a retryable failure."
                    GLOBAL_FAILED_PKGS+=("$CASK")
                    continue
                fi

                if cask_is_running "$APP_NAME" "$SEARCH_TERM"; then
                    log "    [SKIP] '$CASK' was started mid-run — deferring forced reinstall."
                    notify_user "Update Available: $CASK" \
                        "A security update for '$CASK' is ready. Please install it via MDM Self Service when you are done using the app." \
                        "$SUPPRESS_KEY"
                    continue
                fi

                log "    [FIX] Reinstalling cask '$CASK' with --force (durable receipt fix)..."
                REINSTALL_EXIT=0
                REINSTALL_OUTPUT=$(run_brew "$brew_bin" "$IS_ROSETTA" reinstall --cask --force "$CASK" 2>&1) || REINSTALL_EXIT=$?

                while IFS= read -r line; do
                    log "    $line"
                done <<< "$REINSTALL_OUTPUT"

                if [[ "$REINSTALL_EXIT" -ne 0 ]]; then
                    log "    [WARN] Forced reinstall of '$CASK' also failed (exit code: $REINSTALL_EXIT)."
                    GLOBAL_FAILED_PKGS+=("$CASK")
                else
                    log "    [OK] '$CASK' recovered via forced reinstall."
                fi
            fi
        done <<< "$OUTDATED_CASKS"
    else
        log "    No outdated casks found."
    fi

    log "    Cleaning up old versions..."
    CLEANUP_OUTPUT=$(run_brew "$brew_bin" "$IS_ROSETTA" cleanup 2>&1 || true)
    while IFS= read -r line; do log "    $line"; done <<< "$CLEANUP_OUTPUT"

    if /usr/bin/grep -q "Could not cleanup old kegs" <<< "$CLEANUP_OUTPUT"; then
        CLEAN_PATHS=$(/usr/bin/awk -v pfx="$BREW_PREFIX/" '
                /Could not cleanup old kegs/ { grab=1; next }
                grab && NF==0 { next }
                grab && index($1, pfx)==1 { print $1; next }
                grab { grab=0 }' <<< "$CLEANUP_OUTPUT" \
            | /usr/bin/sed -E 's/\.+$//' | /usr/bin/sort -u || true)
        if [[ -n "$CLEAN_PATHS" ]]; then
            log "    [WARN] brew cleanup is blocked by filesystem permissions — NOT repairing ownership:"
            while IFS= read -r cp; do
                [[ -z "$cp" ]] && continue
                PERM_STALE_KEGS+=("$cp")
                log "    [WARN]   $cp"
            done <<< "$CLEAN_PATHS"
        fi
    fi
done

if [[ ${#MIGRATED_PKGS[@]} -gt 0 ]]; then
    UNIQUE_MIGRATED=(${(u)MIGRATED_PKGS})
    MIGRATED_STR=${(j:, :)UNIQUE_MIGRATED}
    log "[REPORT] Casks auto-migrated out of brew (MDM-managed; Caskroom record removed, apps untouched): $MIGRATED_STR"
fi

if [[ ${#MDM_CONFLICT_PKGS[@]} -gt 0 ]]; then
    UNIQUE_MDM=(${(u)MDM_CONFLICT_PKGS})
    MDM_STR=${(j:, :)UNIQUE_MDM}
    log "[REPORT] Casks skipped to avoid clobbering an externally-managed copy (migrate out of brew): $MDM_STR"
fi

if [[ -n "$AUTOAPP_DETECT_BROKEN" ]]; then
    log "[REPORT] MDM Auto App detection is broken on this device: $AUTOAPP_DETECT_BROKEN. MDM-managed casks were NOT recognised this run."
    FORMULA_ERROR=1
fi

if [[ ${#PERM_LEFTOVER_PATHS[@]} -gt 0 ]]; then
    UNIQUE_LEFTOVER=(${(u)PERM_LEFTOVER_PATHS})
    log "[REPORT] Root-owned leftovers left in place (script no longer deletes as root): ${(j:, :)UNIQUE_LEFTOVER}"
fi
if [[ ${#PERM_STALE_KEGS[@]} -gt 0 ]]; then
    UNIQUE_KEGS=(${(u)PERM_STALE_KEGS})
    log "[REPORT] Stale kegs brew cleanup could not remove (root-owned): ${(j:, :)UNIQUE_KEGS}"
fi
if [[ ${#PERM_COSMETIC_PATHS[@]} -gt 0 ]]; then
    UNIQUE_COSMETIC=(${(u)PERM_COSMETIC_PATHS})
    log "[REPORT] Unwritable doc/completion trees under a brew prefix (symlink targets only, brew still works): ${(j:, :)UNIQUE_COSMETIC}"
fi

if [[ "$PERM_BLOCKED" -eq 1 ]]; then
    FORMULA_ERROR=1
    UNIQUE_PERM=(${(u)PERM_BLOCKED_PATHS})
    log "[REPORT] brew blocked by filesystem permissions on: ${(j:, :)UNIQUE_PERM}"
    # Never instruct users to run chown on /usr/local because root-owned MDM binaries live there.
    if [[ "$PERM_BLOCKED_INTEL" -eq 1 && "$PERM_BLOCKED_ARM" -eq 0 ]]; then
        log "[REPORT] Intel Homebrew under Rosetta — recommend migrating to native arm64 brew in /opt/homebrew."
        notify_user "Homebrew Needs Migrating" \
            "Your Homebrew lives in /usr/local and runs through Rosetta, and it can no longer update itself because of file permissions. Moving it to the native Apple Silicon version fixes this for good. In Terminal, one line at a time:

1. Save what you have installed:
   arch -x86_64 /usr/local/bin/brew bundle dump --file ~/Desktop/Brewfile
2. Remove the old Rosetta copy:
   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)\" -- --path=/usr/local
3. Install the native version:
   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"
4. Restore your packages:
   brew bundle install --file ~/Desktop/Brewfile

Step 1 saves everything and step 4 restores it, so nothing is lost. If you want help or a step fails, contact #it-support." \
            "brew-perm-migrate-arm"
    else
        notify_user "Homebrew Cannot Update" \
            "Homebrew cannot update itself because the permissions on its own folders are wrong. In Terminal:

1. Restore ownership to your user account:
   sudo chown -R $console_user /opt/homebrew
2. Verify that Homebrew works:
   brew update && brew upgrade

macOS will ask for your password at step 1. If that does not help, or you also have Homebrew in /usr/local, contact #it-support. Do not run chown on /usr/local yourself because other software lives there." \
            "brew-perm-blocked"
    fi
fi

if [[ ${#DEVTOOLS_BLOCKED_PKGS[@]} -gt 0 ]]; then
    log "[REPORT] Blocked by developer tools (CLT/Xcode), no Self Service alert sent: ${(j:, :)${(u)DEVTOOLS_BLOCKED_PKGS}}"
fi
if [[ ${#GLOBAL_FAILED_PKGS[@]} -gt 0 ]]; then
    UNIQUE_FAILED=(${(u)${GLOBAL_FAILED_PKGS:|DEVTOOLS_BLOCKED_PKGS}})
    FAILED_STR=${(j:, :)UNIQUE_FAILED}
    if [[ -n "$FAILED_STR" ]]; then
        log "[REPORT] The following packages failed to update: $FAILED_STR"
        notify_user "Update Incomplete" \
            "The following packages could not be updated automatically: $FAILED_STR. Please try updating via MDM Self Service or check your network connection." \
            "brew-update-incomplete"
    fi
fi

if [[ "$FORMULA_ERROR" -eq 1 ]]; then
    log "=== Global Remediation Completed with FORMULA ERRORS ==="
    exit 1
else
    log "=== Global Remediation Complete ==="
    exit 0
fi
