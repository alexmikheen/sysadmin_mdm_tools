#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
# Licensed under the MIT License. See LICENSE in the project root for details.
#
# Description: Install Homebrew on Apple Silicon for the active console user, or run a full upgrade if Homebrew already exists.
# Dependencies: macOS built-ins (git, dscl, id, softwareupdate, xcrun, xcodebuild, caffeinate, sudo, launchctl, profiles, osascript), MDM agent CLI (optional).
# Expected Result: Installs Homebrew at /opt/homebrew and writes /etc/paths.d/homebrew. Upgrades all unpinned formulae and non-MDM casks when already installed. Exits 1 on hard errors or failed upgrades.
# Required Permissions: root (MDM execution context).
# Inputs: Optional BREW_HELP_URL environment variable for MDM alert help links.
# Outputs: Status messages to stdout.
# Logs Place: /var/log/brew-install.log.
# Rollback: Delete /opt/homebrew/Homebrew, /opt/homebrew/bin/brew, and /etc/paths.d/homebrew. See https://docs.brew.sh/FAQ#how-do-i-uninstall-homebrew for full removal.
# Safety Notes: Skips when no console user is active or on non-arm64 Macs. Displays a blocking warning before upgrading an existing install. Creates the CLT marker with O_EXCL and runs all git operations as the console user.
# Known Limitations: /etc/paths.d/homebrew applies to new login shells only. Requires network access to github.com.
# Credit: Core directory setup adapted from Kandji's MIT-licensed InstallHomebrew.zsh and the official Homebrew installer.

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

set -e
set -u
set -o pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

LOG_FILE="/var/log/brew-install.log"
if [[ ! -w "$(/usr/bin/dirname "$LOG_FILE")" || ( -e "$LOG_FILE" && ! -w "$LOG_FILE" ) ]]; then
    LOG_FILE="/tmp/$(/usr/bin/basename "$LOG_FILE")"
fi
/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")"

if [[ -f "$LOG_FILE" ]]; then
    /usr/bin/tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && /bin/mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi

exec > >(/usr/bin/tee -a "$LOG_FILE") 2>&1

log() { echo "[$(/bin/date '+%Y-%m-%d %H:%M:%S')] $1"; }

# Stop starting new cask upgrades after 45 minutes because MDM agents terminate scripts at 60 minutes.
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

time_budget_exceeded() {
    (( $(/bin/date +%s) - SCRIPT_START_EPOCH > TIME_BUDGET_SECONDS ))
}

log "=== Starting Homebrew Install/Repair ==="

console_user=$(/usr/bin/stat -f%Su /dev/console)
if [[ -z "$console_user" || "$console_user" == "root" || "$console_user" == "loginwindow" || "$console_user" == "_mbsetupuser" ]]; then
    log "No active console user found (got '${console_user:-<empty>}'). Skipping."
    exit 0
fi

if ! /usr/bin/dscl . -read "/Users/$console_user" >/dev/null 2>&1; then
    log "[ERROR] Console user '$console_user' is not a valid local user."
    exit 1
fi
user_uid=$(/usr/bin/id -u "$console_user")
user_home=$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory | /usr/bin/awk '{print $2}')
if [[ -z "$user_home" ]]; then
    log "[ERROR] Could not resolve home directory for '$console_user'."
    exit 1
fi
log "Console user: $console_user"

host_arch=$(/usr/bin/uname -m)
if [[ "$host_arch" != "arm64" ]]; then
    log "Host architecture is '$host_arch', not arm64. This script only supports native Apple Silicon Homebrew (/opt/homebrew) — skipping."
    exit 0
fi
brew_prefix="/opt/homebrew"
brew_bin="$brew_prefix/bin/brew"
log "Target Homebrew prefix: $brew_prefix"

BREW_ENV_FILE="/etc/homebrew/brew.env"
/bin/mkdir -p /etc/homebrew
/usr/bin/touch "$BREW_ENV_FILE"
for kv in HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1; do
    key="${kv%%=*}"
    /usr/bin/grep -q "^${key}=" "$BREW_ENV_FILE" || echo "$kv" >> "$BREW_ENV_FILE"
done
/bin/chmod 644 "$BREW_ENV_FILE"

BREW_ENV=(HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1)

run_as_console_user() {
    /usr/bin/caffeinate -i /bin/launchctl asuser "$user_uid" \
        /usr/bin/sudo -u "$console_user" \
        /usr/bin/env HOME="$user_home" "${BREW_ENV[@]}" \
        "$brew_bin" "$@" </dev/null
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

warn_user_blocking() {
    local title="$1" msg="$2" waited=0 pid
    local -a extra_args
    extra_args=()
    [[ -n "$BREW_HELP_URL" ]] && extra_args+=(--help-url "$BREW_HELP_URL")
    if [[ -n "$MDM_AGENT_BIN" ]]; then
        "$MDM_AGENT_BIN" display-alert --title "$title" --message "$msg" "${extra_args[@]}" >/dev/null 2>&1 &
    else
        /bin/launchctl asuser "$user_uid" /usr/bin/sudo -u "$console_user" /usr/bin/osascript \
            -e 'on run argv' \
            -e 'display dialog (item 1 of argv) with title (item 2 of argv) buttons {"OK"} default button 1 giving up after 120' \
            -e 'end run' \
            -- "$msg" "$title" >/dev/null 2>&1 &
    fi
    pid=$!
    while kill -0 "$pid" 2>/dev/null && (( waited < 120 )); do
        /bin/sleep 5; waited=$(( waited + 5 ))
    done
    if kill -0 "$pid" 2>/dev/null; then
        log "Warning dialog still open after ${waited}s — proceeding with the upgrade anyway."
    fi
    return 0
}

notify_user() {
    local title="$1" msg="$2"
    local -a extra_args
    extra_args=()
    [[ -n "$BREW_HELP_URL" ]] && extra_args+=(--help-url "$BREW_HELP_URL")
    if [[ -n "$MDM_AGENT_BIN" ]]; then
        "$MDM_AGENT_BIN" display-alert --title "$title" --message "$msg" "${extra_args[@]}" --no-wait >/dev/null 2>&1 || true
    else
        /bin/launchctl asuser "$user_uid" /usr/bin/sudo -u "$console_user" /usr/bin/osascript \
            -e 'on run argv' \
            -e 'display notification (item 1 of argv) with title (item 2 of argv)' \
            -e 'end run' \
            -- "$msg" "$title" 2>/dev/null || true
    fi
}

normalize_name() { print -r -- "$1" | /usr/bin/tr '[:upper:]' '[:lower:]' | /usr/bin/tr -cd 'a-z0-9'; }

mdm_manages_cask() {
    local cask="$1" appname="" norm_cask norm_app norm_name name a mf
    local -a meta_files
    [[ -z "$MDM_AUTOAPP_NAMES" ]] && return 1
    meta_files=(
        "$brew_prefix/Caskroom/$cask"/.metadata/*/*/Casks/*.rb(N.)
        "$brew_prefix/Caskroom/$cask"/.metadata/*/*/Casks/*.json(N.)
        "$brew_prefix/Caskroom/$cask"/.metadata/*/*/*/Casks/*.rb(N.)
        "$brew_prefix/Caskroom/$cask"/.metadata/*/*/*/Casks/*.json(N.)
    )
    for mf in "${meta_files[@]}"; do
        [[ -f "$mf" && ! -L "$mf" && ! -p "$mf" ]] || continue
        appname=$(/usr/bin/sudo -u "$console_user" /usr/bin/grep -hoE '"[^"]+\.app"' "$mf" 2>/dev/null \
            | /usr/bin/head -n 1 | /usr/bin/tr -d '"' || true)
        [[ -n "$appname" ]] && break
    done
    appname="${appname##*/}"; appname="${appname%.app}"
    norm_cask=$(normalize_name "$cask")
    norm_app=$(normalize_name "$appname")
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        norm_name=$(normalize_name "$name")
        [[ -z "$norm_name" ]] && continue
        for a in "$norm_cask" "$norm_app"; do
            [[ -z "$a" ]] && continue
            [[ "$a" == "$norm_name" ]] && return 0
            if (( ${#a} >= 4 )) && [[ "$norm_name" == *"$a"* ]]; then
                return 0
            fi
        done
    done <<< "$MDM_AUTOAPP_NAMES"
    return 1
}

log_brew_output() {
    local indent="$1" line
    print -r -- "$2" | /usr/bin/tr '\r' '\n' | while IFS= read -r line; do
        [[ "$line" =~ '^[[:space:]#=O-]*([0-9.]+%)?[[:space:]]*$' && "$line" == *[#=O-]* ]] && continue
        log "${indent}${line}"
    done
    return 0
}

update_homebrew() {
    UPDATE_EXIT=0
    UPDATE_OUTPUT=$(run_as_console_user update --force 2>&1) || UPDATE_EXIT=$?
    log_brew_output "    " "$UPDATE_OUTPUT"
}

upgrade_formulae() {
    UPGRADE_EXIT=0
    UPGRADE_OUTPUT=$(run_as_console_user upgrade --formula 2>&1) || UPGRADE_EXIT=$?
    log_brew_output "    " "$UPGRADE_OUTPUT"
}

PATHS_D_FILE="/etc/paths.d/homebrew"
ensure_system_path() {
    if [[ -f "$PATHS_D_FILE" && ! -L "$PATHS_D_FILE" ]] && /usr/bin/grep -qFx "$brew_prefix/bin" "$PATHS_D_FILE"; then
        log "$brew_prefix/bin already in $PATHS_D_FILE."
        return 0
    fi
    log "Adding $brew_prefix/bin to the system PATH via $PATHS_D_FILE..."
    /bin/rm -f "$PATHS_D_FILE"
    echo "$brew_prefix/bin" > "$PATHS_D_FILE"
    /bin/chmod 644 "$PATHS_D_FILE"
}

if [[ -x "$brew_bin" ]]; then
    log "Homebrew already installed at $brew_bin."
    ensure_system_path
    log "Running 'brew update'..."
    update_homebrew
    if [[ "$UPDATE_EXIT" -ne 0 ]]; then
        case "$(devtools_verdict "$UPDATE_OUTPUT")" in
            license)
                log "[FIX] Xcode license not accepted blocks git and brew update — accepting it as root..."
                if repair_xcode_license; then
                    log "[OK] Xcode license accepted — retrying brew update once..."
                    update_homebrew
                else
                    log "[WARN] 'xcodebuild -license accept' failed — manual acceptance needed on this Mac."
                fi
                ;;
            clt)
                log "[FIX] Missing or outdated Command Line Tools block git and brew update — reinstalling CLT via softwareupdate..."
                if repair_clt; then
                    log "[OK] Retrying brew update once..."
                    update_homebrew
                fi
                ;;
        esac
    fi
    if [[ "$UPDATE_EXIT" -ne 0 ]]; then
        log "[ERROR] '$brew_bin' failed to run as $console_user (broken existing install, missing developer tools, or no network). Needs manual repair — leaving the existing install untouched."
        exit 1
    fi

    PROFILES_RAW=$(/usr/bin/profiles -C -o stdout 2>/dev/null || true)
    MDM_AUTOAPP_NAMES=$(print -r -- "$PROFILES_RAW" \
        | /usr/bin/awk -F'"' '
            /ProfileDisplayName =/  {name=$2; sub(/ Settings$/,"",name)}
            /ProfileIdentifier = "com\.kandji\.profile\.autoapp\./ {print name}' \
        | /usr/bin/sort -u || true)
    MDM_AUTOAPP_COUNT=$(print -r -- "$MDM_AUTOAPP_NAMES" | /usr/bin/grep -c . || true)
    log "MDM Auto Apps on this Mac: $MDM_AUTOAPP_COUNT"

    warn_user_blocking "Homebrew update" "Homebrew will now update and upgrade every formula and cask on this Mac. Apps installed through Homebrew may be closed and relaunched during the upgrade — save your work first. This can take a while; you can keep working in the meantime."

    FAILED=0
    FAILED_ITEMS=()

    log "Upgrading all unpinned formulae..."
    upgrade_formulae
    case "$(devtools_verdict "$UPGRADE_OUTPUT")" in
        license)
            log "[FIX] Xcode license not accepted blocks brew — accepting it as root..."
            if repair_xcode_license; then
                log "[OK] Xcode license accepted — retrying formula upgrade once..."
                upgrade_formulae
            else
                log "[WARN] 'xcodebuild -license accept' failed — manual acceptance needed on this Mac."
            fi
            ;;
        clt)
            log "[FIX] Outdated or missing Command Line Tools block brew — reinstalling CLT via softwareupdate..."
            if repair_clt; then
                log "[OK] Retrying formula upgrade once..."
                upgrade_formulae
            fi
            ;;
        xcode)
            XCODE_DETAIL=$(xcode_outdated_detail "$UPGRADE_OUTPUT")
            log "[WARN] $XCODE_DETAIL — update Xcode from the App Store, or delete it so brew uses the Command Line Tools."
            notify_user "Xcode update required" "Homebrew cannot build packages: $XCODE_DETAIL. Update Xcode from the App Store, or delete it so Homebrew uses the Command Line Tools instead."
            ;;
    esac
    UPGRADED_FORMULAE=(${(f)"$(/usr/bin/grep -E '^==> Upgrading [^0-9]' <<< "$UPGRADE_OUTPUT" | /usr/bin/sed -E 's/^==> Upgrading //; s/.* dependency: //; s/ .*//' | /usr/bin/sort -u || true)"})
    if [[ "$UPGRADE_EXIT" -ne 0 ]]; then
        FAILED=1
        log "[ERROR] Formula upgrade failed (exit code: $UPGRADE_EXIT)."
        while IFS= read -r pkg; do
            [[ -n "$pkg" ]] && FAILED_ITEMS+=("$pkg")
        done <<< "$(run_as_console_user outdated --formula -q 2>/dev/null || true)"
        UPGRADED_FORMULAE=(${UPGRADED_FORMULAE:|FAILED_ITEMS})
    fi

    # Leave HOMEBREW_NO_UPGRADE_QUIT_CASKS unset because the user received a blocking warning above.
    UPGRADED_CASKS=()
    SKIPPED_MDM_CASKS=()
    DEFERRED_CASKS=()
    OUTDATED_CASKS=""
    if [[ "$MDM_AUTOAPP_COUNT" -eq 0 ]]; then
        FAILED=1
        FAILED_ITEMS+=("casks (MDM Auto App detection returned nothing)")
        log "[ERROR] 'profiles -C -o stdout' listed no MDM Auto Apps — cannot tell brew casks from MDM-managed apps, skipping the cask phase."
    else
        log "Upgrading outdated casks (greedy-auto-updates, MDM-managed ones skipped)..."
        OUTDATED_CASKS=$(run_as_console_user outdated --cask --greedy-auto-updates -q 2>/dev/null || true)
    fi
    while IFS= read -r cask; do
        [[ -z "$cask" ]] && continue
        if mdm_manages_cask "$cask"; then
            log "    [SKIP-MDM] $cask is an MDM Auto App — leaving it to MDM."
            SKIPPED_MDM_CASKS+=("$cask")
            continue
        fi
        if time_budget_exceeded; then
            log "    [INFO] 45-min time budget reached — deferring $cask to the next run."
            DEFERRED_CASKS+=("$cask")
            continue
        fi
        log "    ==> Upgrading cask $cask"
        CASK_EXIT=0
        CASK_OUTPUT=$(run_as_console_user upgrade --cask --greedy-auto-updates "$cask" 2>&1) || CASK_EXIT=$?
        log_brew_output "        " "$CASK_OUTPUT"
        if [[ "$CASK_EXIT" -eq 0 ]]; then
            UPGRADED_CASKS+=("$cask")
        else
            FAILED=1
            FAILED_ITEMS+=("$cask")
            log "    [ERROR] Cask $cask failed to upgrade (exit code: $CASK_EXIT)."
        fi
    done <<< "$OUTDATED_CASKS"

    log "Running 'brew cleanup'..."
    run_as_console_user cleanup || true

    UPGRADED_ALL=("${UPGRADED_FORMULAE[@]}" "${UPGRADED_CASKS[@]}")
    if (( ${#UPGRADED_ALL[@]} == 0 )); then
        SUMMARY="Nothing was outdated — Homebrew is already up to date."
    else
        SUMMARY="Upgraded ${#UPGRADED_FORMULAE[@]} formula(e) and ${#UPGRADED_CASKS[@]} cask(s): ${(j:, :)UPGRADED_ALL}."
    fi
    (( ${#SKIPPED_MDM_CASKS[@]} > 0 )) && SUMMARY="$SUMMARY Left to MDM (managed apps): ${(j:, :)SKIPPED_MDM_CASKS}."
    (( ${#DEFERRED_CASKS[@]} > 0 )) && SUMMARY="$SUMMARY Not started (time budget), run again: ${(j:, :)DEFERRED_CASKS}."
    log "[REPORT] $SUMMARY"
    if [[ "$FAILED" -eq 1 ]]; then
        FAILED_STR=${(j:, :)${(u)FAILED_ITEMS}}
        log "[REPORT] Failed to upgrade: ${FAILED_STR:-see log}"
        notify_user "Homebrew update finished with errors" "$SUMMARY Could not upgrade: ${FAILED_STR:-see /var/log/brew-install.log}."
        log "=== Homebrew Update & Upgrade Completed with ERRORS (already present) ==="
        exit 1
    fi
    notify_user "Homebrew is up to date" "$SUMMARY"
    log "=== Homebrew Update & Upgrade Complete (already present) ==="
    exit 0
fi

log "Homebrew not found at $brew_prefix. Proceeding with install."

if [[ -L "$brew_prefix" ]]; then
    log "[ERROR] $brew_prefix is a symlink. Aborting."
    exit 1
fi
if [[ -d "$brew_prefix" ]]; then
    local_entries=( "$brew_prefix"/*(NDY1) )
    if (( ${#local_entries[@]} > 0 )); then
        log "[ERROR] $brew_prefix exists and is not empty without an executable $brew_bin. Aborting."
        exit 1
    fi
fi

XCRUN_OUT=$(/usr/bin/xcrun --version 2>&1) || XCRUN_OUT="FAILED: $XCRUN_OUT"
if [[ "$XCRUN_OUT" != FAILED:* ]]; then
    log "Xcode CLI Tools already present."
elif [[ "$XCRUN_OUT" == *license* ]]; then
    log "[FIX] xcrun is blocked by the Xcode license — accepting it as root..."
    if ! repair_xcode_license || ! /usr/bin/xcrun --version >/dev/null 2>&1; then
        log "[ERROR] Xcode license could not be accepted, or xcrun still fails after it. Open Xcode once or run 'sudo xcodebuild -license', then rerun. Aborting."
        exit 1
    fi
else
    log "Xcode CLI Tools not found. Installing..."
    if ! repair_clt; then
        log "[ERROR] Could not install the Xcode CLI Tools via softwareupdate (catalog unreachable, label format changed, or the download failed). git needs CLT — aborting before creating anything under $brew_prefix."
        exit 1
    fi
    if ! /usr/bin/xcrun --version >/dev/null 2>&1; then
        log "[ERROR] softwareupdate reported success but xcrun still isn't usable. Aborting."
        exit 1
    fi
fi

log "Creating Homebrew directories under $brew_prefix..."
/bin/mkdir -p "$brew_prefix"
if [[ -L "$brew_prefix" ]]; then
    log "[ERROR] $brew_prefix is a symlink. Aborting."
    exit 1
fi
/usr/sbin/chown "$console_user:admin" "$brew_prefix"
/bin/chmod 0755 "$brew_prefix"
/usr/bin/sudo -u "$console_user" /bin/mkdir -p \
    "$brew_prefix/Caskroom" "$brew_prefix/Cellar" "$brew_prefix/Frameworks" \
    "$brew_prefix/Homebrew" "$brew_prefix/bin" "$brew_prefix/etc" "$brew_prefix/include" \
    "$brew_prefix/lib" "$brew_prefix/opt" "$brew_prefix/sbin" "$brew_prefix/share/doc" \
    "$brew_prefix/share/man/man1" "$brew_prefix/share/zsh" "$brew_prefix/share/zsh/site-functions" \
    "$brew_prefix/var/homebrew/linked"

GIT_SAFE_OPTS=(-c core.autocrlf=false -c core.symlinks=true)
run_git_as_console_user() {
    /usr/bin/sudo -H -u "$console_user" /usr/bin/git "${GIT_SAFE_OPTS[@]}" "$@"
}

log "Fetching Homebrew via git (a plain tarball extraction leaves no .git, which breaks 'brew update' later)..."
if [[ ! -d "$brew_prefix/Homebrew/.git" ]]; then
    run_git_as_console_user -C "$brew_prefix/Homebrew" init --quiet
    run_git_as_console_user -C "$brew_prefix/Homebrew" remote add origin "https://github.com/Homebrew/brew"
else
    run_git_as_console_user -C "$brew_prefix/Homebrew" remote set-url origin "https://github.com/Homebrew/brew" 2>/dev/null \
        || run_git_as_console_user -C "$brew_prefix/Homebrew" remote add origin "https://github.com/Homebrew/brew"
fi
run_git_as_console_user -C "$brew_prefix/Homebrew" config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"
run_git_as_console_user -C "$brew_prefix/Homebrew" config --bool core.autocrlf false
run_git_as_console_user -C "$brew_prefix/Homebrew" config --bool core.symlinks true

/usr/bin/caffeinate -i /usr/bin/sudo -H -u "$console_user" \
    /usr/bin/git "${GIT_SAFE_OPTS[@]}" -C "$brew_prefix/Homebrew" fetch --quiet --force --tags origin

latest_tag=$(run_git_as_console_user -C "$brew_prefix/Homebrew" tag --list --sort="-version:refname" | /usr/bin/head -n1)
if [[ -z "$latest_tag" ]]; then
    log "[ERROR] Failed to determine the latest Homebrew/brew git tag. Aborting."
    exit 1
fi
run_git_as_console_user -C "$brew_prefix/Homebrew" checkout --quiet --force -B stable "$latest_tag"

if [[ ! -f "$brew_prefix/Homebrew/bin/brew" ]]; then
    log "[ERROR] Homebrew binary not found after checkout. Aborting."
    exit 1
fi

log "Linking $brew_bin..."
/usr/bin/sudo -u "$console_user" /bin/ln -sf ../Homebrew/bin/brew "$brew_bin"

ensure_system_path

log "Running 'brew update --force --quiet' as $console_user..."
run_as_console_user update --force --quiet

log "Running 'brew cleanup' as $console_user..."
run_as_console_user cleanup || true

log "Running 'brew doctor' to validate the install..."
if run_as_console_user doctor; then
    log "Homebrew installation complete. System is ready to brew."
else
    log "[WARN] 'brew doctor' reported issues (see above). Some warnings are expected and non-blocking."
fi

log "NOTE: PATH takes effect in new Terminal windows/login shells only (system-wide via /etc/paths.d)."
log "=== Homebrew Install/Repair Complete ==="
exit 0
