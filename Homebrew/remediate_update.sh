#!/usr/bin/env zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
# Licensed under the MIT License. See LICENSE in the project root for details.
#
# Description: Global remediation script to update all unpinned Homebrew packages (formulae and casks) on macOS, run from a root MDM execution context.
# Dependencies: stat, awk, dscl, brew, pmset, caffeinate, osascript, profiles, softwareupdate, codesign, and a site-specific MDM agent CLI at /usr/local/bin/mdm-agent (optional, used only for user notifications).
# Expected Result: all unpinned formulae upgraded. Casks: skipped while running, deferred past budget, or kept under brew on a team mismatch; broken receipts fixed by forced reinstall; MDM-managed ones migrated out (record removed, app untouched). Exit 1: formula failure, brew cannot write its own prefix, Auto App detection broken. Warn only: casks, leftovers, stale kegs, doc/completion trees.
# Required Permissions: root (MDM execution context)
# Inputs: none
# Outputs: Status to stdout
# Logs Place: /var/log/brew-global-remediation.log
# Rollback: Manual downgrade via 'brew install <package>@<version>'
# Safety Notes: aborts below 20% battery; caffeinate holds off sleep. Tap trust per item only. Team ID gates MDM-managed migration. 45-min budget (agent kills at 60). User-owned deletes drop to the console user; brew always runs with stdin closed.

set -e
set -u
set -o pipefail

# Force Homebrew to run non-interactively (crucial for v6.0.0+) and hide hints
export HOMEBREW_NO_INTERACTIVE=1
export HOMEBREW_NO_ENV_HINTS=1
# Never quit a running GUI app during a cask upgrade (belt-and-braces over the pgrep skip below).
export HOMEBREW_NO_UPGRADE_QUIT_CASKS=1

LOG_FILE="/var/log/brew-global-remediation.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }

log "=== Starting Global Brew Vulnerability Remediation (Multi-Arch) ==="

# Kandji kills scripts at 60 min, so stop STARTING heavy work at 45; the daily run finishes the rest.
SCRIPT_START_EPOCH=$(/bin/date +%s)
TIME_BUDGET_SECONDS=2700

BATT_INFO=$(pmset -g batt)
if grep -q "Battery Power" <<< "$BATT_INFO" || grep -q "Discharging" <<< "$BATT_INFO"; then
    BATT_PCT=$(echo "$BATT_INFO" | grep -oE '[0-9]+%' | tr -d '%' | head -n 1 || true)
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

# --- BREW GLOBAL CONFIG (brew.env) ---
# The runners pass HOMEBREW_* explicitly, but brew re-execs itself (and spawns vendor installers) and an inner process can lose them. brew always reads brew.env at startup regardless of invocation context, so persist them there too. Append-only: never clobber foreign keys.
BREW_ENV_FILE="/etc/homebrew/brew.env"
/bin/mkdir -p /etc/homebrew
/usr/bin/touch "$BREW_ENV_FILE"
# Trust is per item in the prefix loop — drop the deprecated global opt-out an old version may have set.
/usr/bin/sed -i '' '/^HOMEBREW_NO_REQUIRE_TAP_TRUST=/d' "$BREW_ENV_FILE" 2>/dev/null || true
for kv in HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_UPGRADE_QUIT_CASKS=1; do
    key="${kv%%=*}"
    /usr/bin/grep -q "^${key}=" "$BREW_ENV_FILE" || echo "$kv" >> "$BREW_ENV_FILE"
done
/bin/chmod 644 "$BREW_ENV_FILE"

candidate_brews=(
  /opt/homebrew/bin/brew   # Apple Silicon
  /usr/local/bin/brew      # Intel
)

# ARM: as-console-user runs brew's startup repo self-check (git -C /opt/homebrew describe/rev-parse)
# as ROOT before it drops — executing the user-writable Cellar git as root. Drop to the console
# user FIRST (same pattern the Rosetta runner uses) so brew and its git preflight run as the user.
# `</dev/null` on BOTH runners is load-bearing: the cask/relink loops feed `while read`
# from a here-string, and brew inheriting that stdin swallows the rest of the list and ends the loop
# early, silently skipping casks. It also turns an unexpected prompt into a fast failure, not a hang.
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

# Intel/Rosetta: same drop, plus the x86_64 arch prefix.
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

# Dispatcher: pick the right runner based on which prefix we're working with.
run_brew() {
    local brew_bin="$1"; shift
    local is_rosetta="$1"; shift
    if [[ "$is_rosetta" == "1" ]]; then
        run_brew_rosetta "$brew_bin" "$@"
    else
        run_brew_arm "$brew_bin" "$@"
    fi
}

# Checked before each prefix, the CLT install and each cask, so runs end cleanly.
time_budget_exceeded() {
    (( $(/bin/date +%s) - SCRIPT_START_EPOCH > TIME_BUDGET_SECONDS ))
}

# --- PERMISSION STATE (NO-CHOWN RATIONALE — the anchor other sections point back to) ---
# Declared here because under `set -u` a `+=` on an unset name aborts. USER-FACING → FORMULA_ERROR (brew cannot write its own working state, only a reinstall fixes it):
#   PERM_BLOCKED/_ARM/_INTEL/_PATHS; PERM_ATTEMPT_BLOCKED/_PATHS is one attempt's scratch, promoted by the prefix loop after the retry chain.
# IT-FACING ONLY, never FORMULA_ERROR or an alert: PERM_LEFTOVER_PATHS (declined root delete), PERM_STALE_KEGS (cleanup could not remove), PERM_COSMETIC_PATHS/_ATTEMPT_COSMETIC (doc/completion   trees — link targets, not working state: brew warns "Could not symlink ..." and exits 0).
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

# Delete a user-owned path (lock dir, download cache, Caskroom record) without giving root an arbitrary-delete primitive. The user owns the PARENT dirs, and though `rm -rf` won't follow a symlink passed as its argument, the kernel resolves symlinked parent components — so a swapped parent redirects a root delete out of the prefix. As the user it is race-free: a redirect can only reach what they could already delete themselves. No root fallback.
remove_user_path() {
    local target="$1"
    [[ -e "$target" || -L "$target" ]] || return 0
    /usr/bin/sudo -u "$console_user" /bin/rm -rf "$target" 2>/dev/null && return 0
    [[ -e "$target" || -L "$target" ]] || return 0
    # The old root fallback string-checked the resolved path then let root re-walk it — but the user can swap a mid-path component between check and delete. Unclosable in shell; report instead.
    PERM_LEFTOVER_PATHS+=("$target")
    log "    [WARN] '$target' is not removable as $console_user (root-owned leftovers) — NOT removing as root; reporting instead."
    return 1
}

# Extract the owning tap from a keg/cask INSTALL_RECEIPT.json (.source.tap). Root can always read these; brew won't even NAME untrusted-tap items.
receipt_tap() {
    /usr/bin/grep -oE '"tap"[[:space:]]*:[[:space:]]*"[^"]+"' "$1" 2>/dev/null \
        | /usr/bin/head -n 1 | /usr/bin/sed -E 's/.*"([^"]+)"$/\1/' || true
}

# `brew upgrade --formula` into UPGRADE_OUTPUT / UPGRADE_EXIT. One definition for the initial pass and every retry (CLT, cache, sibling trust) so they cannot drift. The permission scan lives HERE, not at a call site: each retry reassigns UPGRADE_OUTPUT, and an attempt that clears the first
# blocker can hit a permission wall a per-call-site scan would miss. In-prefix paths split by CLASS — share/man|info|doc|zsh|fish|bash-completion and etc/bash_completion.d are link targets → COSMETIC (IT-facing); anything else (Cellar, opt, var, lib, bin, bare `share`) → BLOCKING (user-facing). Records THIS attempt only; the prefix loop promotes the final verdict.
run_formula_upgrade() {
    local brew_bin="$1" is_rosetta="$2" line p perm_paths
    UPGRADE_EXIT=0
    UPGRADE_OUTPUT=$(run_brew "$brew_bin" "$is_rosetta" upgrade --formula 2>&1) || UPGRADE_EXIT=$?
    while IFS= read -r line; do
        log "    $line"
    done <<< "$UPGRADE_OUTPUT"

    # Per attempt, never accumulated: a blocker a retry clears must not keep the device red.
    # Latching here used to pop "Homebrew needs a reinstall" after the cache repair had already fixed it.
    PERM_ATTEMPT_BLOCKED=0
    PERM_ATTEMPT_PATHS=()
    PERM_ATTEMPT_COSMETIC=()

    # Two message shapes, because brew reports permission failures both ways:
    #   Ruby errno: "Permission denied @ <op> - <path>"  (apply2files, dir_s_mkdir, rb_sysopen, ...)
    #   brew's own: "<path> is not writable"             (e.g. after "Could not symlink share/...")
    perm_paths=$( { grep -oE 'Permission denied @ [a-z_0-9]+ - [^[:space:]]+' <<< "$UPGRADE_OUTPUT" \
                      | sed -E 's/^Permission denied @ [a-z_0-9]+ - //' || true
                    grep -oE '/[^[:space:]]+ is not writable' <<< "$UPGRADE_OUTPUT" \
                      | sed 's/ is not writable$//' || true; } | sort -u || true)
    [[ -z "$perm_paths" ]] && return 0

    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        # Only in-prefix means "brew cannot write its own prefix". brew also names paths it merely touched — usually a ~/Library/Caches/Homebrew entry the cache repair clears this same run.
        if [[ -z "${BREW_PREFIX:-}" || "$p" != "$BREW_PREFIX"/* ]]; then
            log "    [INFO] permission complaint outside the brew prefix — not treated as a broken install: $p"
            continue
        fi
        # These trees are only symlink targets: an unwritable one warns "Could not symlink ..." while brew exits 0, fully upgraded. Counting them as broken made /usr/local devices fail daily and pop "migrate to Apple Silicon" over man pages. `case` with no match returns 0 → set -e safe.
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

# Notify the console user via the Kandji agent, else osascript. Optional 3rd arg is an Kandji suppression key, giving the alert a "don't show again" scoped to it (no effect on the fallback). Keying it "brew-update-<cask>-<ver>" caps it at one alert per version: muting kills the daily repeats, and the next release gets a fresh key → one fresh alert.
notify_user() {
    local title="$1"
    local msg="$2"
    local suppress_key="${3:-}"
    local -a extra_args
    extra_args=()
    [[ -n "$suppress_key" ]] && extra_args=(--suppression-key "$suppress_key")
    if [[ -x /usr/local/bin/mdm-agent ]]; then
        /usr/local/bin/mdm-agent display-alert \
            --title "$title" \
            --message "$msg" \
            "${extra_args[@]}" \
            --no-wait 2>/dev/null || true
    else
        /bin/launchctl asuser "$user_uid" /usr/bin/osascript \
            -e "display notification \"$msg\" with title \"$title\"" 2>/dev/null || true
    fi
}

# --- Kandji OWNERSHIP CHECK ---
# `kandji library` is not scriptable, so Kandji ownership is inferred. Either signal means "Kandji owns this app — never force brew over it":
#   1. Auto App profiles — per-device and self-updating: identifier com.kandji.profile.autoapp.<uuid> (a VENDOR string — do NOT rebrand it to Kandji, the agent writes it literally), display name "<App> Settings".
#   2. Cask-loop path heuristic: brew's "already an App at" pointing outside its own Caskroom means someone else installed the live copy.
# Auto App names + signing Team IDs from this Mac's profiles. ProfileDisplayName precedes ProfileIdentifier per dict, so awk carries the last name seen. Team IDs come in three shapes, all required: {RuleType=TeamIdentifier; RuleValue=X}, inline "TeamIdentifier = X;", and "certificate leaf[subject.OU]=X" in PPPC CodeRequirements. Teams GATE migration — a name match proves nothing: cask "gemini" is MacPaw's duplicate finder, not Google's "Gemini", and was once migrated over it.
# Records are TAB-delimited, " Settings" stripped at capture. `print -r --` everywhere this dump is re-piped, NEVER `echo`: zsh's echo eats backslash escapes — measured, 2046 lines → 493, 25 apps → 14.
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

# Sanity floor on the detector. Zero Auto Apps used to be a plain WARN, so a broken matcher looked exactly like a device that has none, so a fleet-wide break would ship silently.
# Deliberately INDEPENDENT of the awk matcher — a plain grep, without the -F'"' splitting and carried-name state that are the fragile parts; a check reusing that pattern could not detect it being wrong. Do NOT probe 'com.kandji.profile.' (an earlier version did): mdmprofile, pppc, certificate.*, custom.*, firewall.*, filevault.*, wifi.*, restrictions.* all match it on EVERY enrolled Mac, which failed healthy no-Auto-App Macs daily and made the genuine-empty branch unreachable.
AUTOAPP_PROFILE_COUNT=$(print -r -- "$PROFILES_RAW" \
    | /usr/bin/grep -c 'ProfileIdentifier = "com\.kandji\.profile\.autoapp\.' || true)
AUTOAPP_NAME_COUNT=$(print -r -- "$MDM_AUTOAPP_NAMES" | /usr/bin/grep -c . || true)
if [[ -z "$PROFILES_RAW" ]]; then
    # Running as root under MDM there is always at least the enrolment profile, so an empty dump means the probe itself failed, not "no profiles".
    AUTOAPP_DETECT_BROKEN="'profiles -C -o stdout' returned nothing (not root, or profiles unreadable)"
    log "[ERROR] $AUTOAPP_DETECT_BROKEN — Auto App detection is DOWN, every Kandji-managed cask will be treated as brew-managed."
elif (( AUTOAPP_PROFILE_COUNT == 0 )); then
    # Profiles readable, no Auto App profiles at all: a genuine no-Auto-Apps device (fresh enrolment, blueprint without apps). Not an anomaly.
    log "[WARN] No Kandji Auto App profiles on this Mac — no cask will be recognised as Kandji-managed (the path heuristic in the cask loop still applies)."
elif (( AUTOAPP_NAME_COUNT == 0 )); then
    # Unambiguous breakage: the profiles are on disk, the matcher got nothing.
    AUTOAPP_DETECT_BROKEN="$AUTOAPP_PROFILE_COUNT Auto App profile(s) on disk but the matcher extracted no display name"
    log "[ERROR] $AUTOAPP_DETECT_BROKEN — the identifier pattern is stale or the payload shape changed."
else
    log "Kandji Auto Apps detected on this Mac ($AUTOAPP_NAME_COUNT of $AUTOAPP_PROFILE_COUNT profile(s)): $(print -r -- "$MDM_AUTOAPP_NAMES" | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//; s/,/, /g')"
    # A shortfall is suspicious, not proof: two Auto Apps can share a name and `sort -u` folds them.
    # WARN only (greppable, and it would have caught the `echo` regression) so a duplicate cannot turn a healthy Mac red the way the old com.kandji.profile.* probe did.
    if (( AUTOAPP_NAME_COUNT < AUTOAPP_PROFILE_COUNT )); then
        log "[WARN] Auto App matcher extracted $AUTOAPP_NAME_COUNT name(s) from $AUTOAPP_PROFILE_COUNT profile(s) — duplicate display names, or the matcher is partially broken."
    fi
fi

# Lowercase, strip non-alphanumerics: cask "google-chrome" -> "googlechrome", profile name "Google Chrome" -> "googlechrome".
normalize_name() { print -r -- "$1" | /usr/bin/tr '[:upper:]' '[:lower:]' | /usr/bin/tr -cd 'a-z0-9'; }

# Sets MDM_MATCHED_PROFILE to the matched Auto App name so the caller can verify signing teams and log WHAT matched — the gemini incident was undebuggable without it. A return of 0 therefore ALWAYS carries a profile name, which is what lets the caller verify unconditionally.
mdm_manages_cask() {
    local cask="$1"
    local norm_cask norm_name name
    MDM_MATCHED_PROFILE=""
    [[ -z "$MDM_AUTOAPP_NAMES" ]] && return 1
    norm_cask=$(normalize_name "$cask")
    [[ -z "$norm_cask" ]] && return 1
    # One-directional substring: cask token inside profile name, covering drift ("zoom" -> "Zoom Client for Meetings"). Migrating out of brew is safe even with auto-updates off — the Kandji Vulnerability Response policy enforces updates on CVE detection. Same-name products still collide, so the caller gates migration on the signing Team ID.
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        norm_name=$(normalize_name "$name")
        if [[ -n "$norm_name" && "$norm_name" == *"$norm_cask"* ]]; then
            MDM_MATCHED_PROFILE="$name"
            return 0
        fi
    done <<< "$MDM_AUTOAPP_NAMES"
    return 1
}

# --- TAP TRUST (Homebrew 6+) ---
# Since 6.0.0 brew skips untrusted third-party taps ("Skipping X: tap formula is not trusted"), so vendor tools silently stop updating.
GLOBAL_FAILED_PKGS=()
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

    # Guards the whole prefix, not just its cask loop: a formula phase plus a multi-minute CLT install on a second prefix could blow past the 60-min kill mid-operation.
    if time_budget_exceeded; then
        log "==> 45-min time budget reached — deferring $brew_bin and any remaining prefixes to the next daily run."
        break
    fi

    PREFIX_LABEL="$brew_bin$([[ "$IS_ROSETTA" -eq 1 ]] && echo ' (via Rosetta)' || true)"
    log "==> Processing Homebrew Prefix: $PREFIX_LABEL"

    # Can this brew run here at all? Several ways it refuses ("Running Homebrew as root is extremely dangerous", half-uninstalled brew, a prefix the console user cannot execute), and each used to kill the script via set -e on this line, leaving the second prefix unchecked. Now: log, skip, go on.
    BREW_PROBE=""
    BREW_PROBE=$(run_brew "$brew_bin" "$IS_ROSETTA" --prefix 2>&1) || {
        log "    [ERROR] brew at $brew_bin cannot run in this context — skipping this prefix. Reason: $(echo "$BREW_PROBE" | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' ')"
        continue
    }
    # Last ABSOLUTE-PATH line, not `tail -n 1`: brew may append an env hint after the prefix, which would then fail the sanity check below and silently skip a healthy prefix.
    BREW_PREFIX=$(echo "$BREW_PROBE" | /usr/bin/grep '^/' | /usr/bin/tail -n 1 || true)
    if [[ "$BREW_PREFIX" != /opt/homebrew* && "$BREW_PREFIX" != /usr/local* ]]; then
        log "    [ERROR] Unexpected BREW_PREFIX '$BREW_PREFIX' for $brew_bin. Skipping for safety."
        continue
    fi

    LOCK_DIR="$BREW_PREFIX/var/homebrew/locks"
    if [[ -d "$LOCK_DIR" ]]; then
        log "    Clearing stale lock files..."
        remove_user_path "$LOCK_DIR" || true
    fi

    log "    Updating formula definitions..."
    run_brew "$brew_bin" "$IS_ROSETTA" update 2>&1 | while IFS= read -r line; do
        log "    $line"
    done || true

    # Read installed items from on-disk receipts, NOT `brew list --full-name`: brew refuses to even NAME untrusted-tap items (formulae vanish; casks lose their tap prefix so `grep '/'` drops them), so exactly the items needing trust are invisible there — a catch-22 confirmed live.
    # Root can always read receipts. Skip homebrew/* and anything already in trust.json, then one `brew trust` per kind (it takes many targets) instead of a brew spawn per keg. Pins untouched — orthogonal to trust.
    #   formulae: Cellar/*/*/INSTALL_RECEIPT.json               -> .source.tap
    #   casks:    Caskroom/*/.metadata/**/INSTALL_RECEIPT.json  -> .source.tap
    log "    Trusting installed third-party tap formulae/casks..."
    TRUST_JSON=""
    for tj in "$user_home/.homebrew/trust.json" "$user_home/.config/homebrew/trust.json"; do
        [[ -r "$tj" ]] && TRUST_JSON+="$(/bin/cat "$tj" 2>/dev/null || true)"
    done
    typeset -a trust_formulae trust_casks
    trust_formulae=(); trust_casks=(); trust_seen=""
    for receipt in "$BREW_PREFIX"/Cellar/*/*/INSTALL_RECEIPT.json(N); do
        tap=$(receipt_tap "$receipt")
        [[ -z "$tap" || "$tap" == homebrew/* ]] && continue
        full="$tap/${receipt:h:h:t}"
        [[ "$trust_seen" == *"|$full|"* ]] && continue      # de-dupe multiple installed versions
        trust_seen+="|$full|"
        [[ "$TRUST_JSON" == *"\"$full\""* || "$TRUST_JSON" == *"\"$tap\""* ]] && continue   # already trusted (item or whole tap)
        trust_formulae+=("$full")
    done
    for creceipt in "$BREW_PREFIX"/Caskroom/*/.metadata/**/INSTALL_RECEIPT.json(N); do
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

    # --- 1. UPGRADE FORMULAE (CLI TOOLS) ---
    log "    Upgrading ALL unpinned formulae (CLI packages)..."
    run_formula_upgrade "$brew_bin" "$IS_ROSETTA"

    # --- CLT AUTO-REPAIR ---
    # "Command Line Tools are too outdated" blocks every from-source build. Reinstalls unattended as root; one retry after, never a loop. Match ONLY that error, NOT the non-fatal "newer ... release is available" hint, which would burn minutes on a healthy Mac.
    if grep -q "Command Line Tools are too outdated" <<< "$UPGRADE_OUTPUT"; then
        if time_budget_exceeded; then
            log "    [INFO] Time budget reached — deferring Command Line Tools reinstall to the next daily run."
        else
            log "    [FIX] Outdated Command Line Tools block brew — reinstalling CLT via softwareupdate..."
            # softwareupdate only lists CLT with this marker, at Apple's exact path in world-writable /tmp — so root must not create it naively: `touch` FOLLOWS symlinks, so a pre-planted one lets a local user have root touch any file's mtime or create a root-owned file anywhere. Unlink first (rm takes the symlink, not its target), then verify it is a real file.
            CLT_MARKER=/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
            /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
            /usr/bin/touch "$CLT_MARKER" 2>/dev/null || true
            if [[ -L "$CLT_MARKER" || ! -f "$CLT_MARKER" ]]; then
                log "    [WARN] '$CLT_MARKER' is not a regular file (symlink or missing) — refusing to run the CLT repair on this Mac."
                /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
                CLT_LABEL=""
            else
            # Pick the HIGHEST-version label (sort -V), not merely the last listed.
            CLT_LABEL=$(/usr/sbin/softwareupdate -l 2>/dev/null \
                | /usr/bin/grep -oE 'Label: Command Line Tools[^,]*' \
                | /usr/bin/sed 's/^Label: //' | /usr/bin/sort -V | /usr/bin/tail -n 1 || true)
            fi
            if [[ -n "$CLT_LABEL" ]]; then
                log "    [FIX] Installing '$CLT_LABEL' (can take several minutes)..."
                if /usr/bin/caffeinate -i /usr/sbin/softwareupdate -i "$CLT_LABEL" >/dev/null 2>&1; then
                    log "    [OK] Command Line Tools updated — retrying formula upgrade once..."
                    run_formula_upgrade "$brew_bin" "$IS_ROSETTA"
                else
                    log "    [WARN] softwareupdate failed to install '$CLT_LABEL' — manual CLT reinstall needed on this Mac."
                fi
            elif [[ -f "$CLT_MARKER" ]]; then
                log "    [WARN] softwareupdate offered no Command Line Tools package — manual CLT reinstall needed on this Mac."
            fi
            /bin/rm -f "$CLT_MARKER" 2>/dev/null || true
        fi
    fi

    # Permission failures are scanned inside run_formula_upgrade, after the initial attempt and every retry below; the binding decision is the PERMISSION VERDICT block after the last one.

    # --- DOWNLOAD-CACHE REPAIR ---
    # A stale cache shows as "Failed to download resource X" then "No such file ... Caches/Homebrew/downloads/<hash>" (openjdk, bun, qemu, sqlite, awscli). Clear it and retry once: a truncated bottle re-downloads cleanly, a real network outage just fails again. The retry is NOT gated on the dir existing — "No such file" can mean the whole dir is gone, and the retry rebuilds it.
    # NOTE `.*` not `[^\n]*`: in a POSIX bracket expression the backslash is literal, so `[^\n]` reads as "not a backslash, not the letter n" and skipped every home path containing an 'n'.
    if grep -q "Failed to download resource" <<< "$UPGRADE_OUTPUT" \
       && grep -qE "rb_sysopen -.*Caches/Homebrew/downloads" <<< "$UPGRADE_OUTPUT"; then
        DL_CACHE="$user_home/Library/Caches/Homebrew/downloads"
        # Only ever remove something shaped exactly like a user's download cache, never a system
        # path.
        if [[ "$DL_CACHE" == /Users/*/Library/Caches/Homebrew/downloads && -d "$DL_CACHE" ]]; then
            log "    [FIX] Inconsistent Homebrew download cache — clearing $DL_CACHE before retrying..."
            remove_user_path "$DL_CACHE" || true
        else
            log "    [FIX] Homebrew download cache entry missing ($DL_CACHE absent) — retrying the upgrade to rebuild it..."
        fi
        run_formula_upgrade "$brew_bin" "$IS_ROSETTA"
    fi

    # --- SIBLING-FORMULA TRUST (Homebrew 6+) ---
    # Upgrading a tap formula makes brew LOAD its siblings. An uninstalled sibling has no receipt for the pass above to find, so brew aborts the ENTIRE remaining batch ("Refusing to load formula <tap>/<name> from untrusted tap") — up to a dozen packages lost as collateral. brew names the item, so trust THAT one and retry, but only if this Mac already has something installed from the same tap (trust_seen). Never whole-tap. Casks stay with the cask phase; only formulae collateral.
    SIBLING_ROUND=0
    while :; do
        SIBLING_ITEMS=$(grep -oE 'Refusing to load formula [^[:space:]]+' <<< "$UPGRADE_OUTPUT" \
            | /usr/bin/sed 's/^Refusing to load formula //' | sort -u || true)
        [[ -z "$SIBLING_ITEMS" ]] && break
        (( SIBLING_ROUND >= 3 )) && { log "    [WARN] sibling trust: still blocked after $SIBLING_ROUND rounds — giving up."; break; }
        SIBLING_ROUND=$(( SIBLING_ROUND + 1 ))
        SIBLING_TRUSTED=0
        while IFS= read -r sib; do
            [[ -z "$sib" ]] && continue
            sib_tap="${sib%/*}"                      # user/tap/name -> user/tap
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
        run_formula_upgrade "$brew_bin" "$IS_ROSETTA"
    done

    # --- PERMISSION VERDICT FOR THIS PREFIX ---
    # After every retry above, so the verdict is the state the prefix is LEFT in, not the first attempt's symptoms. Cosmetic paths promote UNCONDITIONALLY — they are orthogonal to blocked, and the common case is cosmetic findings with nothing else wrong. Guard keeps it `set -u`-safe.
    if (( ${#PERM_ATTEMPT_COSMETIC[@]} )); then
        PERM_COSMETIC_PATHS+=("${PERM_ATTEMPT_COSMETIC[@]}")
    fi
    if (( PERM_ATTEMPT_BLOCKED )); then
        PERM_BLOCKED=1
        PERM_BLOCKED_PATHS+=("${PERM_ATTEMPT_PATHS[@]}")
        # Keyed off the prefix PATH, not the Rosetta mode: on a real Intel host /usr/local runs with IS_ROSETTA=0, which would file the Intel prefix under ARM and invert the report IT reads.
        if [[ "$brew_bin" == /usr/local/* ]]; then
            PERM_BLOCKED_INTEL=1
        else
            PERM_BLOCKED_ARM=1
        fi
        # A broken install, not a transient failure, so it must fail the run even when brew exited 0 — otherwise the user gets a "contact IT" popup while the MDM still reports the device compliant.
        FORMULA_ERROR=1
    fi

    if [[ "$UPGRADE_EXIT" -ne 0 ]]; then
        # Detect symlink conflicts — fixable via brew link --overwrite, not a security failure.
        LINK_PKGS=$(echo "$UPGRADE_OUTPUT" \
            | grep -oE 'brew link --overwrite [^ ]+' \
            | grep -v -- '--dry-run' \
            | awk '{print $NF}' \
            | sort -u || true)

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
            # Check if failures are solely due to intentionally pinned packages. "brew unpin X" in the output means a dependency is blocked by a user-approved pin.
            PINNED_BLOCKING=$(echo "$UPGRADE_OUTPUT" | grep -c "brew unpin" || true)
            OTHER_ERRORS=$(echo "$UPGRADE_OUTPUT" | grep "^Error:" | grep -v "brew unpin" || true)

            if [[ "$PINNED_BLOCKING" -gt 0 && -z "$OTHER_ERRORS" ]]; then
                # Handle both backtick style (`brew unpin pkg`) and single-quote style ('brew unpin pkg'): Homebrew 6.0.0+ switched from single quotes to backticks in error messages.
                BLOCKED_PKGS=$(echo "$UPGRADE_OUTPUT" \
                    | grep "brew unpin" \
                    | grep -oE "['\`]brew unpin [^'\`]+['\`]" \
                    | sed "s/.*brew unpin //; s/['\`]$//" \
                    | sort -u | tr '\n' ' ' || true)
                log "    [INFO] Upgrade blocked by intentional pin(s): ${BLOCKED_PKGS}— expected per user policy, skipping."
            elif [[ "$PINNED_BLOCKING" -gt 0 && -n "$OTHER_ERRORS" ]]; then
                log "    [ERROR] Formula upgrade failed for $brew_bin with errors beyond pinned dependencies:"
                while IFS= read -r line; do log "    $line"; done <<< "$OTHER_ERRORS"
                FORMULA_ERROR=1
                STILL_OUTDATED=$(run_brew "$brew_bin" "$IS_ROSETTA" outdated --formula -q 2>/dev/null || true)
                PINNED_PKGS=$(run_brew "$brew_bin" "$IS_ROSETTA" list --pinned 2>/dev/null || true)
                while IFS= read -r pkg; do
                    [[ -z "$pkg" ]] && continue
                    if ! grep -qFx -- "$pkg" <<< "$PINNED_PKGS"; then
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
                    if ! grep -qFx -- "$pkg" <<< "$PINNED_PKGS"; then
                        GLOBAL_FAILED_PKGS+=("$pkg")
                    fi
                done <<< "$STILL_OUTDATED"
            fi
        fi
    fi

    # --- 2. UPGRADE CASKS (GUI APPS) SAFELY ---
    log "    Checking for outdated casks (GUI apps)..."
    # --verbose prints "token (installed) != new_version"; the new version feeds the suppression key.
    OUTDATED_CASKS=$(run_brew "$brew_bin" "$IS_ROSETTA" outdated --cask --verbose 2>/dev/null || true)

    if [[ -n "$OUTDATED_CASKS" ]]; then
        while IFS= read -r CASK_LINE; do
            [[ -z "$CASK_LINE" ]] && continue
            CASK=$(echo "$CASK_LINE" | awk '{print $1}')
            [[ -z "$CASK" ]] && continue
            MISMATCH_FALLTHROUGH=0

            # Stop starting cask work at 45 min; the next daily run continues (the script is idempotent).
            if time_budget_exceeded; then
                log "    [INFO] 45-min time budget reached — deferring '$CASK' and the remaining casks to the next daily run (the agent kills scripts at 60 min)."
                break
            fi
            NEW_VERSION=$(echo "$CASK_LINE" | awk 'NF > 1 {print $NF}')
            SUPPRESS_KEY="brew-update-${CASK}${NEW_VERSION:+-$NEW_VERSION}"

            # Kandji-managed casks migrate out IMMEDIATELY — no upgrade, no alert. Kandji owns their updates, and keeping them here only produced a daily "Remediated" loop plus per-version alerts for always-running apps like google-chrome.
            # Removes ONLY the Caskroom record — never the .app, never `brew uninstall --cask`, which could delete the live app. A name match proves nothing (gemini), so a profile Team ID must match the app's; mismatch → not Kandji's → brew handling below. Unverifiable (no team, unsigned, no metadata) → proceed.
            if mdm_manages_cask "$CASK"; then
                # A 0 return now ALWAYS carries a profile name (the manual list is gone), so the team check runs unconditionally — there is no unverified migration path left.
                MIGRATE_OK=1
                PROFILE_TEAMS=$(print -r -- "$MDM_AUTOAPP_TEAMS" | /usr/bin/awk -F'\t' -v n="$MDM_MATCHED_PROFILE" '$1=="TEAM" && $2==n {print $3}' | /usr/bin/sort -u || true)
                # Search BOTH app dirs — casks can install to ~/Applications or a custom --appdir.
                APP_NAME=$(/usr/bin/grep -rhoE '"[^"]+\.app"' "$BREW_PREFIX/Caskroom/$CASK/.metadata" 2>/dev/null | /usr/bin/head -n 1 | /usr/bin/tr -d '"' || true)
                APP_NAME="${APP_NAME##*/}"   # strip inner dirs: "Foo-1.2/Foo.app" -> "Foo.app"
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
                    # Profile declares a team → migration must be POSITIVELY verified; missing or mismatched means keep it under brew. Fail-closed is what stops the gemini collision even when the other app is in ~/Applications or unreadable.
                    if [[ -n "$APP_TEAM" ]] && grep -qFx "$APP_TEAM" <<< "$PROFILE_TEAMS"; then
                        MIGRATE_NOTE="Auto App profile '$MDM_MATCHED_PROFILE' (verified: app team $APP_TEAM matches)"
                    else
                        log "    [SKIP-Kandji-MISMATCH] '$CASK' name-matches Auto App profile '$MDM_MATCHED_PROFILE' but its app (${APP_PATH:-not found in /Applications or ~/Applications}) team '${APP_TEAM:-unknown}' does not match the profile team(s) $(echo "$PROFILE_TEAMS" | /usr/bin/tr '\n' ' ')— refusing to migrate a possibly-different same-name product. Keeping it under brew."
                        MIGRATE_OK=0
                        MISMATCH_FALLTHROUGH=1
                    fi
                else
                    # Profile carries no Team ID — nothing to verify against.
                    MIGRATE_NOTE="Auto App profile '$MDM_MATCHED_PROFILE' (no Team ID in profile — cannot verify, proceeding)"
                fi
                if [[ "$MIGRATE_OK" -eq 1 ]]; then
                    CASKROOM_DIR="$BREW_PREFIX/Caskroom/$CASK"
                    if [[ -d "$CASKROOM_DIR" ]]; then
                        log "    [MIGRATE-Kandji] '$CASK' matched $MIGRATE_NOTE — removing brew's Caskroom record ($CASKROOM_DIR); the application itself is untouched."
                        if remove_user_path "$CASKROOM_DIR"; then
                            MIGRATED_PKGS+=("$CASK")
                        else
                            log "    [WARN] Could not remove $CASKROOM_DIR — manual cleanup needed."
                            MDM_CONFLICT_PKGS+=("$CASK")
                        fi
                    else
                        log "    [SKIP-Kandji] '$CASK' matched $MIGRATE_NOTE but has no Caskroom record at $CASKROOM_DIR — nothing to forget."
                        MDM_CONFLICT_PKGS+=("$CASK")
                    fi
                    continue
                fi
                # Team mismatch: deliberately fall through to normal brew handling (running-check, upgrade, receipt fixes) below.
            fi

            SEARCH_TERM=$(echo "$CASK" | tr '-' ' ')
            # After a name mismatch the token matches the OTHER product's processes, so skip the coarse pgrep and let brew try — HOMEBREW_NO_UPGRADE_QUIT_CASKS still won't quit a live app.
            if [[ "$MISMATCH_FALLTHROUGH" != 1 ]] && pgrep -i -f "$SEARCH_TERM" >/dev/null 2>&1; then
                log "    [SKIP] '$CASK' is currently running — notifying user to update via Self Service."
                notify_user "Update Available: $CASK" \
                    "A security update for '$CASK' is ready. Please install it via Kandji Self Service when you are done using the app." \
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

            # "cannot be upgraded as-is" exits 0 (the docker-desktop case) — treat it as a failure too, otherwise the cask silently stays outdated forever.
            if [[ "$CASK_EXIT" -ne 0 ]] || grep -q "cannot be upgraded as-is" <<< "$CASK_OUTPUT"; then
                # SKIP-EXTERNAL below does NOT forget the cask: the owner may be a manual install, and forgetting it leaves the app with no updater at all (a ghost app). Classify by CONFLICT PATH, NOT the revert line — brew prints "Reverting upgrade for Cask" on nearly every mid-install failure, so matching it first shadows both branches below. `|| true` is load-bearing under pipefail: a no-match grep exits 1 and set -e kills the cask loop.
                CONFLICT_PATH=$(grep -oE "already an App at '[^']+'" <<< "$CASK_OUTPUT" | head -n 1 | sed "s/^already an App at '//; s/'$//" || true)
                # A conflict OUTSIDE the Caskroom means the live copy belongs to Kandji, a manual install, or a rolled-back artifact — a forced reinstall clobbers it either way. IT-facing only.
                if [[ -n "$CONFLICT_PATH" && "$CONFLICT_PATH" != "$BREW_PREFIX"/Caskroom/* ]]; then
                    log "    [SKIP-EXTERNAL] '$CASK': conflicting copy at '$CONFLICT_PATH' was not staged by brew — likely Kandji-managed, manually installed, or a rolled-back mid-install. Migrate it out of brew."
                    MDM_CONFLICT_PKGS+=("$CASK")
                    continue
                fi
                # Rolled-back mid-install (e.g. a vendor installer.sh exiting 1): a forced reinstall won't fix a broken installer, so just retry next run.
                if [[ -z "$CONFLICT_PATH" ]] && grep -qE "Reverting upgrade for Cask|Rolling back the failed upgrade" <<< "$CASK_OUTPUT"; then
                    log "    [WARN] '$CASK' upgrade failed mid-install and brew rolled it back — treating as a retryable failure."
                    GLOBAL_FAILED_PKGS+=("$CASK")
                    continue
                fi

                # Re-check the app was not launched while we were busy: the run can stall for hours across laptop sleep, and a reinstall must never race a now-running app. Same as the skip above — NOT a failure (the "check your network" popup would mislead).
                if pgrep -i -f "$SEARCH_TERM" >/dev/null 2>&1; then
                    log "    [SKIP] '$CASK' was started mid-run — deferring forced reinstall."
                    notify_user "Update Available: $CASK" \
                        "A security update for '$CASK' is ready. Please install it via Kandji Self Service when you are done using the app." \
                        "$SUPPRESS_KEY"
                    continue
                fi

                # Durable fix for both "already an App at ..." and "cannot be upgraded as-is": reinstall writes the receipt the upgrade path does not (Homebrew/homebrew-cask#251226). Plain uninstall+install keeps user data — prefs and sessions go only with --zap, never passed.
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

    # --- CLEANUP PERMISSION DIAGNOSTICS (report only — no repair, by design) ---
    if grep -q "Could not cleanup old kegs" <<< "$CLEANUP_OUTPUT"; then
        # ONLY the paths under that header: grepping the whole output also catches "Removing:
        # <path>... (N files)" progress lines. Strip the ellipsis brew appends to them.
        CLEAN_PATHS=$(/usr/bin/awk -v pfx="$BREW_PREFIX/" '
                /Could not cleanup old kegs/ { grab=1; next }
                grab && NF==0 { next }
                grab && index($1, pfx)==1 { print $1; next }
                grab { grab=0 }' <<< "$CLEANUP_OUTPUT" \
            | /usr/bin/sed -E 's/\.+$//' | sort -u || true)
        if [[ -n "$CLEAN_PATHS" ]]; then
            log "    [WARN] brew cleanup is blocked by filesystem permissions — NOT repairing ownership:"
            # Own array: a declined delete and an uncleanable keg mean different things. They dedup INDEPENDENTLY, so a dir hit by both appears in BOTH [REPORT] lines — never sum them.
            while IFS= read -r cp; do
                [[ -z "$cp" ]] && continue
                PERM_STALE_KEGS+=("$cp")
                log "    [WARN]   $cp"
            done <<< "$CLEAN_PATHS"
        fi
    fi
done

# --- 3. FINAL SUMMARY NOTIFICATION ---
if [[ ${#MIGRATED_PKGS[@]} -gt 0 ]]; then
    UNIQUE_MIGRATED=(${(u)MIGRATED_PKGS})
    MIGRATED_STR=${(j:, :)UNIQUE_MIGRATED}
    log "[REPORT] Casks auto-migrated out of brew (Kandji-managed; Caskroom record removed, apps untouched): $MIGRATED_STR"
fi

if [[ ${#MDM_CONFLICT_PKGS[@]} -gt 0 ]]; then
    UNIQUE_MDM=(${(u)MDM_CONFLICT_PKGS})
    MDM_STR=${(j:, :)UNIQUE_MDM}
    # IT-facing only — migrating a cask out of brew is an IT action, not a user one.
    log "[REPORT] Casks skipped to avoid clobbering an externally-managed copy (migrate out of brew): $MDM_STR"
fi

# Detection is the primary ownership signal; with it down every Kandji cask silently falls back to brew. FORMULA_ERROR so the device surfaces in Kandji, not just in one per-device log line.
if [[ -n "$AUTOAPP_DETECT_BROKEN" ]]; then
    log "[REPORT] Kandji Auto App detection is broken on this device: $AUTOAPP_DETECT_BROKEN. Kandji-managed casks were NOT recognised this run."
    FORMULA_ERROR=1
fi

# IT-facing only — brew may well still be working. NOTE dedup and join must stay TWO steps: `${(j:, :)${(u)arr}}` applies NEITHER flag (verified) and `${(uj:, :)arr}` joins without deduping.
if [[ ${#PERM_LEFTOVER_PATHS[@]} -gt 0 ]]; then
    UNIQUE_LEFTOVER=(${(u)PERM_LEFTOVER_PATHS})
    log "[REPORT] Root-owned leftovers left in place (script no longer deletes as root): ${(j:, :)UNIQUE_LEFTOVER}"
fi
if [[ ${#PERM_STALE_KEGS[@]} -gt 0 ]]; then
    UNIQUE_KEGS=(${(u)PERM_STALE_KEGS})
    log "[REPORT] Stale kegs brew cleanup could not remove (root-owned): ${(j:, :)UNIQUE_KEGS}"
fi
# Link targets only, so brew is intact: it warned "Could not symlink ..." and exited 0 fully upgraded. Reported for IT, but NO FORMULA_ERROR and NO notify_user — treating this class as a broken prefix is what used to fire a daily "Homebrew Needs Reinstalling" alert over unwritable man pages.
if [[ ${#PERM_COSMETIC_PATHS[@]} -gt 0 ]]; then
    UNIQUE_COSMETIC=(${(u)PERM_COSMETIC_PATHS})
    log "[REPORT] Unwritable doc/completion trees under a brew prefix (symlink targets only, brew still works): ${(j:, :)UNIQUE_COSMETIC}"
fi

# brew cannot write its own working state — only a reinstall fixes it now. FORMULA_ERROR is re-asserted HERE, not trusted from the far-off PERMISSION VERDICT block: this popup tells the user to reinstall, so the run MUST exit non-zero. Local and idempotent, otherwise a future path setting PERM_BLOCKED fires the alert while the MDM still reports the device compliant.
if [[ "$PERM_BLOCKED" -eq 1 ]]; then
    FORMULA_ERROR=1
    UNIQUE_PERM=(${(u)PERM_BLOCKED_PATHS})
    log "[REPORT] brew blocked by filesystem permissions on: ${(j:, :)UNIQUE_PERM}"
    # Both messages carry the actual commands, so a confident user can self-serve and everyone else has one Slack channel to ask. Two rules they encode:
    #   * NEVER tell anyone to chown /usr/local — it is shared with other vendors and holds /usr/local/bin/mdm-agent, the root-run MDM agent, so a broad chown there is a privilege escalation (the same reason this script refuses to do it). /opt/homebrew is brew-only, so the documented chown is safe there and is offered.
    #   * `$console_user` is interpolated, not `\$(whoami)` — the script runs as root, so a live substitution would paste "root" into the user's instructions.
    # arm64 migration is recommended only when Intel is the ONLY blocked prefix; with both blocked, naming /usr/local sends the user to fix one and leaves the other popping the same alert.
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
4. Put your packages back:
   brew bundle install --file ~/Desktop/Brewfile

Step 1 saves everything and step 4 restores it, so nothing is lost. Rather we did it for you, or a step fails? Write in Slack #it-support." \
            "brew-perm-migrate-arm"
    else
        notify_user "Homebrew Cannot Update" \
            "Homebrew cannot update itself because the permissions on its own folders are wrong. In Terminal:

1. Give the folder back to yourself:
   sudo chown -R $console_user /opt/homebrew
2. Check it worked:
   brew update && brew upgrade

It will ask for your Mac password at step 1. If that does not help, or you also have Homebrew in /usr/local, write in Slack #it-support — do not run chown on /usr/local yourself, other software lives there too." \
            "brew-perm-blocked"
    fi
fi

if [[ ${#GLOBAL_FAILED_PKGS[@]} -gt 0 ]]; then
    UNIQUE_FAILED=(${(u)GLOBAL_FAILED_PKGS})  # zsh: deduplicate array
    FAILED_STR=${(j:, :)UNIQUE_FAILED}         # zsh: join with ", "
    log "[REPORT] The following packages failed to update: $FAILED_STR"
    notify_user "Update Incomplete" \
        "The following packages could not be updated automatically: $FAILED_STR. Please try updating via Kandji Self Service or check your network connection." \
        "brew-update-incomplete"
fi

if [[ "$FORMULA_ERROR" -eq 1 ]]; then
    log "=== Global Remediation Completed with FORMULA ERRORS ==="
    exit 1
else
    log "=== Global Remediation Complete ==="
    exit 0
fi
