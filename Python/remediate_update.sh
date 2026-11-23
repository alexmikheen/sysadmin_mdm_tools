#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
#
# Description: Remediate superseded Python installations on managed macOS devices.
#              Before the cutoff date in standalone mode, show a warning alert to the user.
#              On or after the deadline, recheck blockers and remove safe candidates.
#              Block removal if any dependency probe fails or reaches the scan limit.
# Location: Python/remediate_update.sh
# Dependencies: pkgutil, rm, readlink, PlistBuddy, stat, codesign, iru/kandji/osascript, brew (optional), caffeinate
# Expected Result: Exit 0 after warning before the cutoff or after successful removal.
#                  Exit 1 when a removal command fails.
# Required Permissions: root (MDM execution context)
# Inputs: none
# Outputs: PY_REM status lines to stdout and log
# Logs: /var/log/mdm_tools/python-remediation.log
# Rollback: Reinstall the removed version from python.org or run brew install python@X.Y.
# Safety Notes: Keep candidate logic identical to Python/audit_update.sh.
#               Recheck every blocker immediately before removal.
#               Supports standalone mode (SLA_MODE=all) and CVE-gated mode (SLA_MODE=cve_gated).

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# --- CONFIGURATION ---
SLA_MODE="all"
SLA_ENFORCE_FROM="20991231"
# --- SLA_DEADLINES (managed automatically in cve_gated mode - do not edit manually) ---
SLA_DEADLINES=""
# --- /SLA_DEADLINES ---
LOG_DIR="/var/log/mdm_tools"
LOG_FILE="${LOG_DIR}/python-remediation.log"
SUPPRESSION_PREFIX="sysadmin-mdm-python"
SUPPORT_CHANNEL="#it-support"
HELP_URL=""
# --- /CONFIGURATION ---

TODAY=$(/bin/date '+%Y%m%d')
/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")" 2>/dev/null || true
if [[ -f "$LOG_FILE" ]]; then { /usr/bin/tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && /bin/mv "${LOG_FILE}.tmp" "$LOG_FILE"; } 2>/dev/null || true; fi
log() { local m="[$(/bin/date '+%Y-%m-%d %H:%M:%S')] $1"; print -r -- "$m"; { print -r -- "$m" >> "$LOG_FILE"; } 2>/dev/null || true; }

console_user=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)
[[ "$console_user" == "root" || "$console_user" == "loginwindow" ]] && console_user=""
console_uid=""; [[ -n "$console_user" ]] && console_uid=$(/usr/bin/id -u "$console_user" 2>/dev/null || true)

verify_mdm_bin() {
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

MDM_ALERT_BIN=""
for b in /usr/local/bin/iru /usr/local/bin/kandji; do
 if resolved_bin=$(verify_mdm_bin "$b"); then
  MDM_ALERT_BIN="$resolved_bin"
  break
 fi
done

show_alert() {
 local title="$1" message="$2" supp_key="$3"
 if [[ -n "$MDM_ALERT_BIN" ]]; then
  local -a args
  args=(display-alert --title "$title" --message "$message" --suppression-key "$supp_key" --no-wait)
  [[ -n "$HELP_URL" ]] && args+=(--help-url "$HELP_URL")
  "$MDM_ALERT_BIN" "${args[@]}" >/dev/null 2>&1
  return $?
 elif [[ -n "$console_uid" && -n "$console_user" ]]; then
  /bin/launchctl asuser "$console_uid" /usr/bin/sudo -u "$console_user" /usr/bin/osascript \
   -e 'on run argv' \
   -e 'display dialog (item 1 of argv) with title (item 2 of argv) buttons {"OK"} default button "OK" giving up after 60' \
   -e 'end run' -- "$message" "$title" >/dev/null 2>&1 &
  return 0
 fi
 return 1
}

minor_num() { print -r -- "$1" | /usr/bin/awk -F. '{printf "%d%03d", $1, $2}'; }

fw_version() {
 local d="$1" m="$2" v="" h
 if [[ -f "$d/Resources/Info.plist" && ! -L "$d/Resources/Info.plist" ]]; then
  v=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$d/Resources/Info.plist" 2>/dev/null) || v=""
 fi
 if [[ ! "$v" =~ '^[0-9]+\.[0-9]+\.[0-9]+' ]]; then
  for h in "$d/include/python${m}/patchlevel.h" "$d/include/python${m}t/patchlevel.h"; do
   [[ -f "$h" && ! -L "$h" ]] || continue
   v=$(/usr/bin/awk '/^#define[[:space:]]+PY_VERSION[[:space:]]+"/{gsub(/"/,"",$3); print $3; exit}' "$h" 2>/dev/null) || v=""
   [[ -n "$v" ]] && break
  done
 fi
 [[ "$v" =~ '^[0-9]+\.[0-9]+(\.[0-9]+[A-Za-z0-9.+-]*)?$' ]] || v="${m}.0"
 print -rn -- "$v"
}

verify_brew_prefix() {
 local bin="$1" prefix="${1:h:h}" real_bin p owner group mode
 local target_user="$console_user"
 [[ $EUID -ne 0 && -z "$target_user" ]] && target_user=$(/usr/bin/id -un 2>/dev/null || true)
 [[ -n "$target_user" && -f "$bin" && -x "$bin" ]] || return 1
 real_bin=$(/usr/bin/readlink -f "$bin" 2>/dev/null) || return 1
 [[ -f "$real_bin" && -x "$real_bin" ]] || return 1
 for p in "$bin" "$real_bin" "${bin:h}" "$prefix"; do
  owner=$(/usr/bin/stat -f%Su "$p" 2>/dev/null) || return 1
  [[ "$owner" == "$target_user" || "$owner" == "root" ]] || return 1
  if [[ ! -L "$p" ]]; then
   mode=$(/usr/bin/stat -f%Lp "$p" 2>/dev/null) || return 1
   [[ "$mode" =~ '^[0-7]+$' ]] || return 1
   (( (8#$mode & 8#002) == 0 )) || return 1
   if (( (8#$mode & 8#020) != 0 )); then
    group=$(/usr/bin/stat -f%Sg "$p" 2>/dev/null) || return 1
    [[ "$group" == "admin" || "$group" == "wheel" ]] || return 1
   fi
  fi
 done
 return 0
}

# Return empty for any non-YYYYMMDD value so zsh arithmetic never triggers early removal.
sla_deadline() { local k="$1" e v; for e in ${(z)SLA_DEADLINES}; do [[ "$e" == "$k="* ]] || continue; v="${e#*=}"; [[ "$v" == [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] ]] && print -rn -- "$v"; return; done; }

log "=== Starting Python Cleanup Remediation (mode=$SLA_MODE) ==="

if [[ "$SLA_ENFORCE_FROM" != [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] ]]; then
 log "[ERROR] SLA_ENFORCE_FROM '$SLA_ENFORCE_FROM' is not YYYYMMDD - forcing warn-only mode, fix the date in the MDM script"
 SLA_ENFORCE_FROM="20991231"
fi
for e in ${(z)SLA_DEADLINES}; do [[ "$e" =~ '^cpython:[0-9]+\.[0-9]+\.[0-9]+=[0-9]{8}$' ]] || log "[ERROR] SLA_DEADLINES entry '$e' is not cpython:X.Y.Z=YYYYMMDD - ignored (version kept)"; done

pyorg_date() {
 local d=$(sla_deadline "cpython:${PYORG_VER[$1]:-unknown}")
 [[ -z "$d" && "$SLA_MODE" == "all" ]] && d="$SLA_ENFORCE_FROM"
 print -rn -- "$d"
}
brew_date() {
 local k v d dl=""
 for k in ${=1}; do v="${k%%_*}"; d=$(sla_deadline "cpython:$v"); [[ -n "$d" && ( -z "$dl" || "$d" -lt "$dl" ) ]] && dl="$d"; done
 [[ -z "$dl" && "$SLA_MODE" == "all" ]] && dl="$SLA_ENFORCE_FROM"
 print -rn -- "$dl"
}

distinfo_list() { local d n; for d in "$@"; do for n in "$d"/*.dist-info(N/); do n="${n:t}"; n="${n%.dist-info}"; [[ "$n" == *-* ]] || continue; [[ "${n%%-*}" == (pip|setuptools|wheel) ]] || print -r -- "${n%%-*}==${n#*-}"; done; done; }

snapshot_packages() {
 local label="$1" py="$2"; shift 2
 local tag="${label// /-}"; tag="${tag//[^A-Za-z0-9._-]/}"
 local list="" dest="" user_home dir fname file desk desk_owner expected_owner
 as_user() { if [[ $EUID -eq 0 ]]; then /usr/bin/sudo -u "$console_user" -H /bin/sh -c 'umask 022; exec "$@"' sh "$@"; else ( umask 022; "$@" ); fi; }
 write_snapshot_file() {
  local target_dir="$1" target_name="$2" body="$3"
  print -r -- "$body" | as_user /bin/sh -c '
   d="$1"; f="$2"
   [ ! -L "$d" ] || exit 1
   /bin/mkdir -p "$d" 2>/dev/null || exit 1
   [ -d "$d" ] && [ ! -L "$d" ] || exit 1
   [ ! -L "$d/$f" ] || exit 1
   tmp=$(/usr/bin/mktemp "$d/.snap.XXXXXX") || exit 1
   if /bin/cat > "$tmp"; then
    /bin/mv -f "$tmp" "$d/$f" && exit 0
   fi
   /bin/rm -f "$tmp"
   exit 1
  ' sh "$target_dir" "$target_name" >/dev/null 2>&1
 }
 if [[ -x "$py" && ( $EUID -ne 0 || -n "$console_user" ) ]]; then list=$(as_user /usr/bin/env PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 "$py" -m pip list --format=freeze --exclude-editable </dev/null 2>/dev/null) || list=""; fi
 [[ -z "$list" ]] && list=$(distinfo_list "$@")
 list=$(print -r -- "$list" | /usr/bin/grep -vE '^(pip|setuptools|wheel)==' | /usr/bin/grep -E '^[A-Za-z0-9_.-]+==' | /usr/bin/sort -u)
 local -a names; names=(${(f)list}); names=(${names%%==*})
 local count=${#names} top="${(j:, :)names[1,8]}"
 [[ $count -gt 8 ]] && top+=", ..."
 [[ $count -eq 0 ]] && { print -rn -- "0||"; return 0; }
 [[ $EUID -eq 0 && -z "$console_user" ]] && { print -rn -- "$count||$top"; return 0; }
 # Query Directory Services for the home directory to support mobile and renamed accounts.
 if [[ $EUID -eq 0 ]]; then
  user_home=$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')
  [[ -z "$user_home" ]] && user_home="/Users/$console_user"
 else
  user_home="$HOME"
 fi
 dir="$user_home/Library/Logs/python-cleanup"
 fname="${tag}-packages-${TODAY}.txt"
 file="$dir/$fname"
 local content="# $label packages saved by IT python cleanup on $TODAY before the version was removed."$'\n'"# Restore them in a virtualenv: python3 -m venv ~/venvs/work && ~/venvs/work/bin/pip install -r \"$file\""$'\n'"$list"
 if write_snapshot_file "$dir" "$fname" "$content"; then dest="$file"; fi
 desk="$user_home/Desktop"
 expected_owner="$console_user"
 [[ $EUID -ne 0 && -z "$expected_owner" ]] && expected_owner=$(/usr/bin/id -un 2>/dev/null || true)
 if [[ -d "$desk" && ! -L "$desk" ]]; then
  desk_owner=$(/usr/bin/stat -f%Su "$desk" 2>/dev/null || true)
  if [[ "$desk_owner" == "$expected_owner" ]] && write_snapshot_file "$desk" "$fname" "$content"; then
   dest="$desk/$fname"
  fi
 fi
 [[ -z "$dest" ]] && { print -rn -- "$count||$top"; return 0; }
 print -rn -- "$count|$dest|$top"
}

log_snapshot() { local mk="$1" lb="$2" sc="${3%%|*}" sd="${${3#*|}%%|*}" st="${3##*|}"
 if [[ "$sc" == "0" ]]; then log "$mk: snapshot $lb: no third-party packages"; return 1
 elif [[ -n "$sd" ]]; then log "$mk: snapshot $lb: $sc packages -> $sd ($st)"; return 0
 else log "[WARN] snapshot $lb: $sc packages ($st) NOT saved - no writable target in console user home"; return 1; fi
}

SCAN_CAP=0
FW_MINORS=(); typeset -A PYORG_VER
for d in /Library/Frameworks/Python.framework/Versions/*(N/); do
 m="${d:t}"
 [[ "$m" =~ '^[0-9]+\.[0-9]+$' ]] || continue
 v=$(fw_version "$d" "$m")
 FW_MINORS+=("$m"); PYORG_VER[$m]="${v:-unknown}"
done
NEWEST=""; for m in $FW_MINORS; do [[ -z "$NEWEST" || $(minor_num "$m") -gt $(minor_num "$NEWEST") ]] && NEWEST="$m"; done

DEFAULT_TARGET=$(/usr/bin/readlink -f /usr/local/bin/python3 2>/dev/null || true)
DEFAULT_MINOR=""; DEFAULT_UNKNOWN=0
if [[ -e /usr/local/bin/python3 ]]; then
 if [[ "$DEFAULT_TARGET" == *"/Library/Frameworks/Python"* ]]; then
  DEFAULT_MINOR=$(print -r -- "$DEFAULT_TARGET" | /usr/bin/sed -n 's|.*/Versions/\([0-9][0-9.]*\)/.*|\1|p')
  [[ -z "$DEFAULT_MINOR" ]] && DEFAULT_UNKNOWN=1
 elif [[ "$DEFAULT_TARGET" != *"/Cellar/"* && "$DEFAULT_TARGET" != *"/opt/homebrew/"* && "$DEFAULT_TARGET" != "/usr/bin/"* ]]; then
  DEFAULT_UNKNOWN=1
 fi
fi

VENV_LIST=$({ /usr/bin/find /Users/*/ -maxdepth 7 \( -name Library -o -name .Trash -o -name node_modules -o -name .git \) -prune -o -name pyvenv.cfg -type f -print 2>/dev/null; print -l /Users/*/Library/Caches/pypoetry/virtualenvs/*/pyvenv.cfg(N.) /Users/*/.virtualenvs/*/pyvenv.cfg(N.); } | /usr/bin/head -n 500) || true
VENV_N=$(print -r -- "$VENV_LIST" | /usr/bin/grep -c . 2>/dev/null) || VENV_N=0
[[ $VENV_N -ge 500 ]] && SCAN_CAP=1
VENV_HOMES=$(print -r -- "$VENV_LIST" | while IFS= read -r f; do [[ -n "$f" && -f "$f" && ! -L "$f" && ! -p "$f" ]] && /usr/bin/head -n 50 "$f" 2>/dev/null | /usr/bin/sed -n 's/^home *= *//p'; done | /usr/bin/sort -u) || true

typeset -a bin_files launchd_files
bin_files=( /Users/*/bin/*(N-.) /Users/*/.local/bin/*(N-.) /usr/local/bin/*(N-.) )
SHEBANGS=""
(( ${#bin_files} > 0 )) && SHEBANGS=$(/usr/bin/grep -ha -m1 -o '^#!.*python[0-9.]*' -- "${bin_files[@]}" </dev/null 2>/dev/null | /usr/bin/sort -u || true)
launchd_files=( /Library/LaunchDaemons/*(N-.) /Library/LaunchAgents/*(N-.) /Users/*/Library/LaunchAgents/*(N-.) )
LAUNCHD_REFS=""
(( ${#launchd_files} > 0 )) && LAUNCHD_REFS=$(/usr/bin/grep -hao 'Python\.framework/Versions/[0-9][0-9.]*' -- "${launchd_files[@]}" </dev/null 2>/dev/null | /usr/bin/sort -u || true)

pyorg_blockers() { local m="$1" esc="${1//./\\.}" why=""
 [[ "$m" == "$NEWEST" ]] && { print -r -- "newest"; return; }
 [[ $SCAN_CAP -eq 1 ]] && why+="scan-cap,"
 [[ $DEFAULT_UNKNOWN -eq 1 ]] && why+="default-unknown,"
 [[ "$m" == "$DEFAULT_MINOR" ]] && why+="default,"
 [[ -n "$VENV_HOMES" ]] && print -r -- "$VENV_HOMES" | /usr/bin/grep -qE "/Versions/${esc}(/|$)" && why+="venv,"
 [[ -n "$SHEBANGS" ]] && print -r -- "$SHEBANGS" | /usr/bin/grep -qE "(python${esc}([^0-9]|$)|/Versions/${esc}/)" && why+="shebang,"
 [[ -n "$LAUNCHD_REFS" ]] && print -r -- "$LAUNCHD_REFS" | /usr/bin/grep -qE "Versions/${esc}$" && why+="launchd,"
 [[ "$why" == "default," ]] && { print -r -- "stale-default"; return; }
 print -r -- "${why%,}"
}

typeset -a PYORG_RM BREW_RM ALERT_ITEMS
typeset -A KEGS
brew_kegs() { local k out=""; for k in ${(k)KEGS}; do [[ "$k" == *"|$1" ]] && out+=" ${KEGS[$k]}"; done; print -rn -- "$out"; }
ESC_DEFAULT=""
for m in $FW_MINORS; do
 b=$(pyorg_blockers "$m")
 if [[ -z "$b" ]]; then PYORG_RM+=("$m"); ALERT_ITEMS+=("python.org $m")
 elif [[ "$b" == "stale-default" ]]; then ESC_DEFAULT="$m"; log "PY_REM: pyorg $m is stale-default (old default, no other dependents) - escalation path"
 else log "PY_REM: pyorg $m kept (${b})"
 fi
done

for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
 [[ -x "$brew_bin" && ( -n "$console_user" || $EUID -ne 0 ) ]] || continue
 if ! verify_brew_prefix "$brew_bin"; then
  log "[WARN] brew prefix ownership or permission check failed for $brew_bin - prefix skipped"
  continue
 fi
 prefix="${brew_bin:h:h}"
 runb() { if [[ $EUID -eq 0 ]]; then /usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>/dev/null; else HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>/dev/null; fi; }
 LISTV=$(runb list --formula --versions); rc=$?
 [[ $rc -ne 0 ]] && {
  if [[ $EUID -eq 0 ]]; then berr=$(/usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 "$brew_bin" list --formula --versions </dev/null 2>&1 >/dev/null | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' '); else berr=$("$brew_bin" list --formula --versions </dev/null 2>&1 >/dev/null | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' '); fi
  log "[WARN] brew list --formula --versions failed for $brew_bin (rc=$rc): ${berr:-no stderr} - prefix skipped, nothing removable here"; continue; }
 PY_FORMULAS=()
 for line in ${(f)LISTV}; do
  f="${line%% *}"
  [[ "$f" =~ '^python@[0-9]+\.[0-9]+$' ]] || continue
  PY_FORMULAS+=("$f"); KEGS["$brew_bin|$f"]="${line#* }"
 done
 [[ ${#PY_FORMULAS} -eq 0 ]] && continue
 BREW_NEWEST=""; for f in $PY_FORMULAS; do m="${f#python@}"; [[ -z "$BREW_NEWEST" || $(minor_num "$m") -gt $(minor_num "$BREW_NEWEST") ]] && BREW_NEWEST="$m"; done
 BREW_DEFAULT=$(/usr/bin/readlink -f "${brew_bin:h}/python3" 2>/dev/null || true)
 for f in $PY_FORMULAS; do
  m="${f#python@}"; esc="${m//./\\.}"
  uses_out=$(runb uses --installed "$f"); uses_rc=$?
  uses_n=$(print -r -- "$uses_out" | /usr/bin/grep -c . 2>/dev/null) || uses_n=0
  pin="false"; [[ -e "$prefix/var/homebrew/pinned/$f" ]] && pin="true"
  why=""
  [[ "$m" == "$BREW_NEWEST" ]] && why+="newest,"
  [[ $SCAN_CAP -eq 1 ]] && why+="scan-cap,"
  [[ $uses_rc -ne 0 ]] && why+="uses-failed,"
  [[ $uses_n -gt 0 ]] && why+="uses,"
  [[ "$pin" == "true" ]] && why+="pinned,"
  [[ -n "$BREW_DEFAULT" && ( "$BREW_DEFAULT" == *"python@$m/"* || "$BREW_DEFAULT" == *"/Versions/$m/"* ) ]] && why+="default,"
  [[ -n "$VENV_HOMES" ]] && print -r -- "$VENV_HOMES" | /usr/bin/grep -qE "python@${esc}(/|$)" && why+="venv,"
  [[ -n "$SHEBANGS" ]] && print -r -- "$SHEBANGS" | /usr/bin/grep -qE "(python@${esc}/|python${esc}([^0-9]|$))" && why+="shebang,"
  if [[ -z "$why" ]]; then
   BREW_RM+=("$brew_bin|$f"); ALERT_ITEMS+=("Homebrew $f")
  else
   log "PY_REM: brew $f kept (${why%,})"
  fi
 done
done

if [[ ${#PYORG_RM} -eq 0 && ${#BREW_RM} -eq 0 && -z "$ESC_DEFAULT" ]]; then log "Nothing removable - done."; exit 0; fi

ESC_DATE=""; [[ -n "$ESC_DEFAULT" ]] && ESC_DATE=$(pyorg_date "$ESC_DEFAULT")
warn_default() {
 [[ -n "$ESC_DEFAULT" && -n "$ESC_DATE" ]] || return 0
 show_alert \
  "Your default Python is outdated" \
  "Your default python3 is the outdated $ESC_DEFAULT while $NEWEST is already installed. Switch the default or remove $ESC_DEFAULT via Self Service. If nothing changes, IT will remove $ESC_DEFAULT and point python3 at $NEWEST automatically." \
  "${SUPPRESSION_PREFIX}-default-$ESC_DEFAULT" \
  && log "PY_REM: stale-default alert shown (python.org $ESC_DEFAULT -> $NEWEST)" || log "[WARN] stale-default alert failed (python.org $ESC_DEFAULT)"
}

if [[ "$SLA_MODE" == "all" && "$TODAY" -lt "$SLA_ENFORCE_FROM" ]]; then
 typeset -a GATED
 for it in "${ALERT_ITEMS[@]}"; do
  case "$it" in
   python.org*) [[ -n "$(pyorg_date "${it#python.org }")" ]] && GATED+=("$it") ;;
   "Homebrew python@"*) [[ -n "$(brew_date "$(brew_kegs "${it#Homebrew }")")" ]] && GATED+=("$it") ;;
  esac
 done
 if [[ ${#GATED} -gt 0 ]]; then
  LIST=$(printf '%s, ' "${GATED[@]}"); LIST="${LIST%, }"
  show_alert \
   "Old Python versions scheduled for removal" \
   "Unused Python versions ($LIST) will be removed soon. You can delete them now via Self Service. Future Python updates will be automated by IT." \
   "${SUPPRESSION_PREFIX}-cleanup" \
   && log "PY_REM: pre-cutoff alert shown ($LIST)" || log "[WARN] pre-cutoff alert failed ($LIST)"
 fi
 warn_default
 exit 0
fi

if [[ -n "$ESC_DEFAULT" ]]; then
 if [[ -z "$ESC_DATE" ]]; then
  log "PY_REM: stale-default $ESC_DEFAULT (${PYORG_VER[$ESC_DEFAULT]}) kept - no active CVEs"
  ESC_DEFAULT=""
 elif [[ "$TODAY" -ge "$ESC_DATE" ]]; then
  log "PY_REM: stale-default $ESC_DEFAULT (${PYORG_VER[$ESC_DEFAULT]}) SLA date $ESC_DATE reached - removing and relinking default to $NEWEST"
  PYORG_RM+=("$ESC_DEFAULT")
 else
  warn_default
  log "PY_REM: stale-default $ESC_DEFAULT NOT removed - SLA date $ESC_DATE not reached"
  ESC_DEFAULT=""
 fi
fi
if [[ ${#PYORG_RM} -eq 0 && ${#BREW_RM} -eq 0 ]]; then exit 0; fi

/usr/bin/caffeinate -imsu -w $$ >/dev/null 2>&1 &
FAILED=0
typeset -a REMOVED SNAPSHOTS
for m in $PYORG_RM; do
 fw="/Library/Frameworks/Python.framework/Versions/$m"
 [[ -d "$fw" ]] || { log "PY_REM: pyorg $m already gone - skipped"; continue; }
 dl=$(pyorg_date "$m")
 if [[ -z "$dl" ]]; then log "PY_REM: pyorg $m (${PYORG_VER[$m]}) kept - no active CVEs"; continue; fi
 if [[ "$TODAY" -lt "$dl" ]]; then log "PY_REM: pyorg $m (${PYORG_VER[$m]}) NOT removed - SLA date $dl not reached"; continue; fi
 snap=$(snapshot_packages "python.org $m" "$fw/bin/python3" "$fw/lib/python$m/site-packages"); saved=0; log_snapshot PY_REM "python.org $m (${PYORG_VER[$m]})" "$snap" && saved=1
 log "PY_REM: removing python.org $m (${PYORG_VER[$m]}, SLA date $dl)"
 /bin/rm -rf "$fw" 2>/dev/null || { log "[ERROR] rm framework $m failed"; FAILED=1; continue; }
 REMOVED+=("python.org $m")
 [[ $saved -eq 1 ]] && { SNAPSHOTS+=("python.org $m: ${snap%%|*} packages -> ${${snap#*|}%%|*}"); log "PY_REM: removed python.org $m (${PYORG_VER[$m]}): ${snap%%|*} packages saved to ${${snap#*|}%%|*} (${snap##*|})"; }
 /bin/rm -rf "/Applications/Python $m" 2>/dev/null || true
 for r in PythonFramework PythonApplications PythonUnixTools PythonDocumentation; do
  /usr/sbin/pkgutil --forget "org.python.Python.$r-$m" >/dev/null 2>&1 || true
 done
 cur=$(/usr/bin/readlink /Library/Frameworks/Python.framework/Versions/Current 2>/dev/null || true)
 if [[ "$cur" == "$m" && -n "$NEWEST" ]]; then
  /bin/ln -sfn "$NEWEST" /Library/Frameworks/Python.framework/Versions/Current 2>/dev/null || true
  log "PY_REM: Current relinked -> $NEWEST"
 fi
 for l in /usr/local/bin/python3*(N@) /usr/local/bin/pip3*(N@) /usr/local/bin/idle3*(N@) /usr/local/bin/pydoc3*(N@) /usr/local/bin/2to3*(N@); do
  [[ ! -e "$l" ]] && { /bin/rm -f "$l" 2>/dev/null || true; log "PY_REM: dangling symlink removed: $l"; }
 done
 if [[ -n "$NEWEST" ]]; then
  nb="/Library/Frameworks/Python.framework/Versions/$NEWEST/bin"
  for name in python3 pip3 python3-config idle3; do
   if [[ ! -e "/usr/local/bin/$name" && -x "$nb/$name" ]]; then
    /bin/ln -s "$nb/$name" "/usr/local/bin/$name" 2>/dev/null && log "PY_REM: relinked /usr/local/bin/$name -> $NEWEST" || log "[WARN] relink /usr/local/bin/$name failed"
   fi
  done
 fi
done
for entry in $BREW_RM; do
 brew_bin="${entry%%|*}"; f="${entry##*|}"; prefix="${brew_bin:h:h}"
 verify_brew_prefix "$brew_bin" || { log "[WARN] brew prefix check failed before uninstall for $brew_bin - skipped"; continue; }
 runb() { if [[ $EUID -eq 0 ]]; then /usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>&1; else HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>&1; fi; }
 m="${f#python@}"; kegs="${KEGS[$entry]}"; dl=$(brew_date "$kegs")
 if [[ -z "$dl" ]]; then log "PY_REM: brew $f ($kegs) kept - no active CVEs"; continue; fi
 if [[ "$TODAY" -lt "$dl" ]]; then log "PY_REM: brew $f ($kegs) NOT removed - SLA date $dl not reached"; continue; fi
 if [[ $EUID -eq 0 ]]; then uses_out=$(/usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" uses --installed "$f" </dev/null 2>/dev/null); else uses_out=$(HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" uses --installed "$f" </dev/null 2>/dev/null); fi; uses_rc=$?
 [[ $uses_rc -ne 0 ]] && { log "PY_REM: brew $f kept (uses re-check failed rc=$uses_rc)"; continue; }
 [[ -n "$uses_out" ]] && { log "PY_REM: brew $f kept (dependent appeared)"; continue; }
 [[ -e "$prefix/var/homebrew/pinned/$f" ]] && { log "PY_REM: brew $f kept (pinned appeared)"; continue; }
 snap=$(snapshot_packages "Homebrew $f" "$prefix/opt/$f/bin/python3" "$prefix/lib/python$m/site-packages"); saved=0; log_snapshot PY_REM "Homebrew $f ($kegs)" "$snap" && saved=1
 log "PY_REM: removing Homebrew $f ($kegs, SLA date $dl)"
 OUT=$(runb uninstall "$f") && { log "PY_REM: brew $f uninstalled"; REMOVED+=("Homebrew $f"); [[ $saved -eq 1 ]] && { SNAPSHOTS+=("Homebrew $f: ${snap%%|*} packages -> ${${snap#*|}%%|*}"); log "PY_REM: removed Homebrew $f ($kegs): ${snap%%|*} packages saved to ${${snap#*|}%%|*} (${snap##*|})"; }; } || { log "[ERROR] brew uninstall $f: $(print -r -- "$OUT" | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' ')"; FAILED=1; }
done

if [[ ${#REMOVED} -gt 0 ]]; then
 RLIST=$(printf '%s, ' "${REMOVED[@]}"); RLIST="${RLIST%, }"
 SNAPTXT=""; [[ ${#SNAPSHOTS} -gt 0 ]] && SNAPTXT=" Packages that were installed in them are listed in: $(printf '%s; ' "${SNAPSHOTS[@]}")- restore them in a virtualenv: python3 -m venv ~/venvs/work && ~/venvs/work/bin/pip install -r <that file>. Virtualenvs are never removed."
 show_alert \
  "Old Python versions removed" \
  "As announced, unused Python versions were removed from this Mac: $RLIST.${NEWEST:+ python3 now points at $NEWEST.}$SNAPTXT Questions? Ask in $SUPPORT_CHANNEL." \
  "${SUPPRESSION_PREFIX}-removed" \
  && log "PY_REM: post-removal alert shown ($RLIST)" || log "[WARN] post-removal alert failed ($RLIST)"
fi

[[ $FAILED -eq 0 ]] && { log "=== Cleanup complete ==="; exit 0; } || { log "=== Cleanup finished with errors ==="; exit 1; }
