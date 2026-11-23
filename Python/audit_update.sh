#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
#
# Description: Inventory every Python interpreter from python.org and Homebrew.
#              Classify superseded versions as removal candidates with dependency evidence.
#              Block removal if any dependency probe fails or reaches the scan limit.
# Location: Python/audit_update.sh
# Dependencies: find, readlink, grep, sed, awk, PlistBuddy, stat, brew (optional)
# Expected Result: Exit 1 when at least one candidate is removable or stale-default.
#                  Exit 0 when no removable candidate exists.
# Required Permissions: root (MDM execution context)
# Inputs: none
# Outputs: Single-line JSON markers (PY_BUILD, PY_SUMMARY, PY_INV) to stdout and log.
# Logs: /var/log/mdm_tools/python-audit.log
# Rollback: none (read-only audit)
# Safety Notes: Do not enable set -e because a failed probe must not stop stdout output.
#               Use print -r -- in log() so zsh does not alter JSON escape sequences.
#               Never invoke /usr/bin/python3 because xcrun opens a developer tools prompt.

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# --- CONFIGURATION ---
BUILD_ID="sysadmin-mdm-python"
SCHEMA_VERSION=2
LOG_DIR="/var/log/mdm_tools"
LOG_FILE="${LOG_DIR}/python-audit.log"
# --- /CONFIGURATION ---

/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")" 2>/dev/null || true
if [[ -f "$LOG_FILE" ]]; then { /usr/bin/tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && /bin/mv "${LOG_FILE}.tmp" "$LOG_FILE"; } 2>/dev/null || true; fi
log() { local m="[$(/bin/date '+%Y-%m-%d %H:%M:%S')] $1"; print -r -- "$m"; { print -r -- "$m" >> "$LOG_FILE"; } 2>/dev/null || true; }
typeset -a WARN_LINES
# Buffer warnings so JSON markers print first before MDM truncates stdout tails.
warn() { WARN_LINES+=("$1"); }
jesc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"; print -rn -- "$s"; }

console_user=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)
[[ "$console_user" == "root" || "$console_user" == "loginwindow" ]] && console_user=""

EOL_MINORS=(2.7 3.0 3.1 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10)
is_eol() { [[ " ${EOL_MINORS[*]} " == *" $1 "* ]]; }
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

distinfo_list() { local d n; for d in "$@"; do for n in "$d"/*.dist-info(N/); do n="${n:t}"; n="${n%.dist-info}"; [[ "$n" == *-* ]] || continue; [[ "${n%%-*}" == (pip|setuptools|wheel) ]] || print -r -- "${n%%-*}==${n#*-}"; done; done; }

pkg_inventory() { local -a names; names=(${(f)"$(distinfo_list "$@")"}); names=(${names%%==*}); names=(${(ou)names}); local top="${(j:, :)names[1,8]}"; [[ ${#names} -gt 8 ]] && top+=", ..."; print -rn -- "${#names}|${top[1,120]}"; }

typeset -a INV_LINES
typeset -A PYORG_VER
removable=0; blocked=0; eol_present=0; SCAN_CAP=0; stale_default=0

FW_MINORS=(); T_MINORS=()
for d in /Library/Frameworks/Python.framework/Versions/*(N/); do
 m="${d:t}"
 [[ "$m" =~ '^[0-9]+\.[0-9]+$' ]] || continue
 v=$(fw_version "$d" "$m")
 FW_MINORS+=("$m"); PYORG_VER[$m]="${v:-unknown}"
done
for d in /Library/Frameworks/PythonT.framework/Versions/*(N/); do
 m="${d:t}"
 [[ "$m" =~ '^[0-9]+\.[0-9]+$' ]] || continue
 T_MINORS+=("$m")
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

SHADOWS=""; for u in /Users/*(N/); do
 [[ -d "$u/.pyenv/versions" ]] && SHADOWS+="pyenv "
 [[ -d "$u/.local/share/uv/python" ]] && SHADOWS+="uv "
 [[ -d "$u/miniconda3" || -d "$u/anaconda3" ]] && SHADOWS+="conda "
done
SHADOWS=$(print -r -- "$SHADOWS" | /usr/bin/tr ' ' '\n' | /usr/bin/sort -u | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ $//')

verdict_pyorg() {
 local m="$1" esc="${1//./\\.}" why=""
 [[ "$m" == "$NEWEST" ]] && { print -r -- "keep:newest"; return; }
 [[ $SCAN_CAP -eq 1 ]] && why+="scan-cap,"
 [[ $DEFAULT_UNKNOWN -eq 1 ]] && why+="default-unknown,"
 [[ "$m" == "$DEFAULT_MINOR" ]] && why+="default,"
 [[ -n "$VENV_HOMES" ]] && print -r -- "$VENV_HOMES" | /usr/bin/grep -qE "/Versions/${esc}(/|$)" && why+="venv,"
 [[ -n "$SHEBANGS" ]] && print -r -- "$SHEBANGS" | /usr/bin/grep -qE "(python${esc}([^0-9]|$)|/Versions/${esc}/)" && why+="shebang,"
 [[ -n "$LAUNCHD_REFS" ]] && print -r -- "$LAUNCHD_REFS" | /usr/bin/grep -qE "Versions/${esc}$" && why+="launchd,"
 [[ "$why" == "default," ]] && { print -r -- "stale-default"; return; }
 [[ -n "$why" ]] && print -r -- "blocked:${why%,}" || print -r -- "removable"
}

for m in $FW_MINORS; do
 v=$(verdict_pyorg "$m"); e="false"; is_eol "$m" && { e="true"; eol_present=$((eol_present+1)); }
 [[ "$v" == "removable" ]] && removable=$((removable+1)); [[ "$v" == blocked:* ]] && blocked=$((blocked+1)); [[ "$v" == "stale-default" ]] && stale_default=$((stale_default+1))
 pk=$(pkg_inventory "/Library/Frameworks/Python.framework/Versions/$m/lib/python$m/site-packages" /Users/*/Library/Python/$m/lib/python/site-packages(N/))
 INV_LINES+=("PY_INV: {\"src\":\"pyorg\",\"fw\":\"std\",\"minor\":\"$(jesc $m)\",\"ver\":\"$(jesc ${PYORG_VER[$m]})\",\"eol\":$e,\"pkgs\":${pk%%|*},\"pkg_top\":\"$(jesc ${pk#*|})\",\"verdict\":\"$(jesc $v)\"}")
done
for m in $T_MINORS; do
 tv=$(fw_version "/Library/Frameworks/PythonT.framework/Versions/$m" "$m")
 e="false"; is_eol "$m" && { e="true"; eol_present=$((eol_present+1)); }
 INV_LINES+=("PY_INV: {\"src\":\"pyorg\",\"fw\":\"t\",\"minor\":\"$(jesc $m)\",\"ver\":\"$(jesc ${tv:-unknown})\",\"eol\":$e,\"verdict\":\"keep:freethreaded\"}")
done

brew_count=0
for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
 [[ -x "$brew_bin" ]] || continue
 [[ -n "$console_user" || $EUID -ne 0 ]] || { warn "[WARN] no console user - brew inventory skipped for $brew_bin"; continue; }
 if ! verify_brew_prefix "$brew_bin"; then
  warn "[WARN] brew prefix ownership or permission check failed for $brew_bin - prefix skipped"
  continue
 fi
 prefix="${brew_bin:h:h}"
 runb() { if [[ $EUID -eq 0 ]]; then /usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>/dev/null; else HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>/dev/null; fi; }
 LISTV=$(runb list --formula --versions); rc=$?
 [[ $rc -ne 0 ]] && {
  if [[ $EUID -eq 0 ]]; then berr=$(/usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 "$brew_bin" list --formula --versions </dev/null 2>&1 >/dev/null | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' '); else berr=$("$brew_bin" list --formula --versions </dev/null 2>&1 >/dev/null | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' '); fi
  warn "[WARN] brew list --formula --versions failed for $brew_bin (rc=$rc): ${berr:-no stderr} - prefix skipped, nothing removable here"; continue; }
 PY_FORMULAS=(); typeset -A KEGS
 for line in ${(f)LISTV}; do
  f="${line%% *}"
  [[ "$f" =~ '^python@[0-9]+\.[0-9]+$' ]] || continue
  PY_FORMULAS+=("$f"); KEGS[$f]="${line#* }"
 done
 [[ ${#PY_FORMULAS} -eq 0 ]] && continue
 BREW_NEWEST=""; for f in $PY_FORMULAS; do m="${f#python@}"; [[ -z "$BREW_NEWEST" || $(minor_num "$m") -gt $(minor_num "$BREW_NEWEST") ]] && BREW_NEWEST="$m"; done
 BREW_DEFAULT=$(/usr/bin/readlink -f "${brew_bin:h}/python3" 2>/dev/null || true)
 for f in $PY_FORMULAS; do
  m="${f#python@}"; esc="${m//./\\.}"
  brew_count=$((brew_count+1))
  uses_out=$(runb uses --installed "$f"); uses_rc=$?
  uses_n=$(print -r -- "$uses_out" | /usr/bin/grep -c . 2>/dev/null) || uses_n=0
  uses_disp=$(print -r -- "$uses_out" | /usr/bin/head -n 5 | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ $//')
  # Check pin receipts on disk because brew list --pinned can return empty under MDM.
  pin="false"; [[ -e "$prefix/var/homebrew/pinned/$f" ]] && pin="true"
  why=""
  [[ "$m" == "$BREW_NEWEST" ]] && why+="newest,"
  [[ $SCAN_CAP -eq 1 ]] && why+="scan-cap,"
  [[ $uses_rc -ne 0 ]] && why+="uses-failed,"
  [[ $uses_n -gt 0 ]] && why+="uses,"
  [[ "$pin" == "true" ]] && why+="pinned,"
  [[ -n "$BREW_DEFAULT" && ( "$BREW_DEFAULT" == *"python@$m/"* || "$BREW_DEFAULT" == *"/Versions/$m/"* ) ]] && why+="default,"
  [[ -n "$VENV_HOMES" ]] && print -r -- "$VENV_HOMES" | /usr/bin/grep -qE "python@${esc}(/|$)" && why+="venv,"
  # Block both brew and python.org when a bare pythonX.Y shebang has no channel path.
  [[ -n "$SHEBANGS" ]] && print -r -- "$SHEBANGS" | /usr/bin/grep -qE "(python@${esc}/|python${esc}([^0-9]|$))" && why+="shebang,"
  v="removable"; [[ -n "$why" ]] && v="blocked:${why%,}"
  [[ "$v" == "removable" ]] && removable=$((removable+1)) || blocked=$((blocked+1))
  e="false"; is_eol "$m" && { e="true"; eol_present=$((eol_present+1)); }
  linked="${$(/usr/bin/readlink "$prefix/opt/$f" 2>/dev/null):t}"
  stale=""; [[ -n "$linked" ]] && stale=$(/bin/ls "$prefix/Cellar/$f" 2>/dev/null | /usr/bin/grep -vFx -- "$linked" | /usr/bin/tr '\n' ' ' | /usr/bin/sed 's/ $//')
  pk=$(pkg_inventory "$prefix/lib/python$m/site-packages")
  INV_LINES+=("PY_INV: {\"src\":\"brew\",\"prefix\":\"$(jesc $prefix)\",\"minor\":\"$(jesc $m)\",\"kegs\":\"$(jesc ${KEGS[$f]})\",\"uses\":\"$(jesc $uses_disp)\",\"uses_n\":$uses_n,\"pinned\":$pin,\"stale\":\"$(jesc $stale)\",\"eol\":$e,\"pkgs\":${pk%%|*},\"pkg_top\":\"$(jesc ${pk#*|})\",\"verdict\":\"$(jesc $v)\"}")
 done
done

log "PY_BUILD: $BUILD_ID sv=$SCHEMA_VERSION"
log "PY_SUMMARY: {\"sv\":$SCHEMA_VERSION,\"pyorg\":${#FW_MINORS},\"pyorgT\":${#T_MINORS},\"newest\":\"$(jesc $NEWEST)\",\"default\":\"$(jesc $DEFAULT_MINOR)\",\"defaultUnknown\":$DEFAULT_UNKNOWN,\"brew\":$brew_count,\"removable\":$removable,\"staleDefault\":$stale_default,\"blocked\":$blocked,\"eol\":$eol_present,\"venvs\":$VENV_N,\"scanCap\":$SCAN_CAP,\"shadows\":\"$(jesc $SHADOWS)\"}"
for l in $INV_LINES; do log "$l"; done
for w in $WARN_LINES; do log "$w"; done
[[ -n "$DEFAULT_MINOR" && -n "$NEWEST" && "$DEFAULT_MINOR" != "$NEWEST" ]] && log "PY_NOTE: default python3 points at $DEFAULT_MINOR while $NEWEST is installed - the python.org installer relinks to the LAST install, not the newest"
[[ $DEFAULT_UNKNOWN -eq 1 ]] && log "PY_NOTE: /usr/local/bin/python3 exists but its target could not be attributed ($DEFAULT_TARGET) - all python.org candidates are blocked (fail-closed)"
[[ $SCAN_CAP -eq 1 ]] && log "PY_NOTE: venv scan hit the 500-file cap - evidence incomplete, all candidates blocked this run (fail-closed)"

if [[ $removable -gt 0 || $stale_default -gt 0 ]]; then log "Audit result: $removable removable + $stale_default stale-default candidate(s) - triggering remediation."; exit 1; fi
log "Audit passed: no removable Python versions."
exit 0
