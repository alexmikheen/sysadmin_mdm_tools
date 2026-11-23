#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
#
# Description: Interactive Self Service script that removes unused Python versions.
#              Show the candidate list with Cancel and Remove now buttons.
#              Remove safe candidates (removable and stale-default) after user consent.
#              Show a summary dialog of removed and kept versions.
# Location: Python/self_service_cleanup.sh
# Dependencies: osascript, pkgutil, rm, readlink, stat, brew (optional), caffeinate
# Expected Result: Exit 0 for normal outcomes including cancel, nothing to do, and success.
# Required Permissions: root (MDM Self Service context, dialogs run as console user)
# Inputs: none
# Outputs: PY_SS status lines to stdout and log
# Logs: /var/log/mdm_tools/python-selfservice.log
# Rollback: Reinstall the removed version from python.org or run brew install python@X.Y.
# Safety Notes: Keep candidate logic identical to Python/audit_update.sh.
#               User consent allows immediate stale-default removal with symlink repair.
#               Never override venv, shebang, launchd, or brew uses blockers.

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# --- CONFIGURATION ---
LOG_DIR="/var/log/mdm_tools"
LOG_FILE="${LOG_DIR}/python-selfservice.log"
# --- /CONFIGURATION ---

TODAY=$(/bin/date '+%Y%m%d')
/bin/mkdir -p "$(/usr/bin/dirname "$LOG_FILE")" 2>/dev/null || true
if [[ -f "$LOG_FILE" ]]; then { /usr/bin/tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && /bin/mv "${LOG_FILE}.tmp" "$LOG_FILE"; } 2>/dev/null || true; fi
log() { local m="[$(/bin/date '+%Y-%m-%d %H:%M:%S')] $1"; print -r -- "$m"; { print -r -- "$m" >> "$LOG_FILE"; } 2>/dev/null || true; }

console_user=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)
[[ "$console_user" == "root" || "$console_user" == "loginwindow" ]] && console_user=""
console_uid=""; [[ -n "$console_user" ]] && console_uid=$(/usr/bin/id -u "$console_user" 2>/dev/null || true)
minor_num() { print -r -- "$1" | /usr/bin/awk -F. '{printf "%d%03d", $1, $2}'; }

dialog() {
 local msg="$1" mode="${2:-ok}" title="Python cleanup"
 local -a osa_cmd
 if [[ "$mode" == "confirm" ]]; then
  osa_cmd=(/usr/bin/osascript
   -e 'on run argv'
   -e 'display dialog (item 1 of argv) with title (item 2 of argv) buttons {"Cancel", "Remove now"} default button "Remove now" giving up after 180'
   -e 'end run' -- "$msg" "$title")
 else
  osa_cmd=(/usr/bin/osascript
   -e 'on run argv'
   -e 'display dialog (item 1 of argv) with title (item 2 of argv) buttons {"OK"} default button "OK" giving up after 180'
   -e 'end run' -- "$msg" "$title")
 fi
 if [[ $EUID -eq 0 && -n "$console_uid" && -n "$console_user" ]]; then
  /bin/launchctl asuser "$console_uid" /usr/bin/sudo -u "$console_user" "${osa_cmd[@]}" 2>/dev/null
 else
  "${osa_cmd[@]}" 2>/dev/null
 fi
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

log "=== Starting Python Self Service Cleanup ==="
[[ -z "$console_user" ]] && { log "[WARN] no console user - nothing to show, exiting"; exit 0; }

SCAN_CAP=0
FW_MINORS=()
for d in /Library/Frameworks/Python.framework/Versions/*(N/); do
 m="${d:t}"
 [[ "$m" =~ '^[0-9]+\.[0-9]+$' ]] || continue
 FW_MINORS+=("$m")
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

typeset -a PYORG_RM KEPT_LINES
ESC_DEFAULT=""
for m in $FW_MINORS; do
 b=$(pyorg_blockers "$m")
 if [[ -z "$b" ]]; then PYORG_RM+=("$m")
 elif [[ "$b" == "stale-default" ]]; then ESC_DEFAULT="$m"; PYORG_RM+=("$m")
 elif [[ "$b" == "newest" ]]; then :
 else KEPT_LINES+=("python.org $m - in use ($b)"); log "PY_SS: pyorg $m kept (${b})"
 fi
done

typeset -a BREW_RM
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
  PY_FORMULAS+=("$f")
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
  if [[ -z "$why" ]]; then BREW_RM+=("$brew_bin|$f")
  elif [[ "$why" == "newest," ]]; then :
  else KEPT_LINES+=("Homebrew $f - in use (${why%,})"); log "PY_SS: brew $f kept (${why%,})"
  fi
 done
done

if [[ ${#PYORG_RM} -eq 0 && ${#BREW_RM} -eq 0 ]]; then
 MSG="Nothing to clean up - your Python installs are all in use or current. You are all set, thanks!"
 [[ ${#KEPT_LINES} -gt 0 ]] && MSG+=$'\n\n'"Kept (in use):"$'\n'"$(printf '%s\n' "${KEPT_LINES[@]}")"
 dialog "$MSG" "ok" >/dev/null || true
 log "PY_SS: nothing removable - done"
 exit 0
fi

typeset -a CAND_LINES
for m in $PYORG_RM; do
 if [[ "$m" == "$ESC_DEFAULT" ]]; then CAND_LINES+=("python.org $m (your current default - python3 will be switched to $NEWEST)")
 else CAND_LINES+=("python.org $m"); fi
done
for entry in $BREW_RM; do CAND_LINES+=("Homebrew ${entry##*|}"); done
MSG="These Python versions are superseded and nothing on this Mac depends on them:"$'\n\n'"$(printf '%s\n' "${CAND_LINES[@]}")"$'\n\n'"Remove them now?"
[[ ${#KEPT_LINES} -gt 0 ]] && MSG+=$'\n\n'"(Kept as in use: $(printf '%s; ' "${KEPT_LINES[@]}"))"
CHOICE=$(dialog "$MSG" "confirm"); drc=$?
if [[ $drc -ne 0 || "$CHOICE" != *"Remove now"* || "$CHOICE" == *"gave up:true"* ]]; then
 log "PY_SS: user cancelled or dialog timed out - nothing removed"
 exit 0
fi
log "PY_SS: user confirmed removal (${CAND_LINES[*]})"
/usr/bin/caffeinate -imsu -w $$ >/dev/null 2>&1 &

FAILED=0
typeset -a REMOVED SNAPSHOTS
for m in $PYORG_RM; do
 fw="/Library/Frameworks/Python.framework/Versions/$m"
 [[ -d "$fw" ]] || { log "PY_SS: pyorg $m already gone - skipped"; continue; }
 snap=$(snapshot_packages "python.org $m" "$fw/bin/python3" "$fw/lib/python$m/site-packages"); saved=0; log_snapshot PY_SS "python.org $m" "$snap" && saved=1
 log "PY_SS: removing python.org $m"
 /bin/rm -rf "$fw" 2>/dev/null || { log "[ERROR] rm framework $m failed"; FAILED=1; continue; }
 REMOVED+=("python.org $m")
 [[ $saved -eq 1 ]] && SNAPSHOTS+=("python.org $m: ${snap%%|*} packages -> ${${snap#*|}%%|*}")
 /bin/rm -rf "/Applications/Python $m" 2>/dev/null || true
 for r in PythonFramework PythonApplications PythonUnixTools PythonDocumentation; do
  /usr/sbin/pkgutil --forget "org.python.Python.$r-$m" >/dev/null 2>&1 || true
 done
 cur=$(/usr/bin/readlink /Library/Frameworks/Python.framework/Versions/Current 2>/dev/null || true)
 if [[ "$cur" == "$m" && -n "$NEWEST" ]]; then
  /bin/ln -sfn "$NEWEST" /Library/Frameworks/Python.framework/Versions/Current 2>/dev/null || true
  log "PY_SS: Current relinked -> $NEWEST"
 fi
 for l in /usr/local/bin/python3*(N@) /usr/local/bin/pip3*(N@) /usr/local/bin/idle3*(N@) /usr/local/bin/pydoc3*(N@) /usr/local/bin/2to3*(N@); do
  [[ ! -e "$l" ]] && { /bin/rm -f "$l" 2>/dev/null || true; log "PY_SS: dangling symlink removed: $l"; }
 done
 if [[ -n "$NEWEST" ]]; then
  nb="/Library/Frameworks/Python.framework/Versions/$NEWEST/bin"
  for name in python3 pip3 python3-config idle3; do
   if [[ ! -e "/usr/local/bin/$name" && -x "$nb/$name" ]]; then
    /bin/ln -s "$nb/$name" "/usr/local/bin/$name" 2>/dev/null && log "PY_SS: relinked /usr/local/bin/$name -> $NEWEST" || log "[WARN] relink /usr/local/bin/$name failed"
   fi
  done
 fi
done
for entry in $BREW_RM; do
 brew_bin="${entry%%|*}"; f="${entry##*|}"; prefix="${brew_bin:h:h}"
 verify_brew_prefix "$brew_bin" || { log "[WARN] brew prefix check failed before uninstall for $brew_bin - skipped"; continue; }
 runb() { if [[ $EUID -eq 0 ]]; then /usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>&1; else HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" "$@" </dev/null 2>&1; fi; }
 if [[ $EUID -eq 0 ]]; then uses_out=$(/usr/bin/sudo -u "$console_user" -H /usr/bin/env HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" uses --installed "$f" </dev/null 2>/dev/null); else uses_out=$(HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INTERACTIVE=1 HOMEBREW_NO_ENV_HINTS=1 "$brew_bin" uses --installed "$f" </dev/null 2>/dev/null); fi; uses_rc=$?
 [[ $uses_rc -ne 0 ]] && { log "PY_SS: brew $f kept (uses re-check failed rc=$uses_rc)"; continue; }
 [[ -n "$uses_out" ]] && { log "PY_SS: brew $f kept (dependent appeared)"; continue; }
 [[ -e "$prefix/var/homebrew/pinned/$f" ]] && { log "PY_SS: brew $f kept (pinned appeared)"; continue; }
 m="${f#python@}"
 snap=$(snapshot_packages "Homebrew $f" "$prefix/opt/$f/bin/python3" "$prefix/lib/python$m/site-packages"); saved=0; log_snapshot PY_SS "Homebrew $f" "$snap" && saved=1
 OUT=$(runb uninstall "$f") && { log "PY_SS: brew $f uninstalled"; REMOVED+=("Homebrew $f"); [[ $saved -eq 1 ]] && SNAPSHOTS+=("Homebrew $f: ${snap%%|*} packages -> ${${snap#*|}%%|*}"); } || { log "[ERROR] brew uninstall $f: $(print -r -- "$OUT" | /usr/bin/head -n 2 | /usr/bin/tr '\n' ' ')"; FAILED=1; }
done

REPORT=""
if [[ ${#REMOVED} -gt 0 ]]; then
 REPORT="Removed:"$'\n'"$(printf '%s\n' "${REMOVED[@]}")"
 [[ -n "$NEWEST" ]] && REPORT+=$'\n'"Your python3 now points at $NEWEST."
 [[ ${#SNAPSHOTS} -gt 0 ]] && REPORT+=$'\n\n'"Packages that were installed in the removed versions are listed in:"$'\n'"$(printf '%s\n' "${SNAPSHOTS[@]}")"$'\n'"Restore them in a virtualenv (never removed by the cleanup): python3 -m venv ~/venvs/work && ~/venvs/work/bin/pip install -r <that file>"
else
 REPORT="Nothing was removed."
fi
[[ ${#KEPT_LINES} -gt 0 ]] && REPORT+=$'\n\n'"Kept (still in use):"$'\n'"$(printf '%s\n' "${KEPT_LINES[@]}")"
[[ $FAILED -ne 0 ]] && REPORT+=$'\n\n'"Some removals failed - IT has the details in the logs."
REPORT+=$'\n\n'"Thank you for keeping your Mac tidy!"
dialog "$REPORT" "ok" >/dev/null || true
for sn in $SNAPSHOTS; do log "PY_SS: removed $sn"; done
log "PY_SS: report shown (removed: ${REMOVED[*]:-none}; failed: $FAILED)"
exit 0
