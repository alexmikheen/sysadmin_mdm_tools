#!/bin/zsh
# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 Aleksandr Mikheenko (alexmikheen)
# Licensed under the MIT License. See LICENSE in the project root for details.
#
# Description: Unit tests for the shared devtools block in remediate_update.sh and install.sh.
# Dependencies: zsh, awk, caffeinate (run on a workstation without root privileges).
# Expected Result: Print PASS for each test case and exit 0. Print FAIL with details and exit 1 on mismatch.
# Required Permissions: none.
# Inputs: none.
# Outputs: PASS or FAIL lines to stdout.
# Logs Place: stdout.
# Rollback: none.
# Safety Notes: Redirects the CLT marker path into a temporary directory and stubs softwareupdate and xcodebuild.

if [ -z "${ZSH_VERSION:-}" ]; then
    exec /bin/zsh "$0" "$@"
fi

set -u
set -o pipefail
HERE="${0:A:h}"
SCRIPT="${HERE}/../remediate_update.sh"
INSTALL="${HERE}/../install.sh"
TMPD=$(/usr/bin/mktemp -d -t brewdevtools); trap '/bin/rm -rf "$TMPD"' EXIT

extract_block() { /usr/bin/awk '/^# ===== BEGIN devtools block/{f=1} f{print} /^# ===== END devtools block/{f=0}' "$1"; }
extract_block "$SCRIPT" > "$TMPD/block.zsh"
[[ -s "$TMPD/block.zsh" ]] || { print "FAIL: devtools block not found in $SCRIPT"; exit 1; }

/usr/bin/awk '/^retry_without_source_builds\(\) \{/{f=1} f{print} f&&/^\}/{f=0}' "$SCRIPT" > "$TMPD/retry.zsh"
[[ -s "$TMPD/retry.zsh" ]] || { print "FAIL: retry_without_source_builds not found in $SCRIPT"; exit 1; }

typeset -a LOGS; LOGS=()
log() { LOGS+=("$1"); }
source "$TMPD/block.zsh"
DEVTOOLS_SKIPPED=()
DEVTOOLS_RETRY_NAMES=()
source "$TMPD/retry.zsh"
BUDGET_EXCEEDED=1
time_budget_exceeded() { return $BUDGET_EXCEEDED; }

fail=0
pass() { print "PASS $1"; }
flunk() { print "FAIL $1"; (( fail++ )); }
check() { local name="$1" got="$2" want="$3"; if [[ "$got" == "$want" ]]; then pass "$name"; else flunk "$name: got '$got', want '$want'"; fi; }
logs_have() { local needle="$1" l; for l in "${LOGS[@]}"; do [[ "$l" == *"$needle"* ]] && return 0; done; return 1; }

CASE_CLT_MACOS27='==> Fetching downloads for: netbirdio/tap/netbird, libssh, ansible
==> Would upgrade 7 outdated packages
==> Upgrading netbirdio/tap/netbird
  0.78.1 -> 0.80.0
Error: Your Command Line Tools (CLT) does not support macOS 27.
It is either outdated or was modified.
Please update your Command Line Tools (CLT) or delete it if no updates are available.
Update them from Software Update in System Settings.'
CASE_XCODE_OUTDATED='==> Upgrading mise
==> Upgrading docker-buildx
==> Upgrading hashicorp/tap/packer
Error: Your Xcode (26.1.1) at /Applications/Xcode.app is too outdated.
Please update to Xcode 27.0 (or delete it).
Xcode can be updated from the App Store.'
GIT_SHIM_LICENCE='==> Updating Homebrew...
Agreeing to the Xcode/iOS license requires admin privileges, please run "sudo xcodebuild -license" and then retry this command.
Error: Failure while executing; `git fetch` exited with 69.'
CASE_XCODE_LICENSE='==> Upgrading foo
Error: You have not agreed to the Xcode license. Please resolve this by running:
  sudo xcodebuild -license'
OLD_CLT='Error: Your Command Line Tools are too outdated.
Update them from Software Update in System Settings.'
NO_DEVTOOLS='Error: No developer tools installed.
Install the Command Line Tools:
  xcode-select --install'
XCODE_NEEDS_CLT='Error: Xcode alone is not sufficient on macOS Tahoe.
Install the Command Line Tools:
  xcode-select --install'
XCODE_SDK='Error: Your Xcode does not support macOS 27.
It is either outdated or was modified.'
CASE_NONFATAL_WARN='==> Upgrading glib
Warning: Your Xcode (26.6) is outdated.
Please update to Xcode 27.0 (or delete it).
Xcode can be updated from the App Store.
Warning: A newer Command Line Tools release is available.
You should download the Command Line Tools for Xcode 27.0.
==> Upgrading glib dependency: python@3.14 (3.14.8 -> 3.14.8_1)
/opt/homebrew/Cellar/glib/2.86.0: 541 files, 36MB'
CLEAN='==> Upgrading 2 outdated packages:
git 2.55.0 -> 2.56.0
node 26.8.2 -> 26.11.0_1
==> Upgrading git
/opt/homebrew/Cellar/git/2.56.0: 1,734 files, 66MB'
CASE_GIT_MISSING='/opt/homebrew/Library/Homebrew/os/mac/version.rb:49:in `initialize'"'"': unknown or unsupported macOS version: "27.0.1" (MacOSVersionError)
Error: '"'"'git'"'"' must be installed and in your PATH!'
CASE_SUMMARY_COUNT='==> Upgrading hdrhistogram_c
==> Upgrading simdutf
==> Upgrading 1 dependent of upgraded formulae:
Error: Failed to download resource "node"'
DEP_FORM='==> Upgrading lima
==> Upgrading lima dependency: go (1.27.1 -> 1.27.2)
Error: Your Command Line Tools are too outdated.'

check "verdict: CLT does not support macOS 27"              "$(devtools_verdict "$CASE_CLT_MACOS27")" clt
check "verdict: CLT too outdated (legacy text)"             "$(devtools_verdict "$OLD_CLT")" clt
check "verdict: no developer tools installed"               "$(devtools_verdict "$NO_DEVTOOLS")" clt
check "verdict: git missing means CLT missing"              "$(devtools_verdict "$CASE_GIT_MISSING")" clt
check "verdict: Xcode alone requires CLT"                   "$(devtools_verdict "$XCODE_NEEDS_CLT")" clt
check "verdict: full Xcode too outdated"                    "$(devtools_verdict "$CASE_XCODE_OUTDATED")" xcode
check "verdict: Xcode does not support macOS 27"            "$(devtools_verdict "$XCODE_SDK")" xcode
check "verdict: Xcode license not accepted"                 "$(devtools_verdict "$CASE_XCODE_LICENSE")" license
check "verdict: git shim license text from brew update"     "$(devtools_verdict "$GIT_SHIM_LICENCE")" license
check "verdict: non-fatal warnings only"                    "$(devtools_verdict "$CASE_NONFATAL_WARN")" none
check "verdict: clean upgrade"                              "$(devtools_verdict "$CLEAN")" none
check "verdict: empty output"                               "$(devtools_verdict "")" none
check "verdict: license wins over CLT when both appear"     "$(devtools_verdict "$CASE_CLT_MACOS27"$'\n'"$CASE_XCODE_LICENSE")" license
check "verdict: CLT wins over Xcode when both appear"       "$(devtools_verdict "$CASE_XCODE_OUTDATED"$'\n'"$OLD_CLT")" clt

check "culprit: tap-qualified formula"                      "$(devtools_culprit "$CASE_CLT_MACOS27")" netbirdio/tap/netbird
check "culprit: last Upgrading line wins"                   "$(devtools_culprit "$CASE_XCODE_OUTDATED")" hashicorp/tap/packer
check "culprit: dependency line names the dependency"       "$(devtools_culprit "$DEP_FORM")" go
check "culprit: plain name"                                 "$(devtools_culprit "$CLEAN")" git
check "culprit: summary lines with a count are skipped"     "$(devtools_culprit "$CASE_SUMMARY_COUNT")" simdutf
check "culprit: count-only output returns empty"            "$(devtools_culprit "==> Upgrading 7 outdated packages:")" ""
check "culprit: no match returns empty"                     "$(devtools_culprit "Error: nothing here")" ""

d=$(xcode_outdated_detail "$CASE_XCODE_OUTDATED")
if [[ "$d" == *"26.1.1"* && "$d" == *"/Applications/Xcode.app"* && "$d" == *"Please update to Xcode 27.0"* ]]; then pass "xcode detail: version, path and target"; else flunk "xcode detail outdated: '$d'"; fi
d=$(xcode_outdated_detail "$XCODE_SDK")
if [[ "$d" == *"does not support macOS 27"* ]]; then pass "xcode detail: unsupported macOS format"; else flunk "xcode detail SDK: '$d'"; fi

mkdir -p "$TMPD/bin"
export STUB_LOG="$TMPD/stub.log"; : > "$STUB_LOG"
cat > "$TMPD/bin/softwareupdate" <<'STUB'
#!/bin/zsh
print -r -- "$*" >> "$STUB_LOG"
if [[ "$1" == "-l" ]]; then
    [[ -n "${STUB_NO_LABELS:-}" ]] && { echo "No new software available."; exit 0; }
    cat <<'L'
Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: Command Line Tools for Xcode-27.0
	Title: Command Line Tools for Xcode, Version: 27.0, Size: 800000KiB, Recommended: YES,
* Label: Command Line Tools for Xcode-26.6
	Title: Command Line Tools for Xcode, Version: 26.6, Size: 800000KiB, Recommended: YES,
L
    exit 0
fi
exit "${STUB_INSTALL_RC:-0}"
STUB
cat > "$TMPD/bin/xcodebuild" <<'STUB'
#!/bin/zsh
print -r -- "$*" >> "$STUB_LOG"
exit 0
STUB
chmod +x "$TMPD/bin/softwareupdate" "$TMPD/bin/xcodebuild"
SOFTWAREUPDATE_BIN="$TMPD/bin/softwareupdate"
XCODEBUILD_BIN="$TMPD/bin/xcodebuild"

CLT_MARKER="$TMPD/marker"; LOGS=(); : > "$STUB_LOG"
repair_clt; rc=$?
check "repair_clt: success rc" "$rc" 0
check "repair_clt: highest label by sort -V, not list order" "$(/usr/bin/grep -c -- '-i Command Line Tools for Xcode-27.0' "$STUB_LOG")" 1
if [[ ! -e "$CLT_MARKER" ]]; then pass "repair_clt: marker removed after success"; else flunk "repair_clt: marker left behind"; fi

LOGS=(); : > "$STUB_LOG"
STUB_INSTALL_RC=1 repair_clt; rc=$?
check "repair_clt: install failure rc" "$rc" 1
if [[ ! -e "$CLT_MARKER" ]]; then pass "repair_clt: marker removed after failure"; else flunk "repair_clt: marker left behind on failure"; fi

LOGS=(); : > "$STUB_LOG"
STUB_NO_LABELS=1 repair_clt; rc=$?
check "repair_clt: no label rc" "$rc" 1
if logs_have "offered no Command Line Tools"; then pass "repair_clt: no-label warning logged"; else flunk "repair_clt: no-label warning missing: ${(j: | :)LOGS}"; fi
check "repair_clt: no install attempted without a label" "$(/usr/bin/grep -c -- '^-i ' "$STUB_LOG")" 0

print -r -- "victim content" > "$TMPD/victim"; /bin/ln -s "$TMPD/victim" "$CLT_MARKER"; LOGS=(); : > "$STUB_LOG"
repair_clt; rc=$?
check "repair_clt: pre-planted symlink is unlinked, not followed (rc)" "$rc" 0
check "repair_clt: symlink target untouched" "$(<"$TMPD/victim")" "victim content"
if [[ ! -e "$CLT_MARKER" && ! -L "$CLT_MARKER" ]]; then pass "repair_clt: marker gone after symlink case"; else flunk "repair_clt: marker still present after symlink case"; fi

if (( EUID == 0 )); then
    print "SKIP repair_clt: refusal path needs a non-root run (root ignores directory modes)"
else
    mkdir -p "$TMPD/ro"; chmod 555 "$TMPD/ro"; CLT_MARKER="$TMPD/ro/marker"; LOGS=(); : > "$STUB_LOG"
    repair_clt; rc=$?
    check "repair_clt: cannot create a fresh marker -> refuses (rc)" "$rc" 1
    if logs_have "refusing to run the CLT repair"; then pass "repair_clt: refusal logged"; else flunk "repair_clt: refusal not logged: ${(j: | :)LOGS}"; fi
    check "repair_clt: softwareupdate never called when refusing" "$(/usr/bin/wc -l < "$STUB_LOG" | /usr/bin/tr -d ' ')" 0
    chmod 755 "$TMPD/ro"
fi
CLT_MARKER="$TMPD/marker"

: > "$STUB_LOG"
repair_xcode_license; rc=$?
check "repair_xcode_license: rc" "$rc" 0
check "repair_xcode_license: runs xcodebuild -license accept" "$(<"$STUB_LOG")" "-license accept"

# Record upgrade calls in a file because run_formula_upgrade calls run_brew inside a subshell.
typeset -a OUTDATED_LIST PINNED_LIST
CALLS="$TMPD/upgrade_calls"
upgrade_calls() { [[ -s "$CALLS" ]] && /usr/bin/paste -sd '|' "$CALLS" || true; }
upgrade_n() { [[ -s "$CALLS" ]] && /usr/bin/wc -l < "$CALLS" | /usr/bin/tr -d ' ' || echo 0; }
run_formula_upgrade() { local b="$1" r="$2"; shift 2; UPGRADE_EXIT=0; UPGRADE_OUTPUT=$(run_brew "$b" "$r" upgrade --formula "$@" 2>&1) || UPGRADE_EXIT=$?; }
run_brew() {
    shift 2
    case "$1 $2" in
        "outdated --formula") print -l -- "${OUTDATED_LIST[@]}" ;;
        "list --pinned")      print -l -- "${PINNED_LIST[@]}" ;;
        "upgrade --formula")  shift 2; print -r -- "$*" >> "$CALLS"; scenario "$@" ;;
    esac
}
reset_scenario() { OUTDATED_LIST=("$@"); PINNED_LIST=(); : > "$CALLS"; LOGS=(); }

reset_scenario netbirdio/tap/netbird git node
scenario() { if [[ "$*" == "git node" ]]; then print -r -- "$CLEAN"; return 0; fi; print -r -- "$CASE_CLT_MACOS27"; return 1; }
UPGRADE_OUTPUT="$CASE_CLT_MACOS27"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 1: skipped list" "${(j:,:)DEVTOOLS_SKIPPED}" "netbirdio/tap/netbird"
check "retry 1: retried with bottled names only" "$(upgrade_calls)" "git node"
check "retry 1: final exit" "$UPGRADE_EXIT" 0
check "retry 1: one retry" "$(upgrade_n)" 1
check "retry 1: narrowed list kept for later retries" "${(j:,:)DEVTOOLS_RETRY_NAMES}" "git,node"

reset_scenario a b c d
scenario() { print -r -- "==> Upgrading $1"$'\n'"$OLD_CLT"; return 1; }
UPGRADE_OUTPUT="==> Upgrading a"$'\n'"$OLD_CLT"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 2: three culprits collected" "${(j:,:)DEVTOOLS_SKIPPED}" "a,b,c"
check "retry 2: calls narrow each round" "$(upgrade_calls)" "b c d|c d|d"
check "retry 2: capped at 3 rounds" "$(upgrade_n)" 3
check "retry 2: still failing" "$UPGRADE_EXIT" 1

reset_scenario a b; PINNED_LIST=(b)
scenario() { print -r -- "$CLEAN"; return 0; }
UPGRADE_OUTPUT="==> Upgrading a"$'\n'"$OLD_CLT"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 3: culprit recorded" "${(j:,:)DEVTOOLS_SKIPPED}" "a"
check "retry 3: no upgrade call when nothing remains" "$(upgrade_n)" 0
check "retry 3: narrowed list stays empty when nothing was retried" "${#DEVTOOLS_RETRY_NAMES[@]}" 0
if logs_have "Nothing left to upgrade"; then pass "retry 3: nothing-left logged"; else flunk "retry 3: log missing: ${(j: | :)LOGS}"; fi

reset_scenario lima go
scenario() { if [[ "$*" == "lima" ]]; then print -r -- "$CLEAN"; return 0; fi; print -r -- "$DEP_FORM"; return 1; }
UPGRADE_OUTPUT="$DEP_FORM"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 4: dependency culprit" "${(j:,:)DEVTOOLS_SKIPPED}" "go"
check "retry 4: retried without it" "$(upgrade_calls)" "lima"
reset_scenario homebrew/core/netbird git
scenario() { print -r -- "$CLEAN"; return 0; }
UPGRADE_OUTPUT="==> Upgrading netbird"$'\n'"$OLD_CLT"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 5: short culprit excludes tap-qualified outdated name" "$(upgrade_calls)" "git"

reset_scenario a b
BUDGET_EXCEEDED=0
UPGRADE_OUTPUT="==> Upgrading a"$'\n'"$OLD_CLT"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 7: budget exceeded makes no calls" "$(upgrade_n)" 0
check "retry 7: budget exceeded skips nothing" "${#DEVTOOLS_SKIPPED[@]}" 0
if logs_have "Time budget reached"; then pass "retry 7: deferral logged"; else flunk "retry 7: log missing: ${(j: | :)LOGS}"; fi
BUDGET_EXCEEDED=1

reset_scenario a b
UPGRADE_OUTPUT="$NO_DEVTOOLS"; UPGRADE_EXIT=1
retry_without_source_builds /opt/homebrew/bin/brew 0
check "retry 6: no culprit makes no calls" "$(upgrade_n)" 0

if /usr/bin/diff -q <(extract_block "$SCRIPT") <(extract_block "$INSTALL") >/dev/null; then pass "install.sh carries the same devtools block"; else flunk "install.sh devtools block differs from remediate_update.sh"; fi
if ! /usr/bin/grep -q 'retry_without_source_builds' "$INSTALL"; then pass "install.sh has no copy of retry_without_source_builds"; else flunk "install.sh must not carry retry_without_source_builds"; fi

print -- "--- $fail failure(s)"
exit $(( fail > 0 ))
