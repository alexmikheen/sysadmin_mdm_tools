# Homebrew Fleet Management

This directory contains scripts that install, audit, and update Homebrew on managed macOS devices.
Each script runs as `root` from a Mobile Device Management (MDM) agent and drops privileges to the active console user through `launchctl asuser` and `sudo -u`.

All scripts re-execute in `/bin/zsh` automatically if an administrator invokes them with `sh` or `bash`.
If a non-root run cannot write to `/var/log`, the script writes its log file to `/tmp` instead.

## Multi-Architecture Support

The audit and remediation scripts inspect both Homebrew locations on each device:

- `/opt/homebrew/bin/brew` for native Apple Silicon installations
- `/usr/local/bin/brew` for Intel installations and Rosetta installations on Apple Silicon

When an Apple Silicon device has a `/usr/local` installation, the script wraps `brew` commands with `/usr/bin/arch -x86_64` if Rosetta is available.
If Rosetta is absent, the script skips `/usr/local` and continues with `/opt/homebrew`.

## Scripts

| Script | Role | Log Path |
| :--- | :--- | :--- |
| `audit_update.sh` | Audits cache age, outdated unpinned formulae, and outdated casks. | `/var/log/brew-global-audit.log` |
| `remediate_update.sh` | Updates eligible formulae and casks with safety checks and automatic repairs. | `/var/log/brew-global-remediation.log` |
| `install.sh` | Installs native Apple Silicon Homebrew or repairs an existing installation. | `/var/log/brew-install.log` |
| `tests/test_remediate_update.zsh` | Runs unit tests for developer-tool repairs and retry logic. | `stdout` |

## `Homebrew/audit_update.sh`

This script audits every executable Homebrew installation without modifying packages or running `brew update`.

### Checks

1. Check that an active console user exists. If no GUI user is active, exit `0`.
2. Probe each prefix with `brew --repository` and `brew --cache`.
3. Check the modification time of `.git/FETCH_HEAD` and `api/formula.jws.json`. Mark the prefix non-compliant if the cache is 2 days old or older.
4. List outdated formulae with `brew outdated --formula -q`. Query `brew info --json=v2` per formula to skip formulae pinned by user policy.
5. List outdated casks with `brew outdated --cask -q`.

### Exit Codes

- `0`: No Homebrew installation exists, no GUI user is active, or all prefixes are compliant.
- `1`: At least one prefix has a stale cache, an outdated unpinned formula, an outdated cask, or a failed probe.

## `Homebrew/remediate_update.sh`

This script updates all unpinned formulae and eligible casks while protecting active user sessions.

### Safety Guards

- **Battery guard**: Abort with exit `0` when the device runs on battery power below 20 percent charge.
- **Sleep prevention**: Wrap every `brew` command and `softwareupdate` install in `caffeinate -i`.
- **Time budget**: Stop starting new prefixes, CLT installs, retries, or cask upgrades after 45 minutes (`2700` seconds). This prevents MDM agents from terminating the script at 60 minutes.
- **Stale lock protection**: Check `lsof +D` on `var/homebrew/locks` and `pgrep` for an active `brew` binary before deleting stale lock files.

### Tap Trust and Formula Upgrades

Before upgrading formulae, the script reads `INSTALL_RECEIPT.json` files from `Cellar` and `Caskroom`.
It trusts installed third-party tap formulae and casks individually instead of disabling tap trust globally.
When an uninstalled sibling formula from an installed tap blocks an upgrade, the script trusts that sibling formula. It retries up to 3 rounds.

If a download cache error occurs, the script removes the user download cache directory as the console user and retries once.
If symlink conflicts occur, the script runs `brew link --overwrite` on each affected formula.

### Developer Tools Repair (`devtools`)

When a formula upgrade fails due to Apple developer tools, the shared `devtools` block classifies the error and runs a targeted repair:

- **Xcode license**: Run `xcodebuild -license accept` as `root` and retry the upgrade once.
- **Command Line Tools (CLT)**: Create `/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress` with `noclobber`, install the newest CLT label via `softwareupdate -i`, remove the marker, and retry once.
- **Outdated Xcode**: Notify the console user to update or remove Xcode from the App Store because MDM cannot upgrade full Xcode.

If developer tools still block a source build after repair, `retry_without_source_builds` identifies the failing formula and retries the remaining bottled formulae for up to 3 rounds.
The script exits `1` so MDM records the blocked formula while still patching all bottled formulae.

### Running GUI App Protection and MDM Auto App Migration

Before upgrading a cask, the script reads MDM configuration profiles (`profiles -C -o stdout`) for `com.kandji.profile.autoapp.` entries and extracts their display names and 10-character Apple Team IDs.

- **Matched MDM app**: If a cask matches an Auto App profile and its `.app` bundle has a matching `codesign` Team ID, the script removes `Caskroom/<cask>`. It runs removal as the console user and leaves the application binary untouched under MDM management.
- **Unmatched or unconfirmed match**: When the Team ID does not match or is absent, the script keeps the cask under Homebrew.
- **Running GUI apps**: Before upgrading a Homebrew-managed cask, the script checks `pgrep` for the application process. If the app runs, the script skips the upgrade and notifies the user to update through MDM Self Service.
- **External conflicts**: If a cask upgrade fails because an external copy exists outside `Caskroom`, the script logs the conflict and skips forced reinstallation.

### Permission Diagnostics

The script never runs `chown` or `rm -rf` as `root` on user-owned Homebrew directories.
When Homebrew reports unwritable paths inside its own prefix, the script separates cosmetic documentation or shell-completion paths from blocking prefix paths.
On blocking permission failures, the script logs the affected paths, notifies the user with safe recovery commands, and exits `1`.

## `Homebrew/install.sh`

This script installs native Apple Silicon Homebrew at `/opt/homebrew` for the active console user.
On non-`arm64` devices or devices without an active console user, the script exits `0`.

### Fresh Installation

1. Check that `/opt/homebrew` is not a symlink or a non-empty broken directory.
2. Check `xcrun --version`. Accept the Xcode license or install Command Line Tools via the shared `devtools` block if needed.
3. Create the `/opt/homebrew` directory tree owned by the console user.
4. Clone `https://github.com/Homebrew/brew` as the console user, fetch tags, and switch to the newest release tag.
5. Link `/opt/homebrew/bin/brew` and write `/opt/homebrew/bin` to `/etc/paths.d/homebrew`.
6. Run `brew update`, `brew cleanup`, and `brew doctor`.

### Existing Installation Repair

When `/opt/homebrew/bin/brew` already exists, the script updates Homebrew, displays a blocking warning dialog to the user, upgrades all unpinned formulae, and upgrades non-MDM casks with `--greedy-auto-updates`.
Set the optional `BREW_HELP_URL` environment variable to attach a support link to MDM alerts.

## `Homebrew/tests/test_remediate_update.zsh`

This test suite checks the shared `devtools` block and `retry_without_source_builds` without requiring `root` privileges or live network access.
It stubs `softwareupdate`, `xcodebuild`, and `brew`, redirects the CLT marker into a temporary directory, and checks verbatim `devtools` block parity between `remediate_update.sh` and `install.sh`.

Run the tests from the repository root:

```zsh
zsh Homebrew/tests/test_remediate_update.zsh
```

## MDM Deployment

### Iru (Kandji)

1. Open **Library**, select **Add New**, and select **Custom Script**.
2. Paste `Homebrew/audit_update.sh` into the **Audit Script** field.
3. Paste `Homebrew/remediate_update.sh` into the **Remediation Script** field.
4. Set the execution frequency to daily and assign the item to your blueprint.
5. Create a second Self Service **Custom Script** item with `Homebrew/install.sh` for zero-touch installs and manual repairs.

### Jamf Pro

1. Create an **Extension Attribute** or scheduled audit policy using `Homebrew/audit_update.sh`.
2. Create a **Smart Group** targeting devices where the audit reports non-compliant status.
3. Create a **Policy** scoped to that Smart Group that executes `Homebrew/remediate_update.sh`.
4. Create a Self Service **Policy** that executes `Homebrew/install.sh` for initial installation or repair.
