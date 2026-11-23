# macOS Python Version Cleanup

This folder contains three fail-closed scripts for MDM-managed macOS devices (Iru, Kandji, Jamf Pro, Fleet, or Munki). The scripts inventory Python interpreters from **python.org** and **Homebrew**, check local dependencies, save third-party package lists, and remove superseded versions.

## Why Remove Old Python Versions

Standard macOS updates do not remove older Python minor versions:

- **python.org (`Python.framework`):** Keeps every minor version inside `/Library/Frameworks/Python.framework/Versions/X.Y`. Its PKG installer also links `Versions/Current` and `/usr/local/bin/python3` to the last installed version rather than the newest version.
- **Homebrew (`python@X.Y`):** Installs each minor version as a separate `python@X.Y` formula.

Because neither channel removes superseded versions, software updates alone do not reduce the vulnerable interpreter count on a device.

## Scripts and Operating Modes

All three scripts share identical candidate discovery and dependency checks:

| Script | Role | Execution Context |
| :--- | :--- | :--- |
| `audit_update.sh` | Read-only inventory and dependency scanner. Outputs single-line JSON markers (`PY_BUILD`, `PY_SUMMARY`, `PY_INV`) and exits `1` when at least one candidate is `removable` or `stale-default`. | Root (MDM Audit) |
| `remediate_update.sh` | Before the cutoff date, shows user warning alerts only. On or after the cutoff date, rechecks blockers, saves package snapshots, removes safe candidates, repairs symlinks, and notifies the user. | Root (MDM Remediation) |
| `self_service_cleanup.sh` | Interactive Self Service tool. Shows a confirmation dialog (`Cancel` or `Remove now`), removes `removable` and `stale-default` versions after user consent, and shows a completion summary. | Root (MDM Self Service) |

### Deployment Modes in `remediate_update.sh`

1. **Standalone Mode (`SLA_MODE="all"` — Default):** Runs on any MDM without external automation. Set one cutoff date in `SLA_ENFORCE_FROM="YYYYMMDD"`. Before that date, the script shows warning alerts through `iru`, `kandji`, or `osascript`. On or after `SLA_ENFORCE_FROM`, the script saves package lists and removes rechecked `removable` and `stale-default` versions.
2. **CVE-Gated Mode (`SLA_MODE="cve_gated"`):** Connects to an external vulnerability sync pipeline. The pipeline calculates exact CPython deadlines (`cpython:3.14.8=YYYYMMDD`) and updates the `SLA_DEADLINES` block in `remediate_update.sh`. Enforcement uses only per-version dates in `SLA_DEADLINES` and ignores `SLA_ENFORCE_FROM`. The script leaves versions without active fixable CVEs untouched.

## Fail-Closed Dependency and Safety Rules

Every dependency check fails closed. If a probe fails, a directory scan reaches its limit, or a default symlink is unknown, the script blocks removal.

### 1. `python.org` Framework Rules

The scripts inventory free-threaded `PythonT.framework` builds as `keep:freethreaded` and never remove them. A standard `Python.framework` minor version is `removable` only when all conditions below are true:

- It is not the newest installed minor version.
- It is not the resolved target of `/usr/local/bin/python3`. If `readlink -f` returns an unrecognized target, all candidates fail closed with `default-unknown`.
- No virtual environment references it. The scanner checks `/Users` to depth 7, Poetry caches (`~/Library/Caches/pypoetry`), and `~/.virtualenvs` for `pyvenv.cfg` `home=` entries. At 500 files, `scan-cap` blocks all removals.
- No script shebang in `/Users/*/bin`, `/Users/*/.local/bin`, or `/usr/local/bin` references `pythonX.Y` or `/Versions/X.Y/`.
- No LaunchDaemon or LaunchAgent plist in `/Library/LaunchDaemons`, `/Library/LaunchAgents`, or `/Users/*/Library/LaunchAgents` references its framework path.

**`stale-default` Escalation:** When an outdated minor version has only the `default` blocker, the audit marks it `stale-default`. On or after the cutoff date, or after Self Service consent, the script removes it and links `/usr/local/bin/python3` and `Versions/Current` to the newest installed minor version.

### 2. Homebrew `python@X.Y` Rules

The scripts check both `/opt/homebrew` and `/usr/local` as the console user with `</dev/null` and `HOMEBREW_NO_AUTO_UPDATE=1`. A formula is `removable` only when all conditions below are true:

- A newer `python@X.Y` formula exists in the same Homebrew prefix.
- `brew uses --installed python@X.Y` exits `0` and returns empty output. A non-zero exit blocks removal with `blocked:uses-failed`.
- No pin receipt exists at `<prefix>/var/homebrew/pinned/python@X.Y`.
- It is not the resolved target of `<prefix>/bin/python3`, and no virtual environment or shebang references it.
- The script never runs `brew autoremove`, so unrelated Homebrew packages stay intact.

### 3. Package Snapshots and Privilege Safety

Before any `rm -rf` or `brew uninstall`, `snapshot_packages` writes the third-party package list to `~/Library/Logs/python-cleanup/<label>-packages-<YYYYMMDD>.txt` and `~/Desktop`. It runs `pip list --format=freeze` and uses `*.dist-info` metadata as fallback.

- **No Root Execution in User Space:** Both `pip list` and file writes run as the console user with `umask 022`. Running `pip` as root risks arbitrary code execution from `.pth` or `sitecustomize.py` files, and writing as root in user directories risks symlink privilege escalation.
- **No Xcode CLT Prompts:** The scripts never invoke `/usr/bin/python3` because the macOS `xcrun` shim prompts users to install Command Line Tools.

## Audit Output Contract

MDM agents often truncate long stdout tails. The audit script prints `PY_BUILD`, `PY_SUMMARY`, and `PY_INV` JSON lines first, and buffers `[WARN]` lines until the end:

```text
PY_BUILD: sysadmin-mdm-python sv=2
PY_SUMMARY: {"sv":2,"pyorg":2,"pyorgT":0,"newest":"3.14","default":"3.11","defaultUnknown":0,"brew":1,"removable":0,"staleDefault":1,"blocked":1,"eol":0,"venvs":0,"scanCap":0,"shadows":"uv"}
PY_INV: {"src":"pyorg","fw":"std","minor":"3.11","ver":"3.11.0","eol":false,"pkgs":37,"pkg_top":"jupyterlab, numpy, pandas, scipy, torch, ...","verdict":"stale-default"}
PY_INV: {"src":"brew","prefix":"/opt/homebrew","minor":"3.12","kegs":"3.12.14","uses":"","uses_n":0,"pinned":false,"stale":"","eol":false,"pkgs":0,"pkg_top":"","verdict":"blocked:newest"}
PY_NOTE: default python3 points at 3.11 while 3.14 is installed - the python.org installer relinks to the LAST install, not the newest
```

## Automated CVE SLA Orchestration

For CVE-based removal windows aligned with ISO/IEC 27001 A.8.8, A.8.32, and SOC 2 CC7.x, pair these scripts with the Jenkins pipeline in `Jenkins/`:

- **`Jenkins/python_cve_sla_sync.py`:** Queries the MDM Vulnerability Management API and audit logs, computes per-version deadlines (`cpython:X.Y.Z=YYYYMMDD`) from severity SLAs, updates `SLA_DEADLINES` in `remediate_update.sh`, and sends consolidated Slack DMs to device users.
- **`Jenkins/Jenkinsfile.python-sla`:** Runs `Jenkins/python_cve_sla_sync.py` on a daily schedule with dry-run support and credential bindings.

Teams that already operate n8n can run an equivalent two-stage workflow (a daily producer that patches `SLA_DEADLINES` and a deduplicated Slack DM notifier).
