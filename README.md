# Sysadmin MDM Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Shell](https://img.shields.io/badge/Shell-zsh-blue.svg)](https://www.zsh.org/)

This repository contains scripts and automation workflows for macOS system administrators.
Use these tools with Mobile Device Management (MDM) platforms such as IRU (Kandji), Jamf Pro, Microsoft Intune, Mosyle, and SimpleMDM.

## Overview

MDM agents run scripts as `root` on macOS devices.
Developer tools, package managers, and desktop apps run in the logged-in user session.
These modules solve three operational problems:

- **Execution context**: Scripts run as `root` from the MDM agent and drop privileges into the active console user session when needed.
- **Device safety**: Scripts check battery charge, block system sleep with `caffeinate`, and stop before MDM agent timeout limits.
- **Architecture support**: Scripts inspect both Apple Silicon (`/opt/homebrew`) and Intel (`/usr/local`) environments.

## Repository Structure

```text
sysadmin_mdm_tools/
├── Homebrew/
│   ├── audit_update.sh                  # Audits Homebrew formulae, casks, and cache state
│   ├── remediate_update.sh              # Updates Homebrew packages with safety checks
│   ├── install.sh                       # Installs Homebrew and required developer tools
│   ├── tests/
│   │   └── test_remediate_update.zsh    # Automated unit tests for Homebrew scripts
│   └── README.md                        # Module documentation for Homebrew scripts
├── Python/
│   ├── audit_update.sh                  # Audits local Python installations and CVE status
│   ├── remediate_update.sh              # Removes out-of-policy Python installations
│   ├── self_service_cleanup.sh          # Interactive Python removal script for end users
│   └── README.md                        # Module documentation for Python scripts
├── Jenkins/
│   ├── python_cve_sla_sync.py           # Computes Python CVE deadlines and patches MDM scripts
│   ├── security_notifier.py             # Sends deduplicated Slack alerts to device owners
│   ├── Jenkinsfile.python-sla           # Scheduled Jenkins pipeline for CVE SLA sync
│   ├── tests/
│   │   └── test_python_cve_sla.py       # Unit tests for SLA sync and Slack notifications
│   └── README.md                        # Module documentation for Jenkins pipeline
├── Monitors/
│   ├── audit_monitors.sh                # Audits external display inventory records
│   ├── remediate_monitors.sh            # Collects and logs external display hardware data
│   └── README.md                        # Module documentation for display tracking
├── LICENSE                              # MIT License
└── README.md                            # Root repository documentation
```

## Modules

### Homebrew (`Homebrew/`)

This module installs, audits, and updates Homebrew formulae and GUI casks on macOS devices.
See [`Homebrew/README.md`](Homebrew/README.md) for deployment steps, safety checks, and log paths.

- **`Homebrew/audit_update.sh`**: Checks cache freshness, outdated unpinned formulae, and outdated casks. Exits `0` when compliant and `1` when the device requires updates. Writes logs to `/var/log/brew-global-audit.log`.
- **`Homebrew/remediate_update.sh`**: Updates eligible Homebrew packages and casks. Checks battery level (minimum 20%), uses `caffeinate`, enforces a 45-minute budget, protects running GUI apps, and skips MDM-managed apps by Team ID. Writes logs to `/var/log/brew-global-remediation.log`.
- **`Homebrew/install.sh`**: Installs Homebrew and configures developer tools on new devices. Writes logs to `/var/log/brew-install.log`.
- **`Homebrew/tests/test_remediate_update.zsh`**: Runs automated tests for developer-tool checks and remediation logic.

### Python (`Python/`)

This module audits local Python runtimes and removes vulnerable or unsupported versions.
See [`Python/README.md`](Python/README.md) for configuration options and log formats.

- **`Python/audit_update.sh`**: Scans common Python paths, checks versions against policy, and outputs structured inventory lines.
- **`Python/remediate_update.sh`**: Removes out-of-policy Python installations after SLA deadlines pass.
- **`Python/self_service_cleanup.sh`**: Lets users remove out-of-policy Python installations through MDM Self Service before forced remediation.

### Jenkins (`Jenkins/`)

This module automates Python CVE SLA tracking, MDM script patching, and user notifications.
See [`Jenkins/README.md`](Jenkins/README.md) for environment variables and pipeline configuration.

- **`Jenkins/python_cve_sla_sync.py`**: Fetches CVE data, calculates SLA deadlines, parses MDM audit logs, and updates MDM script deadline maps.
- **`Jenkins/security_notifier.py`**: Sends Slack alerts to device owners with content-hash deduplication and cooldown windows.
- **`Jenkins/Jenkinsfile.python-sla`**: Runs the daily sync and notification workflow inside Jenkins with credential injection.
- **`Jenkins/tests/test_python_cve_sla.py`**: Tests SLA deadline math, log parsing, script patching, and notification deduplication.

### Monitors (`Monitors/`)

This module tracks external displays connected to macOS devices for hardware asset inventory.
See [`Monitors/README.md`](Monitors/README.md) for output schema and deployment notes.

- **`Monitors/audit_monitors.sh`**: Checks whether local display inventory data is current and triggers collection when needed.
- **`Monitors/remediate_monitors.sh`**: Reads connected display identifiers, serial numbers, and models from macOS system tools.

## MDM Deployment

### IRU (Kandji)

1. Open **Library** and select **Add New**, then select **Custom Script**.
2. Paste an audit script into the **Audit Script** field.
3. Paste the matching remediation script into the **Remediation Script** field.
4. Set the run frequency for your blueprint.

### Jamf Pro

1. Create an **Extension Attribute** using the audit script logic to report device compliance.
2. Create a **Smart Group** that targets non-compliant devices.
3. Create a **Policy** scoped to that Smart Group to run the remediation script.

## Verification

Run the test suites from the repository root:

```zsh
zsh Homebrew/tests/test_remediate_update.zsh
python3 -m unittest discover -s Jenkins/tests -v
```

## License

This project uses the [MIT License](LICENSE).
You can use, modify, and distribute these scripts under the terms of that license.
