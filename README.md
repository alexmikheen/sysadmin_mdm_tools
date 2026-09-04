# Sysadmin MDM Tools & Scripts Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Shell](https://img.shields.io/badge/Shell-zsh-blue.svg)](https://www.zsh.org/)

A production-ready lab and collection of scripts, utilities, and automation workflows for macOS system administrators and IT platform engineers managing device fleets via Mobile Device Management (MDM) platforms, such as **IRU (Kandji)**, **Jamf Pro**, **Microsoft Intune**, **Mosyle**, and **SimpleMDM**.

---

## 📌 Overview

Managing macOS workstations via MDM presents unique architectural hurdles:
- **Root vs. User Execution Context**: MDM agents execute payloads as privileged `root`, whereas user environments, preferences, and developer tools (like Homebrew and GUI applications) live in the logged-in user's space.
- **Reliability & Safeguards**: Automated remediation must not drain user battery, corrupt package states due to sudden sleep/hibernation, or get terminated mid-upgrade when hitting agent execution timeouts.
- **Fleet Architecture**: Seamless support across multi-architecture environments (Apple Silicon `arm64` and Intel `x86_64`).

This repository provides field-tested, robust scripts designed specifically for automated **Audit & Remediation** workflows.

---

## 📂 Repository Structure

```text
sysadmin_mdm_tools/
├── Homebrew/
│   ├── audit_update.sh       # Global audit script for Homebrew packages & cache
│   └── remediate_update.sh   # Safe, multi-arch Homebrew remediation script
├── LICENSE                   # MIT License
└── README.md                 # Project documentation
```

---

## 🛠 Tools & Modules

### 🍺 `Homebrew/` Directory

Scripts designed to audit and safely update Homebrew packages (CLI formulae and GUI casks) across corporate macOS fleets.

#### 1. `Homebrew/audit_update.sh` (Audit Script)
Evaluates compliance of the target Mac against software currency policies without making any modifications.

- **Multi-Architecture**: Automatically inspects both Apple Silicon (`/opt/homebrew`) and Intel (`/usr/local`) prefixes.
- **Context Handling**: Executes as `root` from the MDM agent, resolves the active console user via `/dev/console`, and drops privileges into the user's session via `launchctl asuser` and `sudo -u`.
- **Key Checks**:
  - **Cache Freshness**: Verifies `FETCH_HEAD` / `formula.jws.json`. If the cache is older than 2 days or missing, remediation is triggered.
  - **Outdated Formulae**: Detects unpinned CLI packages requiring updates while strictly respecting packages pinned by the user (`"pinned": true`).
  - **Outdated Casks**: Identifies outdated GUI applications installed via Homebrew.
- **Exit Codes**:
  - `0`: Compliant (Homebrew is not installed, or all unpinned packages and casks are up to date).
  - `1`: Non-compliant / Remediation required (outdated packages found or cache probe failed).
- **Log Path**: `/var/log/brew-global-audit.log`

#### 2. `Homebrew/remediate_update.sh` (Remediation Script)
Performs safe, unattended upgrades of all eligible Homebrew packages and casks.

- **Safety & Guardrails**:
  - **Battery Safeguard**: Automatically aborts if running on battery power with less than 20% charge remaining.
  - **Sleep Prevention (`caffeinate`)**: Prevents system sleep during active package upgrades.
  - **Time Budget Enforcement**: Standard MDM agents (such as IRU (Kandji)) hard-kill scripts after 60 minutes. The script enforces an internal 45-minute budget to finish ongoing operations cleanly and exit gracefully before hitting agent timeouts. The next cycle will pick up remaining tasks.
  - **GUI App Protection**: Sets `HOMEBREW_NO_UPGRADE_QUIT_CASKS=1` and performs process checks (`pgrep`) to prevent disrupting user workflows by terminating running apps.
  - **MDM Ownership & Team ID Matching**: Inspects Developer Team IDs to prevent clobbering or duplicate installations of apps already managed by MDM (Auto Apps).
- **Log Path**: `/var/log/brew-global-remediation.log`

---

## 🚀 MDM Deployment Guide

### IRU (Kandji) (Custom Scripts / Automated Remediation)
1. Navigate to **Library** > **Add New** > **Custom Script**.
2. Paste the contents of [`Homebrew/audit_update.sh`](Homebrew/audit_update.sh) into the **Audit Script** section.
3. Paste the contents of [`Homebrew/remediate_update.sh`](Homebrew/remediate_update.sh) into the **Remediation Script** section.
4. Set execution frequency (e.g., daily or on policy run).

### Jamf Pro
1. **Audit**: Create an **Extension Attribute** that utilizes the logic in `audit_update.sh` to return compliance status (`Compliant` / `Pending Remediation`).
2. **Smart Group**: Create a Smart Group targeting devices where the Extension Attribute indicates pending updates.
3. **Remediation Policy**: Create a policy scoped to that Smart Group that executes `remediate_update.sh` during maintenance windows or check-in.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). You are free to use, adapt, and distribute these scripts in your corporate infrastructure.
