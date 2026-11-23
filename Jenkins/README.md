# Jenkins Python CVE SLA and Notification Suite

This directory contains a Python 3 and Jenkins pipeline suite for Python vulnerability remediation.
The suite reads audit logs and active Python CVEs from the MDM API.
It calculates per-version SLA deadlines, updates the remediation script, and sends Slack messages to device owners.
The Python scripts use only the Python 3 standard library.

## Files

| File | Purpose |
|---|---|
| `python_cve_sla_sync.py` | Reads MDM audit logs and CVEs, updates `SLA_DEADLINES`, and prepares messages. |
| `security_notifier.py` | Resolves device owners, applies cooldown deduplication, and sends Slack messages. |
| `Jenkinsfile.python-sla` | Runs the daily Jenkins pipeline at 13:45 and archives the JSON report. |
| `tests/test_python_cve_sla.py` | Tests SLA math, log parsing, fail-closed patching, and Slack deduplication. |

## SLA Deadline Rules

The sync script requests all paginated active Python CVEs from `/api/v1/vulnerability-management/vulnerabilities`.
For each CVE, the script requests all paginated affected versions from `/api/v1/vulnerability-management/vulnerabilities/{cve}/software`.
The script assigns a deadline from the first detection date plus the severity window:

- Critical: 1 day
- High: 2 days
- Medium: 7 days
- Low: 14 days

The script collects every CPython `X.Y.Z` version from fleet `PY_INV` logs and CVE responses.
The script strips Homebrew `_N` revision suffixes before comparison.
When fleet inventory is non-empty, the script excludes any CVE that affects the newest known version as unfixable.
For every remaining version, the earliest deadline wins and maps to `cpython:X.Y.Z=YYYYMMDD`.

## Log Gates and Fail-Closed Patching

The sync script parses `PY_SUMMARY`, `PY_INV`, and `PY_REM` lines from `/api/v1/library/custom-scripts/{id}/status`.
The script deduplicates device rows by computer ID across audit and remediation scripts.

1. If a device ran Self Service cleanup after the audit timestamp, the script skips that device.
2. If a device log reaches 20000 characters, the script skips that device and sends an operations alert.
3. If a device report is older than 72 hours and has findings, the script sends both a direct message and an operations alert.
4. If a device log includes `PY_REM: removed` within 48 hours, the script adds a post-removal notice and omits that version from warnings.
5. If any audit status request or CVE software request fails, the script keeps the previous `SLA_DEADLINES` block unchanged and sends an operations alert.

## Notification Deduplication

The notifier module stores delivery history in `.jenkins_python_notify_state.json` with `0600` permissions.
If the state file contains corrupt JSON, the notifier backs up the file and sends an operations alert.
Each message part uses a SHA-256 content hash and a cooldown window:

- `warn`: 7 days
- `advisory`: 30 days
- `removed`: 30 days

The notifier sends a part only when its content hash changes or its cooldown window expires.
The notifier requires HTTPS URLs and disables HTTP redirects for all API requests.
The notifier resolves each owner email via Slack `users.lookupByEmail` and sends one direct message via `chat.postMessage`.
Unassigned devices in the `Devices Without Users` blueprint receive no direct message.

## Required Credentials

Configure these Jenkins Secret Text credentials before running `Jenkinsfile.python-sla`:

| Credential ID | Environment Variable | Description |
|---|---|---|
| `mdm-api-url` | `MDM_API_URL` | Base HTTPS URL of the MDM API. |
| `mdm-api-token` | `MDM_API_TOKEN` | Bearer token for MDM API requests. |
| `slack-bot-token` | `SLACK_BOT_TOKEN` | Slack bot token with `users:read.email` and `chat:write`. |
| `mdm-audit-script-id` | `MDM_AUDIT_SCRIPT_ID` | MDM Custom Script ID for Python audit logs. |
| `mdm-remediation-script-id` | `MDM_REMEDIATION_SCRIPT_ID` | MDM Custom Script ID for `Python/remediate_update.sh`. |
| `slack-ops-channel` | `SLACK_OPS_CHANNEL` | Slack channel ID for operations alerts. |
| `exception-portal-url` | `EXCEPTION_PORTAL_URL` | Portal URL for Python exception requests. |

Both Python scripts read `MDM_API_TOKEN` and `SLACK_BOT_TOKEN` from environment variables only.
The Jenkinsfile pins execution to the `AGENT_LABEL` parameter (default `mdm-sync`) and enables `--apply` automatically on scheduled cron runs.
Set the optional `MDM_SELF_SERVICE_SCRIPT_ID` parameter to enable Self Service suppression.

## Usage

Run in dry-run mode (default) to preview deadlines and planned messages without changes:

```bash
python3 Jenkins/python_cve_sla_sync.py --dry-run --report-file python_cve_sla_report.json
```

Run in apply mode to update `SLA_DEADLINES` in MDM and send Slack messages:

```bash
python3 Jenkins/python_cve_sla_sync.py --apply --report-file python_cve_sla_report.json
```

Run the unit test suite:

```bash
python3 -m unittest discover -s Jenkins/tests -v
```
