# macOS External Monitor Inventory Tracker

This folder contains a two-script MDM pair that tracks external monitor connections on macOS laptops over a 21-day rolling window. The scripts use macOS built-in tools (`ioreg`, `awk`, `grep`, `date`) and emit structured JSON lines for downstream asset reconciliation in Jira Cloud Assets, Slack, and Jenkins.

## Scripts

| Script | Role | Execution Context |
| :--- | :--- | :--- |
| `audit_monitors.sh` | Reads connected external monitors from `ioreg`, updates local 21-day history, emits `MONITOR_EVENT` and `MONITOR_INVENTORY` JSON lines, and exits `1` when a monitor crosses `DAYS_THRESHOLD`. | Root (MDM Audit) |
| `remediate_monitors.sh` | Runs when the audit exits `1`. Copies pending `(monitor_serial, laptop_serial)` pairs from `monitor_pending.txt` to `monitor_notified.txt` and clears `monitor_pending.txt`. | Root (MDM Remediation) |

## How Tracking Works

### 1. Local State Directory

Both scripts store local state in `/Library/Application Support/MDM_Monitor_Tracker` with mode `0700` when run as root. Non-root test runs can override `HISTORY_DIR` in the environment.

| File | Purpose | Retention |
| :--- | :--- | :--- |
| `monitor_history.txt` | Stores one line per monitor per day as `SERIAL\|MODEL\|DATE\|MFG_YEAR\|MFG_WEEK`. | Pruned automatically to 21 days (`ROLLING_WINDOW_DAYS=21`). |
| `monitor_notified.txt` | Records `(monitor_serial, laptop_serial)` pairs already handled by remediation. | Capped automatically at the newest 500 lines. |
| `monitor_pending.txt` | Lists pairs that crossed `DAYS_THRESHOLD` during the current audit run. | Rebuilt on each audit run and cleared by remediation. |

### 2. 21-Day Rolling Window and 7-Day Threshold

The audit script skips built-in Apple displays (`Built-in` and `Color LCD`) and extracts `ProductName`, `AlphanumericSerialNumber`, `YearOfManufacture`, and `WeekOfManufacture` from `ioreg -lw0`.

1. The script removes lines older than `ROLLING_WINDOW_DAYS=21` from `monitor_history.txt`.
2. For each connected external monitor, the script appends one line for today if no line exists yet.
3. The script counts unique days for that monitor serial inside the 21-day window (`DAYS_CONNECTED`).
4. When `DAYS_CONNECTED` reaches `DAYS_THRESHOLD=7`, the script checks `monitor_notified.txt`. If the `(monitor_serial, laptop_serial)` pair is absent, the script appends it to `monitor_pending.txt` and exits `1`.

The 7-day threshold excludes transient connections such as conference room monitors or hot desks. Deduplicating on the `(monitor_serial, laptop_serial)` pair ensures that moving a monitor to a different laptop triggers a new event.

### 3. Daily `MONITOR_INVENTORY` Replay

MDM APIs expose only the latest audit stdout log. A user may disconnect a monitor or close the laptop lid before a scheduled poll runs. A live-only `ioreg` snapshot would lose that monitor for the day.

To prevent data loss, `audit_monitors.sh` replays every monitor recorded in `monitor_history.txt` for today's date as a `MONITOR_INVENTORY` JSON line:

```text
MONITOR_EVENT: {"monitor_serial":"ABC1234","monitor_model":"DELL U2723QE","laptop_serial":"C02XYZ123456","days_connected":7,"action_needed":true,"already_handled":false,"date":"2026-10-14"}
MONITOR_INVENTORY: {"monitor_serial":"ABC1234","monitor_model":"DELL U2723QE","laptop_serial":"C02XYZ123456","mfg_year":2024,"mfg_week":18,"days_connected":7,"date":"2026-10-14"}
```

## Asset Reconciliation Workflow

`remediate_monitors.sh` handles local MDM alert state only and does not call external APIs. External reconciliation runs from a scheduled Jenkins job or automation workflow:

1. Poll the MDM library item status endpoint and parse `MONITOR_INVENTORY` JSON lines from the audit log.
2. Match `laptop_serial` to the laptop owner in Jira Cloud Assets (or another CMDB).
3. Filter for monitors where `days_connected` is at least `7`.
4. Compare `monitor_serial`, `monitor_model`, `mfg_year`, and `mfg_week` against existing asset records to flag missing assignments or factory barcode mismatches.
5. Notify IT operations in Slack or open a human-reviewed Jira ticket for asset updates.

## Rollback

Unassign the audit and remediation script item in your MDM console. Local files inside `/Library/Application Support/MDM_Monitor_Tracker` stay inactive until removed. To trigger an alert again for one pair, remove its line from `monitor_notified.txt`.
