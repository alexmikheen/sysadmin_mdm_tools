#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deliver Slack notifications with per-part deduplication and cooldown windows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

DEFAULT_STATE_FILE = ".jenkins_python_notify_state.json"
DEFAULT_COOLDOWN_DAYS = {
    "warn": 7,
    "advisory": 30,
    "removed": 30,
}
STATE_RETENTION_DAYS = 180
HTTP_TIMEOUT_SECONDS = 30
WAREHOUSE_BLUEPRINT_NAME = "devices without users"

HttpRequester = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, Any]]]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "Redirects are disabled",
            headers,
            fp,
        )


_HTTP_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def compute_content_hash(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_state(state_file: str, backup_corrupt: bool = True) -> Dict[str, Any]:
    """Load notification state and handle corrupt or unreadable state files."""
    if not state_file:
        return {"_sent": {}}
    if os.path.islink(state_file):
        raise OSError(f"State file cannot be a symlink: {state_file}")
    if not os.path.exists(state_file):
        return {"_sent": {}}
    try:
        with open(state_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("_sent"), dict):
            return data
    except ValueError:
        pass
    except OSError as exc:
        err_msg = f"State file read error at {state_file}: {exc}"
        if not backup_corrupt:
            print(f"Warning: {err_msg}", file=sys.stderr)
        return {
            "_sent": {},
            "_corrupt_error": err_msg,
            "_state_read_error": True,
        }

    if not backup_corrupt:
        err_msg = f"Corrupt state file at {state_file} (dry-run, not renamed)"
        print(f"Warning: {err_msg}", file=sys.stderr)
        return {"_sent": {}, "_corrupt_error": err_msg}

    backup_path = f"{state_file}.corrupt.{int(time.time())}"
    try:
        os.replace(state_file, backup_path)
    except OSError:
        backup_path = state_file
    return {
        "_sent": {},
        "_corrupt_backup": backup_path,
        "_corrupt_error": f"Corrupt state file backed up to {backup_path}",
    }


def save_state(state_file: str, state: Dict[str, Any]) -> None:
    """Write notification state atomically with 0600 permissions."""
    if not state_file:
        return
    if os.path.islink(state_file):
        raise OSError(f"State file cannot be a symlink: {state_file}")
    parent = os.path.dirname(os.path.abspath(state_file))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=parent,
            prefix=".notify_state.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = handle.name
            os.chmod(tmp_path, 0o600)
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.islink(state_file):
            raise OSError(f"State file cannot be a symlink: {state_file}")
        os.replace(tmp_path, state_file)
    except BaseException:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def prune_old_state(sent: Dict[str, Dict[str, Any]], now_ms: int) -> Dict[str, Dict[str, Any]]:
    cutoff_ms = now_ms - STATE_RETENTION_DAYS * 86400 * 1000
    pruned: Dict[str, Dict[str, Any]] = {}
    for key, record in sent.items():
        if not isinstance(record, dict):
            continue
        newest_ts = 0
        for part_state in record.values():
            if isinstance(part_state, dict):
                ts_val = int(part_state.get("ts") or 0)
                if ts_val > newest_ts:
                    newest_ts = ts_val
        if newest_ts >= cutoff_ms:
            pruned[key] = record
    return pruned


def _filter_parts_for_device(
    parts: List[Dict[str, Any]],
    device_record: Dict[str, Any],
    now_ms: int,
) -> List[Dict[str, Any]]:
    kept_parts: List[Dict[str, Any]] = []
    for part in parts:
        part_key = str(part.get("key") or "")
        part_text = str(part.get("text") or "")
        default_days = DEFAULT_COOLDOWN_DAYS.get(part_key, 7)
        throttle_days = int(part.get("throttleDays") or default_days)
        content_hash = str(part.get("h") or compute_content_hash(part_text))

        previous = device_record.get(part_key, {})
        prev_hash = previous.get("h") if isinstance(previous, dict) else None
        prev_ts = int(previous.get("ts") or 0) if isinstance(previous, dict) else 0
        window_ms = throttle_days * 86400 * 1000

        if prev_hash != content_hash or (now_ms - prev_ts) > window_ms:
            kept_part = dict(part)
            kept_part["h"] = content_hash
            kept_parts.append(kept_part)
    return kept_parts


def filter_throttled_items(
    items: List[Dict[str, Any]],
    sent_state: Dict[str, Dict[str, Any]],
    now_ms: int,
) -> Tuple[List[Dict[str, Any]], int]:
    """Keep ops alerts and message parts that changed or expired."""
    passed: List[Dict[str, Any]] = []
    throttled_count = 0

    for item in items:
        if item.get("ops"):
            passed.append(item)
            continue

        device_id = item.get("deviceId")
        parts = item.get("parts")
        if not device_id or not isinstance(parts, list):
            continue

        source = str(item.get("source") or "?")
        state_key = f"{source}:{device_id}"
        device_record = sent_state.get(state_key, {})
        kept_parts = _filter_parts_for_device(parts, device_record, now_ms)

        if not kept_parts:
            throttled_count += 1
            continue

        passed.append(
            {
                "deviceId": device_id,
                "deviceName": item.get("deviceName", "?"),
                "source": source,
                "parts": kept_parts,
                "footer": item.get("footer", ""),
            }
        )

    return passed, throttled_count


def default_http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Send an HTTPS request with redirects disabled and return status and JSON."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("HTTPS URL required")

    req = urllib.request.Request(url=url, data=body, headers=headers, method=method)
    try:
        with _HTTP_OPENER.open(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200)
            data = json.loads(raw) if raw.strip() else {}
            if not isinstance(data, dict):
                data = {"data": data}
            return status, data
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
        try:
            payload = json.loads(raw) if raw.strip() else {"error": str(exc)}
        except ValueError:
            payload = {"error": f"HTTP {exc.code}: {raw[:200]}"}
        if not isinstance(payload, dict):
            payload = {"data": payload, "error": f"HTTP {exc.code}"}
        elif "error" not in payload:
            payload["error"] = f"HTTP {exc.code}"
        return exc.code, payload
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return 0, {"error": str(exc)}


def fetch_device_owner(
    mdm_api_url: str,
    mdm_api_token: str,
    device_id: str,
    requester: HttpRequester = default_http_request,
) -> Dict[str, Any]:
    base = mdm_api_url.rstrip("/")
    url = f"{base}/api/v1/devices/{urllib.parse.quote(device_id, safe='')}"
    headers = {
        "Authorization": f"Bearer {mdm_api_token}",
        "Accept": "application/json",
    }
    status, data = requester("GET", url, headers, None)
    if status < 200 or status >= 300:
        return {"error": data.get("error", f"HTTP {status}")}
    return data


def is_warehouse_device(device_info: Dict[str, Any], warehouse_blueprint_id: str = "") -> bool:
    if device_info.get("error"):
        return False
    blueprint_id = str(device_info.get("blueprint_id") or "")
    blueprint_name = str(device_info.get("blueprint_name") or "").strip().lower()
    if warehouse_blueprint_id and blueprint_id == warehouse_blueprint_id:
        return True
    return blueprint_name == WAREHOUSE_BLUEPRINT_NAME


def lookup_slack_user_id(
    slack_bot_token: str,
    email: str,
    requester: HttpRequester = default_http_request,
) -> Tuple[Optional[str], Optional[str]]:
    if not email:
        return None, "missing owner email"
    query = urllib.parse.urlencode({"email": email})
    url = f"https://slack.com/api/users.lookupByEmail?{query}"
    headers = {
        "Authorization": f"Bearer {slack_bot_token}",
        "Accept": "application/json",
    }
    status, data = requester("GET", url, headers, None)
    if status < 200 or status >= 300:
        return None, str(data.get("error", f"HTTP {status}"))
    if not data.get("ok"):
        return None, str(data.get("error", "lookup_failed"))
    user = data.get("user") or {}
    user_id = user.get("id")
    if not user_id:
        return None, "missing user id in response"
    return str(user_id), None


def post_slack_message(
    slack_bot_token: str,
    channel: str,
    text: str,
    requester: HttpRequester = default_http_request,
) -> Tuple[bool, Optional[str]]:
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {slack_bot_token}",
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
    }
    payload = json.dumps({"channel": channel, "text": text}).encode("utf-8")
    status, data = requester("POST", url, headers, payload)
    if status < 200 or status >= 300:
        return False, str(data.get("error", f"HTTP {status}"))
    if not data.get("ok"):
        return False, str(data.get("error", "post_failed"))
    return True, None


def compose_dm_text(parts: List[Dict[str, Any]], footer: str) -> str:
    body = "\n\n".join(str(part.get("text") or "") for part in parts if part.get("text"))
    if footer:
        return f"{body}\n\n{footer}"
    return body


def deliver_notifications(
    items: List[Dict[str, Any]],
    *,
    mdm_api_url: str,
    mdm_api_token: str,
    slack_bot_token: str,
    slack_ops_channel: str,
    state_file: str = DEFAULT_STATE_FILE,
    warehouse_blueprint_id: str = "",
    apply_changes: bool = False,
    now_ms: Optional[int] = None,
    requester: HttpRequester = default_http_request,
) -> Dict[str, Any]:
    """Deliver device DMs and ops alerts while persisting deduplication state."""
    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    state = load_state(state_file, backup_corrupt=apply_changes)
    corrupt_backup = str(state.pop("_corrupt_backup", "") or "")
    corrupt_error = str(state.pop("_corrupt_error", "") or "")
    state_read_error = bool(state.pop("_state_read_error", False))
    can_save_state = apply_changes and not state_read_error
    sent_state: Dict[str, Dict[str, Any]] = state.get("_sent", {})

    work_items = list(items)
    if corrupt_backup:
        print(
            f"Warning: corrupt state file backed up to {corrupt_backup}",
            file=sys.stderr,
        )
        work_items.append(
            {
                "ops": True,
                "text": (
                    ":warning: *security-notifier*: corrupt notification state file "
                    f"backed up to `{corrupt_backup}` and reset."
                ),
            }
        )
    elif corrupt_error:
        if apply_changes:
            print(f"Warning: {corrupt_error}", file=sys.stderr)
        work_items.append(
            {
                "ops": True,
                "text": f":warning: *security-notifier*: {corrupt_error}",
            }
        )

    active_items, throttled_count = filter_throttled_items(work_items, sent_state, current_ms)

    summary: Dict[str, Any] = {
        "mode": "apply" if apply_changes else "dry-run",
        "input_items": len(items),
        "throttled_devices": throttled_count,
        "skipped_warehouse": 0,
        "dms_planned": 0,
        "dms_sent": 0,
        "dm_failures": [],
        "ops_alerts_planned": 0,
        "ops_alerts_sent": 0,
        "ops_failures": [],
        "state_corrupt_backup": corrupt_backup,
        "state_corrupt_error": corrupt_error,
    }

    email_cache: Dict[str, Tuple[Optional[str], Optional[str]]] = {}

    try:
        for item in active_items:
            if item.get("ops"):
                channel = str(item.get("channel") or slack_ops_channel)
                text = str(item.get("text") or "")
                summary["ops_alerts_planned"] += 1
                if not apply_changes:
                    continue
                if not channel:
                    summary["ops_failures"].append("missing SLACK_OPS_CHANNEL")
                    continue
                ok, err = post_slack_message(slack_bot_token, channel, text, requester=requester)
                if ok:
                    summary["ops_alerts_sent"] += 1
                else:
                    summary["ops_failures"].append(str(err))
                continue

            device_id = str(item["deviceId"])
            device_name = str(item.get("deviceName") or "?")
            source = str(item.get("source") or "?")
            state_key = f"{source}:{device_id}"
            parts = _filter_parts_for_device(
                item.get("parts") or [],
                sent_state.get(state_key, {}),
                current_ms,
            )
            if not parts:
                summary["throttled_devices"] += 1
                continue
            footer = str(item.get("footer") or "")

            device_info = fetch_device_owner(
                mdm_api_url,
                mdm_api_token,
                device_id,
                requester=requester,
            )
            if is_warehouse_device(device_info, warehouse_blueprint_id=warehouse_blueprint_id):
                summary["skipped_warehouse"] += 1
                continue

            user_obj = device_info.get("user") if isinstance(device_info.get("user"), dict) else {}
            email = str(user_obj.get("email") or "").strip() if not device_info.get("error") else ""
            message_text = compose_dm_text(parts, footer)
            summary["dms_planned"] += 1

            if not apply_changes:
                continue

            if email in email_cache:
                slack_user_id, lookup_err = email_cache[email]
            else:
                slack_user_id, lookup_err = lookup_slack_user_id(
                    slack_bot_token,
                    email,
                    requester=requester,
                )
                email_cache[email] = (slack_user_id, lookup_err)

            if lookup_err or not slack_user_id:
                failure_line = f"- {email or 'unknown-email'} [{device_name}]: {lookup_err}"
                summary["dm_failures"].append(failure_line)
                continue

            ok, send_err = post_slack_message(
                slack_bot_token,
                slack_user_id,
                message_text,
                requester=requester,
            )
            if not ok:
                failure_line = f"- {email} [{device_name}]: {send_err}"
                summary["dm_failures"].append(failure_line)
                continue

            summary["dms_sent"] += 1
            record = dict(sent_state.get(state_key, {}))
            for part in parts:
                record[str(part["key"])] = {"h": part["h"], "ts": current_ms}
            sent_state[state_key] = record
            state["_sent"] = sent_state
            if can_save_state:
                save_state(state_file, state)

        if apply_changes and summary["dm_failures"] and slack_ops_channel:
            fail_count = len(summary["dm_failures"])
            fail_body = "\n".join(summary["dm_failures"])
            alert_text = f":warning: *security-notifier: {fail_count} DM(s) failed*\n{fail_body}"
            ok, err = post_slack_message(
                slack_bot_token,
                slack_ops_channel,
                alert_text,
                requester=requester,
            )
            if ok:
                summary["ops_alerts_sent"] += 1
            else:
                summary["ops_failures"].append(str(err))
    finally:
        if can_save_state:
            state["_sent"] = prune_old_state(sent_state, current_ms)
            save_state(state_file, state)

    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deliver Slack notifications with deduplication and cooldown state."
    )
    parser.add_argument(
        "--input",
        default="-",
        help="Path to a JSON list of notification items, or '-' for stdin.",
    )
    parser.add_argument(
        "--state-file",
        default=os.environ.get("NOTIFY_STATE_FILE", DEFAULT_STATE_FILE),
        help="Path to the local JSON deduplication state file.",
    )
    parser.add_argument(
        "--mdm-api-url",
        default=os.environ.get("MDM_API_URL", ""),
        help="Base URL of the MDM API.",
    )
    parser.add_argument(
        "--slack-ops-channel",
        default=os.environ.get("SLACK_OPS_CHANNEL", ""),
        help="Slack channel ID for operations alerts.",
    )
    parser.add_argument(
        "--warehouse-blueprint-id",
        default=os.environ.get("WAREHOUSE_BLUEPRINT_ID", ""),
        help="Optional blueprint ID for unassigned warehouse devices.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate gates and print planned deliveries without sending.",
    )
    mode_group.add_argument(
        "--apply",
        action="store_true",
        help="Send Slack messages and update the local state file.",
    )
    args = parser.parse_args(argv)

    mdm_api_token = os.environ.get("MDM_API_TOKEN", "")
    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN", "")

    if args.input == "-":
        raw_input = sys.stdin.read()
    else:
        with open(args.input, "r", encoding="utf-8") as handle:
            raw_input = handle.read()

    items = json.loads(raw_input) if raw_input.strip() else []
    if not isinstance(items, list):
        print("Error: input JSON must be a list of notification items.", file=sys.stderr)
        return 1

    result = deliver_notifications(
        items,
        mdm_api_url=args.mdm_api_url,
        mdm_api_token=mdm_api_token,
        slack_bot_token=slack_bot_token,
        slack_ops_channel=args.slack_ops_channel,
        state_file=args.state_file,
        warehouse_blueprint_id=args.warehouse_blueprint_id,
        apply_changes=bool(args.apply),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
