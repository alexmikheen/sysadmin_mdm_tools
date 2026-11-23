#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synchronize Python CVE SLA deadlines and send owner notifications."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from Jenkins import security_notifier
except ImportError:
    import security_notifier  # type: ignore[no-redef]

SLA_WINDOW_DAYS: Dict[str, int] = {
    "Critical": 1,
    "High": 2,
    "Medium": 7,
    "Low": 14,
}

DEFAULT_WARN_COOLDOWN_DAYS = 7
DEFAULT_ADVISORY_COOLDOWN_DAYS = 30
DEFAULT_REMOVED_COOLDOWN_DAYS = 30
DEFAULT_STALE_HOURS = 72
REMOVED_REPORT_MAX_HOURS = 48
LOG_TRUNCATION_CHARS = 20000
STATUS_PAGE_SIZE = 300
MAX_STATUS_PAGES = 20
VULN_PAGE_SIZE = 300
SW_PAGE_SIZE = 50
MAX_VULN_PAGES = 20
MAX_SW_PAGES = 20

CVE_ID_RE = re.compile(r"\ACVE-[0-9]{4}-[0-9]{4,}\Z", re.ASCII)
CPYTHON_VER_RE = re.compile(r"\A[23]\.[0-9]+\.[0-9]+\Z", re.ASCII)
MINOR_VER_RE = re.compile(r"\A[23]\.[0-9]+\Z", re.ASCII)
BREW_REV_RE = re.compile(r"_[0-9]+\Z", re.ASCII)
PYTHON_SW_NAME_RE = re.compile(r"\A(python@[0-9]+\.[0-9]+|Python)\Z", re.ASCII)
SLA_KEY_RE = re.compile(r"\Acpython:[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
YYYYMMDD_RE = re.compile(r"\A[0-9]{8}\Z", re.ASCII)
SELF_SERVICE_REMOVED_RE = re.compile(r"PY_SS: report shown \(removed: (?!none)")
PY_REM_TARGET_RE = re.compile(r"\A(python\.org |Homebrew python@)([0-9]+\.[0-9]+)", re.ASCII)
SLA_BLOCK_RE = re.compile(
    r"(# --- SLA_DEADLINES[^\n]*\n)[^\n]*(\n# --- /SLA_DEADLINES ---)"
)

HttpRequester = security_notifier.HttpRequester


def normalize_version(version: Any) -> str:
    return BREW_REV_RE.sub("", str(version or "").strip())


def version_tuple(version: str) -> Tuple[int, int, int]:
    parts = version.split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def parse_iso_timestamp(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_ymd(ymd: str) -> str:
    if not YYYYMMDD_RE.match(ymd):
        return ""
    return f"{ymd[:4]}-{ymd[4:6]}-{ymd[6:8]}"


def _mdm_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _resolve_next_page_url(
    base: str,
    base_list_url: str,
    data: Dict[str, Any],
    page: int,
    page_size: int,
    batch_len: int,
) -> Optional[str]:
    parsed_base = urllib.parse.urlparse(base)
    if "next" in data:
        next_val = data.get("next")
        if isinstance(next_val, str) and next_val.strip():
            next_str = next_val.strip()
            if next_str.startswith("//"):
                raise ValueError(f"Rejected scheme-relative next URL: {next_str}")
            parsed_next = urllib.parse.urlparse(next_str)
            if parsed_next.scheme or parsed_next.netloc:
                if (
                    parsed_next.scheme != "https"
                    or not parsed_base.netloc
                    or parsed_next.netloc != parsed_base.netloc
                ):
                    raise ValueError(f"Rejected cross-origin or non-HTTPS next URL: {next_str}")
                return next_str
            if next_str.startswith("/"):
                candidate = f"{base}{next_str}"
                parsed_cand = urllib.parse.urlparse(candidate)
                if (
                    parsed_cand.scheme != "https"
                    or not parsed_base.netloc
                    or parsed_cand.netloc != parsed_base.netloc
                ):
                    raise ValueError(f"Rejected invalid resolved next URL: {candidate}")
                return candidate
            return f"{base_list_url}&page={page + 1}"
        return None
    if batch_len >= page_size:
        return f"{base_list_url}&page={page + 1}"
    return None


def fetch_script_status_rows(
    mdm_api_url: str,
    mdm_api_token: str,
    script_id: str,
    *,
    requester: HttpRequester = security_notifier.default_http_request,
    page_size: int = STATUS_PAGE_SIZE,
    max_pages: int = MAX_STATUS_PAGES,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Fetch paginated execution status rows and return rows with a failure flag."""
    if not script_id:
        return [], False
    base = mdm_api_url.rstrip("/")
    quoted_id = urllib.parse.quote(script_id, safe="")
    rows: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    for page in range(max_pages):
        offset = page * page_size
        url = (
            f"{base}/api/v1/library/custom-scripts/{quoted_id}/status"
            f"?limit={page_size}&offset={offset}"
        )
        status, data = requester("GET", url, _mdm_headers(mdm_api_token), None)
        if status < 200 or status >= 300 or not isinstance(data, dict) or data.get("error"):
            return rows, True
        batch = data.get("results")
        if batch is None:
            batch = []
        if not isinstance(batch, list):
            return rows, True
        if not batch:
            break
        for row in batch:
            if not isinstance(row, dict):
                continue
            row_id = str(row.get("id") or "")
            if row_id and row_id in seen_ids:
                continue
            if row_id:
                seen_ids.add(row_id)
            rows.append(row)
        if len(batch) < page_size:
            break
        if page == max_pages - 1:
            return rows, True

    return rows, False


def fetch_active_python_cves(
    mdm_api_url: str,
    mdm_api_token: str,
    *,
    requester: HttpRequester = security_notifier.default_http_request,
    vuln_page_size: int = VULN_PAGE_SIZE,
    sw_page_size: int = SW_PAGE_SIZE,
    max_vuln_pages: int = MAX_VULN_PAGES,
    max_sw_pages: int = MAX_SW_PAGES,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Fetch all paginated active Python CVEs and affected software versions."""
    base = mdm_api_url.rstrip("/")
    vuln_filter = urllib.parse.quote('{"software":{"like":["python"]}}', safe="")
    list_base_url = (
        f"{base}/api/v1/vulnerability-management/vulnerabilities"
        f"?size={vuln_page_size}&filter={vuln_filter}"
    )

    candidates: List[Dict[str, Any]] = []
    seen_cves: Set[str] = set()
    failed_count = 0

    next_url: Optional[str] = list_base_url
    for page in range(1, max_vuln_pages + 1):
        if not next_url:
            break
        status, data = requester("GET", next_url, _mdm_headers(mdm_api_token), None)
        if status < 200 or status >= 300 or not isinstance(data, dict) or data.get("error"):
            failed_count += 1
            break
        batch = data.get("results")
        if batch is None:
            batch = []
        if not isinstance(batch, list):
            failed_count += 1
            break
        for row in batch:
            if not isinstance(row, dict):
                continue
            if (row.get("status") or "Active") != "Active":
                continue
            severity = str(row.get("severity") or "")
            if severity not in SLA_WINDOW_DAYS:
                continue
            cve_id = str(row.get("cve_id") or "")
            if not CVE_ID_RE.match(cve_id) or cve_id in seen_cves:
                continue
            first_dt = parse_iso_timestamp(row.get("first_detection_date"))
            if first_dt is None:
                continue
            seen_cves.add(cve_id)
            candidates.append(
                {
                    "cve_id": cve_id,
                    "severity": severity,
                    "window_days": SLA_WINDOW_DAYS[severity],
                    "first_detection": first_dt,
                }
            )
        try:
            next_url = _resolve_next_page_url(
                base,
                list_base_url,
                data,
                page,
                vuln_page_size,
                len(batch),
            )
        except ValueError:
            failed_count += 1
            break
        if next_url and page == max_vuln_pages:
            failed_count += 1
            break

    per_cve: List[Dict[str, Any]] = []
    rejected_versions = 0

    for item in candidates:
        cve_id = item["cve_id"]
        sw_base_url = (
            f"{base}/api/v1/vulnerability-management/vulnerabilities/"
            f"{urllib.parse.quote(cve_id, safe='')}/software?size={sw_page_size}"
        )
        versions: Set[str] = set()
        sw_failed = False
        sw_next_url: Optional[str] = sw_base_url

        for page in range(1, max_sw_pages + 1):
            if not sw_next_url:
                break
            sw_status, sw_data = requester("GET", sw_next_url, _mdm_headers(mdm_api_token), None)
            if (
                sw_status < 200
                or sw_status >= 300
                or not isinstance(sw_data, dict)
                or sw_data.get("error")
            ):
                failed_count += 1
                sw_failed = True
                break
            sw_batch = sw_data.get("results")
            if sw_batch is None:
                sw_batch = []
            if not isinstance(sw_batch, list):
                failed_count += 1
                sw_failed = True
                break

            for sw in sw_batch:
                if not isinstance(sw, dict):
                    continue
                sw_name = str(sw.get("name") or "")
                if not PYTHON_SW_NAME_RE.match(sw_name):
                    continue
                for sv in sw.get("software_versions") or []:
                    if not isinstance(sv, dict):
                        continue
                    norm_ver = normalize_version(sv.get("version"))
                    if not CPYTHON_VER_RE.match(norm_ver):
                        rejected_versions += 1
                        continue
                    versions.add(norm_ver)

            try:
                sw_next_url = _resolve_next_page_url(
                    base,
                    sw_base_url,
                    sw_data,
                    page,
                    sw_page_size,
                    len(sw_batch),
                )
            except ValueError:
                failed_count += 1
                sw_failed = True
                break
            if sw_next_url and page == max_sw_pages:
                failed_count += 1
                sw_failed = True
                break

        if sw_failed:
            continue

        deadline_dt = item["first_detection"] + timedelta(days=item["window_days"])
        deadline = deadline_dt.strftime("%Y%m%d")
        if not YYYYMMDD_RE.match(deadline):
            continue

        per_cve.append(
            {
                "cve": cve_id,
                "severity": item["severity"],
                "deadline": deadline,
                "versions": sorted(versions, key=version_tuple),
            }
        )

    return per_cve, failed_count, rejected_versions


def extract_inventory_versions(rows: List[Dict[str, Any]]) -> Set[str]:
    versions: Set[str] = set()
    for row in rows:
        log_text = str(row.get("log") or row.get("last_audit_log") or "")
        for line in log_text.splitlines():
            idx = line.find("PY_INV: ")
            if idx < 0:
                continue
            try:
                inv = json.loads(line[idx + 8 :])
            except ValueError:
                continue
            if not isinstance(inv, dict):
                continue
            if inv.get("src") == "brew":
                for keg in str(inv.get("kegs") or "").split():
                    ver = normalize_version(keg)
                    if CPYTHON_VER_RE.match(ver):
                        versions.add(ver)
            else:
                ver = normalize_version(inv.get("ver"))
                if CPYTHON_VER_RE.match(ver):
                    versions.add(ver)
    return versions


def compute_sla_deadlines(
    per_cve: List[Dict[str, Any]],
    fleet_versions: Set[str],
) -> Tuple[Dict[str, str], str, int]:
    """Build cpython:X.Y.Z deadlines and exclude CVEs affecting the newest fleet version."""
    fleet_known: Set[str] = set()
    for ver in fleet_versions:
        norm_ver = normalize_version(ver)
        if CPYTHON_VER_RE.match(norm_ver):
            fleet_known.add(norm_ver)

    newest_version = ""
    if fleet_known:
        all_known = set(fleet_known)
        for cve in per_cve:
            for ver in cve.get("versions") or []:
                norm_ver = normalize_version(ver)
                if CPYTHON_VER_RE.match(norm_ver):
                    all_known.add(norm_ver)
        newest_version = max(all_known, key=version_tuple)

    deadlines: Dict[str, str] = {}
    unfixable_count = 0

    for cve in per_cve:
        cve_versions = [normalize_version(v) for v in (cve.get("versions") or [])]
        if newest_version and newest_version in cve_versions:
            unfixable_count += 1
            continue
        deadline = str(cve.get("deadline") or "")
        if not YYYYMMDD_RE.match(deadline):
            continue
        for ver in cve_versions:
            if not CPYTHON_VER_RE.match(ver):
                continue
            key = f"cpython:{ver}"
            if key not in deadlines or deadline < deadlines[key]:
                deadlines[key] = deadline

    return deadlines, newest_version, unfixable_count


def parse_device_log_markers(
    log_text: str,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    summary: Optional[Dict[str, Any]] = None
    inventories: List[Dict[str, Any]] = []
    removed_lines: List[str] = []

    for line in log_text.splitlines():
        sum_idx = line.find("PY_SUMMARY: ")
        if sum_idx >= 0:
            try:
                parsed = json.loads(line[sum_idx + 12 :])
                if isinstance(parsed, dict):
                    summary = parsed
            except ValueError:
                pass
            continue

        inv_idx = line.find("PY_INV: ")
        if inv_idx >= 0:
            try:
                parsed = json.loads(line[inv_idx + 8 :])
                if isinstance(parsed, dict):
                    inventories.append(parsed)
            except ValueError:
                pass
            continue

        rem_idx = line.find("PY_REM: removed ")
        if rem_idx >= 0:
            removed_lines.append(line[rem_idx + 8 :])

    return summary, inventories, removed_lines


def _is_newer_row(candidate: Dict[str, Any], current: Dict[str, Any]) -> bool:
    cand_dt = parse_iso_timestamp(candidate.get("reported_at"))
    cur_dt = parse_iso_timestamp(current.get("reported_at"))
    if cand_dt is None:
        return False
    if cur_dt is None:
        return True
    return cand_dt > cur_dt


def merge_device_status_rows(
    audit_rows: List[Dict[str, Any]],
    remediation_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Deduplicate device status rows by computer ID and attach remediation removals."""
    by_device: Dict[str, Dict[str, Any]] = {}
    device_order: List[str] = []
    unkeyed_rows: List[Dict[str, Any]] = []

    for row in audit_rows:
        dev_id = str((row.get("computer") or {}).get("id") or "")
        if not dev_id:
            unkeyed_rows.append(dict(row))
            continue
        if dev_id not in by_device:
            by_device[dev_id] = dict(row)
            device_order.append(dev_id)
            continue
        existing = by_device[dev_id]
        existing_log = str(existing.get("log") or existing.get("last_audit_log") or "")
        cand_log = str(row.get("log") or row.get("last_audit_log") or "")
        existing_has_inv = "PY_INV:" in existing_log
        cand_has_inv = "PY_INV:" in cand_log

        if (cand_has_inv and not existing_has_inv) or (
            cand_has_inv == existing_has_inv and _is_newer_row(row, existing)
        ):
            merged = dict(row)
            if not _is_newer_row(row, existing):
                _, _, prev_removed = parse_device_log_markers(existing_log)
                extra = list(existing.get("_rem_removed") or []) + prev_removed
                if extra:
                    merged["_rem_removed"] = extra
                    merged["_rem_reported_at"] = (
                        existing.get("_rem_reported_at") or existing.get("reported_at")
                    )
            by_device[dev_id] = merged
        else:
            _, _, cand_removed = parse_device_log_markers(cand_log)
            if cand_removed and not _is_newer_row(existing, row):
                if not existing.get("_rem_reported_at") or _is_newer_row(
                    row, {"reported_at": existing.get("_rem_reported_at")}
                ):
                    existing["_rem_removed"] = list(cand_removed)
                    existing["_rem_reported_at"] = row.get("reported_at")
                else:
                    existing_extra = list(existing.get("_rem_removed") or [])
                    existing_extra.extend(cand_removed)
                    existing["_rem_removed"] = existing_extra

    if remediation_rows:
        rem_by_device: Dict[str, Dict[str, Any]] = {}
        rem_order: List[str] = []
        for row in remediation_rows:
            dev_id = str((row.get("computer") or {}).get("id") or "")
            if not dev_id:
                unkeyed_rows.append(dict(row))
                continue
            if dev_id not in rem_by_device:
                rem_by_device[dev_id] = row
                rem_order.append(dev_id)
            elif _is_newer_row(row, rem_by_device[dev_id]):
                rem_by_device[dev_id] = row

        for dev_id in rem_order:
            rem_row = rem_by_device[dev_id]
            rem_log = str(rem_row.get("log") or rem_row.get("last_audit_log") or "")
            _, _, rem_removed = parse_device_log_markers(rem_log)
            if dev_id in by_device:
                target = by_device[dev_id]
                if rem_removed:
                    existing_extra = list(target.get("_rem_removed") or [])
                    existing_extra.extend(rem_removed)
                    target["_rem_removed"] = existing_extra
                    target["_rem_reported_at"] = rem_row.get("reported_at")
            else:
                by_device[dev_id] = dict(rem_row)
                device_order.append(dev_id)

    return [by_device[dev_id] for dev_id in device_order] + unkeyed_rows


def _deadline_for_inventory(inv: Dict[str, Any], sla_deadlines: Dict[str, str]) -> str:
    if inv.get("src") == "brew":
        earliest = ""
        for keg in str(inv.get("kegs") or "").split():
            ver = normalize_version(keg)
            date_val = sla_deadlines.get(f"cpython:{ver}", "")
            if date_val and (not earliest or date_val < earliest):
                earliest = date_val
        return earliest
    ver = normalize_version(inv.get("ver"))
    return sla_deadlines.get(f"cpython:{ver}", "")


def parse_findings(
    audit_rows: List[Dict[str, Any]],
    self_service_rows: List[Dict[str, Any]],
    sla_deadlines: Dict[str, str],
    *,
    remediation_rows: Optional[List[Dict[str, Any]]] = None,
    cve_failed: int = 0,
    cve_count: int = 0,
    audit_failed: bool = False,
    rem_failed: bool = False,
    ss_failed: bool = False,
    audit_script_id: str = "",
    stale_hours: int = DEFAULT_STALE_HOURS,
    now_dt: Optional[datetime] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Evaluate deduplicated audit logs against gates and return findings and stats."""
    now = now_dt if now_dt is not None else datetime.now(timezone.utc)
    merged_rows = merge_device_status_rows(audit_rows, remediation_rows)

    ss_by_device: Dict[str, Dict[str, Any]] = {}
    for row in self_service_rows:
        dev_id = str((row.get("computer") or {}).get("id") or "")
        if not dev_id:
            continue
        if dev_id not in ss_by_device or _is_newer_row(row, ss_by_device[dev_id]):
            ss_by_device[dev_id] = row

    findings: List[Dict[str, Any]] = []
    stale_devices: List[str] = []
    reported = 0
    truncated = 0
    self_serviced = 0

    for row in merged_rows:
        log_text = str(row.get("log") or row.get("last_audit_log") or "")
        extra_removed: List[str] = list(row.get("_rem_removed") or [])
        if "PY_INV:" not in log_text and "PY_REM: removed " not in log_text and not extra_removed:
            continue
        reported += 1

        if len(log_text) >= LOG_TRUNCATION_CHARS:
            truncated += 1
            continue

        computer = row.get("computer") or {}
        device_id = str(computer.get("id") or "")
        device_name = str(computer.get("name") or "?")
        audit_dt = parse_iso_timestamp(row.get("reported_at"))
        age_seconds = (now - audit_dt).total_seconds() if audit_dt is not None else float("inf")
        is_stale = audit_dt is None or age_seconds > stale_hours * 3600

        ss_row = ss_by_device.get(device_id)
        if ss_row:
            ss_dt = parse_iso_timestamp(ss_row.get("reported_at"))
            ss_log = str(ss_row.get("log") or "")
            if (
                ss_dt is not None
                and (audit_dt is None or ss_dt > audit_dt)
                and SELF_SERVICE_REMOVED_RE.search(ss_log)
            ):
                self_serviced += 1
                continue

        summary, inventories, raw_removed = parse_device_log_markers(log_text)
        newest_minor = ""
        for inv in inventories:
            if inv.get("verdict") == "keep:newest":
                newest_minor = str(inv.get("minor") or "")
        if not newest_minor and summary:
            newest_minor = str(summary.get("newest") or "")

        removables: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        for inv in inventories:
            deadline = _deadline_for_inventory(inv, sla_deadlines)
            verdict = str(inv.get("verdict") or "")
            if verdict == "removable":
                if not deadline:
                    continue
                src = str(inv.get("src") or "")
                minor = str(inv.get("minor") or "")
                ver = str(inv.get("ver") or "")
                label = (
                    f"Homebrew python@{minor}"
                    if src == "brew"
                    else f"python.org {minor} ({ver})"
                )
                removables.append(
                    {
                        "inv": inv,
                        "label": label,
                        "date": deadline,
                        "pkgs": int(inv.get("pkgs") or 0),
                        "pkgTop": str(inv.get("pkg_top") or ""),
                    }
                )
            elif verdict == "stale-default":
                if not deadline:
                    continue
                advisories.append(
                    {
                        "inv": inv,
                        "type": "default",
                        "minor": str(inv.get("minor") or ""),
                        "ver": str(inv.get("ver") or ""),
                        "newest": newest_minor,
                        "date": deadline,
                        "pkgs": int(inv.get("pkgs") or 0),
                        "pkgTop": str(inv.get("pkg_top") or ""),
                    }
                )

        removed_entries: List[str] = []
        seen_removed: Set[str] = set()
        removed_keys: Set[str] = set()

        def _record_removed(
            rem_line: str,
            line_stale: bool,
            line_age_seconds: float,
            allow_suppress: bool = True,
        ) -> None:
            if (
                not line_stale
                and line_age_seconds < REMOVED_REPORT_MAX_HOURS * 3600
                and rem_line not in seen_removed
            ):
                seen_removed.add(rem_line)
                removed_entries.append(rem_line)
            if allow_suppress:
                match = PY_REM_TARGET_RE.match(rem_line[8:])
                if match:
                    prefix = "pyorg:" if match.group(1) == "python.org " else "brew:"
                    removed_keys.add(f"{prefix}{match.group(2)}")

        for rem_line in raw_removed:
            _record_removed(rem_line, is_stale, age_seconds, allow_suppress=True)

        if extra_removed:
            rem_dt = parse_iso_timestamp(row.get("_rem_reported_at"))
            rem_age_seconds = (now - rem_dt).total_seconds() if rem_dt is not None else float("inf")
            rem_is_stale = rem_dt is None or rem_age_seconds > stale_hours * 3600
            rem_can_suppress = rem_dt is not None and (audit_dt is None or rem_dt >= audit_dt)
            for rem_line in extra_removed:
                _record_removed(
                    rem_line,
                    rem_is_stale,
                    rem_age_seconds,
                    allow_suppress=rem_can_suppress,
                )

        def _was_removed(inv_obj: Dict[str, Any]) -> bool:
            prefix = "brew:" if inv_obj.get("src") == "brew" else "pyorg:"
            return f"{prefix}{inv_obj.get('minor', '')}" in removed_keys

        removables = [item for item in removables if not _was_removed(item["inv"])]
        advisories = [item for item in advisories if not _was_removed(item["inv"])]

        if not removables and not advisories and not removed_entries:
            continue

        if is_stale and (removables or advisories):
            hours_ago = round(age_seconds / 3600) if audit_dt is not None else -1
            stale_devices.append(f"{device_name} ({hours_ago}h ago)")

        findings.append(
            {
                "deviceId": device_id or "MISSING-DEVICE-ID",
                "deviceName": device_name,
                "summary": summary or {},
                "removables": removables,
                "advisories": advisories,
                "removed": removed_entries,
                "hasWarn": bool(removables),
                "hasAdv": bool(advisories),
                "hasRemoved": bool(removed_entries),
            }
        )

    if stale_devices:
        sample = ", ".join(stale_devices[:15])
        extra = f" (+{len(stale_devices) - 15} more)" if len(stale_devices) > 15 else ""
        findings.append(
            {
                "ops": True,
                "text": (
                    f":hourglass: *python-cve-sla-sync*: {len(stale_devices)} device(s) "
                    f"carry findings and have not reported for >{stale_hours}h "
                    f"- SLA risk, check agent/device: {sample}{extra}"
                ),
            }
        )

    if audit_failed:
        findings.append(
            {
                "ops": True,
                "text": (
                    ":warning: *python-cve-sla-sync*: failed to fetch audit script "
                    "status rows from the MDM API - SLA_DEADLINES was NOT updated "
                    "this run (previous deadlines kept)."
                ),
            }
        )

    if rem_failed:
        findings.append(
            {
                "ops": True,
                "text": (
                    ":warning: *python-cve-sla-sync*: failed to fetch remediation script "
                    "status rows from the MDM API - PY_REM suppression may be incomplete "
                    "this run."
                ),
            }
        )

    if ss_failed:
        findings.append(
            {
                "ops": True,
                "text": (
                    ":warning: *python-cve-sla-sync*: failed to fetch Self Service script "
                    "status rows from the MDM API - Self Service suppression may be "
                    "incomplete this run."
                ),
            }
        )

    if cve_failed > 0:
        total_cves = cve_failed + cve_count
        findings.append(
            {
                "ops": True,
                "text": (
                    f":warning: *python-cve-sla-sync*: {cve_failed} of {total_cves} "
                    "per-CVE software lookups failed in the MDM API - SLA_DEADLINES "
                    "was NOT updated this run (previous deadlines kept)."
                ),
            }
        )

    if truncated > 0:
        script_note = f" (script {audit_script_id})" if audit_script_id else ""
        findings.append(
            {
                "ops": True,
                "text": (
                    f":warning: *python-cve-sla-sync*: {truncated} device(s) skipped "
                    f"- status log reached the {LOG_TRUNCATION_CHARS}-char limit. "
                    f"These devices receive no warning DM and remain eligible for "
                    f"remediation{script_note}."
                ),
            }
        )

    stats = {
        "reported": reported,
        "truncated": truncated,
        "stale_with_findings": len(stale_devices),
        "self_serviced": self_serviced,
        "audit_failed": audit_failed,
        "rem_failed": rem_failed,
        "ss_failed": ss_failed,
        "devices_to_notify": sum(1 for item in findings if not item.get("ops")),
        "ops_alerts": sum(1 for item in findings if item.get("ops")),
    }
    return findings, stats


def build_notify_payloads(
    findings: List[Dict[str, Any]],
    *,
    exception_portal_url: str = "",
    guide_article_url: str = "",
    announce_url: str = "",
    warn_cooldown_days: int = DEFAULT_WARN_COOLDOWN_DAYS,
    advisory_cooldown_days: int = DEFAULT_ADVISORY_COOLDOWN_DAYS,
    removed_cooldown_days: int = DEFAULT_REMOVED_COOLDOWN_DAYS,
    today_ymd: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Build consolidated Slack notification payloads from parsed findings."""
    today = today_ymd or datetime.now(timezone.utc).strftime("%Y%m%d")
    venv_tip = (
        ":shield: *Keep your packages:* move them into a virtualenv before that date "
        "- virtualenvs are never removed and keep their interpreter installed: "
        "`python3 -m venv ~/venvs/work && ~/venvs/work/bin/pip install <your packages>`"
    )

    def _when(date_str: str) -> str:
        if date_str and date_str > today:
            return f"on {format_ymd(date_str)}"
        return "shortly"

    def _pkg_note(entry: Dict[str, Any]) -> str:
        pkgs = int(entry.get("pkgs") or 0)
        if not pkgs:
            return ""
        pkg_top = str(entry.get("pkgTop") or "")
        return f" - *{pkgs} package(s) installed in it* ({pkg_top}) will be deleted with it"

    payloads: List[Dict[str, Any]] = []
    for item in findings:
        if item.get("ops"):
            payloads.append(item)
            continue

        device_id = item["deviceId"]
        device_name = item["deviceName"]
        removables = item.get("removables") or []
        advisories = item.get("advisories") or []
        removed = item.get("removed") or []

        parts: List[Dict[str, Any]] = []
        if removables:
            lines = "\n".join(
                f"- {v['label']} - auto-removal {_when(v['date'])}{_pkg_note(v)}"
                for v in removables
            )
            parts.append(
                {
                    "key": "warn",
                    "throttleDays": warn_cooldown_days,
                    "text": (
                        f":snake: *Old Python versions on your Mac ({device_name}) "
                        f"are scheduled for removal*\n\n{lines}\n\n{venv_tip}\n\n"
                        "*Why:* flagged as vulnerable in security scans and unused on your Mac.\n"
                        "*Action:* remove them now in Self Service below. Any listed version "
                        "still present on its deadline is removed automatically under security SLA."
                    ),
                }
            )

        if advisories:
            bullets: List[str] = []
            for adv in advisories:
                raw_newest = str(adv.get("newest") or "")
                raw_minor = str(adv.get("minor") or "")
                valid_newest = bool(MINOR_VER_RE.match(raw_newest))
                minor_label = raw_minor if MINOR_VER_RE.match(raw_minor) else "this version"
                pkgs = int(adv.get("pkgs") or 0)
                pkg_top = str(adv.get("pkgTop") or "")
                pkg_clause = (
                    f" {pkgs} package(s) live inside it ({pkg_top}) - move them into a virtualenv first."
                    if pkgs
                    else ""
                )
                if valid_newest:
                    bullets.append(
                        f"- `python.org {minor_label}` is your default `python3`, but `{raw_newest}` "
                        f"is already installed and {minor_label} is flagged as vulnerable.{pkg_clause}\n"
                        f"*Switch default:* `sudo ln -sfn /Library/Frameworks/Python.framework/Versions/"
                        f"{raw_newest}/bin/python3 /usr/local/bin/python3`\n"
                        f"*Or remove it* in *MDM Self Service* below. Otherwise IT removes {minor_label} "
                        f"and switches `python3` to {raw_newest} {_when(adv['date'])} (security SLA)."
                    )
                else:
                    bullets.append(
                        f"- `python.org {minor_label}` is your default `python3` and is flagged as "
                        f"vulnerable.{pkg_clause}\n"
                        f"*Action:* open *MDM Self Service* below to clean up old Python versions. "
                        f"Otherwise IT removes {minor_label} {_when(adv['date'])} (security SLA)."
                    )
            header = (
                ":warning: *Also needs your attention*"
                if removables
                else f":snake: *Outdated Python on your Mac ({device_name}) needs your attention*"
            )
            parts.append(
                {
                    "key": "advisory",
                    "throttleDays": advisory_cooldown_days,
                    "text": f"{header}\n\n" + "\n".join(bullets),
                }
            )

        if removed:
            lines = "\n".join(f"- {entry}" for entry in removed)
            parts.append(
                {
                    "key": "removed",
                    "throttleDays": removed_cooldown_days,
                    "text": (
                        f":wastebasket: *Python versions removed from your Mac ({device_name})*\n\n"
                        f"{lines}\n\n"
                        "*Restore packages in a virtualenv* (snapshot saved to "
                        "~/Library/Logs/python-cleanup): "
                        '`python3 -m venv ~/venvs/work && ~/venvs/work/bin/pip install -r "<snapshot file>"`. '
                        "Virtualenvs are never removed by automated remediation."
                    ),
                }
            )

        if not parts:
            continue

        footer_lines = [
            ":bulb: *Self Service:* open *MDM Self Service* -> *Clean up old Python versions* "
            "-> *Run* (asks for confirmation and never removes versions used by virtualenvs)."
        ]
        if announce_url:
            footer_lines.append(f":mega: <{announce_url}|Security announcement - automated cleanup>")
        if guide_article_url:
            footer_lines.append(
                f":blue_book: <{guide_article_url}|Full guide - Self Service and manual removal>"
            )
        if exception_portal_url:
            targets = [v["label"] for v in removables] + [a["minor"] for a in advisories]
            summary_param = urllib.parse.quote(
                f"Python exclusion request - {device_name}: keep {', '.join(targets)}",
                safe="",
            )
            sep = "&" if "?" in exception_portal_url else "?"
            form_url = f"{exception_portal_url}{sep}summary={summary_param}"
            footer_lines.append(
                f":ticket: *Need an exception?* <{form_url}|Open an exception request>."
            )

        payloads.append(
            {
                "deviceId": device_id,
                "deviceName": device_name,
                "source": "python",
                "parts": parts,
                "footer": "\n".join(footer_lines),
            }
        )

    return payloads


def prepare_sla_script_patch(
    remediation_script: str,
    sla_deadlines: Dict[str, str],
    *,
    cve_failed: int = 0,
    audit_failed: bool = False,
) -> Tuple[Optional[str], str, str]:
    """Build an updated remediation script with validated SLA_DEADLINES."""
    if audit_failed:
        return None, "skipped_audit_failure", ""
    if cve_failed > 0:
        return None, "skipped_cve_failure", ""

    valid_keys = sorted(
        k
        for k, v in sla_deadlines.items()
        if SLA_KEY_RE.match(str(k)) and YYYYMMDD_RE.match(str(v))
    )
    sla_line = 'SLA_DEADLINES="' + " ".join(f"{k}={sla_deadlines[k]}" for k in valid_keys) + '"'

    if not remediation_script:
        return None, "missing_script", sla_line

    if not SLA_BLOCK_RE.search(remediation_script):
        return None, "missing_markers", sla_line

    updated = SLA_BLOCK_RE.sub(
        lambda match: match.group(1) + sla_line + match.group(2),
        remediation_script,
        count=1,
    )
    if updated == remediation_script:
        return None, "unchanged", sla_line
    return updated, "updated", sla_line


def sync_remediation_script_sla(
    mdm_api_url: str,
    mdm_api_token: str,
    remediation_script_id: str,
    sla_deadlines: Dict[str, str],
    *,
    cve_failed: int = 0,
    audit_failed: bool = False,
    apply_changes: bool = False,
    requester: HttpRequester = security_notifier.default_http_request,
) -> Dict[str, Any]:
    """Fetch the remediation script, validate SLA_DEADLINES, and patch when applied."""
    if not remediation_script_id:
        return {"status": "skipped_no_script_id", "patched": False}
    if audit_failed:
        return {
            "status": "skipped_audit_failure",
            "patched": False,
            "reason": "Audit script status fetch failed",
        }
    if cve_failed > 0:
        return {
            "status": "skipped_cve_failure",
            "patched": False,
            "reason": f"{cve_failed} CVE software lookup(s) failed",
        }

    base = mdm_api_url.rstrip("/")
    quoted_id = urllib.parse.quote(remediation_script_id, safe="")
    url = f"{base}/api/v1/library/custom-scripts/{quoted_id}"

    status, item = requester("GET", url, _mdm_headers(mdm_api_token), None)
    if status < 200 or status >= 300 or not isinstance(item, dict) or item.get("error"):
        err_val = item.get("error", f"HTTP {status}") if isinstance(item, dict) else f"HTTP {status}"
        return {
            "status": "fetch_failed",
            "patched": False,
            "error": err_val,
        }

    rem_script = str(item.get("remediation_script") or "")
    updated, patch_status, sla_line = prepare_sla_script_patch(
        rem_script,
        sla_deadlines,
        cve_failed=cve_failed,
        audit_failed=audit_failed,
    )
    if updated is None:
        return {"status": patch_status, "patched": False, "sla_line": sla_line}

    if not apply_changes:
        return {"status": "dry_run_would_patch", "patched": False, "sla_line": sla_line}

    headers = _mdm_headers(mdm_api_token)
    headers["Content-Type"] = "application/json; charset=utf-8"
    body = json.dumps({"remediation_script": updated}).encode("utf-8")
    p_status, p_data = requester("PATCH", url, headers, body)
    if p_status < 200 or p_status >= 300 or not isinstance(p_data, dict) or p_data.get("error"):
        err_val = (
            p_data.get("error", f"HTTP {p_status}")
            if isinstance(p_data, dict)
            else f"HTTP {p_status}"
        )
        return {
            "status": "patch_failed",
            "patched": False,
            "sla_line": sla_line,
            "error": err_val,
        }

    return {"status": "patched", "patched": True, "sla_line": sla_line}


def run_sync(
    *,
    mdm_api_url: str,
    mdm_api_token: str,
    audit_script_id: str,
    remediation_script_id: str,
    self_service_script_id: str = "",
    slack_bot_token: str = "",
    slack_ops_channel: str = "",
    exception_portal_url: str = "",
    guide_article_url: str = "",
    announce_url: str = "",
    warehouse_blueprint_id: str = "",
    state_file: str = security_notifier.DEFAULT_STATE_FILE,
    stale_hours: int = DEFAULT_STALE_HOURS,
    apply_changes: bool = False,
    now_dt: Optional[datetime] = None,
    requester: HttpRequester = security_notifier.default_http_request,
) -> Dict[str, Any]:
    """Run the full Python CVE SLA synchronization and notification pipeline."""
    now = now_dt if now_dt is not None else datetime.now(timezone.utc)

    audit_rows, audit_failed = fetch_script_status_rows(
        mdm_api_url,
        mdm_api_token,
        audit_script_id,
        requester=requester,
    )
    rem_rows: List[Dict[str, Any]] = []
    rem_failed = False
    if remediation_script_id and remediation_script_id != audit_script_id:
        rem_rows, rem_failed = fetch_script_status_rows(
            mdm_api_url,
            mdm_api_token,
            remediation_script_id,
            requester=requester,
        )

    merged_rows = merge_device_status_rows(audit_rows, rem_rows)

    ss_rows: List[Dict[str, Any]] = []
    ss_failed = False
    if self_service_script_id:
        ss_rows, ss_failed = fetch_script_status_rows(
            mdm_api_url,
            mdm_api_token,
            self_service_script_id,
            requester=requester,
        )

    per_cve, cve_failed, rejected_versions = fetch_active_python_cves(
        mdm_api_url,
        mdm_api_token,
        requester=requester,
    )
    fleet_versions = extract_inventory_versions(merged_rows)
    sla_deadlines, newest_version, unfixable_cves = compute_sla_deadlines(
        per_cve,
        fleet_versions,
    )

    findings, parse_stats = parse_findings(
        merged_rows,
        ss_rows,
        sla_deadlines,
        cve_failed=cve_failed,
        cve_count=len(per_cve),
        audit_failed=audit_failed,
        rem_failed=rem_failed,
        ss_failed=ss_failed,
        audit_script_id=audit_script_id,
        stale_hours=stale_hours,
        now_dt=now,
    )

    payloads = build_notify_payloads(
        findings,
        exception_portal_url=exception_portal_url,
        guide_article_url=guide_article_url,
        announce_url=announce_url,
        today_ymd=now.strftime("%Y%m%d"),
    )

    patch_result = sync_remediation_script_sla(
        mdm_api_url,
        mdm_api_token,
        remediation_script_id,
        sla_deadlines,
        cve_failed=cve_failed,
        audit_failed=audit_failed,
        apply_changes=apply_changes,
        requester=requester,
    )

    notify_result = security_notifier.deliver_notifications(
        payloads,
        mdm_api_url=mdm_api_url,
        mdm_api_token=mdm_api_token,
        slack_bot_token=slack_bot_token,
        slack_ops_channel=slack_ops_channel,
        state_file=state_file,
        warehouse_blueprint_id=warehouse_blueprint_id,
        apply_changes=apply_changes,
        now_ms=int(now.timestamp() * 1000),
        requester=requester,
    )

    return {
        "timestamp_utc": now.isoformat(),
        "mode": "apply" if apply_changes else "dry-run",
        "cve_summary": {
            "resolved": len(per_cve),
            "failed": cve_failed,
            "rejected_versions": rejected_versions,
            "newest_version": newest_version,
            "unfixable_excluded": unfixable_cves,
            "deadlines_count": len(sla_deadlines),
            "sla_deadlines": sla_deadlines,
        },
        "parse_stats": parse_stats,
        "script_patch": patch_result,
        "notifications": notify_result,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync Python CVE SLA deadlines to MDM and notify device owners."
    )
    parser.add_argument(
        "--mdm-api-url",
        default=os.environ.get("MDM_API_URL", ""),
        help="Base URL of the MDM API.",
    )
    parser.add_argument(
        "--audit-script-id",
        default=os.environ.get("MDM_AUDIT_SCRIPT_ID", ""),
        help="MDM Custom Script ID for Python audit status logs.",
    )
    parser.add_argument(
        "--remediation-script-id",
        default=os.environ.get("MDM_REMEDIATION_SCRIPT_ID", ""),
        help="MDM Custom Script ID for Python/remediate_update.sh.",
    )
    parser.add_argument(
        "--self-service-script-id",
        default=os.environ.get("MDM_SELF_SERVICE_SCRIPT_ID", ""),
        help="Optional MDM Custom Script ID for Self Service cleanup status.",
    )
    parser.add_argument(
        "--slack-ops-channel",
        default=os.environ.get("SLACK_OPS_CHANNEL", ""),
        help="Slack channel ID for operations alerts.",
    )
    parser.add_argument(
        "--exception-portal-url",
        default=os.environ.get("EXCEPTION_PORTAL_URL", ""),
        help="Portal URL for Python exception requests.",
    )
    parser.add_argument(
        "--guide-article-url",
        default=os.environ.get("GUIDE_ARTICLE_URL", ""),
        help="Optional URL to the internal removal guide.",
    )
    parser.add_argument(
        "--announce-url",
        default=os.environ.get("ANNOUNCE_URL", ""),
        help="Optional URL to the security announcement post.",
    )
    parser.add_argument(
        "--warehouse-blueprint-id",
        default=os.environ.get("WAREHOUSE_BLUEPRINT_ID", ""),
        help="Optional blueprint ID for unassigned warehouse devices.",
    )
    parser.add_argument(
        "--state-file",
        default=os.environ.get("NOTIFY_STATE_FILE", security_notifier.DEFAULT_STATE_FILE),
        help="Path to the local JSON deduplication state file.",
    )
    parser.add_argument(
        "--stale-hours",
        type=int,
        default=DEFAULT_STALE_HOURS,
        help="Hours after which a device audit report counts as stale.",
    )
    parser.add_argument(
        "--report-file",
        default="",
        help="Optional path to write the JSON execution report.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute deadlines and preview deliveries without making changes.",
    )
    mode_group.add_argument(
        "--apply",
        action="store_true",
        help="Patch SLA_DEADLINES in MDM and send Slack notifications.",
    )
    args = parser.parse_args(argv)

    mdm_api_token = os.environ.get("MDM_API_TOKEN", "")
    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN", "")

    if not args.mdm_api_url or not mdm_api_token:
        print("Error: MDM_API_URL and MDM_API_TOKEN are required.", file=sys.stderr)
        return 1
    if not args.audit_script_id:
        print("Error: MDM_AUDIT_SCRIPT_ID is required.", file=sys.stderr)
        return 1

    report = run_sync(
        mdm_api_url=args.mdm_api_url,
        mdm_api_token=mdm_api_token,
        audit_script_id=args.audit_script_id,
        remediation_script_id=args.remediation_script_id,
        self_service_script_id=args.self_service_script_id,
        slack_bot_token=slack_bot_token,
        slack_ops_channel=args.slack_ops_channel,
        exception_portal_url=args.exception_portal_url,
        guide_article_url=args.guide_article_url,
        announce_url=args.announce_url,
        warehouse_blueprint_id=args.warehouse_blueprint_id,
        state_file=args.state_file,
        stale_hours=args.stale_hours,
        apply_changes=bool(args.apply),
    )

    output_json = json.dumps(report, indent=2, sort_keys=True)
    if args.report_file:
        parent = os.path.dirname(os.path.abspath(args.report_file))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.report_file, "w", encoding="utf-8") as handle:
            handle.write(output_json + "\n")

    print(output_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
