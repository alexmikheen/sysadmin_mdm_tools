#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for python_cve_sla_sync.py and security_notifier.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

JENKINS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if JENKINS_DIR not in sys.path:
    sys.path.insert(0, JENKINS_DIR)

import python_cve_sla_sync as sync_mod  # noqa: E402
import security_notifier as notifier_mod  # noqa: E402


class TestSlaDeadlineCalculation(unittest.TestCase):
    def test_severity_windows_and_unfixable_exclusion(self) -> None:
        per_cve = [
            {
                "cve": "CVE-2026-0001",
                "severity": "Critical",
                "deadline": "20261011",
                "versions": ["3.11.0", "3.12.1"],
            },
            {
                "cve": "CVE-2026-0002",
                "severity": "High",
                "deadline": "20261012",
                "versions": ["3.11.0", "3.13.0"],
            },
            {
                "cve": "CVE-2026-0003",
                "severity": "Low",
                "deadline": "20261024",
                "versions": ["3.11.0", "3.14.2"],
            },
        ]
        fleet_versions = {"3.11.0", "3.14.2"}

        deadlines, newest, unfixable = sync_mod.compute_sla_deadlines(
            per_cve,
            fleet_versions,
        )

        self.assertEqual(newest, "3.14.2")
        self.assertEqual(unfixable, 1)
        self.assertEqual(
            deadlines,
            {
                "cpython:3.11.0": "20261011",
                "cpython:3.12.1": "20261011",
                "cpython:3.13.0": "20261012",
            },
        )

    def test_empty_fleet_versions_does_not_exclude_cves_as_unfixable(self) -> None:
        per_cve = [
            {
                "cve": "CVE-2026-0001",
                "severity": "Critical",
                "deadline": "20261011",
                "versions": ["3.11.0", "3.12.1"],
            },
        ]

        deadlines, newest, unfixable = sync_mod.compute_sla_deadlines(per_cve, set())

        self.assertEqual(newest, "")
        self.assertEqual(unfixable, 0)
        self.assertEqual(
            deadlines,
            {
                "cpython:3.11.0": "20261011",
                "cpython:3.12.1": "20261011",
            },
        )

    def test_fetch_active_cves_filters_non_python_and_strips_brew_revision(self) -> None:
        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "/vulnerabilities?size=300" in url:
                return 200, {
                    "results": [
                        {
                            "cve_id": "CVE-2026-1001",
                            "status": "Active",
                            "severity": "Medium",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        },
                        {
                            "cve_id": "CVE-2026-1002",
                            "status": "Resolved",
                            "severity": "Critical",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        },
                        {
                            "cve_id": "INVALID-ID",
                            "status": "Active",
                            "severity": "High",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        },
                        {
                            "cve_id": "CVE-2026-1003",
                            "status": "Active",
                            "severity": "Low",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        },
                    ]
                }
            if "/CVE-2026-1001/software" in url:
                return 200, {
                    "results": [
                        {
                            "name": "python@3.12",
                            "software_versions": [
                                {"version": "3.12.7_2"},
                                {"version": "15.3.2"},
                            ],
                        },
                        {
                            "name": "OtherApp",
                            "software_versions": [{"version": "3.12.9"}],
                        },
                    ]
                }
            if "/CVE-2026-1003/software" in url:
                return 500, {"error": "backend error"}
            return 404, {"error": "not found"}

        per_cve, failed, rejected = sync_mod.fetch_active_python_cves(
            "https://mdm.example.test",
            "tok",
            requester=fake_requester,
        )

        self.assertEqual(failed, 1)
        self.assertEqual(rejected, 1)
        self.assertEqual(len(per_cve), 1)
        self.assertEqual(per_cve[0]["cve"], "CVE-2026-1001")
        self.assertEqual(per_cve[0]["deadline"], "20261008")
        self.assertEqual(per_cve[0]["versions"], ["3.12.7"])

    def test_fetch_active_cves_paginates_vulnerabilities_and_software(self) -> None:
        seen_urls: List[str] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            seen_urls.append(url)
            if "/vulnerabilities?" in url and "page=2" not in url:
                return 200, {
                    "results": [
                        {
                            "cve_id": "CVE-2026-2001",
                            "status": "Active",
                            "severity": "Critical",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        }
                    ],
                    "next": "/api/v1/vulnerability-management/vulnerabilities?size=1&page=2",
                }
            if "/vulnerabilities?" in url and "page=2" in url:
                return 200, {
                    "results": [
                        {
                            "cve_id": "CVE-2026-2002",
                            "status": "Active",
                            "severity": "High",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        }
                    ],
                    "next": None,
                }
            if "/CVE-2026-2001/software" in url and "page=2" not in url:
                return 200, {
                    "results": [
                        {
                            "name": "Python",
                            "software_versions": [{"version": "3.11.1"}],
                        }
                    ]
                }
            if "/CVE-2026-2001/software" in url and "page=2" in url:
                return 200, {
                    "results": [
                        {
                            "name": "python@3.12",
                            "software_versions": [{"version": "3.12.2"}],
                        }
                    ],
                    "next": None,
                }
            if "/CVE-2026-2002/software" in url and "page=2" not in url:
                return 200, {
                    "results": [
                        {
                            "name": "Python",
                            "software_versions": [{"version": "3.10.1"}],
                        }
                    ]
                }
            if "/CVE-2026-2002/software" in url and "page=2" in url:
                return 500, {"error": "page 2 failed"}
            return 404, {"error": "not found"}

        per_cve, failed, _ = sync_mod.fetch_active_python_cves(
            "https://mdm.example.test",
            "tok",
            requester=fake_requester,
            vuln_page_size=1,
            sw_page_size=1,
            max_sw_pages=3,
        )

        self.assertEqual(failed, 1)
        self.assertEqual(len(per_cve), 1)
        self.assertEqual(per_cve[0]["cve"], "CVE-2026-2001")
        self.assertEqual(per_cve[0]["versions"], ["3.11.1", "3.12.2"])
        self.assertTrue(any("page=2" in u for u in seen_urls))

    def test_resolve_next_page_url_rejects_cross_origin_http_and_scheme_relative(self) -> None:
        base = "https://mdm.example.test"
        list_url = f"{base}/api/v1/vulnerability-management/vulnerabilities?size=1"

        self.assertEqual(
            sync_mod._resolve_next_page_url(
                base,
                list_url,
                {"next": "https://mdm.example.test/api/v1/vulnerability-management/vulnerabilities?page=2"},
                1,
                1,
                1,
            ),
            "https://mdm.example.test/api/v1/vulnerability-management/vulnerabilities?page=2",
        )
        self.assertEqual(
            sync_mod._resolve_next_page_url(
                base,
                list_url,
                {"next": "/api/v1/vulnerability-management/vulnerabilities?page=2"},
                1,
                1,
                1,
            ),
            "https://mdm.example.test/api/v1/vulnerability-management/vulnerabilities?page=2",
        )

        for bad_next in (
            "https://evil.test/api/v1/vulnerabilities?page=2",
            "http://mdm.example.test/api/v1/vulnerabilities?page=2",
            "//evil.test/api/v1/vulnerabilities?page=2",
            "https://mdm.example.test@evil.test/api/v1/vulnerabilities?page=2",
        ):
            with self.assertRaises(ValueError):
                sync_mod._resolve_next_page_url(
                    base,
                    list_url,
                    {"next": bad_next},
                    1,
                    1,
                    1,
                )

    def test_fetch_active_cves_rejects_cross_origin_next_without_requesting_it(self) -> None:
        seen_urls: List[str] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            seen_urls.append(url)
            if "/vulnerabilities?" in url:
                return 200, {
                    "results": [
                        {
                            "cve_id": "CVE-2026-3001",
                            "status": "Active",
                            "severity": "Critical",
                            "first_detection_date": "2026-10-01T00:00:00Z",
                        }
                    ],
                    "next": "https://evil.test/steal-token",
                }
            if "/CVE-2026-3001/software" in url:
                return 200, {
                    "results": [
                        {
                            "name": "Python",
                            "software_versions": [{"version": "3.11.1"}],
                        }
                    ],
                    "next": "//evil.test/steal-token-sw",
                }
            return 404, {"error": "not found"}

        per_cve, failed, _ = sync_mod.fetch_active_python_cves(
            "https://mdm.example.test",
            "secret-tok",
            requester=fake_requester,
            vuln_page_size=1,
            sw_page_size=1,
        )

        self.assertEqual(failed, 2)
        self.assertEqual(per_cve, [])
        self.assertTrue(all("evil.test" not in u for u in seen_urls))


class TestLogParsingAndPayloads(unittest.TestCase):
    def test_parse_markers_gates_and_removed_deduplication(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
        fresh_ts = (now - timedelta(hours=6)).isoformat()
        stale_ts = (now - timedelta(hours=80)).isoformat()
        newer_ss_ts = (now - timedelta(hours=2)).isoformat()

        sla_deadlines = {
            "cpython:3.11.0": "20261020",
            "cpython:3.12.4": "20261022",
            "cpython:3.10.9": "20261018",
        }

        device_a_log = "\n".join(
            [
                '[2026-10-15 06:00:00] PY_SUMMARY: {"sv":2,"newest":"3.14","default":"3.11"}',
                '[2026-10-15 06:00:00] PY_INV: {"src":"pyorg","minor":"3.14","ver":"3.14.0","verdict":"keep:newest"}',
                '[2026-10-15 06:00:00] PY_INV: {"src":"pyorg","minor":"3.11","ver":"3.11.0","pkgs":5,"pkg_top":"numpy, pandas","verdict":"stale-default"}',
                '[2026-10-15 06:00:00] PY_INV: {"src":"brew","minor":"3.12","kegs":"3.12.4_1","pkgs":2,"pkg_top":"requests","verdict":"removable"}',
                '[2026-10-15 06:00:00] PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","pkgs":3,"pkg_top":"flask","verdict":"removable"}',
                "[2026-10-15 06:00:01] PY_REM: removed python.org 3.10 (3.10.9): 3 packages saved to /Users/Shared/python-cleanup/pyorg-3.10-packages-20261015.txt",
            ]
        )
        device_b_log = '[2026-10-12 04:00:00] PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","verdict":"removable"}'
        device_c_log = '[2026-10-15 06:00:00] PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","verdict":"removable"}'
        device_d_log = "PY_INV: " + ("x" * 20000)

        audit_rows = [
            {"id": "1", "computer": {"id": "dev-a", "name": "mac-a"}, "reported_at": fresh_ts, "log": device_a_log},
            {"id": "2", "computer": {"id": "dev-b", "name": "mac-b"}, "reported_at": stale_ts, "log": device_b_log},
            {"id": "3", "computer": {"id": "dev-c", "name": "mac-c"}, "reported_at": fresh_ts, "log": device_c_log},
            {"id": "4", "computer": {"id": "dev-d", "name": "mac-d"}, "reported_at": fresh_ts, "log": device_d_log},
        ]
        ss_rows = [
            {
                "id": "ss-1",
                "computer": {"id": "dev-c", "name": "mac-c"},
                "reported_at": newer_ss_ts,
                "log": "PY_SS: report shown (removed: python.org 3.10)",
            }
        ]

        findings, stats = sync_mod.parse_findings(
            audit_rows,
            ss_rows,
            sla_deadlines,
            audit_script_id="script-1",
            now_dt=now,
        )

        self.assertEqual(stats["reported"], 4)
        self.assertEqual(stats["truncated"], 1)
        self.assertEqual(stats["self_serviced"], 1)
        self.assertEqual(stats["stale_with_findings"], 1)
        self.assertEqual(stats["devices_to_notify"], 2)
        self.assertEqual(stats["ops_alerts"], 2)

        dev_a = next(item for item in findings if item.get("deviceId") == "dev-a")
        self.assertEqual(len(dev_a["removables"]), 1)
        self.assertEqual(dev_a["removables"][0]["label"], "Homebrew python@3.12")
        self.assertEqual(len(dev_a["advisories"]), 1)
        self.assertEqual(dev_a["advisories"][0]["newest"], "3.14")
        self.assertEqual(len(dev_a["removed"]), 1)
        self.assertIn("/Users/Shared/python-cleanup/", dev_a["removed"][0])

        payloads = sync_mod.build_notify_payloads(
            findings,
            exception_portal_url="https://portal.example.test/exception",
            today_ymd="20261015",
        )
        dev_a_payload = next(p for p in payloads if p.get("deviceId") == "dev-a")
        part_keys = [p["key"] for p in dev_a_payload["parts"]]
        self.assertEqual(part_keys, ["warn", "advisory", "removed"])
        self.assertIn("python3 -m venv ~/venvs/work", dev_a_payload["parts"][0]["text"])
        self.assertIn("2 package(s) installed in it", dev_a_payload["parts"][0]["text"])
        self.assertIn("sudo ln -sfn /Library/Frameworks/Python.framework/Versions/3.14/bin/python3", dev_a_payload["parts"][1]["text"])
        self.assertIn("https://portal.example.test/exception?summary=", dev_a_payload["footer"])

    def test_deduplicates_device_across_audit_and_remediation_rows(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
        audit_ts = (now - timedelta(hours=8)).isoformat()
        rem_ts = (now - timedelta(hours=2)).isoformat()
        sla_deadlines = {
            "cpython:3.10.9": "20261018",
            "cpython:3.12.4": "20261022",
        }

        audit_rows = [
            {
                "id": "aud-1",
                "computer": {"id": "dev-1", "name": "mac-1"},
                "reported_at": audit_ts,
                "log": "\n".join(
                    [
                        'PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","verdict":"removable"}',
                        'PY_INV: {"src":"brew","minor":"3.12","kegs":"3.12.4","verdict":"removable"}',
                    ]
                ),
            }
        ]
        remediation_rows = [
            {
                "id": "rem-1",
                "computer": {"id": "dev-1", "name": "mac-1"},
                "reported_at": rem_ts,
                "log": "PY_REM: removed python.org 3.10 (3.10.9)",
            }
        ]

        findings, stats = sync_mod.parse_findings(
            audit_rows,
            [],
            sla_deadlines,
            remediation_rows=remediation_rows,
            now_dt=now,
        )

        self.assertEqual(stats["devices_to_notify"], 1)
        self.assertEqual(len(findings), 1)
        dev = findings[0]
        self.assertEqual(len(dev["removables"]), 1)
        self.assertEqual(dev["removables"][0]["label"], "Homebrew python@3.12")
        self.assertEqual(len(dev["removed"]), 1)

    def test_stale_remediation_does_not_suppress_newer_audit_finding(self) -> None:
        now = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
        old_rem_ts = (now - timedelta(hours=12)).isoformat()
        newer_audit_ts = (now - timedelta(hours=2)).isoformat()
        sla_deadlines = {
            "cpython:3.10.9": "20261018",
        }

        audit_rows = [
            {
                "id": "aud-old",
                "computer": {"id": "dev-1", "name": "mac-1"},
                "reported_at": old_rem_ts,
                "log": "\n".join(
                    [
                        'PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","verdict":"removable"}',
                        "PY_REM: removed python.org 3.10 (3.10.9)",
                    ]
                ),
            },
            {
                "id": "aud-new",
                "computer": {"id": "dev-1", "name": "mac-1"},
                "reported_at": newer_audit_ts,
                "log": 'PY_INV: {"src":"pyorg","minor":"3.10","ver":"3.10.9","verdict":"removable"}',
            },
        ]
        remediation_rows = [
            {
                "id": "rem-old",
                "computer": {"id": "dev-1", "name": "mac-1"},
                "reported_at": old_rem_ts,
                "log": "PY_REM: removed python.org 3.10 (3.10.9)",
            }
        ]

        findings, stats = sync_mod.parse_findings(
            audit_rows,
            [],
            sla_deadlines,
            remediation_rows=remediation_rows,
            now_dt=now,
        )

        self.assertEqual(stats["devices_to_notify"], 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]["removables"]), 1)
        self.assertEqual(findings[0]["removables"][0]["label"], "python.org 3.10 (3.10.9)")

    def test_advisory_omits_sudo_ln_when_newest_is_invalid_or_empty(self) -> None:
        findings = [
            {
                "deviceId": "dev-bad",
                "deviceName": "mac-bad",
                "removables": [],
                "advisories": [
                    {
                        "type": "default",
                        "minor": "3.11",
                        "ver": "3.11.0",
                        "newest": "3.14; rm -rf /",
                        "date": "20261020",
                        "pkgs": 0,
                        "pkgTop": "",
                    }
                ],
                "removed": [],
            },
            {
                "deviceId": "dev-empty",
                "deviceName": "mac-empty",
                "removables": [],
                "advisories": [
                    {
                        "type": "default",
                        "minor": "3.11",
                        "ver": "3.11.0",
                        "newest": "",
                        "date": "20261020",
                        "pkgs": 0,
                        "pkgTop": "",
                    }
                ],
                "removed": [],
            },
        ]

        payloads = sync_mod.build_notify_payloads(findings, today_ymd="20261015")
        self.assertEqual(len(payloads), 2)
        for payload in payloads:
            adv_text = payload["parts"][0]["text"]
            self.assertNotIn("sudo ln", adv_text)
            self.assertNotIn("rm -rf", adv_text)
            self.assertIn("MDM Self Service", adv_text)

    def test_extract_inventory_versions_ignores_non_dict_json(self) -> None:
        rows = [
            {
                "log": "\n".join(
                    [
                        "PY_INV: null",
                        "PY_INV: [1, 2, 3]",
                        'PY_INV: "string"',
                        "PY_INV: 42",
                        'PY_INV: {"src":"pyorg","ver":"3.12.5"}',
                    ]
                )
            }
        ]
        versions = sync_mod.extract_inventory_versions(rows)
        self.assertEqual(versions, {"3.12.5"})


class TestFailClosedScriptPatching(unittest.TestCase):
    SAMPLE_SCRIPT = (
        "#!/bin/zsh\n"
        "# --- SLA_DEADLINES ---\n"
        'SLA_DEADLINES="cpython:3.10.0=20261001"\n'
        "# --- /SLA_DEADLINES ---\n"
        "echo done\n"
    )

    def test_fail_closed_when_cve_lookup_failed(self) -> None:
        updated, status, _ = sync_mod.prepare_sla_script_patch(
            self.SAMPLE_SCRIPT,
            {"cpython:3.11.0": "20261020"},
            cve_failed=1,
        )
        self.assertIsNone(updated)
        self.assertEqual(status, "skipped_cve_failure")

    def test_fail_closed_when_audit_status_fetch_failed(self) -> None:
        def failing_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "/custom-scripts/aud-1/status" in url:
                return 503, {"error": "service unavailable"}
            if "/custom-scripts/rem-1/status" in url:
                return 200, {"results": []}
            if "/vulnerabilities?" in url:
                return 200, {"results": []}
            if url.endswith("/custom-scripts/rem-1"):
                raise AssertionError("PATCH or GET on remediation script must not run")
            return 200, {"ok": True}

        rows, failed = sync_mod.fetch_script_status_rows(
            "https://mdm.example.test",
            "tok",
            "aud-1",
            requester=failing_requester,
        )
        self.assertEqual(rows, [])
        self.assertTrue(failed)

        with tempfile.TemporaryDirectory() as tmpdir:
            report = sync_mod.run_sync(
                mdm_api_url="https://mdm.example.test",
                mdm_api_token="tok",
                audit_script_id="aud-1",
                remediation_script_id="rem-1",
                slack_bot_token="xoxb-test",
                slack_ops_channel="COPS123",
                state_file=os.path.join(tmpdir, "state.json"),
                apply_changes=False,
                requester=failing_requester,
            )

        self.assertEqual(report["script_patch"]["status"], "skipped_audit_failure")
        self.assertFalse(report["script_patch"]["patched"])
        self.assertTrue(report["parse_stats"]["audit_failed"])
        self.assertGreaterEqual(report["parse_stats"]["ops_alerts"], 1)

    def test_status_pagination_truncation_and_rem_ss_failures_emit_ops_alerts(self) -> None:
        def paginated_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "offset=0" in url:
                return 200, {"results": [{"id": "1"}, {"id": "2"}]}
            if "offset=2" in url:
                return 200, {"results": [{"id": "3"}, {"id": "4"}]}
            return 200, {"results": []}

        rows, failed = sync_mod.fetch_script_status_rows(
            "https://mdm.example.test",
            "tok",
            "aud-1",
            requester=paginated_requester,
            page_size=2,
            max_pages=2,
        )
        self.assertEqual(len(rows), 4)
        self.assertTrue(failed)

        sent_messages: List[Dict[str, Any]] = []

        def failing_aux_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "/custom-scripts/aud-1/status" in url:
                return 200, {"results": []}
            if "/custom-scripts/rem-1/status" in url:
                return 503, {"error": "rem unavailable"}
            if "/custom-scripts/ss-1/status" in url:
                return 502, {"error": "ss unavailable"}
            if "/vulnerabilities?" in url:
                return 200, {"results": []}
            if url.endswith("/custom-scripts/rem-1"):
                return 200, {"remediation_script": self.SAMPLE_SCRIPT}
            if "chat.postMessage" in url:
                sent_messages.append(json.loads((body or b"{}").decode("utf-8")))
                return 200, {"ok": True}
            return 200, {"ok": True}

        with tempfile.TemporaryDirectory() as tmpdir:
            report = sync_mod.run_sync(
                mdm_api_url="https://mdm.example.test",
                mdm_api_token="tok",
                audit_script_id="aud-1",
                remediation_script_id="rem-1",
                self_service_script_id="ss-1",
                slack_bot_token="xoxb-test",
                slack_ops_channel="COPS123",
                state_file=os.path.join(tmpdir, "state.json"),
                apply_changes=True,
                requester=failing_aux_requester,
            )

        self.assertTrue(report["parse_stats"]["rem_failed"])
        self.assertTrue(report["parse_stats"]["ss_failed"])
        self.assertEqual(report["parse_stats"]["ops_alerts"], 2)
        self.assertEqual(report["notifications"]["ops_alerts_sent"], 2)
        self.assertEqual(len(sent_messages), 2)
        self.assertTrue(any("remediation script" in m["text"] for m in sent_messages))
        self.assertTrue(any("Self Service script" in m["text"] for m in sent_messages))

    def test_fail_closed_when_markers_missing(self) -> None:
        updated, status, _ = sync_mod.prepare_sla_script_patch(
            "#!/bin/zsh\necho no markers\n",
            {"cpython:3.11.0": "20261020"},
            cve_failed=0,
        )
        self.assertIsNone(updated)
        self.assertEqual(status, "missing_markers")

    def test_updates_marker_block_and_drops_invalid_entries(self) -> None:
        updated, status, sla_line = sync_mod.prepare_sla_script_patch(
            self.SAMPLE_SCRIPT,
            {
                "cpython:3.12.1": "20261025",
                "cpython:3.11.0": "20261020",
                "bad;rm -rf /": "20261020",
                "cpython:3.9.0": "invalid",
                "cpython:3.8.0\n": "20261020",
                "cpython:3.8.1": "20261020\n",
                "cpython:٣.11.0": "20261020",
                "cpython:3.8.2": "٢٠٢٦١٠٢٠",
            },
            cve_failed=0,
        )
        self.assertEqual(status, "updated")
        self.assertEqual(sla_line, 'SLA_DEADLINES="cpython:3.11.0=20261020 cpython:3.12.1=20261025"')
        assert updated is not None
        self.assertIn(sla_line, updated)
        self.assertNotIn("rm -rf", updated)

    def test_ascii_anchored_regexes_reject_newlines_and_unicode_digits(self) -> None:
        self.assertIsNone(sync_mod.SLA_KEY_RE.match("cpython:3.11.0\n"))
        self.assertIsNone(sync_mod.SLA_KEY_RE.match("cpython:٣.11.0"))
        self.assertIsNone(sync_mod.YYYYMMDD_RE.match("20261020\n"))
        self.assertIsNone(sync_mod.YYYYMMDD_RE.match("٢٠٢٦١٠٢٠"))
        self.assertIsNone(sync_mod.CPYTHON_VER_RE.match("3.11.0\n"))
        self.assertIsNone(sync_mod.CPYTHON_VER_RE.match("3.١١.0"))
        self.assertIsNone(sync_mod.CVE_ID_RE.match("CVE-2026-1234\n"))
        self.assertIsNone(sync_mod.CVE_ID_RE.match("CVE-٢٠٢٦-1234"))
        self.assertIsNone(sync_mod.MINOR_VER_RE.match("3.14\n"))
        self.assertIsNone(sync_mod.MINOR_VER_RE.match("3.١٤"))

    def test_unchanged_returns_none(self) -> None:
        updated, status, _ = sync_mod.prepare_sla_script_patch(
            self.SAMPLE_SCRIPT,
            {"cpython:3.10.0": "20261001"},
            cve_failed=0,
        )
        self.assertIsNone(updated)
        self.assertEqual(status, "unchanged")

    def test_sync_remediation_script_respects_dry_run(self) -> None:
        calls: List[str] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            calls.append(method)
            if method == "GET":
                return 200, {"remediation_script": self.SAMPLE_SCRIPT}
            return 200, {"ok": True}

        dry_res = sync_mod.sync_remediation_script_sla(
            "https://mdm.example.test",
            "tok",
            "rem-1",
            {"cpython:3.11.0": "20261020"},
            apply_changes=False,
            requester=fake_requester,
        )
        self.assertEqual(dry_res["status"], "dry_run_would_patch")
        self.assertEqual(calls, ["GET"])

        apply_res = sync_mod.sync_remediation_script_sla(
            "https://mdm.example.test",
            "tok",
            "rem-1",
            {"cpython:3.11.0": "20261020"},
            apply_changes=True,
            requester=fake_requester,
        )
        self.assertEqual(apply_res["status"], "patched")
        self.assertTrue(apply_res["patched"])
        self.assertEqual(calls, ["GET", "GET", "PATCH"])


class TestSecurityNotifier(unittest.TestCase):
    def test_https_enforcement_and_redirect_blocking(self) -> None:
        with self.assertRaises(ValueError):
            notifier_mod.default_http_request("GET", "http://mdm.example.test/api", {})
        with self.assertRaises(ValueError):
            notifier_mod.default_http_request("GET", "file:///etc/passwd", {})
        with self.assertRaises(ValueError):
            notifier_mod.default_http_request("GET", "https:///no-host", {})

        handler = notifier_mod._NoRedirectHandler()
        req = urllib.request.Request("https://mdm.example.test/api")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(req, None, 302, "Found", {}, "http://evil.test/")
        self.assertEqual(ctx.exception.code, 302)
        self.assertIn("Redirects are disabled", str(ctx.exception))
        ctx.exception.close()

    def test_non_dict_http_error_json_is_wrapped(self) -> None:
        err = urllib.error.HTTPError(
            "https://mdm.example.test/api",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'["bad payload"]'),
        )
        with mock.patch.object(notifier_mod._HTTP_OPENER, "open", side_effect=err):
            status, payload = notifier_mod.default_http_request(
                "GET",
                "https://mdm.example.test/api",
                {},
            )
        self.assertEqual(status, 400)
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["data"], ["bad payload"])
        self.assertEqual(payload["error"], "HTTP 400")

    def test_state_permissions_symlink_refusal_and_corrupt_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = os.path.join(tmpdir, "state.json")
            notifier_mod.save_state(state_path, {"_sent": {}})
            mode = stat.S_IMODE(os.stat(state_path).st_mode)
            self.assertEqual(mode, 0o600)

            link_path = os.path.join(tmpdir, "link.json")
            os.symlink(state_path, link_path)
            with self.assertRaises(OSError):
                notifier_mod.load_state(link_path)
            with self.assertRaises(OSError):
                notifier_mod.save_state(link_path, {"_sent": {}})

            corrupt_path = os.path.join(tmpdir, "corrupt.json")
            with open(corrupt_path, "w", encoding="utf-8") as handle:
                handle.write("{not valid json")

            stderr_buf = io.StringIO()
            with mock.patch("sys.stderr", stderr_buf):
                dry_loaded = notifier_mod.load_state(corrupt_path, backup_corrupt=False)
            self.assertEqual(dry_loaded["_sent"], {})
            self.assertIn("_corrupt_error", dry_loaded)
            self.assertNotIn("_corrupt_backup", dry_loaded)
            self.assertTrue(os.path.exists(corrupt_path))
            self.assertIn("Corrupt state file", stderr_buf.getvalue())

            loaded = notifier_mod.load_state(corrupt_path)
            self.assertEqual(loaded["_sent"], {})
            backup_path = loaded.get("_corrupt_backup", "")
            self.assertTrue(backup_path.startswith(f"{corrupt_path}.corrupt."))
            self.assertTrue(os.path.exists(backup_path))

    def test_load_state_oserror_reports_corrupt_error_and_ops_alert(self) -> None:
        sent_messages: List[Dict[str, Any]] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "chat.postMessage" in url:
                sent_messages.append(json.loads((body or b"{}").decode("utf-8")))
                return 200, {"ok": True}
            return 200, {"ok": True}

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = os.path.join(tmpdir, "unreadable.json")
            with open(state_path, "w", encoding="utf-8") as handle:
                handle.write('{"_sent": {"python:dev-1": {"warn": {"h": "abc", "ts": 1}}}}')

            with mock.patch("builtins.open", side_effect=PermissionError("permission denied")):
                loaded = notifier_mod.load_state(state_path, backup_corrupt=True)
            self.assertEqual(loaded["_sent"], {})
            self.assertIn("State file read error", loaded.get("_corrupt_error", ""))
            self.assertTrue(loaded.get("_state_read_error"))

            stderr_buf = io.StringIO()
            with (
                mock.patch("sys.stderr", stderr_buf),
                mock.patch("builtins.open", side_effect=PermissionError("permission denied")),
            ):
                summary = notifier_mod.deliver_notifications(
                    [],
                    mdm_api_url="https://mdm.example.test",
                    mdm_api_token="tok",
                    slack_bot_token="xoxb-test",
                    slack_ops_channel="COPS123",
                    state_file=state_path,
                    apply_changes=True,
                    requester=fake_requester,
                )

            self.assertEqual(summary["ops_alerts_sent"], 1)
            self.assertIn("State file read error", summary["state_corrupt_error"])
            self.assertEqual(len(sent_messages), 1)
            self.assertIn("State file read error", sent_messages[0]["text"])
            with open(state_path, "r", encoding="utf-8") as handle:
                self.assertIn("python:dev-1", handle.read())

    def test_dry_run_does_not_consume_corrupt_state_before_apply(self) -> None:
        sent_messages: List[Dict[str, Any]] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "chat.postMessage" in url:
                sent_messages.append(json.loads((body or b"{}").decode("utf-8")))
                return 200, {"ok": True}
            return 200, {"ok": True}

        with tempfile.TemporaryDirectory() as tmpdir:
            corrupt_path = os.path.join(tmpdir, "corrupt_state.json")
            with open(corrupt_path, "w", encoding="utf-8") as handle:
                handle.write("{corrupt")

            with mock.patch("sys.stderr", io.StringIO()):
                dry_summary = notifier_mod.deliver_notifications(
                    [],
                    mdm_api_url="https://mdm.example.test",
                    mdm_api_token="tok",
                    slack_bot_token="xoxb-test",
                    slack_ops_channel="COPS123",
                    state_file=corrupt_path,
                    apply_changes=False,
                    requester=fake_requester,
                )

            self.assertEqual(dry_summary["ops_alerts_planned"], 1)
            self.assertEqual(dry_summary["ops_alerts_sent"], 0)
            self.assertEqual(dry_summary["state_corrupt_backup"], "")
            self.assertTrue(os.path.exists(corrupt_path))

            with mock.patch("sys.stderr", io.StringIO()):
                apply_summary = notifier_mod.deliver_notifications(
                    [],
                    mdm_api_url="https://mdm.example.test",
                    mdm_api_token="tok",
                    slack_bot_token="xoxb-test",
                    slack_ops_channel="COPS123",
                    state_file=corrupt_path,
                    apply_changes=True,
                    requester=fake_requester,
                )

            self.assertEqual(apply_summary["ops_alerts_sent"], 1)
            self.assertTrue(apply_summary["state_corrupt_backup"].startswith(f"{corrupt_path}.corrupt."))
            self.assertTrue(os.path.exists(apply_summary["state_corrupt_backup"]))
            self.assertEqual(len(sent_messages), 1)
            self.assertIn("corrupt notification state file", sent_messages[0]["text"])

    def test_cli_rejects_token_flags(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                sync_mod.main(["--mdm-api-token", "secret"])
            with self.assertRaises(SystemExit):
                notifier_mod.main(["--slack-bot-token", "secret"])

    def test_content_hash_dedup_and_cooldown_expiry(self) -> None:
        base_ms = 1_760_000_000_000
        warn_text = "Old Python 3.11 scheduled for removal"
        adv_text = "Default python3 is stale"

        item = {
            "deviceId": "dev-1",
            "deviceName": "mac-1",
            "source": "python",
            "parts": [
                {"key": "warn", "text": warn_text, "throttleDays": 7},
                {"key": "advisory", "text": adv_text, "throttleDays": 30},
            ],
            "footer": "Self Service footer",
        }

        sent_state = {
            "python:dev-1": {
                "warn": {"h": notifier_mod.compute_content_hash(warn_text), "ts": base_ms},
                "advisory": {"h": notifier_mod.compute_content_hash(adv_text), "ts": base_ms},
            }
        }

        passed, throttled = notifier_mod.filter_throttled_items(
            [item],
            sent_state,
            base_ms + 3 * 86400 * 1000,
        )
        self.assertEqual(len(passed), 0)
        self.assertEqual(throttled, 1)

        passed_after_8d, _ = notifier_mod.filter_throttled_items(
            [item],
            sent_state,
            base_ms + 8 * 86400 * 1000,
        )
        self.assertEqual(len(passed_after_8d), 1)
        self.assertEqual([p["key"] for p in passed_after_8d[0]["parts"]], ["warn"])

        changed_item = dict(item)
        changed_item["parts"] = [
            {"key": "warn", "text": warn_text + " (updated)", "throttleDays": 7},
            {"key": "advisory", "text": adv_text, "throttleDays": 30},
        ]
        passed_changed, _ = notifier_mod.filter_throttled_items(
            [changed_item],
            sent_state,
            base_ms + 1 * 86400 * 1000,
        )
        self.assertEqual(len(passed_changed), 1)
        self.assertEqual([p["key"] for p in passed_changed[0]["parts"]], ["warn"])

    def test_deliver_notifications_persists_state_and_skips_warehouse(self) -> None:
        sent_messages: List[Dict[str, Any]] = []

        def fake_requester(
            method: str,
            url: str,
            headers: Dict[str, str],
            body: Optional[bytes],
        ) -> Tuple[int, Dict[str, Any]]:
            if "/api/v1/devices/dev-1" in url:
                return 200, {
                    "device_id": "dev-1",
                    "blueprint_name": "Standard macOS",
                    "user": {"email": "alice@example.test"},
                }
            if "/api/v1/devices/dev-wh" in url:
                return 200, {
                    "device_id": "dev-wh",
                    "blueprint_name": "Devices Without Users",
                    "user": {},
                }
            if "users.lookupByEmail" in url:
                return 200, {"ok": True, "user": {"id": "U12345"}}
            if "chat.postMessage" in url:
                payload = json.loads((body or b"{}").decode("utf-8"))
                sent_messages.append(payload)
                return 200, {"ok": True}
            return 404, {"error": "not found"}

        items = [
            {
                "deviceId": "dev-1",
                "deviceName": "mac-1",
                "source": "python",
                "parts": [{"key": "warn", "text": "Remove 3.11", "throttleDays": 7}],
                "footer": "Footer text",
            },
            {
                "deviceId": "dev-1",
                "deviceName": "mac-1",
                "source": "python",
                "parts": [{"key": "warn", "text": "Remove 3.11", "throttleDays": 7}],
                "footer": "Footer text",
            },
            {
                "deviceId": "dev-wh",
                "deviceName": "mac-wh",
                "source": "python",
                "parts": [{"key": "warn", "text": "Remove 3.11", "throttleDays": 7}],
                "footer": "Footer text",
            },
            {"ops": True, "text": "Ops status notice"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = os.path.join(tmpdir, "notify_state.json")
            now_ms = 1_760_000_000_000

            res1 = notifier_mod.deliver_notifications(
                items,
                mdm_api_url="https://mdm.example.test",
                mdm_api_token="mdm-tok",
                slack_bot_token="xoxb-test",
                slack_ops_channel="COPS123",
                state_file=state_path,
                apply_changes=True,
                now_ms=now_ms,
                requester=fake_requester,
            )
            self.assertEqual(res1["dms_sent"], 1)
            self.assertEqual(res1["throttled_devices"], 1)
            self.assertEqual(res1["skipped_warehouse"], 1)
            self.assertEqual(res1["ops_alerts_sent"], 1)
            self.assertEqual(len(sent_messages), 2)
            self.assertEqual(sent_messages[0]["channel"], "U12345")
            self.assertEqual(sent_messages[1]["channel"], "COPS123")
            self.assertTrue(os.path.exists(state_path))

            res2 = notifier_mod.deliver_notifications(
                items[:1],
                mdm_api_url="https://mdm.example.test",
                mdm_api_token="mdm-tok",
                slack_bot_token="xoxb-test",
                slack_ops_channel="COPS123",
                state_file=state_path,
                apply_changes=True,
                now_ms=now_ms + 86400 * 1000,
                requester=fake_requester,
            )
            self.assertEqual(res2["throttled_devices"], 1)
            self.assertEqual(res2["dms_sent"], 0)


if __name__ == "__main__":
    unittest.main()
