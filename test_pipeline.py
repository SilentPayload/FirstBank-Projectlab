#!/usr/bin/env python3
"""
Test harness for the SOC training repo.
Covers: generator consistency, mock Splunk export generation,
answer-key correctness, and student-skeleton guard (NotImplementedError).

Run from repo root:
    python test_pipeline.py
"""

import csv
import io
import re
import subprocess
import sys
import unittest
from pathlib import Path
from datetime import datetime

REPO   = Path(__file__).parent
LOGS   = REPO / "logs"
EXPORT = REPO / "logs" / "splunk_export.csv"

# ──────────────────────────────────────────────────────────────────────────────
# Step 0 — ensure logs exist (run generator if not)
# ──────────────────────────────────────────────────────────────────────────────

def ensure_logs(seed: int = 12345) -> None:
    if not (LOGS / "web_access.log").exists():
        print(f"[setup] Running generator (seed={seed}) …")
        import os, sys as _sys
        env = {**os.environ, "STUDENT_SEED": str(seed), "OUTPUT_DIR": str(LOGS)}
        result = subprocess.run(
            [_sys.executable, str(REPO / "data-generator" / "generate_logs.py")],
            env=env, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(result.stderr); sys.exit(1)
        print(result.stdout)


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — build a mock Splunk CSV export from raw log files
# ──────────────────────────────────────────────────────────────────────────────

def build_mock_splunk_export() -> None:
    """
    Converts the three raw log files into a CSV that mimics a Splunk export.
    Real Splunk would produce similar output after running the SPL hint from
    student/README.md Phase 1.5.
    """
    rows: list[dict] = []
    fieldnames = [
        "_time", "sourcetype", "host",
        "src_ip", "AccountName", "EventCode", "LogonType",
        "TargetServerName", "ShareName", "CommandLine", "NewProcessName",
        "HostName", "Status", "Privileges",
        "method", "uri", "useragent",
        "TxnID", "FromAccount", "ToAccount", "Amount", "TxnType",
        "InitiatedBy",
        "_raw",
    ]

    def blank() -> dict:
        return {f: "" for f in fieldnames}

    # ── web_access.log (Apache Combined) ─────────────────────────────────────
    apache_re = re.compile(
        r'(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<uri>\S+) HTTP/\S+" '
        r'(?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)"'
    )
    for line in (LOGS / "web_access.log").read_text().splitlines():
        m = apache_re.match(line)
        if not m: continue
        ts_raw = m["ts"]  # e.g. "20/Feb/2026:23:05:43 +0100"
        ts = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
        row = blank()
        row["_time"]      = ts.strftime("%Y-%m-%dT%H:%M:%S.000+01:00")
        row["sourcetype"] = "access_combined"
        row["host"]       = "WEBSVR"
        row["src_ip"]     = m["src_ip"]
        row["method"]     = m["method"]
        row["uri"]        = m["uri"]
        row["useragent"]  = m["ua"]
        row["Status"]     = m["status"]
        row["_raw"]       = line
        rows.append(row)

    # ── windows_auth.log (KV pairs) ───────────────────────────────────────────
    for line in (LOGS / "windows_auth.log").read_text().splitlines():
        if not line.strip(): continue
        parts = line.split(" ", 2)  # date time rest
        if len(parts) < 3: continue
        ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        kv = dict(re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', parts[2]))
        kv = {k: v.strip('"') for k, v in kv.items()}
        row = blank()
        row["_time"]            = ts.strftime("%Y-%m-%dT%H:%M:%S.000+01:00")
        row["sourcetype"]       = "windows_auth_training"
        row["host"]             = kv.get("HostName") or kv.get("WorkstationName") or kv.get("TargetServerName", "")
        row["src_ip"]           = kv.get("SourceIP", "")
        row["AccountName"]      = kv.get("AccountName", "")
        row["EventCode"]        = kv.get("EventCode", "")
        row["LogonType"]        = kv.get("LogonType", "")
        row["TargetServerName"] = kv.get("TargetServerName", "")
        row["ShareName"]        = kv.get("ShareName", "")
        row["CommandLine"]      = kv.get("CommandLine", "")
        row["NewProcessName"]   = kv.get("NewProcessName", "")
        row["HostName"]         = kv.get("HostName", "")
        row["Status"]           = kv.get("Status", "")
        row["Privileges"]       = kv.get("Privileges", "")
        row["_raw"]             = line
        rows.append(row)

    # ── transaction.log ───────────────────────────────────────────────────────
    for line in (LOGS / "transaction.log").read_text().splitlines():
        if not line.strip(): continue
        parts = line.split(" ", 2)
        if len(parts) < 3: continue
        ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        kv = dict(re.findall(r'(\w+)=(\S+)', parts[2]))
        row = blank()
        row["_time"]        = ts.strftime("%Y-%m-%dT%H:%M:%S.000+01:00")
        row["sourcetype"]   = "banking_transaction"
        row["host"]         = "TXNSVR"
        row["TxnID"]        = kv.get("TxnID", "")
        row["FromAccount"]  = kv.get("FromAccount", "")
        row["ToAccount"]    = kv.get("ToAccount", "")
        row["Amount"]       = kv.get("Amount", "")
        row["TxnType"]      = kv.get("TxnType", "")
        row["Status"]       = kv.get("Status", "")
        row["InitiatedBy"]  = kv.get("InitiatedBy", "")
        row["_raw"]         = line
        rows.append(row)

    # Sort by _time
    rows.sort(key=lambda r: r["_time"])

    with EXPORT.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"[setup] Mock Splunk export: {len(rows)} events → {EXPORT}")


# ──────────────────────────────────────────────────────────────────────────────
# Add repo paths for imports
# ──────────────────────────────────────────────────────────────────────────────

sys.path.insert(0, str(REPO / "instructor"))
sys.path.insert(0, str(REPO / "student"))


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerator(unittest.TestCase):

    def test_all_files_exist(self):
        for fname in ("web_access.log", "transaction.log",
                      "windows_auth.log", "nessus_scan.csv",
                      "scenario_manifest.json"):
            self.assertTrue((LOGS / fname).exists(), f"Missing: {fname}")

    def test_nessus_has_10_hosts(self):
        import csv as _csv
        with (LOGS / "nessus_scan.csv").open() as fh:
            hosts = {row["Host"] for row in _csv.DictReader(fh)}
        self.assertEqual(len(hosts), 10, f"Expected 10 hosts, got {len(hosts)}")

    def test_entry_point_has_sqli_vuln(self):
        import json, csv as _csv
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        ep = manifest["entry_point_host"]
        found = False
        with (LOGS / "nessus_scan.csv").open() as fh:
            for row in _csv.DictReader(fh):
                if row["Host"] == ep and "SQL Injection" in row["Name"]:
                    found = True
                    self.assertEqual(row["Risk"], "Critical")
        self.assertTrue(found, f"Entry point {ep} missing SQLi vuln in nessus_scan.csv")

    def test_attacker_ip_in_web_log(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        content = (LOGS / "web_access.log").read_text()
        self.assertIn(manifest["attacker_ip"], content)
        self.assertIn("sqlmap", content)

    def test_lateral_movement_uses_entry_point_as_source(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        ep = manifest["entry_point_host"]
        found = False
        for line in (LOGS / "windows_auth.log").read_text().splitlines():
            if "EventCode=4624" in line and "LogonType=3" in line and f"SourceIP={ep}" in line:
                found = True
                break
        self.assertTrue(found, "No lateral-movement event with entry_point as SourceIP")

    def test_transfer_script_in_windows_auth(self):
        content = (LOGS / "windows_auth.log").read_text()
        self.assertIn("bulk_transfer.py", content)
        self.assertIn("EventCode=4688", content)

    def test_fraudulent_txns_use_service_account(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        svc = manifest["service_account"]
        found = [l for l in (LOGS / "transaction.log").read_text().splitlines()
                 if f"InitiatedBy={svc}" in l]
        self.assertGreaterEqual(len(found), 5, "Expected ≥5 fraudulent transactions")

    def test_reproducibility(self):
        import os, subprocess, filecmp, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "STUDENT_SEED": "12345", "OUTPUT_DIR": tmp}
            subprocess.run(
                [sys.executable, str(REPO / "data-generator" / "generate_logs.py")],
                env=env, capture_output=True
            )
            for fname in ("web_access.log", "transaction.log",
                          "windows_auth.log", "nessus_scan.csv"):
                self.assertTrue(
                    filecmp.cmp(str(LOGS / fname), f"{tmp}/{fname}", shallow=False),
                    f"{fname} is not reproducible with same seed"
                )


class TestAnswerKey(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import analysis_answer_key as ak
        cls.ak = ak
        cls.nessus  = ak.parse_nessus_csv(str(LOGS / "nessus_scan.csv"))
        cls.events  = ak.parse_splunk_export(str(EXPORT))

    def test_parse_nessus_returns_vulnerabilities(self):
        self.assertGreater(len(self.nessus), 0)
        v = self.nessus[0]
        self.assertIsInstance(v.cvss, float)
        self.assertIn(v.risk, {"Critical", "High", "Medium", "Low", "None"})

    def test_parse_nessus_entry_point_is_critical(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        ep_vulns = [v for v in self.nessus
                    if v.host == manifest["entry_point_host"] and "SQL Injection" in v.name]
        self.assertTrue(ep_vulns, "Entry point has no SQLi vuln in parsed Nessus data")
        self.assertEqual(ep_vulns[0].risk, "Critical")
        self.assertGreaterEqual(ep_vulns[0].cvss, 9.0)

    def test_parse_splunk_events_sorted(self):
        times = [e.timestamp for e in self.events]
        self.assertEqual(times, sorted(times), "Events not sorted by timestamp")

    def test_parse_splunk_has_all_sourcetypes(self):
        types = {e.sourcetype for e in self.events}
        self.assertIn("access_combined",        types)
        self.assertIn("windows_auth_training",  types)
        self.assertIn("banking_transaction",    types)

    def test_score_risk_empty(self):
        self.assertEqual(self.ak.score_risk([]), 0.0)

    def test_score_risk_all_critical_10(self):
        ak = self.ak
        vulns = [ak.Vulnerability("1","CVE-0",10.0,"Critical","h","443","n","s")] * 4
        score = ak.score_risk(vulns)
        self.assertEqual(score, 100.0)

    def test_score_risk_entry_point_above_70(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        ep_vulns = [v for v in self.nessus if v.host == manifest["entry_point_host"]]
        score = self.ak.score_risk(ep_vulns)
        self.assertGreater(score, 70.0, f"Entry-point risk score too low: {score}")

    def test_flag_compromise_finds_entry_point(self):
        import json
        manifest = json.loads((LOGS / "scenario_manifest.json").read_text())
        ep = manifest["entry_point_host"]
        confirmed = self.ak.flag_confirmed_compromise(self.nessus, self.events)
        self.assertIn(ep, confirmed,
                      f"Entry point {ep} not in confirmed list: {confirmed}")

    def test_generate_report_creates_file(self):
        import tempfile, os
        findings = {
            "entry_point": "10.10.3.33", "attacker_ip": "197.188.3.210",
            "attack_timeline": [("2026-02-20 23:14:33", "SQLi success")],
            "compromised_accounts": ["NG12345678"],
            "host_scores": {"10.10.3.33": 95.0, "10.10.1.1": 30.0},
            "confirmed_hosts": ["10.10.3.33"],
        }
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out = f.name
        try:
            self.ak.generate_report(findings, out)
            content = Path(out).read_text()
            for section in ("EXECUTIVE SUMMARY", "ATTACK TIMELINE",
                            "AFFECTED HOSTS AND RISK SCORES",
                            "COMPROMISED ACCOUNTS",
                            "CONFIRMED COMPROMISE HOSTS",
                            "RECOMMENDATIONS"):
                self.assertIn(section, content, f"Missing section: {section}")
        finally:
            os.unlink(out)


class TestStudentSkeleton(unittest.TestCase):
    """Confirm each stub raises NotImplementedError (guards against accidental completion)."""

    @classmethod
    def setUpClass(cls):
        import analysis as student
        cls.s = student

    def test_parse_nessus_raises(self):
        with self.assertRaises(NotImplementedError):
            self.s.parse_nessus_csv("dummy.csv")

    def test_parse_splunk_raises(self):
        with self.assertRaises(NotImplementedError):
            self.s.parse_splunk_export("dummy.csv")

    def test_score_risk_raises(self):
        with self.assertRaises(NotImplementedError):
            self.s.score_risk([])

    def test_flag_compromise_raises(self):
        with self.assertRaises(NotImplementedError):
            self.s.flag_confirmed_compromise([], [])

    def test_generate_report_raises(self):
        with self.assertRaises(NotImplementedError):
            self.s.generate_report({}, "/tmp/x.txt")


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ensure_logs()
    build_mock_splunk_export()
    print("\n[*] Running tests …\n")
    unittest.main(argv=[__file__], verbosity=2)
