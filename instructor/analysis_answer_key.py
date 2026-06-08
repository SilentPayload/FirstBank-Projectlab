#!/usr/bin/env python3
"""
FirstBank Nigeria — SOC Incident Response Analysis
INSTRUCTOR ANSWER KEY — do not distribute to students.

DISCLAIMER: All data is entirely synthetic, fabricated for authorized
cybersecurity training purposes only.
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Data models  (identical to student/analysis.py)
# ──────────────────────────────────────────────────────────────────────────────

class Vulnerability:
    def __init__(self, plugin_id, cve, cvss, risk, host, port, name, synopsis):
        self.plugin_id = plugin_id
        self.cve       = cve
        self.cvss      = cvss
        self.risk      = risk
        self.host      = host
        self.port      = port
        self.name      = name
        self.synopsis  = synopsis

    def __repr__(self):
        return f"Vulnerability(host={self.host!r}, cve={self.cve!r}, cvss={self.cvss}, risk={self.risk!r})"


class SplunkEvent:
    def __init__(self, timestamp, sourcetype, host, raw, fields):
        self.timestamp  = timestamp
        self.sourcetype = sourcetype
        self.host       = host
        self.raw        = raw
        self.fields     = fields

    def get(self, field, default=""):
        return self.fields.get(field, default)

    def __repr__(self):
        return f"SplunkEvent(ts={self.timestamp}, sourcetype={self.sourcetype!r}, host={self.host!r})"


# ──────────────────────────────────────────────────────────────────────────────
# Task 1 — parse_nessus_csv  ✓
# ──────────────────────────────────────────────────────────────────────────────

def parse_nessus_csv(filepath: str) -> list[Vulnerability]:
    """Parse Nessus CSV; return one Vulnerability per data row."""
    vulns: list[Vulnerability] = []
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cvss_raw = row.get("CVSS v2.0 Base Score", "0").strip()
            try:
                cvss = float(cvss_raw)
            except ValueError:
                print(f"[!] Skipping row with non-numeric CVSS: {cvss_raw!r}",
                      file=sys.stderr)
                continue
            vulns.append(Vulnerability(
                plugin_id = row.get("Plugin ID", "").strip(),
                cve       = row.get("CVE", "").strip(),
                cvss      = cvss,
                risk      = row.get("Risk", "None").strip(),
                host      = row.get("Host", "").strip(),
                port      = row.get("Port", "").strip(),
                name      = row.get("Name", "").strip(),
                synopsis  = row.get("Synopsis", "").strip(),
            ))
    return vulns


# ──────────────────────────────────────────────────────────────────────────────
# Task 2 — parse_splunk_export  ✓
# ──────────────────────────────────────────────────────────────────────────────

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",   # Splunk ISO with microseconds+tz
    "%Y-%m-%dT%H:%M:%S%z",      # Splunk ISO without microseconds
    "%Y-%m-%d %H:%M:%S",        # fallback plain
    "%m/%d/%Y %H:%M:%S",        # US locale Splunk default
]


def _parse_ts(raw: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {raw!r}")


def parse_splunk_export(filepath: str) -> list[SplunkEvent]:
    """Parse Splunk CSV export; return events sorted by timestamp."""
    events: list[SplunkEvent] = []
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            ts_raw = row.get("_time", "").strip()
            if not ts_raw:
                continue
            try:
                ts = _parse_ts(ts_raw)
            except ValueError as exc:
                print(f"[!] Skipping row with bad timestamp: {exc}", file=sys.stderr)
                continue
            events.append(SplunkEvent(
                timestamp  = ts,
                sourcetype = row.get("sourcetype", "").strip(),
                host       = row.get("host", "").strip(),
                raw        = row.get("_raw", "").strip(),
                fields     = {k: v for k, v in row.items()},
            ))
    return sorted(events, key=lambda e: e.timestamp)


# ──────────────────────────────────────────────────────────────────────────────
# Task 3 — score_risk  ✓
# ──────────────────────────────────────────────────────────────────────────────

_SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}


def score_risk(host_vulns: list[Vulnerability]) -> float:
    """
    Return a 0–100 risk score for one host.

    Formula
    -------
    weighted_cvss  = Σ(cvss_i × weight_i)
    total_weight   = Σ(weight_i)
    base           = (weighted_cvss / total_weight / 10.0) × 70   (→ 0–70)
    critical_bonus = min(30, count(Critical) × 10)                (→ 0–30)
    score          = min(100, base + critical_bonus)
    """
    if not host_vulns:
        return 0.0

    total_weight  = 0.0
    weighted_cvss = 0.0
    critical_count = 0

    for v in host_vulns:
        w = _SEVERITY_WEIGHT.get(v.risk, 0)
        weighted_cvss += v.cvss * w
        total_weight  += w
        if v.risk == "Critical":
            critical_count += 1

    if total_weight == 0:
        return 0.0

    base           = (weighted_cvss / total_weight / 10.0) * 70.0
    critical_bonus = min(30.0, critical_count * 10.0)
    return round(min(100.0, base + critical_bonus), 1)


# ──────────────────────────────────────────────────────────────────────────────
# Task 4 — flag_confirmed_compromise  ✓
# ──────────────────────────────────────────────────────────────────────────────

_ATTACK_EVENT_CODES = {"4624", "4648", "4672", "4688", "4689", "5140"}


def flag_confirmed_compromise(
    nessus_data: list[Vulnerability],
    splunk_events: list[SplunkEvent],
) -> list[str]:
    """
    Return sorted list of host IPs present in both Nessus scan results and
    Splunk attack events.

    Strategy
    --------
    1.  Collect all unique host IPs from nessus_data.
    2.  Collect all IPs seen in attack-relevant Splunk events by checking:
        * event['SourceIP']  — attacker/pivot source
        * event['host']      — the server that logged the event (may be a
          hostname; only match if it looks like an IP)
        * event['_raw']      — full raw event text for substring search
    3.  Intersect the two sets.
    """
    nessus_ips: set[str] = {v.host for v in nessus_data}

    attack_ips: set[str] = set()
    for ev in splunk_events:
        code = ev.get("EventCode", "")
        if code not in _ATTACK_EVENT_CODES:
            continue
        for field in ("SourceIP", "host"):
            val = ev.get(field, "").strip()
            if val and _looks_like_ip(val):
                attack_ips.add(val)
        # Also scan raw text for any IP that matches nessus_ips
        for ip in nessus_ips:
            if ip in ev.raw:
                attack_ips.add(ip)

    return sorted(nessus_ips & attack_ips)


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Task 5 — generate_report  ✓
# ──────────────────────────────────────────────────────────────────────────────

_HR = "=" * 72
_HR2 = "-" * 72


def generate_report(findings: dict[str, Any], output_path: str) -> None:
    """Write a structured plain-text incident report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        _HR,
        "FIRSTBANK NIGERIA — CYBERSECURITY INCIDENT REPORT",
        "SOC Training Exercise  |  SYNTHETIC DATA  |  Not for distribution",
        f"Generated : {now}",
        _HR,
        "",
        # ── 1. Executive Summary ──────────────────────────────────────────────
        "1.  EXECUTIVE SUMMARY",
        _HR2,
        (
            "On 2026-02-20 overnight, an unauthorized actor exploited a SQL injection "
            "vulnerability in the FirstBank Nigeria internet banking login form to gain "
            "access to internal systems.  The attacker performed lateral movement to the "
            "core transaction processing server and executed a bulk-transfer script that "
            "initiated multiple fraudulent wire transfers totalling an estimated "
            f"[see Section 4] NGN across {len(findings.get('compromised_accounts', []))} "
            "customer accounts."
        ),
        "",
        f"Entry-point host   : {findings.get('entry_point', 'unknown')}",
        f"Attacker source IP : {findings.get('attacker_ip', 'unknown')}",
        f"Confirmed hosts    : {', '.join(findings.get('confirmed_hosts', [])) or 'none identified'}",
        "",
        # ── 2. Attack Timeline ────────────────────────────────────────────────
        "2.  ATTACK TIMELINE",
        _HR2,
    ]

    timeline = findings.get("attack_timeline", [])
    if timeline:
        for ts, desc in timeline:
            lines.append(f"  {ts:<30}  {desc[:80]}")
    else:
        lines.append("  No timeline events extracted.")

    lines += [
        "",
        # ── 3. Affected Hosts ─────────────────────────────────────────────────
        "3.  AFFECTED HOSTS AND RISK SCORES",
        _HR2,
        f"  {'Host':<20} {'Risk Score':>12}  {'Severity Tier'}",
        f"  {'-'*20} {'-'*12}  {'-'*15}",
    ]

    host_scores = findings.get("host_scores", {})
    for host, score in sorted(host_scores.items(), key=lambda x: -x[1]):
        tier = (
            "CRITICAL" if score >= 90 else
            "HIGH"     if score >= 70 else
            "MEDIUM"   if score >= 40 else
            "LOW"
        )
        marker = " ◀ COMPROMISED" if host in findings.get("confirmed_hosts", []) else ""
        lines.append(f"  {host:<20} {score:>12.1f}  {tier}{marker}")

    lines += [
        "",
        # ── 4. Compromised Accounts ───────────────────────────────────────────
        "4.  COMPROMISED ACCOUNTS",
        _HR2,
    ]

    accounts = findings.get("compromised_accounts", [])
    if accounts:
        for acct in accounts:
            lines.append(f"  {acct}")
    else:
        lines.append("  No compromised accounts identified in Splunk export.")

    lines += [
        "",
        # ── 5. Confirmed Compromise Hosts ─────────────────────────────────────
        "5.  CONFIRMED COMPROMISE HOSTS",
        _HR2,
        (
            "The following hosts appear in BOTH the Nessus vulnerability scan "
            "(exploitable CVEs) AND Splunk attack-event logs, confirming active compromise:"
        ),
        "",
    ]

    for host in findings.get("confirmed_hosts", []):
        score = host_scores.get(host, 0.0)
        lines.append(f"  {host}  (risk score {score:.1f})")

    if not findings.get("confirmed_hosts"):
        lines.append("  None identified — check flag_confirmed_compromise() implementation.")

    lines += [
        "",
        # ── 6. Recommendations ────────────────────────────────────────────────
        "6.  RECOMMENDATIONS",
        _HR2,
        "Immediate (0–24 h):",
        "  [1] Isolate entry-point web server from production network.",
        "  [2] Rotate all service-account credentials; audit group memberships.",
        "  [3] Freeze outbound wire-transfer queue pending fraud review.",
        "  [4] Notify CBN (Central Bank of Nigeria) per BOFIA 2020 s.62 and",
        "      the CBN Risk-Based Cybersecurity Framework within 2 hours of",
        "      confirmed compromise.",
        "  [5] Notify NDPC (Nigeria Data Protection Commission) within 72 hours",
        "      if customer PII was exfiltrated (NDPA 2023 s.40).",
        "",
        "Short-term (1–7 days):",
        "  [6] Patch /login endpoint: replace dynamic SQL with parameterised",
        "      queries (PDO / SQLAlchemy / ORM).",
        "  [7] Deploy WAF rule to block SQLi patterns on all public endpoints.",
        "  [8] Enforce network segmentation: web tier must not authenticate",
        "      directly to transaction server; require jump-host + MFA.",
        "  [9] Implement Privileged Access Management (PAM) for service accounts.",
        " [10] Enable Splunk alerting on EventCode=4688 with transfer-script",
        "      keywords.",
        "",
        "Long-term (30+ days):",
        " [11] Conduct full penetration test of internet-banking stack.",
        " [12] Remediate all Critical/High CVEs identified in Nessus scan.",
        " [13] Implement SIEM use-case library aligned to MITRE ATT&CK FS (T1190,",
        "      T1078, T1053, T1110).",
        " [14] Run quarterly CBN-mandated Business Continuity Plan (BCP) drills.",
        "",
        _HR,
        "END OF REPORT",
        _HR,
    ]

    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers (identical to student version)
# ──────────────────────────────────────────────────────────────────────────────

def _group_by_host(vulns):
    result = {}
    for v in vulns:
        result.setdefault(v.host, []).append(v)
    return result


def _extract_attack_events(events):
    ATTACK_CODES   = {"4624", "4634", "4648", "4672", "4688", "4689", "5140"}
    SQLI_KEYWORDS  = ("sqlmap", "' OR '", "1=1", "%27", "bulk_transfer")
    attack = []
    for ev in events:
        if ev.get("EventCode") in ATTACK_CODES:
            attack.append(ev); continue
        if any(kw.lower() in ev.raw.lower() for kw in SQLI_KEYWORDS):
            attack.append(ev)
    return attack


def _load_manifest(logs_dir):
    import json
    p = Path(logs_dir) / "scenario_manifest.json"
    return json.loads(p.read_text()) if p.exists() else {}


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args():
    p = argparse.ArgumentParser(description="Answer key — FirstBank SOC Analysis")
    p.add_argument("--nessus",   required=True)
    p.add_argument("--splunk",   required=True)
    p.add_argument("--report",   default="incident_report_answer_key.txt")
    p.add_argument("--logs-dir", default="../logs")
    return p.parse_args()


def main():
    args = _parse_args()

    print("[*] Parsing Nessus CSV …")
    nessus_data = parse_nessus_csv(args.nessus)
    print(f"    {len(nessus_data)} vulnerability records.")

    print("[*] Parsing Splunk export …")
    splunk_events = parse_splunk_export(args.splunk)
    print(f"    {len(splunk_events)} events.")

    print("[*] Scoring hosts …")
    by_host     = _group_by_host(nessus_data)
    host_scores = {h: score_risk(vs) for h, vs in by_host.items()}
    for h, s in sorted(host_scores.items(), key=lambda x: -x[1]):
        print(f"    {h:<18} risk={s:.1f}")

    print("[*] Flagging compromise …")
    confirmed = flag_confirmed_compromise(nessus_data, splunk_events)
    print(f"    Confirmed: {confirmed}")

    manifest      = _load_manifest(args.logs_dir)
    attack_events = _extract_attack_events(splunk_events)
    timeline = [
        (str(ev.timestamp), ev.raw[:120])
        for ev in sorted(attack_events, key=lambda e: e.timestamp)
    ]

    attacker_ip = ""
    for ev in splunk_events:
        if ev.sourcetype == "access_combined":
            src = ev.get("src_ip") or ev.get("clientip", "")
            if "sqlmap" in ev.raw.lower() or "%27" in ev.raw:
                attacker_ip = src; break

    compromised_accounts: list[str] = []
    for ev in splunk_events:
        if ev.sourcetype == "banking_transaction":
            acct = ev.get("FromAccount", "")
            if acct.startswith("NG") and acct not in compromised_accounts:
                compromised_accounts.append(acct)

    findings = {
        "entry_point":          manifest.get("entry_point_host", "unknown"),
        "attacker_ip":          attacker_ip or manifest.get("attacker_ip", "unknown"),
        "attack_timeline":      timeline,
        "compromised_accounts": compromised_accounts,
        "host_scores":          host_scores,
        "confirmed_hosts":      confirmed,
    }

    print(f"[*] Writing report to {args.report} …")
    generate_report(findings, args.report)
    print(f"[+] Done — {args.report}")


if __name__ == "__main__":
    main()
