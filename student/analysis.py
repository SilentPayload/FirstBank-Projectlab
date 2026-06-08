#!/usr/bin/env python3
"""
FirstBank Nigeria — SOC Incident Response Analysis
Student Script  (Phase 2)

DISCLAIMER: All data processed by this script is entirely synthetic and
fabricated for authorized cybersecurity training purposes only.

Instructions
------------
1.  Run the data generator and start Splunk (see README.md).
2.  Complete the TODO sections below.  Do NOT modify function signatures or
    the main() block — the auto-grader relies on them.
3.  Run:  python analysis.py --nessus ../logs/nessus_scan.csv \
                              --splunk  splunk_export.csv \
                              --report  my_report.txt
"""

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

class Vulnerability:
    """Represents a single finding row from the Nessus CSV export."""

    def __init__(self, plugin_id: str, cve: str, cvss: float, risk: str,
                 host: str, port: str, name: str, synopsis: str):
        self.plugin_id  = plugin_id
        self.cve        = cve
        self.cvss       = cvss
        self.risk       = risk
        self.host       = host
        self.port       = port
        self.name       = name
        self.synopsis   = synopsis

    def __repr__(self) -> str:
        return f"Vulnerability(host={self.host!r}, cve={self.cve!r}, cvss={self.cvss}, risk={self.risk!r})"


class SplunkEvent:
    """Represents one event row exported from a Splunk search result."""

    def __init__(self, timestamp: datetime, sourcetype: str, host: str,
                 raw: str, fields: dict[str, str]):
        self.timestamp  = timestamp
        self.sourcetype = sourcetype
        self.host       = host
        self.raw        = raw
        self.fields     = fields          # all key=value pairs from the row

    def get(self, field: str, default: str = "") -> str:
        return self.fields.get(field, default)

    def __repr__(self) -> str:
        return f"SplunkEvent(ts={self.timestamp}, sourcetype={self.sourcetype!r}, host={self.host!r})"


# ──────────────────────────────────────────────────────────────────────────────
# Task 1 — Parse Nessus CSV export
# ──────────────────────────────────────────────────────────────────────────────

def parse_nessus_csv(filepath: str) -> list[Vulnerability]:
    """
    Parse a Nessus CSV export file and return a list of Vulnerability objects.

    Expected CSV columns (subset used):
        Plugin ID, CVE, CVSS v2.0 Base Score, Risk,
        Host, Port, Name, Synopsis

    Parameters
    ----------
    filepath : str
        Path to the Nessus CSV file (e.g. ``../logs/nessus_scan.csv``).

    Returns
    -------
    list[Vulnerability]
        One Vulnerability object per non-header row.  Rows where CVSS cannot
        be converted to float should be skipped with a warning to stderr.

    Hints
    -----
    * Open with ``csv.DictReader`` so column names are used as keys.
    * The CVSS column is a string — cast it with ``float()``.
    * The ``Host`` column contains the IP address of the scanned target.
    """
    # TODO: implement this function
    raise NotImplementedError("parse_nessus_csv — implement me!")


# ──────────────────────────────────────────────────────────────────────────────
# Task 2 — Parse Splunk CSV export
# ──────────────────────────────────────────────────────────────────────────────

def parse_splunk_export(filepath: str) -> list[SplunkEvent]:
    """
    Parse a Splunk search-result CSV export and return a list of SplunkEvent
    objects ordered by timestamp ascending.

    Expected CSV columns (from the recommended SPL — see README):
        _time, sourcetype, host, src_ip, AccountName,
        EventCode, CommandLine, Status, method, uri, useragent

    The ``_time`` column uses the format ``%Y-%m-%dT%H:%M:%S.%f%z`` when
    exported from Splunk in ISO-8601 form.  Fall back to
    ``%Y-%m-%d %H:%M:%S`` if parsing fails.

    Parameters
    ----------
    filepath : str
        Path to the Splunk CSV export file.

    Returns
    -------
    list[SplunkEvent]
        Events sorted by timestamp (earliest first).

    Hints
    -----
    * All CSV columns become ``SplunkEvent.fields``; the three special ones
      (``_time``, ``sourcetype``, ``host``) also map to dedicated attributes.
    * ``_raw`` may or may not be present; store empty string if absent.
    """
    # TODO: implement this function
    raise NotImplementedError("parse_splunk_export — implement me!")


# ──────────────────────────────────────────────────────────────────────────────
# Task 3 — Risk scoring
# ──────────────────────────────────────────────────────────────────────────────

def score_risk(host_vulns: list[Vulnerability]) -> float:
    """
    Compute a risk score in the range 0–100 for a single host given the list
    of its vulnerabilities.

    Scoring formula (design your own, but it must match these properties):
    * An empty list returns 0.0.
    * A host with only CVSS 10.0 Criticals must score > 90.
    * A host with only CVSS 0.0 / Risk=None must score < 10.
    * Each additional Critical finding should *increase* the score (up to 100).

    Suggested approach
    ------------------
    severity_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}

    weighted_cvss   = sum(v.cvss * severity_weight[v.risk] for v in host_vulns)
    total_weight    = sum(severity_weight[v.risk] for v in host_vulns)
    base_score      = (weighted_cvss / total_weight / 10.0) * 70   # → 0–70
    critical_bonus  = min(30, number_of_criticals * 10)            # → 0–30
    return min(100.0, base_score + critical_bonus)

    Parameters
    ----------
    host_vulns : list[Vulnerability]
        All vulnerabilities for *one* host.

    Returns
    -------
    float
        Risk score rounded to one decimal place.
    """
    # TODO: implement this function
    raise NotImplementedError("score_risk — implement me!")


# ──────────────────────────────────────────────────────────────────────────────
# Task 4 — Flag confirmed-compromise hosts
# ──────────────────────────────────────────────────────────────────────────────

def flag_confirmed_compromise(
    nessus_data: list[Vulnerability],
    splunk_events: list[SplunkEvent],
) -> list[str]:
    """
    Identify hosts that appear in BOTH the Nessus vulnerability data AND the
    Splunk attack events (i.e. hosts confirmed as part of the attack path).

    A host is "seen in Splunk attack events" if any SplunkEvent whose
    ``sourcetype`` is ``windows_auth_training`` contains an ``EventCode``
    value of ``4624``, ``4648``, ``4688``, or ``5140`` AND the event's
    ``host`` field (or ``TargetServerName`` / ``HostName`` fields) matches
    a host IP from the Nessus data.

    Tip: the ``host`` column in the Splunk CSV represents the server that
    *generated* the event (the Windows hostname), while ``SourceIP`` is the
    *connecting* client.  The entry-point IP will appear as ``SourceIP`` in
    lateral-movement events; the Nessus ``Host`` column is always an IP.
    Map hostnames to IPs using the ``scenario_manifest.json`` if needed, or
    look for the IP in the ``SourceIP`` field.

    Parameters
    ----------
    nessus_data   : list[Vulnerability]
    splunk_events : list[SplunkEvent]

    Returns
    -------
    list[str]
        Sorted list of IP addresses confirmed as compromised.
    """
    # TODO: implement this function
    raise NotImplementedError("flag_confirmed_compromise — implement me!")


# ──────────────────────────────────────────────────────────────────────────────
# Task 5 — Generate report
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(findings: dict[str, Any], output_path: str) -> None:
    """
    Write a structured plain-text incident report to ``output_path``.

    The ``findings`` dict has the following keys (all populated by main()):

    ``entry_point``     : str  — IP of the web server where SQLi occurred
    ``attacker_ip``     : str  — source IP of the attack (from web_access.log)
    ``attack_timeline`` : list[tuple[str, str]]
                          Ordered list of (timestamp_str, event_description)
    ``compromised_accounts`` : list[str] — victim account numbers
    ``host_scores``     : dict[str, float] — {host_ip: risk_score}
    ``confirmed_hosts`` : list[str] — IPs confirmed compromised

    Required report sections (match these headings exactly):
    1. EXECUTIVE SUMMARY
    2. ATTACK TIMELINE
    3. AFFECTED HOSTS AND RISK SCORES
    4. COMPROMISED ACCOUNTS
    5. CONFIRMED COMPROMISE HOSTS
    6. RECOMMENDATIONS

    Parameters
    ----------
    findings    : dict[str, Any]
    output_path : str  — path to the output .txt file

    Returns
    -------
    None  (side-effect: file written)
    """
    # TODO: implement this function
    raise NotImplementedError("generate_report — implement me!")


# ──────────────────────────────────────────────────────────────────────────────
# Helper utilities (provided — do not modify)
# ──────────────────────────────────────────────────────────────────────────────

def _group_by_host(vulns: list[Vulnerability]) -> dict[str, list[Vulnerability]]:
    """Return a dict mapping each host IP to its list of Vulnerability objects."""
    result: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        result.setdefault(v.host, []).append(v)
    return result


def _extract_attack_events(events: list[SplunkEvent]) -> list[SplunkEvent]:
    """Filter Splunk events to only those indicative of attack activity."""
    ATTACK_CODES = {"4624", "4634", "4648", "4672", "4688", "4689", "5140"}
    SQLI_KEYWORDS = ("sqlmap", "' OR '", "1=1", "%27", "bulk_transfer")

    attack: list[SplunkEvent] = []
    for ev in events:
        code = ev.get("EventCode")
        if code in ATTACK_CODES:
            attack.append(ev)
            continue
        raw = ev.raw.lower()
        if any(kw.lower() in raw for kw in SQLI_KEYWORDS):
            attack.append(ev)
    return attack


def _load_manifest(logs_dir: str) -> dict:
    """Load scenario_manifest.json if available (for cross-referencing IPs)."""
    import json
    p = Path(logs_dir) / "scenario_manifest.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Main  (do not modify)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="FirstBank Nigeria SOC — Incident Analysis Tool"
    )
    p.add_argument("--nessus", required=True,
                   help="Path to nessus_scan.csv (from data-generator output)")
    p.add_argument("--splunk", required=True,
                   help="Path to Splunk CSV export (downloaded from Splunk Web)")
    p.add_argument("--report", default="incident_report.txt",
                   help="Output path for the plain-text incident report")
    p.add_argument("--logs-dir", default="../logs",
                   help="Directory containing scenario_manifest.json")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    print("[*] Parsing Nessus CSV …")
    nessus_data = parse_nessus_csv(args.nessus)
    print(f"    {len(nessus_data)} vulnerability records loaded.")

    print("[*] Parsing Splunk export …")
    splunk_events = parse_splunk_export(args.splunk)
    print(f"    {len(splunk_events)} events loaded.")

    print("[*] Scoring host risk …")
    by_host = _group_by_host(nessus_data)
    host_scores = {host: score_risk(vulns) for host, vulns in by_host.items()}
    for host, score in sorted(host_scores.items(), key=lambda x: -x[1]):
        print(f"    {host:<18}  risk={score:.1f}")

    print("[*] Flagging confirmed compromise hosts …")
    confirmed = flag_confirmed_compromise(nessus_data, splunk_events)
    print(f"    Confirmed: {confirmed}")

    manifest = _load_manifest(args.logs_dir)

    # Build findings bundle for report
    attack_events = _extract_attack_events(splunk_events)
    timeline = [
        (str(ev.timestamp), ev.raw[:120])
        for ev in sorted(attack_events, key=lambda e: e.timestamp)
    ]

    # Derive attacker IP from web events
    attacker_ip = ""
    for ev in splunk_events:
        if ev.sourcetype == "access_combined":
            src = ev.get("src_ip") or ev.get("clientip", "")
            raw_lower = ev.raw.lower()
            if "sqlmap" in raw_lower or "%27" in raw_lower:
                attacker_ip = src
                break

    # Derive compromised accounts from transaction events
    compromised_accounts: list[str] = []
    for ev in splunk_events:
        if ev.sourcetype == "banking_transaction":
            acct = ev.get("FromAccount", "")
            if acct.startswith("NG") and acct not in compromised_accounts:
                compromised_accounts.append(acct)

    findings: dict[str, Any] = {
        "entry_point":           manifest.get("entry_point_host", "unknown"),
        "attacker_ip":           attacker_ip or manifest.get("attacker_ip", "unknown"),
        "attack_timeline":       timeline,
        "compromised_accounts":  compromised_accounts,
        "host_scores":           host_scores,
        "confirmed_hosts":       confirmed,
    }

    print(f"[*] Writing report to {args.report} …")
    generate_report(findings, args.report)
    print(f"[+] Done.  Report saved to {args.report}")


if __name__ == "__main__":
    main()
