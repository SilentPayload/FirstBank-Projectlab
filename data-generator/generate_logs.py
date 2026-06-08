#!/usr/bin/env python3
"""
FirstBank Nigeria SOC Training — Synthetic Log Generator

DISCLAIMER: All data produced by this script is entirely synthetic and
fabricated for authorized cybersecurity training purposes only.  No real
customer accounts, IP addresses, transactions, or personally-identifiable
information are represented.  Use only within the scope of this training
exercise.
"""

import csv
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ─── Scenario constants ───────────────────────────────────────────────────────

ATTACK_START = datetime(2026, 2, 20, 23, 0, 0)   # 11 PM WAT
ATTACK_END   = datetime(2026, 2, 21,  1, 0, 0)   # 01 AM WAT
BIZ_START    = datetime(2026, 2, 20,  8, 0, 0)
BIZ_END      = datetime(2026, 2, 20, 18, 0, 0)

ATTACKER_FIRST_OCTETS = [45, 91, 103, 185, 194, 196, 197, 198, 199, 203, 212, 217]

NORMAL_USERS = [
    "adaobi.okafor", "chidi.nwosu", "funke.adeyemi",
    "emeka.eze", "ngozi.ibrahim", "tunde.afolabi",
    "amaka.obi", "segun.bello", "kemi.lawal", "ifeanyi.nduka",
]

NORMAL_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]

NORMAL_ENDPOINTS = [
    ("GET",  "/dashboard",              "200", "4096"),
    ("GET",  "/account/summary",        "200", "2048"),
    ("GET",  "/account/transactions",   "200", "8192"),
    ("POST", "/transfer/initiate",      "200", "512"),
    ("GET",  "/statements/download",    "200", "16384"),
    ("GET",  "/profile",                "200", "1024"),
    ("GET",  "/notifications",          "200", "768"),
    ("POST", "/login",                  "200", "512"),
    ("GET",  "/logout",                 "302", "0"),
    ("GET",  "/help",                   "200", "2048"),
    ("GET",  "/favicon.ico",            "200", "1150"),
    ("GET",  "/static/main.css",        "304", "0"),
]

SVC_ACCOUNTS = ["svc_backup", "svc_monitor", "svc_deploy", "svc_report", "svc_audit"]

# Each entry: (plugin_id, cve, cvss, risk, protocol, port, name, synopsis, solution)
VULN_POOL = [
    ("98710", "CVE-2023-23752", "9.8",  "Critical", "tcp", "443",
     "Web Application Login Form SQL Injection",
     "The remote web application login form fails to sanitize user input, allowing SQL injection.",
     "Use parameterized queries / prepared statements; deploy a WAF."),

    ("20007", "CVE-2021-44228", "10.0", "Critical", "tcp", "8080",
     "Apache Log4j Remote Code Execution (Log4Shell)",
     "Apache Log4j2 <=2.14.1 JNDI features allow attacker-controlled LDAP lookups leading to RCE.",
     "Upgrade Log4j to 2.17.1+ or set log4j2.formatMsgNoLookups=true."),

    ("45590", "CVE-2014-6271", "10.0", "Critical", "tcp", "80",
     "GNU Bash Remote Code Execution (Shellshock)",
     "GNU Bash through 4.3 processes trailing strings after function definitions, enabling RCE via CGI.",
     "Upgrade Bash to 4.3 patch 25 or later."),

    ("12085", "CVE-2021-34527", "8.8",  "High",     "tcp", "445",
     "Windows Print Spooler Remote Code Execution (PrintNightmare)",
     "Windows Print Spooler performs privileged file operations improperly, enabling RCE.",
     "Apply KB5004945 and disable remote printing if not required."),

    ("56984", "CVE-2020-1472",  "10.0", "Critical", "tcp", "135",
     "Netlogon Privilege Escalation (Zerologon)",
     "An attacker can establish an unauthenticated Netlogon channel to escalate to Domain Admin.",
     "Apply the August 2020 cumulative update and enforce secure channel."),

    ("65821", "CVE-2022-26134", "9.8",  "Critical", "tcp", "8090",
     "Atlassian Confluence OGNL Injection RCE",
     "Unauthenticated OGNL injection in Confluence Server allows arbitrary code execution.",
     "Upgrade Confluence to 7.4.17 / 7.13.7 / 7.18.1 or later."),

    ("33929", "CVE-2019-0708",  "9.8",  "Critical", "tcp", "3389",
     "BlueKeep: Windows RDP Remote Code Execution",
     "An unauthenticated attacker can connect via RDP and execute arbitrary code pre-auth.",
     "Apply MS19-0708 and enable Network Level Authentication."),

    ("78479", "CVE-2021-26855", "9.8",  "Critical", "tcp", "443",
     "Microsoft Exchange Server SSRF (ProxyLogon)",
     "SSRF allows authentication bypass on Exchange Server.",
     "Apply Exchange cumulative update for February 2021."),

    ("55976", "CVE-2023-44487", "7.5",  "High",     "tcp", "443",
     "HTTP/2 Rapid Reset Denial of Service",
     "A flaw in HTTP/2 allows DoS via rapid request cancellation (Rapid Reset).",
     "Update web server and apply vendor patches for HTTP/2 handling."),

    ("88912", "CVE-2018-11776", "9.8",  "Critical", "tcp", "8080",
     "Apache Struts Remote Code Execution",
     "Apache Struts 2.3-2.3.34 / 2.5-2.5.16 allow RCE when alwaysSelectFullNamespace=true.",
     "Upgrade to Struts 2.3.35 or 2.5.17."),

    ("23910", "CVE-2021-4034",  "7.8",  "High",     "tcp", "22",
     "Linux polkit Local Privilege Escalation (PwnKit)",
     "polkit pkexec allows unprivileged users to escalate to root.",
     "Update polkit via distribution package manager."),

    ("48243", "CVE-2021-40438", "9.0",  "Critical", "tcp", "80",
     "Apache HTTP Server mod_proxy SSRF",
     "A crafted request URI-path causes mod_proxy to forward requests to an attacker-chosen origin.",
     "Upgrade Apache to 2.4.51 or later."),

    ("71049", "CVE-2020-5902",  "10.0", "Critical", "tcp", "443",
     "F5 BIG-IP TMUI Remote Code Execution",
     "The Traffic Management User Interface is vulnerable to unauthenticated RCE.",
     "Upgrade BIG-IP or apply Hotfix-BIGIP-15.1.0.4-0.0.6."),

    ("66789", "CVE-2023-0386",  "7.0",  "High",     "tcp", "22",
     "Linux Kernel OverlayFS Privilege Escalation",
     "A flaw in OverlayFS allows privilege escalation via FUSE mount.",
     "Update the Linux kernel to a patched version."),

    ("34243", "CVE-2022-21907", "9.8",  "Critical", "tcp", "80",
     "Windows HTTP.sys Remote Code Execution",
     "Specially crafted HTTP requests to http.sys can achieve RCE.",
     "Apply Windows cumulative update KB5009543."),

    ("11213", "CVE-2022-22965", "9.8",  "Critical", "tcp", "8080",
     "Spring Framework RCE (Spring4Shell)",
     "Spring MVC on JDK 9+ allows RCE via data binding with a crafted request.",
     "Upgrade Spring Framework to 5.3.18 / 5.2.20+ and Spring Boot to 2.6.6 / 2.5.12."),

    ("51192", "CVE-2022-1388",  "9.8",  "Critical", "tcp", "443",
     "F5 BIG-IP iControl REST Authentication Bypass",
     "Undisclosed requests may bypass iControl REST authentication.",
     "Upgrade BIG-IP to 16.1.2.2 / 15.1.5.1 / 14.1.4.6 / 13.1.5."),

    ("10107", "CVE-2014-0160",  "5.0",  "Medium",   "tcp", "443",
     "OpenSSL Heartbleed Information Disclosure",
     "OpenSSL 1.0.1 through 1.0.1f allows remote attackers to read process memory.",
     "Upgrade OpenSSL to 1.0.1g or later."),

    ("44065", "CVE-2017-5638",  "10.0", "Critical", "tcp", "80",
     "Apache Struts Jakarta Multipart Parser RCE (Equifax)",
     "Malicious Content-Type header triggers RCE through the multipart parser.",
     "Upgrade to Apache Struts 2.3.32 / 2.5.10.1."),

    ("12345", "CVE-2022-0847",  "7.8",  "High",     "tcp", "22",
     "Linux Kernel Dirty Pipe Privilege Escalation",
     "A flaw in pipe memory pages allows privilege escalation.",
     "Update kernel to 5.16.11 / 5.15.25 / 5.10.102+."),
]


# ─── Scenario builder ─────────────────────────────────────────────────────────

def build_scenario(seed: int) -> dict:
    """Derive all attack-scenario constants deterministically from `seed`."""
    rng = random.Random(seed)

    # Attacker public IP
    first = rng.choice(ATTACKER_FIRST_OCTETS)
    attacker_ip = f"{first}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"

    # Entry-point web server (internal, subnet 10.10.1–5)
    ep3 = rng.randint(1, 5)
    ep4 = rng.randint(10, 50)
    entry_point_ip       = f"10.10.{ep3}.{ep4}"
    entry_point_hostname = f"WEBSVR{ep3:02d}"

    # Transaction server (different subnet, 10.10.6–10)
    ts3 = rng.randint(6, 10)
    ts4 = rng.randint(10, 50)
    txn_server_ip       = f"10.10.{ts3}.{ts4}"
    txn_server_hostname = f"TXNSVR{ts3 - 5:02d}"

    service_account = rng.choice(SVC_ACCOUNTS)
    batch_file = f"overnight_batch_{ATTACK_START.strftime('%Y%m%d')}.csv"

    # ── Attack timeline ──────────────────────────────────────────────────────
    t0_off = rng.randint(120, 600)                                  # recon start
    t0 = ATTACK_START + timedelta(seconds=t0_off)
    t1 = t0 + timedelta(minutes=rng.randint(8, 18),  seconds=rng.randint(0, 59))  # SQLi success
    t2 = t1 + timedelta(minutes=rng.randint(1,  3),  seconds=rng.randint(0, 59))  # svc acct session
    t3 = t2 + timedelta(minutes=rng.randint(1,  2),  seconds=rng.randint(0, 59))  # lateral movement
    t4 = t3 + timedelta(minutes=rng.randint(2,  5),  seconds=rng.randint(0, 59))  # script exec
    t5 = t4 + timedelta(minutes=rng.randint(5, 10),  seconds=rng.randint(0, 59))  # first fraud txn

    # ── Accounts ─────────────────────────────────────────────────────────────
    victim_accounts   = [f"NG{rng.randint(10_000_000, 99_999_999):08d}" for _ in range(5)]
    attacker_accounts = [f"EX{rng.randint(10_000_000, 99_999_999):08d}" for _ in range(3)]
    transfer_amounts  = [round(rng.uniform(500_000, 5_000_000), 2) for _ in range(10)]

    # ── Fraud transaction timestamps ─────────────────────────────────────────
    txn_count  = rng.randint(5, 8)
    txn_spread = int((ATTACK_END - t5).total_seconds())
    txn_times  = sorted(
        t5 + timedelta(seconds=rng.randint(0, txn_spread))
        for _ in range(txn_count)
    )

    # ── Nessus host list (10 hosts, index 0 = entry point) ───────────────────
    seen  = {entry_point_ip}
    other_hosts: list[str] = []
    while len(other_hosts) < 9:
        h = f"10.10.{rng.randint(1,10)}.{rng.randint(10,250)}"
        if h not in seen:
            seen.add(h)
            other_hosts.append(h)

    return {
        "seed":                 seed,
        "attacker_ip":          attacker_ip,
        "entry_point_ip":       entry_point_ip,
        "entry_point_hostname": entry_point_hostname,
        "txn_server_ip":        txn_server_ip,
        "txn_server_hostname":  txn_server_hostname,
        "service_account":      service_account,
        "batch_file":           batch_file,
        "t0": t0, "t1": t1, "t2": t2,
        "t3": t3, "t4": t4, "t5": t5,
        "txn_times":       txn_times,
        "txn_count":       txn_count,
        "victim_accounts": victim_accounts,
        "attacker_accounts": attacker_accounts,
        "transfer_amounts": transfer_amounts,
        "nessus_hosts":    [entry_point_ip] + other_hosts,
    }


# ─── Log generators ───────────────────────────────────────────────────────────

def _fmt_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0100")

def _rand_internal_ip(rng: random.Random) -> str:
    return f"10.10.{rng.randint(1,5)}.{rng.randint(10,100)}"


def generate_web_access_log(sc: dict, rng: random.Random, out: Path) -> None:
    lines: list[str] = []

    def apache_line(dt, src_ip, method, uri, status, size, ua, referer="-"):
        return (f'{src_ip} - - [{_fmt_apache(dt)}] '
                f'"{method} {uri} HTTP/1.1" {status} {size} '
                f'"{referer}" "{ua}"')

    # ── Business-hours normal traffic ────────────────────────────────────────
    cur = BIZ_START
    while cur < BIZ_END:
        user_ip = _rand_internal_ip(rng)
        meth, uri, status, size = rng.choice(NORMAL_ENDPOINTS)
        ua = rng.choice(NORMAL_UAS)
        ref = "https://banking.firstbanknigeria.com/login" if uri != "/login" else "-"
        lines.append(apache_line(cur, user_ip, meth, uri, status, size, ua, ref))
        cur += timedelta(seconds=rng.randint(30, 300))

    # ── Evening normal traffic ───────────────────────────────────────────────
    cur = BIZ_END
    while cur < ATTACK_START:
        user_ip = _rand_internal_ip(rng)
        meth, uri, status, size = rng.choice(NORMAL_ENDPOINTS)
        ua = rng.choice(NORMAL_UAS)
        lines.append(apache_line(cur, user_ip, meth, uri, status, size, ua))
        cur += timedelta(seconds=rng.randint(180, 900))

    # ── Phase 0: Recon / brute-force (failed logins from attacker IP) ────────
    cur = sc["t0"]
    sqli_ua = "sqlmap/1.7.8#stable (https://sqlmap.org)"
    for _ in range(rng.randint(12, 25)):
        lines.append(apache_line(cur, sc["attacker_ip"], "POST", "/login",
                                 "401", "256", sqli_ua))
        cur += timedelta(seconds=rng.randint(5, 30))

    # ── Phase 1: SQL injection success ───────────────────────────────────────
    # Probing GET with visible payload
    sqli_uri = "/login?username=%27+OR+%271%27%3D%271%27+--+&password=x"
    lines.append(apache_line(sc["t1"] - timedelta(seconds=45),
                             sc["attacker_ip"], "GET", sqli_uri, "200", "1024",
                             sqli_ua))
    # Successful POST exploitation
    lines.append(apache_line(sc["t1"], sc["attacker_ip"], "POST", "/login",
                             "200", "2048", sqli_ua))
    # Attacker enumerates after login
    for uri in ["/admin/users", "/admin/accounts", "/admin/export"]:
        cur = sc["t1"] + timedelta(seconds=rng.randint(10, 90))
        lines.append(apache_line(cur, sc["attacker_ip"], "GET", uri,
                                 "200", rng.randint(4096, 32768), sqli_ua))

    # ── Post-attack sparse normal traffic ────────────────────────────────────
    cur = sc["t4"] + timedelta(minutes=20)
    while cur < datetime(2026, 2, 21, 8, 0, 0):
        user_ip = _rand_internal_ip(rng)
        meth, uri, status, size = rng.choice(NORMAL_ENDPOINTS)
        ua = rng.choice(NORMAL_UAS)
        lines.append(apache_line(cur, user_ip, meth, uri, status, size, ua))
        cur += timedelta(seconds=rng.randint(600, 2400))

    lines.sort()
    out_path = out / "web_access.log"
    out_path.write_text("\n".join(lines) + "\n")
    print(f"  [+] {out_path.name}: {len(lines)} lines")


def generate_transaction_log(sc: dict, rng: random.Random, out: Path) -> None:
    lines: list[str] = []

    def txn_line(dt, txn_id, src_acct, dst_acct, amount, txn_type, status, actor):
        return (f"{dt.strftime('%Y-%m-%d %H:%M:%S')} "
                f"TxnID=TXN-{txn_id} "
                f"FromAccount={src_acct} "
                f"ToAccount={dst_acct} "
                f"Amount={amount:.2f} "
                f"TxnType={txn_type} "
                f"Status={status} "
                f"InitiatedBy={actor}")

    seq = 1000
    # Normal daytime transactions
    cur = BIZ_START + timedelta(minutes=15)
    internal_accts = [f"NG{rng.randint(10_000_000,99_999_999):08d}" for _ in range(20)]

    while cur < BIZ_END:
        src = rng.choice(internal_accts)
        dst = rng.choice([a for a in internal_accts if a != src])
        amount = round(rng.uniform(5_000, 200_000), 2)
        actor = rng.choice(NORMAL_USERS)
        txn_type = rng.choice(["INTERNAL_TRANSFER", "BILL_PAYMENT", "SALARY_PAYMENT"])
        lines.append(txn_line(cur, seq, src, dst, amount, txn_type, "COMPLETED", actor))
        seq += 1
        cur += timedelta(seconds=rng.randint(120, 900))

    # Fraudulent overnight transfers
    used_amounts = list(sc["transfer_amounts"])
    for i, dt in enumerate(sc["txn_times"]):
        victim  = sc["victim_accounts"][i % len(sc["victim_accounts"])]
        recv    = sc["attacker_accounts"][i % len(sc["attacker_accounts"])]
        amount  = used_amounts[i % len(used_amounts)]
        lines.append(txn_line(dt, seq, victim, recv, amount,
                              "WIRE_TRANSFER", "COMPLETED", sc["service_account"]))
        seq += 1

    lines.sort()
    out_path = out / "transaction.log"
    out_path.write_text("\n".join(lines) + "\n")
    print(f"  [+] {out_path.name}: {len(lines)} lines")


def generate_windows_auth_log(sc: dict, rng: random.Random, out: Path) -> None:
    lines: list[str] = []

    def auth_line(dt, **kv):
        parts = " ".join(f"{k}={v}" for k, v in kv.items())
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {parts}"

    # Normal business-hours logon/logoff events
    cur = BIZ_START
    while cur < BIZ_END:
        user = rng.choice(NORMAL_USERS)
        host = f"WKST-{rng.randint(1,30):03d}"
        lines.append(auth_line(cur, EventCode="4624", LogonType="2",
                                AccountName=user, SourceIP=_rand_internal_ip(rng),
                                WorkstationName=host, TargetServerName=host,
                                Status="Success"))
        off_offset = rng.randint(1800, 14400)
        lines.append(auth_line(cur + timedelta(seconds=off_offset),
                               EventCode="4634", LogonType="2",
                               AccountName=user, WorkstationName=host,
                               Status="Success"))
        cur += timedelta(seconds=rng.randint(120, 600))

    # ── T2: Service account session created on entry point ───────────────────
    lines.append(auth_line(sc["t2"],
                           EventCode="4648",
                           AccountName=sc["service_account"],
                           SourceIP=sc["attacker_ip"],
                           WorkstationName=sc["entry_point_hostname"],
                           TargetServerName=sc["entry_point_hostname"],
                           LogonType="8",
                           Status="Success"))

    # Privilege assignment immediately after
    lines.append(auth_line(sc["t2"] + timedelta(seconds=3),
                           EventCode="4672",
                           AccountName=sc["service_account"],
                           WorkstationName=sc["entry_point_hostname"],
                           Privileges="SeBackupPrivilege SeRestorePrivilege",
                           Status="Success"))

    # ── T3: Lateral movement — svc account connects to transaction server ─────
    lines.append(auth_line(sc["t3"],
                           EventCode="4624",
                           LogonType="3",
                           AccountName=sc["service_account"],
                           SourceIP=sc["entry_point_ip"],
                           WorkstationName=sc["entry_point_hostname"],
                           TargetServerName=sc["txn_server_hostname"],
                           Status="Success"))

    # Admin share access on txn server
    lines.append(auth_line(sc["t3"] + timedelta(seconds=rng.randint(5, 20)),
                           EventCode="5140",
                           AccountName=sc["service_account"],
                           SourceIP=sc["entry_point_ip"],
                           ShareName=f"\\\\{sc['txn_server_hostname']}\\ADMIN$",
                           WorkstationName=sc["txn_server_hostname"],
                           Status="Success"))

    # ── T4: Transfer script executed on transaction server ────────────────────
    lines.append(auth_line(sc["t4"],
                           EventCode="4688",
                           AccountName=sc["service_account"],
                           NewProcessName="C:\\Windows\\System32\\cmd.exe",
                           ParentProcess="services.exe",
                           HostName=sc["txn_server_hostname"],
                           Status="Success"))

    lines.append(auth_line(sc["t4"] + timedelta(seconds=8),
                           EventCode="4688",
                           AccountName=sc["service_account"],
                           NewProcessName="C:\\Python310\\python.exe",
                           CommandLine=f"python.exe C:\\Scripts\\bulk_transfer.py --batch {sc['batch_file']} --execute",
                           ParentProcess="cmd.exe",
                           HostName=sc["txn_server_hostname"],
                           Status="Success"))

    # Script completion
    lines.append(auth_line(sc["txn_times"][-1] + timedelta(seconds=rng.randint(30, 90)),
                           EventCode="4689",
                           AccountName=sc["service_account"],
                           ProcessName="C:\\Python310\\python.exe",
                           HostName=sc["txn_server_hostname"],
                           ExitCode="0x0",
                           Status="Success"))

    # Attacker disconnects
    lines.append(auth_line(sc["txn_times"][-1] + timedelta(seconds=rng.randint(120, 300)),
                           EventCode="4634",
                           LogonType="3",
                           AccountName=sc["service_account"],
                           WorkstationName=sc["txn_server_hostname"],
                           Status="Success"))

    lines.sort()
    out_path = out / "windows_auth.log"
    out_path.write_text("\n".join(lines) + "\n")
    print(f"  [+] {out_path.name}: {len(lines)} lines")


def generate_nessus_csv(sc: dict, rng: random.Random, out: Path) -> None:
    """
    10 hosts; index 0 (entry_point_ip) always carries the SQLi plugin.
    Each host gets 1-4 additional vulns drawn from VULN_POOL (no duplicates per host).
    """
    fieldnames = [
        "Plugin ID", "CVE", "CVSS v2.0 Base Score", "Risk",
        "Host", "Protocol", "Port", "Name",
        "Synopsis", "Description", "Solution", "See Also", "Plugin Output",
    ]

    # SQLi vuln is always first in VULN_POOL
    sqli_vuln = VULN_POOL[0]
    other_vulns = VULN_POOL[1:]

    rows: list[dict] = []

    for idx, host in enumerate(sc["nessus_hosts"]):
        host_pool = list(other_vulns)
        rng.shuffle(host_pool)
        num_vulns = rng.randint(1, 4)
        assigned = host_pool[:num_vulns]

        if idx == 0:
            assigned = [sqli_vuln] + assigned   # entry point always has SQLi

        for v in assigned:
            pid, cve, cvss, risk, proto, port, name, synopsis, solution = v
            rows.append({
                "Plugin ID":            pid,
                "CVE":                  cve,
                "CVSS v2.0 Base Score": cvss,
                "Risk":                 risk,
                "Host":                 host,
                "Protocol":             proto,
                "Port":                 port,
                "Name":                 name,
                "Synopsis":             synopsis,
                "Description":          f"Detected on host {host}:{port}. {synopsis}",
                "Solution":             solution,
                "See Also":             f"https://nvd.nist.gov/vuln/detail/{cve}",
                "Plugin Output":        f"Plugin fired on {host}:{port} — {name}.",
            })

    out_path = out / "nessus_scan.csv"
    with out_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  [+] {out_path.name}: {len(rows)} vulnerability rows across {len(sc['nessus_hosts'])} hosts")


def write_manifest(sc: dict, out: Path) -> None:
    """Write a seed-manifest JSON so the student knows their scenario variables."""
    import json
    manifest = {
        "seed":                 sc["seed"],
        "scenario_date":        "2026-02-20",
        "attack_window":        "2026-02-20 23:00 – 2026-02-21 01:00 WAT",
        "attacker_ip":          sc["attacker_ip"],
        "entry_point_host":     sc["entry_point_ip"],
        "entry_point_hostname": sc["entry_point_hostname"],
        "txn_server_host":      sc["txn_server_ip"],
        "txn_server_hostname":  sc["txn_server_hostname"],
        "service_account":      sc["service_account"],
    }
    out_path = out / "scenario_manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"  [+] {out_path.name}: scenario manifest written")


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    seed_str = os.environ.get("STUDENT_SEED", "12345")
    try:
        seed = int(seed_str)
    except ValueError:
        print(f"[!] STUDENT_SEED must be an integer, got: {seed_str!r}", file=sys.stderr)
        sys.exit(1)

    output_dir_str = os.environ.get("OUTPUT_DIR", "./logs")
    out = Path(output_dir_str)
    out.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] FirstBank Nigeria SOC Training — Log Generator")
    print(f"[*] Seed : {seed}")
    print(f"[*] Output : {out.resolve()}\n")

    sc   = build_scenario(seed)
    # Separate RNG for noise so attack artifacts are seed-stable regardless of
    # how many noise events are generated.
    noise_rng = random.Random(seed ^ 0xDEAD_BEEF)

    generate_web_access_log(sc,   noise_rng, out)
    generate_transaction_log(sc,  noise_rng, out)
    generate_windows_auth_log(sc, noise_rng, out)
    generate_nessus_csv(sc,       noise_rng, out)
    write_manifest(sc, out)

    print(f"\n[+] All artifacts written to {out.resolve()}")
    print(f"[+] Import nessus_scan.csv directly into your Python analysis.")
    print(f"[+] Upload the three .log files via Splunk (see README for instructions).\n")


if __name__ == "__main__":
    main()
