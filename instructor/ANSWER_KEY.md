# Instructor Answer Key — FirstBank Nigeria SOC Training

> **RESTRICTED — Do not distribute to students.**
> All data is synthetic; this key reflects the structure of answers, not a
> single fixed ground truth, because **findings vary by seed**.

---

## How Findings Are Derived From the Seed

The data generator (`data-generator/generate_logs.py`) uses `random.Random(seed)` to
deterministically produce every scenario parameter.  Run the generator with the
student's seed and inspect `logs/scenario_manifest.json` for the exact values.

```bash
STUDENT_SEED=<seed> python data-generator/generate_logs.py
cat logs/scenario_manifest.json
```

Example output (seed = 12345):

```json
{
  "seed": 12345,
  "scenario_date": "2026-02-20",
  "attack_window": "2026-02-20 23:00 – 2026-02-21 01:00 WAT",
  "attacker_ip":          "<external IP derived from seed>",
  "entry_point_host":     "<10.10.x.y — web server IP>",
  "entry_point_hostname": "<WEBSVRxx>",
  "txn_server_host":      "<10.10.a.b — transaction server IP>",
  "txn_server_hostname":  "<TXNSVRxx>",
  "service_account":      "<svc_backup | svc_monitor | …>"
}
```

All answers below reference these symbolic names; substitute actual values from
the manifest.

---

## Expected Findings By Phase

### Phase 1 — Splunk Investigation

#### 1.1  SQL Injection Detection

| Field | Expected Value |
|-------|----------------|
| Source IP | `<attacker_ip>` (external; non-RFC1918) |
| Target URI | `/login` |
| User-Agent | `sqlmap/1.7.8#stable` |
| Request method | `POST` (successful exploit) and `GET` (probing) |
| HTTP status | `401` (brute-force) then `200` (success) |
| Suspicious URI pattern | `%27+OR+%271%27%3D%271%27` in GET probe |

**Recommended SPL:**
```spl
index=banking_soc sourcetype=access_combined uri="/login"
| eval is_attack=if(like(useragent,"%sqlmap%") OR like(uri,"%27%") OR like(uri,"%1%3D1%"), "YES","no")
| where is_attack="YES"
| table _time, src_ip, method, status, useragent, uri
| sort _time
```

#### 1.2  Lateral Movement

| Event | EventCode | Key Fields |
|-------|-----------|------------|
| Service account session on web server | `4648` | `AccountName=<service_account>`, `SourceIP=<attacker_ip>` |
| Privilege assignment | `4672` | `AccountName=<service_account>`, `Privileges=SeBackupPrivilege…` |
| Network logon to txn server | `4624` | `LogonType=3`, `SourceIP=<entry_point_ip>`, `TargetServerName=<txn_server_hostname>` |
| Admin share access | `5140` | `ShareName=\\<txn_server_hostname>\ADMIN$` |

**Recommended SPL:**
```spl
index=banking_soc sourcetype=windows_auth_training
| where EventCode IN ("4624","4648","4672","5140")
| table _time, EventCode, AccountName, SourceIP, WorkstationName, TargetServerName, Privileges, ShareName
| sort _time
```

#### 1.3  Transfer Script Execution

| Event | EventCode | Key Fields |
|-------|-----------|------------|
| cmd.exe spawned | `4688` | `NewProcessName=…cmd.exe`, `AccountName=<service_account>`, `HostName=<txn_server_hostname>` |
| python.exe spawned | `4688` | `CommandLine=…bulk_transfer.py --batch overnight_batch_20260220.csv --execute` |
| Script exit | `4689` | `ExitCode=0x0` |

**Recommended SPL:**
```spl
index=banking_soc sourcetype=windows_auth_training EventCode=4688
| table _time, AccountName, NewProcessName, CommandLine, HostName
| sort _time
```

#### 1.4  Fraudulent Transfer Window

| Field | Expected Value |
|-------|----------------|
| `InitiatedBy` | `<service_account>` |
| `FromAccount` | `NG…` (victim Nigerian accounts) |
| `ToAccount` | `EX…` (external receiving accounts) |
| `TxnType` | `WIRE_TRANSFER` |
| Count | 5–8 transactions |
| Window | From ~`<t4 + 5-10 min>` to before `2026-02-21 01:00` |

**Recommended SPL:**
```spl
index=banking_soc sourcetype=banking_transaction InitiatedBy=svc_*
| table _time, TxnID, FromAccount, ToAccount, Amount, TxnType, Status, InitiatedBy
| sort _time
```

#### 1.5  Full Timeline Correlation

```spl
index=banking_soc
| eval event_summary=case(
    sourcetype="access_combined" AND like(_raw,"%sqlmap%"), "SQLi Probe/Success",
    sourcetype="windows_auth_training" AND EventCode="4648", "Svc Acct Session Created",
    sourcetype="windows_auth_training" AND EventCode="4624" AND LogonType="3", "Lateral Movement",
    sourcetype="windows_auth_training" AND EventCode="4688", "Process Execution",
    sourcetype="banking_transaction"   AND like(InitiatedBy,"svc_%"), "Fraudulent Transfer",
    true(), "Normal Activity"
  )
| where event_summary != "Normal Activity"
| table _time, sourcetype, event_summary, AccountName, SourceIP, Amount, CommandLine
| sort _time
```

---

### Phase 2 — Python Analysis

#### Task 1: `parse_nessus_csv()`

- Opens `nessus_scan.csv` with `csv.DictReader`
- Column `"CVSS v2.0 Base Score"` → `float`
- Returns a list of `Vulnerability` objects
- **Marker**: the entry point host will have `Name = "Web Application Login Form SQL Injection"`, `CVE = CVE-2023-23752`, `CVSS = 9.8`, `Risk = Critical`

#### Task 2: `parse_splunk_export()`

- Handles both ISO-8601 (`%Y-%m-%dT%H:%M:%S.%f%z`) and plain (`%Y-%m-%d %H:%M:%S`) timestamps
- All CSV columns go into `SplunkEvent.fields`
- Returns events sorted ascending by timestamp

#### Task 3: `score_risk()`

Reference values for the entry point host (SQLi vuln + 1–4 other vulns):

| Scenario | Expected range |
|----------|----------------|
| Only SQLi (CVSS 9.8, Critical) | ~73–83 |
| SQLi + 1 more Critical | ~73–100 |
| SQLi + 3 Criticals | 100 |

The formula provided in the docstring yields:

```
base           = (weighted_cvss / total_weight / 10.0) × 70
critical_bonus = min(30, n_criticals × 10)
score          = min(100, base + critical_bonus)
```

#### Task 4: `flag_confirmed_compromise()`

The intersection of:
- Nessus host IPs (all 10 scanned hosts)
- IPs appearing in `windows_auth_training` attack events (`EventCode` in `{4624,4648,4672,4688,4689,5140}`)

**Expected confirmed hosts**: `[<entry_point_ip>, <txn_server_ip>]`
- `entry_point_ip` appears as `SourceIP` in EventCode=4624 lateral-movement events
- `txn_server_ip` appears as the host in EventCode=4688 (script execution) events  
  (match by finding the IP in `_raw` since `host` may be a hostname)

Graders: accept a student's answer if it correctly identifies at least `entry_point_ip`.
Credit for `txn_server_ip` if the student scanned `_raw` for IPs.

#### Task 5: `generate_report()`

Mandatory sections (exact heading match required):

1. `EXECUTIVE SUMMARY`
2. `ATTACK TIMELINE`
3. `AFFECTED HOSTS AND RISK SCORES`
4. `COMPROMISED ACCOUNTS`
5. `CONFIRMED COMPROMISE HOSTS`
6. `RECOMMENDATIONS`

Deduct 5 points if any section is missing.

---

## Point Breakdown

| Component | Points |
|-----------|--------|
| **Phase 1 — Splunk** | **40** |
| SQLi detection (correct IP, URI, UA) | 10 |
| Lateral movement events (correct EventCodes + IPs) | 10 |
| Transfer script execution (correct CommandLine) | 10 |
| Reconstructed timeline (ordered, complete) | 10 |
| **Phase 2 — Python** | **40** |
| `parse_nessus_csv` working | 8 |
| `parse_splunk_export` working | 8 |
| `score_risk` correct formula | 8 |
| `flag_confirmed_compromise` correct intersection | 8 |
| `generate_report` all 6 sections, readable | 8 |
| **Phase 3 — Written Report** | **20** |
| Executive summary (non-technical, accurate) | 4 |
| Customer impact + account list | 4 |
| CBN/NDPC regulatory considerations | 6 |
| Remediation (technical + process) | 6 |
| **Bonus** | **+10** |
| Correctly identifies ALL compromised accounts | +5 |
| Identifies MITRE ATT&CK TTPs (T1190, T1078, T1059) | +5 |
| **Total** | **100 (+10)** |

---

## MITRE ATT&CK Mapping (for bonus grading)

| TTP | Technique | Evidence in logs |
|-----|-----------|------------------|
| T1190 | Exploit Public-Facing Application | SQLi in `web_access.log` |
| T1078 | Valid Accounts (Service Accounts) | `windows_auth.log` EventCode 4648/4624 |
| T1021.002 | SMB/Windows Admin Shares | EventCode 5140 `ADMIN$` |
| T1059.003 | Windows Command Shell | EventCode 4688 `cmd.exe` |
| T1059.006 | Python scripting | EventCode 4688 `python.exe bulk_transfer.py` |
| T1537 | Transfer Data to Cloud Account | `transaction.log` `EX…` accounts |

---

## Nigerian Regulatory Framework (Phase 3 grading notes)

Students should reference at least two of:

- **CBN Risk-Based Cybersecurity Framework (2022)** — mandates 2-hour incident notification to CBN; root-cause analysis within 5 business days.
- **BOFIA 2020 s.62** — requires prompt disclosure of material cybersecurity incidents to the CBN Governor.
- **NDPA 2023 (Nigeria Data Protection Act) s.40** — data breach notification to NDPC within 72 hours; customer notification without undue delay.
- **PCI DSS v4.0** — relevant because payment card data may be involved in wire-transfer infrastructure.

---

## Grading Notes for Instructors

1. **Seed validation**: before grading, run `python data-generator/generate_logs.py` with
   the student's seed and check `scenario_manifest.json`.  The entry point IP and attacker IP
   are seed-specific — don't mark wrong simply because they differ from seed 12345.

2. **`flag_confirmed_compromise` tolerance**: the transaction server IP may not appear in the
   Nessus scan for every seed (it is one of the 9 randomly placed other hosts; there is no
   guarantee it is among them).  If the txn server is not in the Nessus host list, full credit
   for returning only `[entry_point_ip]`.

3. **Splunk export format**: the SPL query in the README produces a CSV with `_time`,
   `sourcetype`, `host`, and extracted KV fields.  Students who used a different export query
   may have different column names — grade on functional correctness, not column name exactness.

4. **Timestamp format in Splunk export**: Splunk's default CSV export uses ISO-8601 with
   timezone offset.  If a student used a custom format, award full credit if parsing works.
